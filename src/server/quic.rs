use crate::server::control_server::handler::ControlHandler;
use crate::server::control_server::service::ControlService;
use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, RecvStream, SendStream};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

pub struct QuicConfig {
    pub addr: SocketAddr,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

pub async fn listen(quic_config: QuicConfig, control_service: ControlService) -> Result<()> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(quic_config.certs, quic_config.key)
        .context("TLS config error")?;

    let server_crypto = QuicServerConfig::try_from(config)
        .map_err(|e| anyhow::anyhow!("QUIC TLS config error: {:?}", e))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let endpoint = quinn::Endpoint::server(server_config, quic_config.addr)
        .context(format!("server error:{}", quic_config.addr))?;
    log::info!("QUIC listening on: {}", quic_config.addr);

    tokio::spawn(async move {
        if let Err(e) = quic_endpoint_accept(endpoint, control_service).await {
            log::error!("quic_endpoint_accept: {:?}", e);
        }
    });

    Ok(())
}
async fn quic_endpoint_accept(
    endpoint: Endpoint,
    control_service: ControlService,
) -> anyhow::Result<()> {
    loop {
        let connecting = endpoint.accept().await.context("quic accept error")?;
        let remote_addr = connecting.remote_address();
        let control_service = control_service.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    log::info!("QUIC connection: {}", remote_addr);
                    match tokio::time::timeout(Duration::from_secs(10), connection.accept_bi())
                        .await
                    {
                        Ok(Ok((send_stream, recv_stream))) => {
                            tokio::spawn(async move {
                                if let Err(e) = quic_stream_handle(
                                    remote_addr,
                                    send_stream,
                                    recv_stream,
                                    control_service,
                                )
                                .await
                                {
                                    log::error!(
                                        "quic_stream_handle error: {:?},remote_addr={remote_addr}",
                                        e
                                    );
                                }
                            });
                        }
                        Ok(Err(e)) => {
                            log::info!("quic close: {remote_addr},{e:?}",);
                        }
                        Err(_e) => {
                            log::error!("quic accept_bi timeout: {remote_addr}");
                        }
                    }
                }
                Err(e) => {
                    log::error!("connect: {:?},remote_addr={remote_addr}", e);
                }
            }
        });
    }
}

async fn quic_stream_handle(
    addr: SocketAddr,
    send_stream: SendStream,
    recv_stream: RecvStream,
    control_service: ControlService,
) -> anyhow::Result<()> {
    let mut framed_write = FramedWrite::new(send_stream, LengthDelimitedCodec::new());
    let mut framed_read = FramedRead::new(recv_stream, LengthDelimitedCodec::new());

    let first = tokio::time::timeout(Duration::from_secs(5), framed_read.next()).await;
    let Ok(first) = first else {
        bail!("quic framed read timed out");
    };
    let Some(first) = first else {
        bail!("framed_read next empty");
    };
    let buf = first?;
    let (out_sender, mut out_receiver) = tokio::sync::mpsc::channel(1024);
    let (in_sender, mut in_receiver) = tokio::sync::mpsc::channel(1024);
    let mut handler = ControlHandler::new(control_service, addr, out_sender.downgrade());

    handler.handle_reg(&buf).await?;
    drop(buf);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(data) = out_receiver.recv() => {
                    if let Err(e) = framed_write.send(data).await {
                        log::warn!("quic framed_write send error: {},addr={addr}", e);
                        break;
                    }
                }
                Some(rs) = framed_read.next() => {
                    match rs {
                        Ok(bytes) => {
                            if in_sender.send(bytes).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::warn!("quic framed_read error: {},addr={addr}", e);
                            break;
                        }
                    }
                }

                else => {
                    break;
                }
            }
        }
        _ = framed_write.close().await;
    });

    while let Ok(Some(buf)) =
        tokio::time::timeout(Duration::from_secs(20), in_receiver.recv()).await
    {
        handler.handle_data(buf).await?;
    }

    Ok(())
}
