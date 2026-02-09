use crate::server::control_server::handler::ControlHandler;
use crate::server::control_server::service::ControlService;
use anyhow::{Context, bail};
use futures::{SinkExt, StreamExt};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct TcpConfig {
    pub addr: SocketAddr,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

pub async fn listen(tcp_config: TcpConfig, control_service: ControlService) -> anyhow::Result<()> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tcp_config.certs, tcp_config.key)
        .context("TLS config error")?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(tcp_config.addr)
        .await
        .context(format!("bind error:{}", tcp_config.addr))?;
    log::info!("TCP listening on: {} (TLS)", tcp_config.addr);
    tokio::spawn(async move {
        if let Err(e) = tcp_accept(acceptor, listener, control_service).await {
            log::error!("tcp_accept:{e:?}")
        }
    });
    Ok(())
}
async fn tcp_accept(
    acceptor: TlsAcceptor,
    listener: TcpListener,
    control_service: ControlService,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await.context("tcp accept error")?;
        log::info!("accept tcp: {peer_addr}");

        let acceptor = acceptor.clone();
        let control_service = control_service.clone();
        if let Err(e) = stream.set_nodelay(true) {
            log::debug!("set_nodelay error: {e:?}");
        }
        tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    log::info!("accept tls tcp: {peer_addr}");
                    if let Err(e) = stream_handle(peer_addr, tls_stream, control_service).await {
                        log::error!("tls_stream_handle error:{:?},peer_addr={peer_addr}", e);
                    }
                }
                Ok(Err(e)) => {
                    log::error!("accept tls tcp error: {e}, peer_addr={peer_addr}");
                }
                Err(_e) => {
                    log::error!("accept tls tcp timeout, peer_addr={peer_addr}");
                }
            }
        });
    }
}
pub async fn stream_handle<S>(
    addr: SocketAddr,
    stream: S,
    control_service: ControlService,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
    let first = tokio::time::timeout(Duration::from_secs(5), framed.next()).await;
    let Ok(first) = first else {
        bail!("quic framed read timed out");
    };
    let Some(first) = first else {
        bail!("framed next empty");
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
                    if let Err(e) = framed.send(data).await {
                        log::warn!("framed send error: {},addr={addr}", e);
                        break;
                    }
                }
                Some(rs) = framed.next() => {
                    match rs {
                        Ok(bytes) => {
                            if let Err(_closed) = in_sender.send(bytes).await {
                                break;
                            }
                        }
                        Err(e) => {
                            log::warn!("framed read error: {},addr={addr}", e);
                            break;
                        }
                    }
                }
                else => {
                    break;
                }
            }
        }
        _ = framed.close().await;
    });

    while let Ok(Some(buf)) =
        tokio::time::timeout(Duration::from_secs(20), in_receiver.recv()).await
    {
        handler.handle_data(buf).await?;
    }

    Ok(())
}
