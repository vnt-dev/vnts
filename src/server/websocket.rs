use crate::server::control_server::handler::ControlHandler;
use crate::server::control_server::service::ControlService;
use anyhow::{Context, bail};
use futures::{SinkExt, StreamExt};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

pub struct WebSocketConfig {
    pub addr: SocketAddr,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

pub async fn listen(
    ws_config: WebSocketConfig,
    control_service: ControlService,
) -> anyhow::Result<()> {
    let certs = ws_config.certs;
    let key = ws_config.key;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS config error")?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(ws_config.addr)
        .await
        .context(format!("tcp bind error:{}", ws_config.addr))?;

    log::info!("WebSocket listening on: {} (TLS)", ws_config.addr,);

    tokio::spawn(async move {
        if let Err(e) = ws_accept(tls_acceptor, listener, control_service).await {
            log::error!("ws_accept:{e:?}")
        }
    });

    Ok(())
}

async fn ws_accept(
    tls_acceptor: TlsAcceptor,
    listener: TcpListener,
    control_service: ControlService,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await.context("tcp accept error")?;
        log::info!("accept websocket connection: {peer_addr}");

        let tls_acceptor = tls_acceptor.clone();
        let control_service = control_service.clone();
        if let Err(e) = stream.set_nodelay(true) {
            log::debug!("set_nodelay error: {e:?}");
        }
        tokio::spawn(async move {
            let result = match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    log::info!("accept wss: {peer_addr}");
                    match accept_async(tls_stream).await {
                        Ok(ws_stream) => {
                            ws_stream_handle(peer_addr, ws_stream, control_service).await
                        }
                        Err(e) => {
                            log::error!("websocket handshake error: {e}, peer_addr={peer_addr}");
                            Ok(())
                        }
                    }
                }
                Err(e) => {
                    log::error!("tls accept error: {e}, peer_addr={peer_addr}");
                    Ok(())
                }
            };

            if let Err(e) = result {
                log::error!("ws_stream_handle error:{:?}, peer_addr={peer_addr}", e);
            }
        });
    }
}

pub async fn ws_stream_handle<S>(
    addr: SocketAddr,
    mut ws_stream: WebSocketStream<S>,
    control_service: ControlService,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let first = tokio::time::timeout(Duration::from_secs(5), ws_stream.next()).await;
    let Ok(first) = first else {
        bail!("quic framed read timed out");
    };
    let Some(first) = first else {
        bail!("websocket connection closed before receiving first message");
    };
    let first_msg = first?;

    let buf = match first_msg {
        Message::Binary(data) => data,
        Message::Close(_) => bail!("received close frame as first message"),
        _ => bail!("unexpected first message type"),
    };

    let (out_sender, mut out_receiver) = tokio::sync::mpsc::channel(1024);
    let (in_sender, mut in_receiver) = tokio::sync::mpsc::channel(1024);

    let mut handler = ControlHandler::new(control_service, addr, out_sender.downgrade());
    handler.handle_reg(&buf).await?;
    drop(buf);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(data) = out_receiver.recv() => {
                    if let Err(e) = ws_stream.send(Message::Binary(data)).await {
                        log::warn!("websocket send error: {},addr={addr}", e);
                        break;
                    }
                }
                Some(rs) = ws_stream.next() => {
                    match rs {
                        Ok(msg) => {
                            match msg {
                                Message::Binary(data) => {
                                    if let Err(_closed) = in_sender.send(data.into()).await {
                                        break;
                                    }
                                }
                                Message::Close(_) => {
                                    log::info!("websocket closed by peer: {},addr={addr}", addr);
                                    break;
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                            log::warn!("websocket read error: {},addr={addr}", e);
                            break;
                        }
                    }
                }

                else => {
                    break;
                }
            }
        }
        _ = ws_stream.close(None).await;
    });

    while let Ok(Some(buf)) =
        tokio::time::timeout(Duration::from_secs(20), in_receiver.recv()).await
    {
        handler.handle_data(buf).await?;
    }

    Ok(())
}
