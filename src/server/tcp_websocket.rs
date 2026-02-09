use crate::server::control_server::service::ControlService;
use anyhow::Context;
use bytes::BufMut;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::accept_async;

pub struct HybridConfig {
    pub addr: SocketAddr,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

pub async fn listen(config: HybridConfig, control_service: ControlService) -> anyhow::Result<()> {
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(config.certs, config.key)
        .context("TLS config error")?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(config.addr)
        .await
        .context(format!("bind error:{}", config.addr))?;

    log::info!("TCP/WebSocket listening on: {} (TLS)", config.addr);

    tokio::spawn(async move {
        if let Err(e) = hybrid_accept(tls_acceptor, listener, control_service).await {
            log::error!("hybrid_accept:{e:?}")
        }
    });

    Ok(())
}

async fn hybrid_accept(
    tls_acceptor: TlsAcceptor,
    listener: TcpListener,
    control_service: ControlService,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await.context("tcp accept error")?;
        log::info!("accept connection: {peer_addr}");

        let tls_acceptor = tls_acceptor.clone();
        let control_service = control_service.clone();
        if let Err(e) = stream.set_nodelay(true) {
            log::debug!("set_nodelay error: {e:?}");
        }
        tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(10), tls_acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    log::info!("TLS handshake success: {peer_addr}");
                    if let Err(e) = handle_connection(peer_addr, tls_stream, control_service).await
                    {
                        log::error!("handle_connection error:{:?}, peer_addr={peer_addr}", e);
                    }
                }
                Ok(Err(e)) => {
                    log::error!("TLS accept error: {e}, peer_addr={peer_addr}");
                }
                Err(_) => {
                    log::error!("TLS accept timeout, peer_addr={peer_addr}");
                }
            }
        });
    }
}

async fn handle_connection(
    addr: SocketAddr,
    tls_stream: TlsStream<TcpStream>,
    control_service: ControlService,
) -> anyhow::Result<()> {
    let mut peekable_stream = PeekableStream::new(tls_stream);

    let first_data = peekable_stream.peek().await?;

    let is_websocket = is_websocket_handshake(first_data);

    if is_websocket {
        log::info!("Detected WebSocket protocol: {addr}");
        handle_websocket(addr, peekable_stream.into_inner(), control_service).await
    } else {
        log::info!("Detected TCP protocol: {addr}");
        crate::server::tcp::stream_handle(addr, peekable_stream.into_inner(), control_service).await
    }
}

fn is_websocket_handshake(first_data: u32) -> bool {
    &first_data.to_be_bytes() == b"GET "
}

async fn handle_websocket<S>(
    addr: SocketAddr,
    stream: S,
    control_service: ControlService,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws_stream = accept_async(stream)
        .await
        .context("WebSocket handshake failed")?;
    crate::server::websocket::ws_stream_handle(addr, ws_stream, control_service).await
}

struct PeekableStream<S> {
    stream: S,
    peeked: Option<u32>,
}

impl<S> PeekableStream<S>
where
    S: AsyncRead + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream,
            peeked: None,
        }
    }

    async fn peek(&mut self) -> std::io::Result<u32> {
        let peeked = self.stream.read_u32().await?;
        self.peeked.replace(peeked);
        Ok(peeked)
    }

    fn into_inner(self) -> PeekableStreamWrapper<S> {
        PeekableStreamWrapper {
            stream: self.stream,
            peeked: self.peeked,
        }
    }
}

pub struct PeekableStreamWrapper<S> {
    stream: S,
    peeked: Option<u32>,
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekableStreamWrapper<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.peeked.is_some() {
            if let Some(peeked) = self.peeked.take() {
                if buf.remaining() < 4 {
                    return std::task::Poll::Ready(Err(std::io::Error::other("too small")));
                }
                buf.put_u32(peeked);
            }
        }

        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekableStreamWrapper<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
