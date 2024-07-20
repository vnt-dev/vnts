use crate::core::service::PacketHandler;
use crate::core::store::cache::VntContext;
use crate::protocol::NetPacket;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Sender};

const TCP_MAX_PACKET_SIZE: usize = (1 << 24) - 1;

pub async fn start(tcp: TcpListener, handler: PacketHandler) {
    if let Err(e) = accept(tcp, handler).await {
        log::error!("accept {:?}", e);
    }
}

async fn accept(tcp: TcpListener, handler: PacketHandler) -> io::Result<()> {
    loop {
        let (stream, addr) = tcp.accept().await?;
        let _ = stream.set_nodelay(true);
        tokio::spawn(stream_handle(stream, addr, handler.clone()));
    }
}

async fn stream_handle(stream: TcpStream, addr: SocketAddr, handler: PacketHandler) {
    {
        let mut buf = [0u8; 1];
        match stream.peek(&mut buf).await {
            Ok(len) => {
                if len == 0 {
                    log::warn!("数据流读取失败 {}", addr);
                    return;
                }
                if buf[0] != 0 {
                    //可能是ws协议
                    crate::core::server::websocket::handle_websocket_connection(
                        stream, addr, handler,
                    )
                    .await;
                    return;
                }
            }
            Err(e) => {
                log::warn!("数据流读取失败 {:?} {}", e, addr);
                return;
            }
        }
    }

    let (r, mut w) = stream.into_split();

    let (sender, mut receiver) = channel::<Vec<u8>>(100);
    tokio::spawn(async move {
        while let Some(data) = receiver.recv().await {
            let len = data.len();
            if len > TCP_MAX_PACKET_SIZE {
                log::warn!("超过了tcp的最大长度传输 地址{}", addr);
                return;
            }
            if let Err(e) = w
                .write_all(&[0, (len >> 16) as u8, (len >> 8) as u8, len as u8])
                .await
            {
                log::info!("发送失败,链接终止:{:?},{:?}", addr, e);
                break;
            }
            if let Err(e) = w.write_all(&data).await {
                log::info!("发送失败,链接终止:{:?},{:?}", addr, e);
                break;
            }
        }
        let _ = w.shutdown().await;
    });
    tokio::spawn(async move {
        let mut context = VntContext {
            link_context: None,
            server_cipher: None,
            link_address: addr,
        };
        if let Err(e) = tcp_read(&mut context, r, addr, sender, &handler).await {
            log::warn!("tcp_read {:?}", e)
        }
        handler.leave(context).await;
    });
}

async fn tcp_read(
    context: &mut VntContext,
    mut read: OwnedReadHalf,
    addr: SocketAddr,
    sender: Sender<Vec<u8>>,
    handler: &PacketHandler,
) -> io::Result<()> {
    let mut head = [0; 4];
    let mut buf = [0; 65536];
    let sender = Some(sender);

    loop {
        read.read_exact(&mut head).await?;
        if head[0] != 0 {
            log::warn!("tcp数据流错误 来源地址 {}", addr);
            return Ok(());
        }
        let len = ((head[1] as usize) << 16) | ((head[2] as usize) << 8) | head[3] as usize;
        if len < 12 || len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "length overflow",
            ));
        }
        read.read_exact(&mut buf[..len]).await?;
        let packet = NetPacket::new0(len, &mut buf)?;
        if let Some(rs) = handler.handle(context, packet, addr, &sender).await {
            if sender
                .as_ref()
                .unwrap()
                .send(rs.buffer().to_vec())
                .await
                .is_err()
            {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "send error"));
            }
        }
    }
}
