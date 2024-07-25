use crate::core::service::PacketHandler;
use crate::core::store::cache::VntContext;
use crate::protocol::NetPacket;
use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::mpsc::channel;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

pub async fn handle_websocket_connection(
    stream: TcpStream,
    addr: SocketAddr,
    handler: PacketHandler,
) {
    tokio::spawn(async move {
        let mut context = VntContext {
            link_context: None,
            server_cipher: None,
            link_address: addr,
        };
        if let Err(e) = handle_websocket_connection0(&mut context, stream, addr, &handler).await {
            log::warn!("websocket err {:?} {}", e, addr);
        }
        handler.leave(context).await;
    });
}

async fn handle_websocket_connection0(
    context: &mut VntContext,
    stream: TcpStream,
    addr: SocketAddr,
    handler: &PacketHandler,
) -> anyhow::Result<()> {
    let ws_stream = accept_async(stream)
        .await
        .with_context(|| format!("Error during WebSocket handshake {}", addr))?;

    let (mut ws_write, mut ws_read) = ws_stream.split();

    let (sender, mut receiver) = channel::<Vec<u8>>(100);
    tokio::spawn(async move {
        while let Some(data) = receiver.recv().await {
            if let Err(e) = ws_write.send(Message::Binary(data)).await {
                log::warn!("websocket err {:?} {}", e, addr);
                break;
            }
        }
        let _ = ws_write.close().await;
    });
    let sender = Some(sender);

    while let Some(msg) = ws_read.next().await {
        let msg = msg.with_context(|| format!("Error during WebSocket read {}", addr))?;
        match msg {
            Message::Text(txt) => log::info!("Received text message: {} {}", txt, addr),
            Message::Binary(mut data) => {
                let packet = NetPacket::new0(data.len(), &mut data)?;
                if let Some(rs) = handler.handle(context, packet, addr, &sender).await {
                    if sender
                        .as_ref()
                        .unwrap()
                        .send(rs.buffer().to_vec())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            Message::Ping(_) | Message::Pong(_) => (),
            Message::Close(_) => break,
            _ => {}
        }
    }
    return Ok(());
}
