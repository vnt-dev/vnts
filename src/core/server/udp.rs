use crate::core::server::wire_guard::WireGuardGroup;
use crate::core::service::PacketHandler;
use crate::core::store::cache::VntContext;
use crate::protocol::NetPacket;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Sender};

pub async fn start(main_udp: Arc<UdpSocket>, handler: PacketHandler, mut wg: WireGuardGroup) {
    let mut udp_group = UdpGroup::new(main_udp.clone(), handler);
    let mut buf = [0u8; 65536];

    loop {
        match main_udp.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                if len == 0 {
                    log::warn!("UnexpectedEof {}", addr);
                    continue;
                }
                let buf = buf[..len].to_vec();
                if WireGuardGroup::maybe_wg(&buf) {
                    // 可能是wg协议
                    wg.handle(buf, addr);
                    continue;
                }
                if let Err(e) = udp_group.handle(buf, addr) {
                    log::error!("{} {:?}", addr, e);
                }
            }
            #[cfg(windows)]
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                // 忽略 ConnectionReset 错误
            }
            Err(e) => {
                log::error!("{:?}", e)
            }
        }
    }
}

pub struct UdpGroup {
    data_channel_map: Arc<Mutex<HashMap<SocketAddr, Sender<Vec<u8>>>>>,
    udp: Arc<UdpSocket>,
    handler: PacketHandler,
}

impl UdpGroup {
    pub fn new(udp: Arc<UdpSocket>, handler: PacketHandler) -> Self {
        Self {
            data_channel_map: Default::default(),
            udp,
            handler,
        }
    }
    pub fn handle(&mut self, buf: Vec<u8>, addr: SocketAddr) -> anyhow::Result<()> {
        if let Some(sender) = self.data_channel_map.lock().get(&addr) {
            sender.try_send(buf)?;
            return Ok(());
        }
        let (udp_sender, mut udp_receiver) = channel(64);
        udp_sender.try_send(buf)?;
        let data_channel_map = self.data_channel_map.clone();
        data_channel_map.lock().insert(addr, udp_sender);
        let handler = self.handler.clone();
        let udp = self.udp.clone();
        tokio::spawn(async move {
            let mut context = VntContext {
                link_context: None,
                server_cipher: None,
                link_address: addr,
            };
            loop {
                let data = match tokio::time::timeout(Duration::from_secs(60), udp_receiver.recv())
                    .await
                {
                    Ok(data) => data,
                    Err(_) => break,
                };
                if let Some(data) = data {
                    match NetPacket::new(data) {
                        Ok(net_packet) => {
                            if let Some(rs) =
                                handler.handle(&mut context, net_packet, addr, &None).await
                            {
                                if let Err(e) = udp.send_to(rs.buffer(), addr).await {
                                    log::error!("{:?} {}", e, addr)
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("{:?} {}", e, addr)
                        }
                    }
                } else {
                    break;
                }
            }
            handler.leave(context).await;
            data_channel_map.lock().remove(&addr);
        });
        Ok(())
    }
}
