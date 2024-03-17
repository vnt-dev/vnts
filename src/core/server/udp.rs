use std::io;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::core::service::PacketHandler;
use crate::protocol::NetPacket;

pub async fn start(main_udp: Arc<UdpSocket>, handler: PacketHandler) {
    tokio::spawn(start0(main_udp, handler));
}

pub async fn start0(main_udp: Arc<UdpSocket>, handler: PacketHandler) {
    loop {
        let mut buf = vec![0u8; 65536];
        match main_udp.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let handler = handler.clone();
                let udp = main_udp.clone();
                tokio::spawn(async move {
                    match NetPacket::new(&mut buf[..len]) {
                        Ok(net_packet) => {
                            if let Some(rs) = handler.handle(&udp, net_packet, addr, &None) {
                                let _ = udp.send_to(rs.buffer(), addr).await;
                            }
                        }
                        Err(e) => {
                            log::error!("{:?}", e)
                        }
                    }
                });
            }
            Err(e) => {
                log::error!("{:?}", e)
            }
        }
    }
}
