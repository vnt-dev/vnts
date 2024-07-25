#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use crate::cipher::RsaCipher;
use crate::core::store::cache::{AppCache, LinkVntContext, VntContext};
use crate::error::*;
use crate::protocol::NetPacket;
use crate::ConfigInfo;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub struct ClientPacketHandler {
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
    udp: Arc<UdpSocket>,
}

impl ClientPacketHandler {
    pub fn new(
        cache: AppCache,
        config: ConfigInfo,
        rsa_cipher: Option<RsaCipher>,
        udp: Arc<UdpSocket>,
    ) -> Self {
        Self {
            cache,
            config,
            rsa_cipher,
            udp,
        }
    }
}

impl ClientPacketHandler {
    pub async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        context: &VntContext,
        net_packet: NetPacket<B>,
        _addr: SocketAddr,
    ) -> Result<()> {
        if let Some(context) = &context.link_context {
            self.handle0(context, net_packet).await
        } else {
            Err(Error::Disconnect)?
        }
    }
}

impl ClientPacketHandler {
    /// 转发到目标地址
    async fn handle0<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        context: &LinkVntContext,
        mut net_packet: NetPacket<B>,
    ) -> Result<()> {
        if net_packet.incr_ttl() > 1 {
            if self.config.check_finger {
                let finger = crate::cipher::Finger::new(&context.group);
                finger.check_finger(&net_packet)?;
            }
            let destination = net_packet.destination();
            if destination.is_broadcast() || self.config.broadcast == destination {
                //处理广播
                broadcast(context, &self.udp, net_packet).await;
            } else {
                let is_encrypt = net_packet.is_encrypt();
                let source_ip = u32::from(net_packet.source());
                let rs = context
                    .network_info
                    .read()
                    .clients
                    .get(&destination.into())
                    .filter(|v| {
                        v.wireguard.is_none()
                            && v.online
                            && v.client_secret == is_encrypt
                            && v.virtual_ip != source_ip
                    })
                    .map(|v| (v.address, v.tcp_sender.clone()));
                if let Some((peer_addr, peer_tcp_sender)) = rs {
                    send_one(&self.udp, peer_addr, peer_tcp_sender, &net_packet).await;
                }
            }
        }
        Ok(())
    }
}

async fn broadcast<B: AsRef<[u8]>>(
    context: &LinkVntContext,
    udp_socket: &UdpSocket,
    net_packet: NetPacket<B>,
) {
    let is_encrypt = net_packet.is_encrypt();
    let source_ip = u32::from(net_packet.source());
    let x: Vec<_> = context
        .network_info
        .read()
        .clients
        .values()
        .filter(|v| {
            v.wireguard.is_none()
                && v.online
                && v.client_secret == is_encrypt
                && v.virtual_ip != source_ip
        })
        .map(|v| (v.address, v.tcp_sender.clone()))
        .collect();
    for (peer_addr, peer_tcp_sender) in x {
        send_one(udp_socket, peer_addr, peer_tcp_sender, &net_packet).await;
    }
}

async fn send_one<B: AsRef<[u8]>>(
    udp_socket: &UdpSocket,
    peer_addr: SocketAddr,
    peer_tcp_sender: Option<Sender<Vec<u8>>>,
    net_packet: &NetPacket<B>,
) {
    if let Some(sender) = &peer_tcp_sender {
        let _ = sender.send(net_packet.buffer().to_vec()).await;
    } else {
        let _ = udp_socket.send_to(net_packet.buffer(), peer_addr).await;
    }
}
