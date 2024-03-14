use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::cipher::RsaCipher;
use crate::ConfigInfo;
use crate::core::entity::ClientInfo;
use crate::core::store::cache::{AppCache, Context};
use crate::error::*;
use crate::protocol::NetPacket;

#[derive(Clone)]
pub struct ClientPacketHandler {
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
}

impl ClientPacketHandler {
    pub fn new(cache: AppCache,
               config: ConfigInfo,
               rsa_cipher: Option<RsaCipher>, ) -> Self {
        Self {
            cache,
            config,
            rsa_cipher,
        }
    }
}

impl ClientPacketHandler {
    pub fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        udp_socket: &UdpSocket,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
    ) -> Result<()> {
        if let Some(context) = self.cache.get_context(&addr) {
            self.handle0(udp_socket, net_packet, context);
            Ok(())
        } else {
            Err(Error::Disconnect)
        }
    }
}

impl ClientPacketHandler {
    /// 转发到目标地址
    fn handle0<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        udp_socket: &UdpSocket,
        mut net_packet: NetPacket<B>,
        context: Context,
    ) {
        if net_packet.incr_ttl() > 1 {
            let destination = net_packet.destination();
            if destination.is_broadcast() || self.config.broadcast == destination {
                //处理广播
                broadcast(udp_socket, context, net_packet);
            } else {
                if let Some(client_info) =
                    context.network_info.read().clients.get(&destination.into())
                {
                    send_one(udp_socket, client_info, &net_packet);
                }
            }
        }
    }
}

fn broadcast<B: AsRef<[u8]>>(udp_socket: &UdpSocket, context: Context, net_packet: NetPacket<B>) {
    for client_info in context.network_info.read().clients.values() {
        send_one(udp_socket, client_info, &net_packet);
    }
}

fn send_one<B: AsRef<[u8]>>(
    udp_socket: &UdpSocket,
    client_info: &ClientInfo,
    net_packet: &NetPacket<B>,
) {
    if client_info.client_secret != net_packet.is_encrypt() {
        //加密状态不相同 不转发
        return;
    }
    if let Some(sender) = &client_info.tcp_sender {
        let _ = sender.try_send(net_packet.buffer().to_vec());
    } else {
        let _ = udp_socket.try_send(net_packet.buffer());
    }
}
