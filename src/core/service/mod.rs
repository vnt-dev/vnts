use crate::cipher::RsaCipher;
use crate::core::service::client::ClientPacketHandler;
use crate::core::service::server::ServerPacketHandler;
use crate::core::store::cache::AppCache;
use crate::error::*;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{error_packet, NetPacket, Protocol, Version, MAX_TTL};
use crate::ConfigInfo;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;

pub mod client;
pub mod server;

#[derive(Clone)]
pub struct PacketHandler {
    config: ConfigInfo,
    cache: AppCache,
    client: ClientPacketHandler,
    server: ServerPacketHandler,
}

impl PacketHandler {
    pub fn new(cache: AppCache, config: ConfigInfo, rsa_cipher: Option<RsaCipher>) -> Self {
        let client = ClientPacketHandler::new(cache.clone(), config.clone(), rsa_cipher.clone());
        let server = ServerPacketHandler::new(cache.clone(), config.clone(), rsa_cipher.clone());
        Self {
            config,
            cache,
            client,
            server,
        }
    }
}

impl PacketHandler {
    pub async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        udp_socket: &UdpSocket,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Option<NetPacket<Vec<u8>>> {
        let source = net_packet.source();
        let mut rs = self
            .handle0(udp_socket, net_packet, addr, tcp_sender)
            .await
            .unwrap_or_else(|e| {
                let rs = vec![0u8; 12 + ENCRYPTION_RESERVED];
                let mut packet = NetPacket::new_encrypt(rs).unwrap();
                match e {
                    Error::Io(_) => {}
                    Error::Channel(_) => {}
                    Error::Protobuf(_) => {}

                    Error::AddressExhausted => {
                        packet.set_transport_protocol(
                            error_packet::Protocol::AddressExhausted.into(),
                        );
                    }
                    Error::TokenError => {
                        packet.set_transport_protocol(error_packet::Protocol::TokenError.into());
                    }
                    Error::IpAlreadyExists => {
                        packet
                            .set_transport_protocol(error_packet::Protocol::IpAlreadyExists.into());
                    }
                    Error::InvalidIp => {
                        packet.set_transport_protocol(error_packet::Protocol::InvalidIp.into());
                    }
                    Error::Other(msg) => {
                        //设置返回内容
                        let bytes = msg.as_bytes();
                        if bytes.len() > u16::MAX as usize {
                            log::warn!("错误信息太长:{:?}", msg);
                            return None;
                        }
                        let rs = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
                        packet = NetPacket::new_encrypt(rs).unwrap();
                        packet.set_payload(bytes).unwrap();
                    }
                    Error::Disconnect => {
                        packet.set_transport_protocol(error_packet::Protocol::Disconnect.into());
                    }
                    Error::NoKey => {
                        packet.set_transport_protocol(error_packet::Protocol::NoKey.into());
                    }
                }
                packet.set_protocol(Protocol::Error);
                Some(packet)
            });
        if let Some(packet) = rs.as_mut() {
            //设置通用参数
            packet.set_version(Version::V1);
            packet.set_destination(source);
            packet.set_source(self.config.gateway);
            packet.first_set_ttl(MAX_TTL);
            packet.set_gateway_flag(true);
            if let Some(aes) = self.cache.cipher_session.get(&addr) {
                // 加密
                if let Err(e) = aes.encrypt_ipv4(packet) {
                    log::error!("encrypt_ipv4 {:?}", e);
                    return None;
                }
            }
        }
        rs
    }
    async fn handle0<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        udp_socket: &UdpSocket,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        if net_packet.is_gateway() {
            self.server.handle(net_packet, addr, tcp_sender).await
        } else {
            self.client.handle(udp_socket, net_packet, addr)?;
            Ok(None)
        }
    }
}
