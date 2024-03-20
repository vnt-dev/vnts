use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::result;
use std::sync::Arc;
use std::time::Duration;

use protobuf::Message;
use tokio::sync::mpsc::Sender;

use crate::cipher::{Aes256GcmCipher, Finger, RsaCipher};
use crate::core::entity::{ClientInfo, NetworkInfo};
use crate::core::store::cache::{AppCache, Context};
use crate::error::*;
use crate::proto::message;
use crate::proto::message::{DeviceList, RegistrationRequest, RegistrationResponse};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{control_packet, service_packet, NetPacket, Protocol};
use crate::{protocol, ConfigInfo};

#[derive(Clone)]
pub struct ServerPacketHandler {
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
}

impl ServerPacketHandler {
    pub fn new(cache: AppCache, config: ConfigInfo, rsa_cipher: Option<RsaCipher>) -> Self {
        Self {
            cache,
            config,
            rsa_cipher,
        }
    }
}

impl ServerPacketHandler {
    pub async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        mut net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        // 握手请求直接处理
        if net_packet.protocol() == Protocol::Service {
            match protocol::service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::HandshakeRequest => {
                    // 回应握手
                    return self.handshake(net_packet, addr);
                }
                service_packet::Protocol::SecretHandshakeRequest => {
                    // 加密握手
                    return self.secret_handshake(net_packet, addr).await;
                }
                _ => {}
            }
        }
        // 解密
        if net_packet.is_encrypt() {
            if let Some(aes) = self.cache.cipher_session.get(&addr) {
                aes.decrypt_ipv4(&mut net_packet)?;
            } else {
                return Err(Error::NoKey);
            }
        }
        // 处理不需要连接上下文的请求
        let net_packet = match self.not_context(net_packet, addr, tcp_sender).await {
            Ok(rs) => {
                return rs;
            }
            Err(net_packet) => net_packet,
        };
        // 需要连接的上下文
        let context = if let Some(context) = self.cache.get_context(&addr) {
            context
        } else {
            return Err(Error::Disconnect);
        };

        match net_packet.protocol() {
            Protocol::Service => {
                match protocol::service_packet::Protocol::from(net_packet.transport_protocol()) {
                    service_packet::Protocol::PollDeviceList => {
                        //拉取网段设备信息
                        return self.poll_device_list(net_packet, addr, &context);
                    }
                    _ => {}
                }
            }
            Protocol::Control => {
                // 控制数据
                match protocol::control_packet::Protocol::from(net_packet.transport_protocol()) {
                    control_packet::Protocol::Ping => {
                        return self.control_ping(net_packet, &context);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        Err(Error::Other("Unknown".into()))
    }
}

impl ServerPacketHandler {
    async fn not_context<B: AsRef<[u8]>>(
        &self,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> result::Result<Result<Option<NetPacket<Vec<u8>>>>, NetPacket<B>> {
        if net_packet.protocol() == Protocol::Service {
            match protocol::service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::RegistrationRequest => {
                    //注册
                    return Ok(self.register(net_packet, addr, tcp_sender).await);
                }
                _ => {}
            }
        } else if net_packet.protocol() == Protocol::Control {
            match protocol::control_packet::Protocol::from(net_packet.transport_protocol()) {
                control_packet::Protocol::AddrRequest => {
                    return Ok(self.control_addr_request(addr));
                }
                _ => {}
            }
        }
        Err(net_packet)
    }
}

impl ServerPacketHandler {
    fn control_ping<B: AsRef<[u8]>>(
        &self,
        net_packet: NetPacket<B>,
        context: &Context,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        let vec = vec![0u8; 12 + 4 + ENCRYPTION_RESERVED];
        let mut packet = NetPacket::new_encrypt(vec)?;
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(control_packet::Protocol::Pong.into());
        packet.set_payload(net_packet.payload())?;
        let mut pong_packet = control_packet::PongPacket::new(packet.payload_mut())?;
        let epoch = context.network_info.read().epoch;
        pong_packet.set_epoch(epoch);
        Ok(Some(packet))
    }
    fn control_addr_request(&self, addr: SocketAddr) -> Result<Option<NetPacket<Vec<u8>>>> {
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                let mut packet = NetPacket::new_encrypt(vec![0u8; 12 + 6 + ENCRYPTION_RESERVED])?;
                packet.set_protocol(Protocol::Control);
                packet.set_transport_protocol(control_packet::Protocol::AddrResponse.into());
                let mut addr_packet = control_packet::AddrPacket::new(packet.payload_mut())?;
                addr_packet.set_ipv4(ipv4);
                addr_packet.set_port(addr.port());
                Ok(Some(packet))
            }
            IpAddr::V6(_) => Ok(None),
        }
    }
}

impl ServerPacketHandler {
    async fn register<B: AsRef<[u8]>>(
        &self,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        let config = &self.config;
        let cache = &self.cache;
        let request = RegistrationRequest::parse_from_bytes(net_packet.payload())?;
        check_reg(&request)?;
        log::info!(
            "register,{},id={:?},name={:?},version={:?},virtual_ip={},client_secret={},allow_ip_change={},is_fast={}",
            addr,
            request.device_id,
            request.name,
            request.version,
            request.virtual_ip,
            request.client_secret,
            request.allow_ip_change,
            request.is_fast
        );
        let group_id = request.token.clone();
        if let Some(white_token) = &config.white_token {
            if !white_token.contains(&group_id) {
                log::info!(
                    "token不在白名单，white_token={:?}，group_id={:?}",
                    white_token,
                    group_id
                );
                return Err(Error::TokenError);
            }
        }
        let mut response = RegistrationResponse::new();
        //公网地址
        response.public_port = addr.port() as u32;
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                response.public_ip = ipv4.into();
            }
            IpAddr::V6(ipv6) => {
                if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                    response.public_ip = ipv4.into();
                } else {
                    response.public_ipv6 = ipv6.octets().to_vec();
                }
            }
        }
        //固定网段
        let gateway: u32 = config.gateway.into();
        let netmask: u32 = config.netmask.into();
        let network: u32 = gateway & netmask;

        response.virtual_netmask = netmask;
        response.virtual_gateway = gateway;

        let v = cache
            .virtual_network
            .optionally_get_with(group_id.clone(), || {
                (
                    Duration::from_secs(7 * 24 * 3600),
                    Arc::new(parking_lot::const_rwlock(NetworkInfo::new(
                        network, netmask, gateway,
                    ))),
                )
            })
            .await;
        let mut virtual_ip = request.virtual_ip;
        // 可分配的ip段
        let ip_range = (response.virtual_gateway & response.virtual_netmask) + 1
            ..response.virtual_gateway | (!response.virtual_netmask);
        {
            let mut lock = v.write();

            if virtual_ip != 0 {
                if u32::from(config.gateway) == virtual_ip
                    || u32::from(config.broadcast) == virtual_ip
                    || !ip_range.contains(&virtual_ip)
                {
                    log::warn!("手动指定的ip无效: {:?}", request);
                    return Err(Error::InvalidIp);
                }
                //指定了ip
                if let Some(info) = lock.clients.get_mut(&request.virtual_ip) {
                    if info.device_id != request.device_id {
                        //ip被占用了,并且不能更改ip
                        if !request.allow_ip_change {
                            log::warn!("手动指定的ip已经存在:{:?}", request);
                            return Err(Error::IpAlreadyExists);
                        }
                        // 重新挑选ip
                        virtual_ip = 0;
                    }
                }
            }
            for x in lock.clients.values() {
                if x.device_id == request.device_id {
                    virtual_ip = x.virtual_ip;
                }
            }
            if virtual_ip == 0 {
                // 从小到大找一个未使用的ip
                for ip in ip_range {
                    if ip == lock.gateway_ip {
                        continue;
                    }
                    if !lock.clients.contains_key(&ip) {
                        virtual_ip = ip;
                        break;
                    }
                }
            }
            if virtual_ip == 0 {
                log::error!("地址使用完:{:?}", request);
                return Err(Error::AddressExhausted);
            }
            let info = lock
                .clients
                .entry(virtual_ip)
                .or_insert_with(|| ClientInfo::default());
            info.name = request.name;
            info.device_id = request.device_id;
            info.client_secret = request.client_secret;
            info.address = addr;
            info.online = true;
            info.virtual_ip = virtual_ip;
            info.tcp_sender = tcp_sender.clone();
            lock.epoch += 1;
            response.epoch = lock.epoch as u32;
            response.device_info_list = Self::clients_info(&lock.clients, virtual_ip);
            drop(lock);
        }
        cache
            .insert_ip_session((group_id.clone(), virtual_ip), addr)
            .await;
        cache
            .insert_addr_session(addr, (group_id, virtual_ip))
            .await;
        response.virtual_ip = virtual_ip;
        let bytes = response.write_to_bytes()?;
        let rs = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
        let mut packet = NetPacket::new_encrypt(rs)?;
        packet.set_protocol(Protocol::Service);
        packet.set_transport_protocol(service_packet::Protocol::RegistrationResponse.into());
        packet.set_payload(&bytes)?;
        Ok(Some(packet))
    }
}

fn check_reg(request: &RegistrationRequest) -> Result<()> {
    if request.token.len() == 0 || request.token.len() > 128 {
        return Err(Error::Other("group length error".into()));
    }
    if request.device_id.len() == 0 || request.device_id.len() > 128 {
        return Err(Error::Other("device_id length error".into()));
    }
    if request.name.len() == 0 || request.name.len() > 128 {
        return Err(Error::Other("name length error".into()));
    }
    Ok(())
}

impl ServerPacketHandler {
    fn handshake<B: AsRef<[u8]>>(
        &self,
        _net_packet: NetPacket<B>,
        _addr: SocketAddr,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        let mut res = message::HandshakeResponse::new();
        res.version = env!("CARGO_PKG_VERSION").to_string();
        if let Some(rsp_cipher) = &self.rsa_cipher {
            res.public_key.extend_from_slice(rsp_cipher.public_key());
            res.secret = true;
            res.key_finger = rsp_cipher.finger();
        }
        let bytes = res.write_to_bytes()?;
        let vec = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
        let mut packet = NetPacket::new_encrypt(vec)?;
        packet.set_protocol(Protocol::Service);
        packet.set_transport_protocol(service_packet::Protocol::HandshakeResponse.into());
        packet.set_payload(&bytes)?;
        Ok(Some(packet))
    }
    async fn secret_handshake<B: AsRef<[u8]>>(
        &self,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        if let Some(rsp_cipher) = &self.rsa_cipher {
            let rsa_secret_body = rsp_cipher.decrypt(&net_packet)?;
            let sync_secret =
                message::SecretHandshakeRequest::parse_from_bytes(rsa_secret_body.data())?;
            let c = Aes256GcmCipher::new(
                sync_secret
                    .key
                    .try_into()
                    .map_err(|_| Error::Other("key err".into()))?,
                Finger::new(&sync_secret.token),
            );
            self.cache.insert_cipher_session(addr, c).await;
            let rs = vec![0u8; 12 + ENCRYPTION_RESERVED];
            let mut packet = NetPacket::new_encrypt(rs)?;
            packet.set_protocol(Protocol::Service);
            packet.set_transport_protocol(service_packet::Protocol::SecretHandshakeResponse.into());
            return Ok(Some(packet));
        }
        Err(Error::Other("no encryption".into()))
    }
}

impl ServerPacketHandler {
    fn poll_device_list<B: AsRef<[u8]>>(
        &self,
        _net_packet: NetPacket<B>,
        _addr: SocketAddr,
        context: &Context,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        let guard = context.network_info.read();
        let ips = Self::clients_info(&guard.clients, context.virtual_ip);
        let epoch = guard.epoch;
        drop(guard);
        let mut device_list = DeviceList::new();
        device_list.epoch = epoch as u32;
        device_list.device_info_list = ips;
        let bytes = device_list.write_to_bytes()?;
        let vec = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
        let mut device_list_packet = NetPacket::new_encrypt(vec)?;
        device_list_packet.set_protocol(Protocol::Service);
        device_list_packet.set_transport_protocol(service_packet::Protocol::PushDeviceList.into());
        device_list_packet.set_payload(&bytes)?;
        return Ok(Some(device_list_packet));
    }
    fn clients_info(
        clients: &HashMap<u32, ClientInfo>,
        current_ip: u32,
    ) -> Vec<message::DeviceInfo> {
        clients
            .iter()
            .filter(|&(_, dev)| dev.virtual_ip != current_ip)
            .map(|(_, device_info)| {
                let mut dev = message::DeviceInfo::new();
                dev.virtual_ip = device_info.virtual_ip;
                dev.name = device_info.name.clone();
                dev.device_status = if device_info.online { 1 } else { 0 };
                dev.client_secret = device_info.client_secret;
                dev
            })
            .collect()
    }
}
