use anyhow::{anyhow, Context};
use chrono::Local;
use packet::icmp::{icmp, Kind};
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use protobuf::Message;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::{io, result};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;

use crate::cipher::{Aes256GcmCipher, Finger, RsaCipher};
use crate::core::entity::{ClientInfo, ClientStatusInfo, NetworkInfo, SimpleClientInfo};
use crate::core::store::cache::{AppCache, LinkVntContext, VntContext};
use crate::error::*;
use crate::proto::message;
use crate::proto::message::{DeviceList, RegistrationRequest, RegistrationResponse};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::ip_turn_packet::BroadcastPacket;
use crate::protocol::{control_packet, error_packet, service_packet, NetPacket, Protocol, MAX_TTL};
use crate::{protocol, ConfigInfo};

#[derive(Clone)]
pub struct ServerPacketHandler {
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
    udp: Arc<UdpSocket>,
}

impl ServerPacketHandler {
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

impl ServerPacketHandler {
    pub async fn leave(&self, context: VntContext) {
        context.leave(&self.cache).await;
    }
    pub async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        context: &mut VntContext,
        mut net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        // 握手请求直接处理
        let source = net_packet.source();
        if net_packet.protocol() == Protocol::Service {
            match protocol::service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::HandshakeRequest => {
                    // 回应握手
                    let mut rs = self.handshake(net_packet, addr)?;
                    self.common_param(&mut rs, source);
                    return Ok(Some(rs));
                }
                service_packet::Protocol::SecretHandshakeRequest => {
                    // 加密握手
                    let rs = self.secret_handshake(context, net_packet, addr).await?;
                    return Ok(Some(rs));
                }
                _ => {}
            }
        }
        // 解密
        let server_secret = net_packet.is_encrypt();
        if server_secret {
            if let Some(aes) = &context.server_cipher {
                aes.decrypt_ipv4(&mut net_packet)?;
            } else {
                log::info!("没有密钥:{},head={:?}", addr, net_packet.head());
                return Ok(Some(self.handle_err(addr, source, &Error::NoKey)?));
            }
        }
        let mut packet = match self
            .handle0(context, net_packet, addr, tcp_sender, server_secret)
            .await
        {
            Ok(rs) => {
                if let Some(rs) = rs {
                    rs
                } else {
                    return Ok(None);
                }
            }
            Err(e) => self.handle_anyhow_err(addr, source, e)?,
        };
        self.common_param(&mut packet, source);
        if server_secret {
            if let Some(aes) = &context.server_cipher {
                aes.encrypt_ipv4(&mut packet)?;
            }
        }
        Ok(Some(packet))
    }
    fn common_param<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
        source: Ipv4Addr,
    ) {
        //设置通用参数
        net_packet.set_default_version();
        net_packet.set_destination(source);
        net_packet.set_source(self.config.gateway);
        net_packet.first_set_ttl(MAX_TTL);
        net_packet.set_gateway_flag(true);
    }
    fn handle_anyhow_err(
        &self,
        addr: SocketAddr,
        source: Ipv4Addr,
        e: anyhow::Error,
    ) -> Result<NetPacket<Vec<u8>>> {
        if let Some(e) = e.downcast_ref() {
            self.handle_err(addr, source, e)
        } else {
            self.handle_err(addr, source, &Error::Other(format!("{}", e)))
        }
    }
    fn handle_err(
        &self,
        addr: SocketAddr,
        source: Ipv4Addr,
        e: &Error,
    ) -> Result<NetPacket<Vec<u8>>> {
        log::warn!("addr={},source={},{:?}", addr, source, e);
        let rs = vec![0u8; 12 + ENCRYPTION_RESERVED];
        let mut packet = NetPacket::new_encrypt(rs)?;
        match e {
            Error::AddressExhausted => {
                packet.set_transport_protocol(error_packet::Protocol::AddressExhausted.into());
            }
            Error::TokenError => {
                packet.set_transport_protocol(error_packet::Protocol::TokenError.into());
            }
            Error::IpAlreadyExists => {
                packet.set_transport_protocol(error_packet::Protocol::IpAlreadyExists.into());
            }
            Error::InvalidIp => {
                packet.set_transport_protocol(error_packet::Protocol::InvalidIp.into());
            }
            Error::Other(msg) => {
                //设置返回内容
                let bytes = msg.as_bytes();
                let rs = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
                packet = NetPacket::new_encrypt(rs)?;
                packet.set_payload(bytes)?;
            }
            Error::Disconnect => {
                packet.set_transport_protocol(error_packet::Protocol::Disconnect.into());
            }
            Error::NoKey => {
                packet.set_transport_protocol(error_packet::Protocol::NoKey.into());
            }
        }
        packet.set_protocol(Protocol::Error);
        self.common_param(&mut packet, source);
        Ok(packet)
    }
    async fn handle0<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        context: &mut VntContext,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
        server_secret: bool,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        // 处理不需要连接上下文的请求
        let mut net_packet = match self
            .not_context(context, net_packet, addr, tcp_sender, server_secret)
            .await
        {
            Ok(rs) => {
                return rs;
            }
            Err(net_packet) => net_packet,
        };
        // 需要连接的上下文
        let link_context = if let Some(link_context) = &context.link_context {
            link_context
        } else {
            return Err(Error::Disconnect)?;
        };

        match net_packet.protocol() {
            Protocol::Service => {
                match protocol::service_packet::Protocol::from(net_packet.transport_protocol()) {
                    service_packet::Protocol::PullDeviceList => {
                        //拉取网段设备信息
                        return self.poll_device_list(net_packet, addr, &link_context);
                    }
                    service_packet::Protocol::ClientStatusInfo => {
                        //客户端上报信息
                        let client_status_info =
                            message::ClientStatusInfo::parse_from_bytes(net_packet.payload())?;
                        self.up_client_status_info(client_status_info, &link_context);
                        return Ok(None);
                    }
                    _ => {}
                }
            }
            Protocol::Control => {
                // 控制数据
                if let control_packet::Protocol::Ping =
                    protocol::control_packet::Protocol::from(net_packet.transport_protocol())
                {
                    return self.control_ping(net_packet, &link_context);
                }
            }
            Protocol::IpTurn => {
                match protocol::ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                    protocol::ip_turn_packet::Protocol::WGIpv4 => {
                        //wg数据转发
                        self.wg_ipv4(&link_context, net_packet).await?;
                        return Ok(None);
                    }
                    protocol::ip_turn_packet::Protocol::Ipv4Broadcast => {
                        //处理选择性广播,进过网关还原成原始广播
                        let broadcast_packet = BroadcastPacket::new(net_packet.payload())?;
                        let exclude = broadcast_packet.addresses();
                        let broadcast_net_packet = NetPacket::new(broadcast_packet.data()?)?;
                        self.broadcast(&link_context, broadcast_net_packet, &exclude)?;
                        return Ok(None);
                    }
                    protocol::ip_turn_packet::Protocol::Ipv4 => {
                        let destination = net_packet.destination();
                        let source = net_packet.source();
                        let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
                        if let ipv4::protocol::Protocol::Icmp = ipv4.protocol() {
                            let mut icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
                            if icmp_packet.kind() == Kind::EchoRequest {
                                //开启ping
                                icmp_packet.set_kind(Kind::EchoReply);
                                icmp_packet.update_checksum();
                                ipv4.set_source_ip(destination);
                                ipv4.set_destination_ip(source);
                                ipv4.update_checksum();
                                return Ok(Some(NetPacket::new0(
                                    net_packet.data_len(),
                                    net_packet.raw_buffer().to_vec(),
                                )?));
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        log::error!(
            "Unknown={:?},{:?},{:?},{:?}",
            net_packet.destination(),
            net_packet.source(),
            net_packet.protocol(),
            net_packet.transport_protocol()
        );
        // Err(Error::Other("Unknown".into()))
        Ok(None)
    }
}

impl ServerPacketHandler {
    async fn not_context<B: AsRef<[u8]>>(
        &self,
        context: &mut VntContext,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
        server_secret: bool,
    ) -> result::Result<Result<Option<NetPacket<Vec<u8>>>>, NetPacket<B>> {
        if net_packet.protocol() == Protocol::Service {
            if let service_packet::Protocol::RegistrationRequest =
                protocol::service_packet::Protocol::from(net_packet.transport_protocol())
            {
                //注册
                return Ok(self
                    .register(context, net_packet, addr, tcp_sender, server_secret)
                    .await);
            }
        } else if net_packet.protocol() == Protocol::Control {
            if let control_packet::Protocol::AddrRequest =
                protocol::control_packet::Protocol::from(net_packet.transport_protocol())
            {
                return Ok(self.control_addr_request(addr));
            }
        }
        Err(net_packet)
    }
}

impl ServerPacketHandler {
    fn control_ping<B: AsRef<[u8]>>(
        &self,
        net_packet: NetPacket<B>,
        context: &LinkVntContext,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        let vec = vec![0u8; 12 + 4 + ENCRYPTION_RESERVED];
        let mut packet = NetPacket::new_encrypt(vec)?;
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(control_packet::Protocol::Pong.into());
        packet.set_payload(net_packet.payload())?;
        let mut pong_packet = control_packet::PongPacket::new(packet.payload_mut())?;
        let epoch = context.network_info.read().epoch;
        // 这里给客户端的是丢失精度的，可能导致客户端无法感知变更
        pong_packet.set_epoch(epoch as u16);
        Ok(Some(packet))
    }
    fn control_addr_request(&self, addr: SocketAddr) -> Result<Option<NetPacket<Vec<u8>>>> {
        let ipv4 = match addr.ip() {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(ip) => {
                if let Some(ipv4) = ip.to_ipv4_mapped() {
                    ipv4
                } else {
                    Ipv4Addr::UNSPECIFIED
                }
            }
        };
        let mut packet = NetPacket::new_encrypt(vec![0u8; 12 + 6 + ENCRYPTION_RESERVED])?;
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(control_packet::Protocol::AddrResponse.into());
        let mut addr_packet = control_packet::AddrPacket::new(packet.payload_mut())?;
        addr_packet.set_ipv4(ipv4);
        addr_packet.set_port(addr.port());
        Ok(Some(packet))
    }
}

impl ServerPacketHandler {
    async fn register<B: AsRef<[u8]>>(
        &self,
        context: &mut VntContext,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
        server_secret: bool,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        let config = &self.config;
        let request = RegistrationRequest::parse_from_bytes(net_packet.payload())?;
        check_reg(&request)?;
        log::info!(
            "register,{},id={:?},name={:?},version={:?},virtual_ip={},client_secret={},allow_ip_change={},is_fast={},tcp={}",
            addr,
            request.device_id,
            request.name,
            request.version,
            Ipv4Addr::from(request.virtual_ip),
            request.client_secret,
            request.allow_ip_change,
            request.is_fast,
            tcp_sender.is_some()
        );
        let group_id = request.token.clone();
        let gateway = config.gateway;
        let netmask = config.netmask;
        if let Some(white_token) = &config.white_token {
            if !white_token.contains(&group_id) {
                log::info!(
                    "token不在白名单，white_token={:?}，group_id={:?}",
                    white_token,
                    group_id
                );
                Err(Error::TokenError)?
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
        let register_client_request = RegisterClientRequest {
            group_id: group_id.clone(),
            virtual_ip: request.virtual_ip.into(),
            gateway,
            netmask,
            allow_ip_change: request.allow_ip_change,
            device_id: request.device_id,
            version: request.version,
            name: request.name,
            client_secret: request.client_secret,
            client_secret_hash: request.client_secret_hash,
            server_secret,
            address: addr,
            tcp_sender: tcp_sender.clone(),
            online: true,
            wireguard: None,
        };
        let register_response = generate_ip(&self.cache, register_client_request).await?;
        let virtual_ip = register_response.virtual_ip.into();
        response.virtual_gateway = gateway.into();
        response.virtual_netmask = netmask.into();
        response.virtual_ip = virtual_ip;
        response.epoch = register_response.epoch as u32;
        response.device_info_list = register_response
            .client_list
            .into_iter()
            .map(|v| v.into())
            .collect();
        context.link_context.replace(LinkVntContext {
            network_info: self
                .cache
                .virtual_network
                .get(&group_id)
                .context("virtual_network is none")?,
            group: group_id.clone(),
            virtual_ip,
            broadcast: config.broadcast,
            timestamp: register_response.timestamp,
        });

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
    if request.token.is_empty() || request.token.len() > 128 {
        Err(anyhow!("group length error"))?
    }
    if request.device_id.is_empty() || request.device_id.len() > 128 {
        Err(anyhow!("device_id length error"))?
    }
    if request.name.is_empty() || request.name.len() > 128 {
        Err(anyhow!("name length error"))?
    }
    if request.client_secret_hash.len() > 128 {
        Err(anyhow!("client_secret_hash length error"))?
    }
    Ok(())
}

impl ServerPacketHandler {
    fn handshake<B: AsRef<[u8]>>(
        &self,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
    ) -> Result<NetPacket<Vec<u8>>> {
        let req = message::HandshakeRequest::parse_from_bytes(net_packet.payload())?;
        log::info!("handshake:{},{}", addr, req);
        let mut res = message::HandshakeResponse::new();
        res.version = env!("CARGO_PKG_VERSION").to_string();
        if let Some(rsp_cipher) = &self.rsa_cipher {
            res.key_finger = rsp_cipher.finger();
            if res.key_finger != req.key_finger {
                //指纹不相同则回应公钥，这有助于重连减少数据传输
                res.public_key.extend_from_slice(rsp_cipher.public_key());
            }
            res.secret = true;
        }
        let bytes = res.write_to_bytes()?;
        let vec = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
        let mut packet = NetPacket::new_encrypt(vec)?;
        packet.set_protocol(Protocol::Service);
        packet.set_transport_protocol(service_packet::Protocol::HandshakeResponse.into());
        packet.set_payload(&bytes)?;
        Ok(packet)
    }
    async fn secret_handshake<B: AsRef<[u8]>>(
        &self,
        context: &mut VntContext,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
    ) -> Result<NetPacket<Vec<u8>>> {
        log::info!("secret_handshake:{}", addr);
        if let Some(rsp_cipher) = &self.rsa_cipher {
            let source = net_packet.source();
            let rsa_secret_body = rsp_cipher.decrypt(&net_packet)?;
            let sync_secret =
                message::SecretHandshakeRequest::parse_from_bytes(rsa_secret_body.data())?;
            let c = Aes256GcmCipher::new(
                sync_secret.key.try_into().map_err(|_| anyhow!("key err"))?,
                Finger::new(&sync_secret.token),
            );
            let rs = vec![0u8; 12 + ENCRYPTION_RESERVED];
            let mut packet = NetPacket::new_encrypt(rs)?;
            packet.set_protocol(Protocol::Service);
            packet.set_transport_protocol(service_packet::Protocol::SecretHandshakeResponse.into());
            self.common_param(&mut packet, source);
            c.encrypt_ipv4(&mut packet)?;
            context.server_cipher.replace(c.clone());
            self.cache.insert_cipher_session(addr, c).await;
            return Ok(packet);
        }
        Err(anyhow!("no encryption"))
    }
}

impl ServerPacketHandler {
    fn poll_device_list<B: AsRef<[u8]>>(
        &self,
        _net_packet: NetPacket<B>,
        _addr: SocketAddr,
        context: &LinkVntContext,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        let guard = context.network_info.read();
        let ips = clients_info(&guard.clients, context.virtual_ip);
        let epoch = guard.epoch;
        drop(guard);
        let mut device_list = DeviceList::new();
        device_list.epoch = epoch as u32;
        device_list.device_info_list = ips.into_iter().map(|v| v.into()).collect();
        let bytes = device_list.write_to_bytes()?;
        let vec = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
        let mut device_list_packet = NetPacket::new_encrypt(vec)?;
        device_list_packet.set_protocol(Protocol::Service);
        device_list_packet.set_transport_protocol(service_packet::Protocol::PushDeviceList.into());
        device_list_packet.set_payload(&bytes)?;
        Ok(Some(device_list_packet))
    }
    fn up_client_status_info(
        &self,
        client_status_info: message::ClientStatusInfo,
        context: &LinkVntContext,
    ) {
        let mut status_info = ClientStatusInfo::default();
        let iplist = &mut status_info.p2p_list;
        *iplist = client_status_info
            .p2p_list
            .iter()
            .map(|v| v.next_ip.into())
            .collect();
        status_info.up_stream = client_status_info.up_stream;
        status_info.down_stream = client_status_info.down_stream;
        status_info.is_cone =
            client_status_info.nat_type.enum_value_or_default() == message::PunchNatType::Cone;
        status_info.update_time = Local::now();
        if let Some(v) = context
            .network_info
            .write()
            .clients
            .get_mut(&client_status_info.source)
        {
            v.client_status = Some(status_info);
        }
    }
    async fn wg_ipv4<B: AsRef<[u8]>>(
        &self,
        context: &LinkVntContext,
        net_packet: NetPacket<B>,
    ) -> anyhow::Result<()> {
        let source = net_packet.source();
        let dest = net_packet.destination();
        let destination = u32::from(dest);
        if destination == context.virtual_ip {
            return Ok(());
        }
        if dest.is_broadcast() || dest == context.broadcast {
            // 广播
            for peer in context.network_info.read().clients.values() {
                if !peer.online || destination == peer.virtual_ip {
                    continue;
                }
                if let Some(sender) = &peer.wg_sender {
                    if let Err(e) = sender.try_send((net_packet.payload().to_vec(), source)) {
                        log::info!("广播到对端wg失败 {}->{},{}", source, dest, e);
                    }
                }
            }
        } else if let Some(peer) = context.network_info.read().clients.get(&destination) {
            // 点对点
            if peer.online {
                if let Some(sender) = &peer.wg_sender {
                    if let Err(e) = sender.try_send((net_packet.payload().to_vec(), source)) {
                        log::info!("发送到对端wg失败 {}->{},{}", source, dest, e);
                    }
                }
            }
        }
        Ok(())
    }
    fn broadcast<B: AsRef<[u8]>>(
        &self,
        context: &LinkVntContext,
        net_packet: NetPacket<B>,
        exclude: &[Ipv4Addr],
    ) -> io::Result<()> {
        let client_secret = net_packet.is_encrypt();
        let destination = u32::from(net_packet.destination());
        for (ip, client_info) in &context.network_info.read().clients {
            if client_info.online
                && destination != *ip
                && client_info.client_secret == client_secret
                && client_info.wireguard.is_none()
                && !exclude.contains(&(*ip).into())
            {
                if let Some(sender) = &client_info.tcp_sender {
                    let _ = sender.try_send(net_packet.buffer().to_vec());
                } else {
                    let _ = self
                        .udp
                        .try_send_to(net_packet.buffer(), client_info.address);
                }
            }
        }
        Ok(())
    }
}

pub struct RegisterClientRequest {
    pub group_id: String,
    // ip 0表示自动分配
    pub virtual_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,

    // 允许分配不一样的ip
    pub allow_ip_change: bool,
    // 设备ID
    pub device_id: String,
    // 版本
    pub version: String,
    // 名称
    pub name: String,
    // 客户端间是否加密
    pub client_secret: bool,
    // 加密hash
    pub client_secret_hash: Vec<u8>,
    // 和服务端是否加密
    pub server_secret: bool,
    // 链接服务器的来源地址
    pub address: SocketAddr,
    pub tcp_sender: Option<Sender<Vec<u8>>>,
    // 是否在线
    pub online: bool,
    // wireguard客户端公钥
    pub wireguard: Option<[u8; 32]>,
}

pub struct RegisterClientResponse {
    timestamp: i64,
    pub virtual_ip: Ipv4Addr,
    // 纪元号
    pub epoch: u64,
    pub client_list: Vec<SimpleClientInfo>,
}

pub async fn generate_ip(
    cache: &AppCache,
    register_request: RegisterClientRequest,
) -> anyhow::Result<RegisterClientResponse> {
    let gateway: u32 = register_request.gateway.into();
    let netmask: u32 = register_request.netmask.into();
    let network: u32 = gateway & netmask;
    let mut virtual_ip: u32 = register_request.virtual_ip.into();
    let device_id = register_request.device_id;
    let allow_ip_change = register_request.allow_ip_change;
    let group_id = register_request.group_id;
    let v = cache
        .virtual_network
        .optionally_get_with(group_id, || {
            (
                Duration::from_secs(7 * 24 * 3600),
                Arc::new(parking_lot::const_rwlock(NetworkInfo::new(
                    network, netmask, gateway,
                ))),
            )
        })
        .await;
    // 可分配的ip段
    let ip_range = network + 1..gateway | (!netmask);
    let timestamp = Local::now().timestamp();
    let mut lock = v.write();
    let mut insert = true;
    if virtual_ip != 0 {
        if gateway == virtual_ip {
            Err(Error::InvalidIp)?
        }
        //指定了ip
        if let Some(info) = lock.clients.get_mut(&virtual_ip) {
            if info.device_id != device_id {
                //ip被占用了,并且不能更改ip
                if !allow_ip_change {
                    Err(Error::IpAlreadyExists)?
                }
                // 重新挑选ip
                virtual_ip = 0;
            } else {
                insert = false;
            }
        }
    }
    let mut old_ip = 0;
    if insert {
        // 找到上一次用的ip
        for (ip, x) in &lock.clients {
            if x.device_id == device_id {
                if virtual_ip == 0 {
                    virtual_ip = *ip;
                } else {
                    old_ip = *ip;
                }
                break;
            }
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
        log::error!("地址使用完:{:?}", lock);
        Err(Error::AddressExhausted)?
    }
    let info = if old_ip == 0 {
        lock.clients
            .entry(virtual_ip)
            .or_insert_with(ClientInfo::default)
    } else {
        let client_info = lock.clients.remove(&old_ip).unwrap();
        lock.clients
            .entry(virtual_ip)
            .or_insert_with(|| client_info)
    };
    info.name = register_request.name;
    info.device_id = device_id;
    info.version = register_request.version;
    info.client_secret = register_request.client_secret;
    info.client_secret_hash = register_request.client_secret_hash;
    info.server_secret = register_request.server_secret;
    info.address = register_request.address;
    info.online = register_request.online;
    info.wireguard = register_request.wireguard;
    info.virtual_ip = virtual_ip;
    info.tcp_sender = register_request.tcp_sender;
    info.last_join_time = Local::now();
    info.timestamp = timestamp;
    lock.epoch += 1;
    let response = RegisterClientResponse {
        timestamp,
        virtual_ip: virtual_ip.into(),
        epoch: lock.epoch,
        client_list: clients_info(&lock.clients, virtual_ip),
    };
    Ok(response)
}
fn clients_info(clients: &HashMap<u32, ClientInfo>, current_ip: u32) -> Vec<SimpleClientInfo> {
    clients
        .iter()
        .filter(|&(_, dev)| dev.virtual_ip != current_ip)
        .map(|(_, device_info)| device_info.into())
        .collect()
}
impl From<SimpleClientInfo> for message::DeviceInfo {
    fn from(value: SimpleClientInfo) -> Self {
        let mut dev = message::DeviceInfo::new();
        dev.virtual_ip = value.virtual_ip;
        dev.name = value.name;
        dev.device_status = if value.online { 0 } else { 1 };
        dev.client_secret = value.client_secret;
        if value.online {
            dev.client_secret_hash = value.client_secret_hash;
        }
        dev.wireguard = value.wireguard;
        dev
    }
}
