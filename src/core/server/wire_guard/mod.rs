use crate::core::entity::{NetworkInfo, WireGuardConfig};
use crate::core::store::cache::AppCache;
use crate::protocol::{ip_turn_packet, NetPacket, Protocol, HEAD_LEN, MAX_TTL};
use crate::ConfigInfo;
use anyhow::{anyhow, Context};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{handshake, Packet, Tunn, TunnResult};
use boringtun::x25519::StaticSecret;
use chrono::Local;
use packet::icmp::{icmp, Kind};
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub struct WireGuardGroup {
    cache: AppCache,
    config: ConfigInfo,
    udp: Arc<UdpSocket>,
    data_channel_map: Arc<Mutex<HashMap<SocketAddr, Sender<Vec<u8>>>>>,
}

impl WireGuardGroup {
    pub fn new(cache: AppCache, config: ConfigInfo, udp: Arc<UdpSocket>) -> Self {
        Self {
            cache,
            config,
            udp,
            data_channel_map: Default::default(),
        }
    }
    pub fn handle(&mut self, buf: Vec<u8>, addr: SocketAddr) {
        if let Err(e) = self.handle0(buf, addr) {
            log::warn!("{},{}", addr, e);
        }
    }
    fn handle0(&mut self, buf: Vec<u8>, addr: SocketAddr) -> anyhow::Result<()> {
        if let Some(sender) = self.data_channel_map.lock().get(&addr) {
            sender.try_send(buf)?;
            return Ok(());
        }
        let config = self.handshake(&buf)?;
        let network_info = self
            .cache
            .virtual_network
            .get(&config.group_id)
            .context("wg配置已过期")?;
        let (network_receiver, broadcast_ip, mask_ip, gateway_ip) = {
            let mut guard = network_info.write();
            let broadcast_ip = guard.network_ip | (!guard.mask_ip);

            let client_info = guard
                .clients
                .get_mut(&config.ip.into())
                .context("wg配置已过期")?;
            if client_info.wireguard.is_none() {
                Err(anyhow!("不是wg配置"))?;
            }
            let (network_sender, network_receiver) = channel(64);
            client_info.wg_sender = Some(network_sender);
            client_info.last_join_time = Local::now();
            client_info.timestamp = client_info.last_join_time.timestamp();
            client_info.address = addr;
            client_info.online = true;
            guard.epoch += 1;
            (
                network_receiver,
                broadcast_ip,
                guard.mask_ip,
                guard.gateway_ip,
            )
        };
        let wg = WireGuard::new(
            network_info.clone(),
            broadcast_ip.into(),
            mask_ip.into(),
            gateway_ip.into(),
            self.cache.clone(),
            self.config.wg_secret_key.clone(),
            self.udp.clone(),
            addr,
            config,
            self.data_channel_map.clone(),
        );
        let (udp_sender, udp_receiver) = channel(64);
        udp_sender.try_send(buf)?;
        self.data_channel_map.lock().insert(addr, udp_sender);
        tokio::spawn(wg.start(udp_receiver, network_receiver));
        Ok(())
    }
    #[inline]
    pub fn maybe_wg(buf: &[u8]) -> bool {
        if buf.len() < 4 {
            return false;
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        (1..=4).contains(&packet_type)
    }
    pub fn handshake(&mut self, buf: &[u8]) -> anyhow::Result<WireGuardConfig> {
        let packet = match Tunn::parse_incoming_packet(buf) {
            Ok(packet) => packet,
            Err(e) => Err(anyhow!("{:?}", e))?,
        };
        match packet {
            Packet::HandshakeInit(data) => {
                let half_handshake = handshake::parse_handshake_anon(
                    &self.config.wg_secret_key,
                    &self.config.wg_public_key,
                    &data,
                )
                .map_err(|e| anyhow!("HandshakeInit {:?}", e))?;
                let config = self
                    .cache
                    .wg_group_map
                    .get(&half_handshake.peer_static_public)
                    .context("需要先在vnts配置wg信息")?
                    .clone();
                Ok(config)
            }
            _ => Err(anyhow!("非握手包")),
        }
    }
}

pub struct WireGuard {
    network_info: Arc<RwLock<NetworkInfo>>,
    ip: Ipv4Addr,
    broadcast_ip: Ipv4Addr,
    mask_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,

    group_id: String,
    tunn: Tunn,
    cache: AppCache,
    wg_source_addr: SocketAddr,
    udp: Arc<UdpSocket>,
    data_channel_map: Arc<Mutex<HashMap<SocketAddr, Sender<Vec<u8>>>>>,
}

impl WireGuard {
    pub fn new(
        network_info: Arc<RwLock<NetworkInfo>>,
        broadcast_ip: Ipv4Addr,
        mask_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        cache: AppCache,
        vnts_secret_key: StaticSecret,
        udp: Arc<UdpSocket>,
        wg_source_addr: SocketAddr,
        config: WireGuardConfig,
        data_channel_map: Arc<Mutex<HashMap<SocketAddr, Sender<Vec<u8>>>>>,
    ) -> Self {
        let tunn = Tunn::new(
            vnts_secret_key,
            config.public_key.into(),
            None,
            Some(config.persistent_keepalive),
            rand::thread_rng().next_u32(),
            None,
        );
        Self {
            network_info,
            ip: config.ip,
            broadcast_ip,
            mask_ip,
            gateway_ip,
            group_id: config.group_id,
            tunn,
            cache,
            wg_source_addr,
            udp,
            data_channel_map,
        }
    }
    pub async fn start(
        mut self,
        udp_receiver: Receiver<Vec<u8>>,
        ipv4_receiver: Receiver<(Vec<u8>, Ipv4Addr)>,
    ) {
        if let Err(e) = self.start0(udp_receiver, ipv4_receiver).await {
            log::warn!(
                "wg连接异常断开 {:?},{:?},{:?},{:?}",
                self.group_id,
                self.ip,
                self.wg_source_addr,
                e
            );
        }
        self.offline();
    }
    fn offline(&self) {
        if let Some(v) = self.cache.virtual_network.get(&self.group_id) {
            if let Some(v) = v.write().clients.get_mut(&self.ip.into()) {
                if v.address == self.wg_source_addr {
                    v.online = false;
                    v.wg_sender = None;
                }
            }
        }
        self.data_channel_map.lock().remove(&self.wg_source_addr);
    }
    pub async fn start0(
        &mut self,
        mut udp_receiver: Receiver<Vec<u8>>,
        mut ipv4_receiver: Receiver<(Vec<u8>, Ipv4Addr)>,
    ) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        let mut dst_buf = [0; 65535];
        let mut dst_buf2 = [0; 65535];
        log::info!(
            "处理wg链接 {},{}/{},{}",
            self.group_id,
            self.ip,
            self.mask_ip,
            self.wg_source_addr
        );
        loop {
            tokio::select! {
                rs = udp_receiver.recv()=>{
                    if let Some(mut data) = rs{
                        self.handle_wg_data(&mut data,&mut dst_buf,&mut dst_buf2).await?;
                    }else{
                        break;
                    }
                }
                rs = ipv4_receiver.recv()=>{
                    if let Some((data,ip)) = rs{
                        if let Err(e) = self.handle_ipv4_data(&data,&mut dst_buf).await{
                            log::warn!("来源{},发送到wg失败,{:?}",ip,e)
                        }
                    }else{
                        break;
                    }
                }
                _ = interval.tick()=>{
                    self.update_timers(&mut dst_buf,&mut dst_buf2).await?
                }
            }
        }
        Ok(())
    }
    pub async fn handle_ipv4_data(&mut self, buf: &[u8], dst_buf: &mut [u8]) -> anyhow::Result<()> {
        let result = self.tunn.encapsulate(buf, dst_buf);
        match result {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(data) => {
                self.udp.send_to(data, self.wg_source_addr).await?;
            }
            e => Err(anyhow!("{:?}", e))?,
        }
        Ok(())
    }

    pub async fn handle_wg_data(
        &mut self,
        mut buf: &mut [u8],
        dst_buf: &mut [u8],
        dst_buf2: &mut [u8],
    ) -> anyhow::Result<()> {
        loop {
            let mut result = self.tunn.decapsulate(None, buf, dst_buf);
            if !self.handle_tunn_result(&mut result, dst_buf2).await? {
                break;
            }
            buf = &mut [];
        }

        Ok(())
    }
    async fn handle_tunn_result(
        &mut self,
        result: &mut TunnResult<'_>,
        dst_buf: &mut [u8],
    ) -> anyhow::Result<bool> {
        match result {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                // 超时了直接断开，vnts不重连，等对端重连
                return Err(anyhow!("链接超时"));
            }
            TunnResult::Err(e) => {
                log::warn!("WireGuard数据异常 {:?}", e);
            }
            TunnResult::WriteToNetwork(data) => {
                self.udp.send_to(data, self.wg_source_addr).await?;
                return Ok(true);
            }
            TunnResult::WriteToTunnelV4(data, _source_ip) => {
                let mut packet = IpV4Packet::new(data)?;
                let source_ip = packet.source_ip();
                let destination_ip = packet.destination_ip();
                if let Err(e) = self
                    .turn_data(source_ip, destination_ip, &mut packet.buffer, dst_buf)
                    .await
                {
                    log::warn!("wg数据转发失败 {}->{} {:?}", source_ip, destination_ip, e);
                }
            }
            TunnResult::WriteToTunnelV6(_packet, ip) => {
                return Err(anyhow!("不支持ipv6连接 {:?}", ip))
            }
        }
        Ok(false)
    }
    /// from 'wireguard_tick':
    /// This is a state keeping function, that need to be called periodically.
    /// Recommended interval: 100ms.
    pub async fn update_timers(
        &mut self,
        dst_buf: &mut [u8],
        dst_buf2: &mut [u8],
    ) -> anyhow::Result<()> {
        let mut result = self.tunn.update_timers(dst_buf);
        self.handle_tunn_result(&mut result, dst_buf2).await?;
        Ok(())
    }
    async fn turn_data(
        &mut self,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        data: &mut [u8],
        dst_buf: &mut [u8],
    ) -> anyhow::Result<()> {
        if dest_ip == self.gateway_ip {
            if self.ping(data, src_ip, dest_ip).is_ok() {
                if let Err(e) = self.handle_ipv4_data(&data, dst_buf).await {
                    log::warn!("发送ping回应到wg失败,{:?}", e)
                }
            }
            return Ok(());
        }
        if dest_ip.is_broadcast() || dest_ip == self.broadcast_ip {
            // 广播
            let x: Vec<_> = self
                .network_info
                .read()
                .clients
                .values()
                .filter(|v| v.online && v.virtual_ip != u32::from(self.ip))
                .map(|v| {
                    (
                        v.address,
                        v.tcp_sender.clone(),
                        v.server_secret,
                        v.wg_sender.clone(),
                    )
                })
                .collect();
            for (peer_addr, peer_tcp_sender, server_secret, peer_wg_sender) in x {
                if let Err(e) = self
                    .send_one(
                        peer_addr,
                        peer_tcp_sender,
                        peer_wg_sender,
                        server_secret,
                        src_ip,
                        dest_ip,
                        data,
                        dst_buf,
                    )
                    .await
                {
                    log::warn!("wg广播失败 {} {} {:?}", src_ip, peer_addr, e);
                }
            }
            return Ok(());
        }

        let (server_secret, peer_addr, peer_tcp_sender, peer_wg_sender) = {
            let guard = self.network_info.read();
            if let Some(dest_client_info) = guard.clients.get(&dest_ip.into()) {
                if !dest_client_info.online {
                    Err(anyhow!("目标不在线"))?
                }
                if !dest_client_info.virtual_ip == u32::from(self.ip) {
                    Err(anyhow!("阻止回路"))?
                }
                let dest_link_addr = dest_client_info.address;
                let server_secret = dest_client_info.server_secret;
                (
                    server_secret,
                    dest_link_addr,
                    dest_client_info.tcp_sender.clone(),
                    dest_client_info.wg_sender.clone(),
                )
            } else {
                Err(anyhow!("目标未注册"))?
            }
        };

        self.send_one(
            peer_addr,
            peer_tcp_sender,
            peer_wg_sender,
            server_secret,
            src_ip,
            dest_ip,
            data,
            dst_buf,
        )
        .await?;
        Ok(())
    }
    async fn send_one(
        &self,
        peer_addr: SocketAddr,
        peer_tcp_sender: Option<Sender<Vec<u8>>>,
        peer_wg_sender: Option<Sender<(Vec<u8>, Ipv4Addr)>>,
        server_secret: bool,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        data: &mut [u8],
        dst_buf: &mut [u8],
    ) -> anyhow::Result<()> {
        if let Some(peer_wg_sender) = peer_wg_sender {
            if let Err(e) = peer_wg_sender.send((data.to_vec(), self.ip)).await {
                Err(anyhow!("发送到对端wg失败 {}", e))?
            }
            return Ok(());
        }
        let mut net_packet = NetPacket::new0(HEAD_LEN + data.len(), dst_buf)?;
        net_packet.set_default_version();
        // 把wg的转发当成是服务端来源的数据，因为服务端没有客户端密钥对数据进行加密
        net_packet.set_gateway_flag(true);
        net_packet.set_protocol(Protocol::IpTurn);
        net_packet.set_transport_protocol(ip_turn_packet::Protocol::WGIpv4.into());
        net_packet.first_set_ttl(MAX_TTL);
        net_packet.set_source(src_ip);
        net_packet.set_destination(dest_ip);
        net_packet.set_payload(data)?;
        if server_secret {
            let cipher = self
                .cache
                .cipher_session
                .get(&peer_addr)
                .context("加密信息不存在")?;
            cipher.encrypt_ipv4(&mut net_packet)?;
        }
        if let Some(tcp_sender) = peer_tcp_sender {
            tcp_sender.send(net_packet.buffer().to_vec()).await?;
        } else {
            self.udp.send_to(net_packet.buffer(), peer_addr).await?;
        }
        Ok(())
    }
    fn ping(&self, data: &mut [u8], src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> anyhow::Result<()> {
        let mut ipv4 = IpV4Packet::new(data)?;
        if let ipv4::protocol::Protocol::Icmp = ipv4.protocol() {
            let mut icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
            if icmp_packet.kind() == Kind::EchoRequest {
                //开启ping
                icmp_packet.set_kind(Kind::EchoReply);
                icmp_packet.update_checksum();
                ipv4.set_source_ip(dest_ip);
                ipv4.set_destination_ip(src_ip);
                ipv4.update_checksum();
                return Ok(());
            }
        }
        Err(anyhow!("非ping Echo 不处理"))
    }
}
