use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::server::control_server::db::{ClientType, DeviceRecord};
use crate::server::control_server::service::{ControlService, Session};
use crate::utils::config::WireGuardConfig;
use anyhow::{Context, bail};
use base64::Engine;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Packet, Tunn, TunnResult, handshake};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::{Bytes, BytesMut};
use pnet_packet::MutablePacket;
use pnet_packet::icmp::{IcmpTypes, MutableIcmpPacket};
use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use rand::RngCore;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

const CHANNEL_CAPACITY: usize = 1024;
const MAX_PACKET_SIZE: usize = 65_535;
/// A WireGuard tunnel has no disconnect message.  Treat a peer as offline when it has
/// not sent us an authenticated packet for this long, rather than waiting for the
/// much longer cryptographic-session expiration in boringtun.
const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone)]
pub struct WireGuardHandle {
    command_tx: mpsc::Sender<Command>,
    #[cfg(test)]
    local_addr: SocketAddr,
}

impl WireGuardHandle {
    #[cfg(test)]
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub async fn disconnect_device(&self, network_code: &str, device_id: &str) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .command_tx
            .send(Command::DisconnectDevice {
                network_code: network_code.to_string(),
                device_id: device_id.to_string(),
                response,
            })
            .await
            .is_err()
        {
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    pub async fn reload_devices(&self, devices: Vec<DeviceRecord>) -> anyhow::Result<()> {
        let devices = decode_devices(devices)?;
        let (response, receiver) = oneshot::channel();
        self.command_tx
            .send(Command::ReloadDevices { devices, response })
            .await?;
        receiver.await?
    }

    pub async fn shutdown(&self) {
        let (response, receiver) = oneshot::channel();
        if self
            .command_tx
            .send(Command::Shutdown { response })
            .await
            .is_ok()
        {
            let _ = receiver.await;
        }
    }
}

enum Command {
    DisconnectDevice {
        network_code: String,
        device_id: String,
        response: oneshot::Sender<bool>,
    },
    ReloadDevices {
        devices: HashMap<[u8; 32], PeerConfig>,
        response: oneshot::Sender<anyhow::Result<()>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
struct PeerConfig {
    network_code: String,
    device_id: String,
    ip: Ipv4Addr,
}

struct Peer {
    config: PeerConfig,
    address: SocketAddr,
    tunnel: Tunn,
    last_authenticated_at: Instant,
    _session: Session,
    relay_task: tokio::task::JoinHandle<()>,
    receiver_idx: Option<u32>,
}

struct RelayPacket {
    public_key: [u8; 32],
    packet: Bytes,
}

pub fn generate_private_key() -> String {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    base64::engine::general_purpose::STANDARD.encode(key)
}

pub fn server_public_key(config: &WireGuardConfig) -> anyhow::Result<String> {
    let private = decode_key(
        config
            .private_key
            .as_deref()
            .context("WireGuard 私钥未配置")?,
    )?;
    let public = PublicKey::from(&StaticSecret::from(private));
    Ok(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
}

pub async fn start(
    config: WireGuardConfig,
    control: ControlService,
) -> anyhow::Result<WireGuardHandle> {
    config.validate()?;
    if !config.enabled {
        bail!("WireGuard 服务未启用");
    }
    let private_key = decode_key(
        config
            .private_key
            .as_deref()
            .context("WireGuard 私钥未配置")?,
    )?;
    let socket = Arc::new(
        UdpSocket::from_std(crate::utils::net::bind_udp_socket(config.bind)?)
            .with_context(|| format!("无法绑定 WireGuard UDP 地址 {}", config.bind))?,
    );
    #[cfg(test)]
    let local_addr = socket.local_addr()?;
    let devices = decode_devices(control.wireguard_devices().await?)?;
    let (command_tx, command_rx) = mpsc::channel(32);
    let (relay_tx, relay_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let service = WireGuardService {
        config,
        private_key,
        socket,
        control,
        devices,
        peers: HashMap::new(),
        address_to_peer: HashMap::new(),
        receiver_to_peer: HashMap::new(),
        command_rx,
        relay_tx,
        relay_rx,
    };
    tokio::spawn(async move {
        if let Err(error) = service.run().await {
            log::error!("WireGuard 服务异常退出: {error:#}");
        }
    });
    Ok(WireGuardHandle {
        command_tx,
        #[cfg(test)]
        local_addr,
    })
}

struct WireGuardService {
    config: WireGuardConfig,
    private_key: [u8; 32],
    socket: Arc<UdpSocket>,
    control: ControlService,
    devices: HashMap<[u8; 32], PeerConfig>,
    peers: HashMap<[u8; 32], Peer>,
    address_to_peer: HashMap<SocketAddr, [u8; 32]>,
    receiver_to_peer: HashMap<u32, [u8; 32]>,
    command_rx: mpsc::Receiver<Command>,
    relay_tx: mpsc::Sender<RelayPacket>,
    relay_rx: mpsc::Receiver<RelayPacket>,
}

impl WireGuardService {
    async fn run(mut self) -> anyhow::Result<()> {
        let mut buffer = [0u8; MAX_PACKET_SIZE];
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buffer) => {
                    let (length, address) = received?;
                    if let Err(error) = self.handle_udp(&buffer[..length], address).await {
                        log::warn!("WireGuard 数据包处理失败: peer={address}, error={error:#}");
                    }
                }
                Some(relay) = self.relay_rx.recv() => {
                    if let Err(error) = self.handle_relay(relay).await {
                        log::warn!("WireGuard 内部转发失败: {error:#}");
                    }
                }
                Some(command) = self.command_rx.recv() => {
                    if self.handle_command(command).await { break; }
                }
                _ = interval.tick() => self.tick().await,
                else => break,
            }
        }
        self.disconnect_all();
        Ok(())
    }

    async fn handle_udp(&mut self, data: &[u8], address: SocketAddr) -> anyhow::Result<()> {
        let parsed =
            Tunn::parse_incoming_packet(data).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let public_key = match parsed {
            Packet::HandshakeInit(handshake_packet) => {
                let private = StaticSecret::from(self.private_key);
                let public = PublicKey::from(&private);
                handshake::parse_handshake_anon(&private, &public, &handshake_packet)
                    .map_err(|error| anyhow::anyhow!("{error:?}"))?
                    .peer_static_public
            }
            Packet::HandshakeResponse(packet) => *self
                .receiver_to_peer
                .get(&packet.receiver_idx)
                .context("未知的 WireGuard 会话")?,
            Packet::PacketCookieReply(packet) => *self
                .receiver_to_peer
                .get(&packet.receiver_idx)
                .context("未知的 WireGuard 会话")?,
            Packet::PacketData(packet) => *self
                .receiver_to_peer
                .get(&packet.receiver_idx)
                .context("未知的 WireGuard 会话")?,
        };
        if !self.peers.contains_key(&public_key) {
            self.connect_peer(public_key, address).await?;
        } else {
            let peer = self.peers.get_mut(&public_key).unwrap();
            if peer.address != address {
                self.address_to_peer.remove(&peer.address);
                peer.address = address;
            }
            self.address_to_peer.insert(address, public_key);
        }
        self.process_tunnel_input(public_key, data).await?;
        // Only refresh liveness after boringtun has successfully authenticated and
        // processed the packet. Parsing a UDP packet or matching its receiver index
        // alone must not keep a peer online.
        if let Some(peer) = self.peers.get_mut(&public_key) {
            peer.last_authenticated_at = Instant::now();
        }
        Ok(())
    }

    async fn connect_peer(
        &mut self,
        public_key: [u8; 32],
        address: SocketAddr,
    ) -> anyhow::Result<()> {
        let peer_config = self
            .devices
            .get(&public_key)
            .context("WireGuard 公钥未绑定到设备")?
            .clone();
        let (sender, mut receiver) = mpsc::channel(CHANNEL_CAPACITY);
        let session = self
            .control
            .register_wireguard(
                peer_config.network_code.clone(),
                peer_config.device_id.clone(),
                sender,
            )
            .await?;
        let relay_tx = self.relay_tx.clone();
        let relay_task = tokio::spawn(async move {
            while let Some(packet) = receiver.recv().await {
                if relay_tx
                    .send(RelayPacket { public_key, packet })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let tunnel_index = rand::rng().next_u32();
        let tunnel = Tunn::new(
            StaticSecret::from(self.private_key),
            PublicKey::from(public_key),
            None,
            (self.config.persistent_keepalive > 0).then_some(self.config.persistent_keepalive),
            tunnel_index,
            None,
        );
        self.address_to_peer.insert(address, public_key);
        self.peers.insert(
            public_key,
            Peer {
                config: peer_config,
                address,
                tunnel,
                last_authenticated_at: Instant::now(),
                _session: session,
                relay_task,
                receiver_idx: None,
            },
        );
        Ok(())
    }

    async fn process_tunnel_input(
        &mut self,
        public_key: [u8; 32],
        data: &[u8],
    ) -> anyhow::Result<()> {
        let mut input = data;
        loop {
            let action = {
                let peer = self
                    .peers
                    .get_mut(&public_key)
                    .context("WireGuard peer 已断开")?;
                let mut output = [0u8; MAX_PACKET_SIZE];
                match peer.tunnel.decapsulate(None, input, &mut output) {
                    TunnResult::Done => TunnelAction::Done,
                    TunnResult::Err(WireGuardError::ConnectionExpired) => TunnelAction::Expired,
                    TunnResult::Err(error) => TunnelAction::Error(format!("{error:?}")),
                    TunnResult::WriteToNetwork(packet) => TunnelAction::Network(packet.to_vec()),
                    TunnResult::WriteToTunnelV4(packet, _) => TunnelAction::Ipv4(packet.to_vec()),
                    TunnResult::WriteToTunnelV6(_, _) => TunnelAction::Error("不支持 IPv6".into()),
                }
            };
            input = &[];
            match action {
                TunnelAction::Done => return Ok(()),
                TunnelAction::Expired => {
                    self.disconnect_peer(public_key);
                    return Ok(());
                }
                TunnelAction::Error(error) => bail!(error),
                TunnelAction::Network(packet) => {
                    self.remember_sender_index(public_key, &packet);
                    let address = self.peers.get(&public_key).unwrap().address;
                    self.socket.send_to(&packet, address).await?;
                }
                TunnelAction::Ipv4(packet) => self.forward_ipv4(public_key, packet).await?,
            }
        }
    }

    async fn forward_ipv4(
        &mut self,
        public_key: [u8; 32],
        mut packet: Vec<u8>,
    ) -> anyhow::Result<()> {
        let peer = self
            .peers
            .get(&public_key)
            .context("WireGuard peer 已断开")?;
        let ipv4 = checked_ipv4(&packet)?;
        let source = ipv4.get_source();
        let destination = ipv4.get_destination();
        if !self
            .control
            .address_owned_by(&peer.config.network_code, peer.config.ip, source)
        {
            bail!("WireGuard 源 IP 冒充: {source}");
        }
        let network_code = peer.config.network_code.clone();
        let device_id = peer.config.device_id.clone();
        let source_id = peer.config.ip;
        let state = peer._session.network_state.clone();
        let gateway = state.gateway();
        let broadcast = ipnet::Ipv4Net::new(state.gateway(), state.net_prefix_len())?
            .trunc()
            .broadcast();
        if destination == gateway && make_ping_reply(&mut packet)? {
            return self.encapsulate(public_key, &packet).await;
        }
        if destination.is_broadcast() || destination == broadcast {
            for key in self
                .peers
                .keys()
                .copied()
                .filter(|key| key != &public_key)
                .collect::<Vec<_>>()
            {
                if self
                    .peers
                    .get(&key)
                    .is_some_and(|target| target.config.network_code == network_code)
                {
                    let _ = self.encapsulate(key, &packet).await;
                }
            }
            for sender in state.sender_map().iter() {
                let target_ip = *sender.key();
                let Some(device) = state.get_device_entry_by_ip(target_ip) else {
                    continue;
                };
                let msg_type = match device.client_type {
                    ClientType::Vnt if device.allow_wireguard => MsgType::WireGuardRelay,
                    ClientType::Ikev2 => MsgType::Ikev2Relay,
                    _ => continue,
                };
                let mut relay = BytesMut::zeroed(HEAD_LENGTH + packet.len());
                let mut relay_packet = NetPacket::new(&mut relay)?;
                relay_packet.set_msg_type(msg_type);
                relay_packet.set_gateway_flag(true);
                relay_packet.set_ttl(5);
                relay_packet.set_src_id(source.into());
                relay_packet.set_dest_id(destination.into());
                relay_packet.set_payload(&packet)?;
                let _ = sender.value().try_send(relay.freeze());
            }
            return Ok(());
        }
        self.control
            .forward_wireguard_packet(&network_code, &device_id, source_id, &packet)
            .await?;
        Ok(())
    }

    async fn handle_relay(&mut self, relay: RelayPacket) -> anyhow::Result<()> {
        let packet = NetPacket::new(relay.packet)?;
        if packet.msg_type()? != MsgType::WireGuardRelay {
            return Ok(());
        }
        let peer = self
            .peers
            .get(&relay.public_key)
            .context("WireGuard peer 已断开")?;
        let ipv4 = checked_ipv4(packet.payload())?;
        let source_id = Ipv4Addr::from(packet.src_id());
        if Ipv4Addr::from(packet.dest_id()) != peer.config.ip
            || !self.control.address_owned_by(
                &peer.config.network_code,
                source_id,
                ipv4.get_source(),
            )
            || !self.control.address_owned_by(
                &peer.config.network_code,
                peer.config.ip,
                ipv4.get_destination(),
            )
        {
            bail!("WireGuard relay 地址不匹配");
        }
        self.encapsulate(relay.public_key, packet.payload()).await
    }

    async fn encapsulate(&mut self, public_key: [u8; 32], payload: &[u8]) -> anyhow::Result<()> {
        let (address, action) = {
            let peer = self
                .peers
                .get_mut(&public_key)
                .context("WireGuard peer 已断开")?;
            let mut output = [0u8; MAX_PACKET_SIZE];
            let action = match peer.tunnel.encapsulate(payload, &mut output) {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                TunnResult::Done => return Ok(()),
                result => bail!("WireGuard 封装失败: {result:?}"),
            };
            (peer.address, action)
        };
        self.remember_sender_index(public_key, &action);
        self.socket.send_to(&action, address).await?;
        Ok(())
    }

    async fn tick(&mut self) {
        let now = Instant::now();
        for key in self.peers.keys().copied().collect::<Vec<_>>() {
            if self
                .peers
                .get(&key)
                .is_some_and(|peer| peer_is_idle(peer.last_authenticated_at, now))
            {
                if let Some(peer) = self.peers.get(&key) {
                    log::info!(
                        "WireGuard peer idle timeout: network_code={},device_id={}",
                        peer.config.network_code,
                        peer.config.device_id
                    );
                }
                self.disconnect_peer(key);
                continue;
            }
            let result = {
                let peer = self.peers.get_mut(&key).unwrap();
                let mut output = [0u8; MAX_PACKET_SIZE];
                match peer.tunnel.update_timers(&mut output) {
                    TunnResult::WriteToNetwork(packet) => Some(Ok(packet.to_vec())),
                    TunnResult::Err(WireGuardError::ConnectionExpired) => Some(Err(())),
                    _ => None,
                }
            };
            match result {
                Some(Ok(packet)) => {
                    self.remember_sender_index(key, &packet);
                    if let Some(peer) = self.peers.get(&key) {
                        let _ = self.socket.send_to(&packet, peer.address).await;
                    }
                }
                Some(Err(())) => self.disconnect_peer(key),
                None => {}
            }
        }
    }

    async fn handle_command(&mut self, command: Command) -> bool {
        match command {
            Command::DisconnectDevice {
                network_code,
                device_id,
                response,
            } => {
                let key = self
                    .peers
                    .iter()
                    .find(|(_, peer)| {
                        peer.config.network_code == network_code
                            && peer.config.device_id == device_id
                    })
                    .map(|(key, _)| *key);
                let disconnected = key
                    .map(|key| {
                        self.disconnect_peer(key);
                        true
                    })
                    .unwrap_or(false);
                let _ = response.send(disconnected);
            }
            Command::ReloadDevices { devices, response } => {
                let removed = self
                    .peers
                    .iter()
                    .filter(|(key, peer)| {
                        devices.get(*key).is_none_or(|config| {
                            config.network_code != peer.config.network_code
                                || config.device_id != peer.config.device_id
                                || config.ip != peer.config.ip
                        })
                    })
                    .map(|(key, _)| *key)
                    .collect::<Vec<_>>();
                for key in removed {
                    self.disconnect_peer(key);
                }
                self.devices = devices;
                let _ = response.send(Ok(()));
            }
            Command::Shutdown { response } => {
                self.disconnect_all();
                let _ = response.send(());
                return true;
            }
        }
        false
    }

    fn disconnect_peer(&mut self, public_key: [u8; 32]) {
        if let Some(peer) = self.peers.remove(&public_key) {
            self.address_to_peer.remove(&peer.address);
            if let Some(receiver_idx) = peer.receiver_idx {
                self.receiver_to_peer.remove(&receiver_idx);
            }
            peer.relay_task.abort();
        }
    }

    fn remember_sender_index(&mut self, public_key: [u8; 32], packet: &[u8]) {
        if packet.len() < 8 || !matches!(u32::from_le_bytes(packet[..4].try_into().unwrap()), 1 | 2)
        {
            return;
        }
        let receiver_idx = u32::from_le_bytes(packet[4..8].try_into().unwrap());
        if let Some(peer) = self.peers.get_mut(&public_key)
            && let Some(old) = peer.receiver_idx.replace(receiver_idx)
        {
            self.receiver_to_peer.remove(&old);
        }
        self.receiver_to_peer.insert(receiver_idx, public_key);
    }

    fn disconnect_all(&mut self) {
        for key in self.peers.keys().copied().collect::<Vec<_>>() {
            self.disconnect_peer(key);
        }
    }
}

fn peer_is_idle(last_authenticated_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_authenticated_at) >= PEER_IDLE_TIMEOUT
}

enum TunnelAction {
    Done,
    Expired,
    Error(String),
    Network(Vec<u8>),
    Ipv4(Vec<u8>),
}

pub(crate) fn decode_key(value: &str) -> anyhow::Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("WireGuard 密钥不是有效的 base64")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("WireGuard 密钥必须为 32 字节"))
}

fn decode_devices(devices: Vec<DeviceRecord>) -> anyhow::Result<HashMap<[u8; 32], PeerConfig>> {
    let mut result = HashMap::new();
    for device in devices {
        if device.client_type != ClientType::Wireguard {
            continue;
        }
        let public_key = decode_key(
            device
                .wireguard_public_key
                .as_deref()
                .context("WireGuard 设备缺少公钥")?,
        )?;
        let private_key = decode_key(
            device
                .wireguard_private_key
                .as_deref()
                .context("WireGuard 设备缺少私钥")?,
        )?;
        if PublicKey::from(&StaticSecret::from(private_key)).as_bytes() != &public_key {
            bail!("WireGuard 设备 '{}' 的密钥对不匹配", device.device_id);
        }
        let ip = device
            .ip
            .as_deref()
            .context("WireGuard 设备缺少 IP")?
            .parse()?;
        result.insert(
            public_key,
            PeerConfig {
                network_code: device.network_code,
                device_id: device.device_id,
                ip,
            },
        );
    }
    Ok(result)
}

fn checked_ipv4(packet: &[u8]) -> anyhow::Result<Ipv4Packet<'_>> {
    let ipv4 = Ipv4Packet::new(packet).context("无效的 IPv4 数据包")?;
    let header_length = ipv4.get_header_length() as usize * 4;
    if ipv4.get_version() != 4
        || header_length < Ipv4Packet::minimum_packet_size()
        || ipv4.get_total_length() as usize != packet.len()
    {
        bail!("IPv4 数据包长度无效");
    }
    Ok(ipv4)
}

fn make_ping_reply(packet: &mut [u8]) -> anyhow::Result<bool> {
    let Some(mut ipv4) = MutableIpv4Packet::new(packet) else {
        return Ok(false);
    };
    if ipv4.get_next_level_protocol() != pnet_packet::ip::IpNextHeaderProtocols::Icmp {
        return Ok(false);
    }
    let source = ipv4.get_source();
    let destination = ipv4.get_destination();
    {
        let Some(mut icmp) = MutableIcmpPacket::new(ipv4.payload_mut()) else {
            return Ok(false);
        };
        if icmp.get_icmp_type() != IcmpTypes::EchoRequest {
            return Ok(false);
        }
        icmp.set_icmp_type(IcmpTypes::EchoReply);
        icmp.set_checksum(pnet_packet::icmp::checksum(&icmp.to_immutable()));
    }
    ipv4.set_source(destination);
    ipv4.set_destination(source);
    ipv4.set_checksum(pnet_packet::ipv4::checksum(&ipv4.to_immutable()));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
    use crate::server::control_server::db::DeviceIpType;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn peer_is_offline_after_idle_timeout() {
        let last_authenticated_at = Instant::now();

        assert!(!peer_is_idle(
            last_authenticated_at,
            last_authenticated_at + PEER_IDLE_TIMEOUT - Duration::from_secs(1),
        ));
        assert!(peer_is_idle(
            last_authenticated_at,
            last_authenticated_at + PEER_IDLE_TIMEOUT,
        ));
    }

    #[tokio::test]
    async fn real_wireguard_handshake_and_gateway_ping_round_trip() {
        let control = ControlService::new(
            "10.95.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let (sender, _receiver) = mpsc::channel(8);
        let seed = control
            .register(
                RegRequestMsg {
                    network_code: "wg-test".to_string(),
                    device_id: "seed".to_string(),
                    ip: None,
                    name: "seed".to_string(),
                    version: "test".to_string(),
                    key_sign: None,
                    ip_variable: true,
                    server_id: 0,
                    registration_mode: RegistrationMode::Normal,
                    advertised_subnets: Vec::new(),
                    allow_ikev2: false,
                    allow_wireguard: false,
                    subscription: None,
                    client_instance_id: Vec::new(),
                },
                sender,
            )
            .await
            .unwrap();
        drop(seed);
        control
            .add_device_typed(
                "wg-test",
                "wg-peer",
                "10.95.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Wireguard,
                None,
                Some("WG peer".to_string()),
                None,
                None,
                Some(vec!["192.168.50.0/24".parse().unwrap()]),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let device = control
            .get_device_record("wg-test", "wg-peer")
            .await
            .unwrap()
            .unwrap();
        let client_private = decode_key(device.wireguard_private_key.as_deref().unwrap()).unwrap();
        let server_private = generate_private_key();
        let config = WireGuardConfig {
            enabled: true,
            bind: "127.0.0.1:0".parse().unwrap(),
            endpoint: "127.0.0.1:51820".to_string(),
            private_key: Some(server_private.clone()),
            persistent_keepalive: 25,
        };
        let handle = start(config, control.clone()).await.unwrap();
        control.set_wireguard_manager(handle.clone());
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_public =
            PublicKey::from(&StaticSecret::from(decode_key(&server_private).unwrap()));
        let mut client = Tunn::new(
            StaticSecret::from(client_private),
            server_public,
            None,
            Some(25),
            7,
            None,
        );
        let mut output = [0u8; MAX_PACKET_SIZE];
        let initiation = match client.format_handshake_initiation(&mut output, false) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            result => panic!("unexpected initiation result: {result:?}"),
        };
        socket
            .send_to(&initiation, handle.local_addr())
            .await
            .unwrap();
        let mut udp = [0u8; MAX_PACKET_SIZE];
        let (length, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut udp))
            .await
            .unwrap()
            .unwrap();
        let mut scratch = [0u8; MAX_PACKET_SIZE];
        match client.decapsulate(None, &udp[..length], &mut scratch) {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(packet) => {
                socket.send_to(packet, handle.local_addr()).await.unwrap();
            }
            result => panic!("unexpected handshake response: {result:?}"),
        }

        control
            .update_device_with_password(
                "wg-test",
                "wg-peer",
                "10.95.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                None,
                Some("WG peer".to_string()),
                None,
                None,
                Some(vec!["192.168.51.0/24".parse().unwrap()]),
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let mut ping = vec![0u8; 28];
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ping).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(28);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(pnet_packet::ip::IpNextHeaderProtocols::Icmp);
            ipv4.set_source("192.168.51.7".parse().unwrap());
            ipv4.set_destination("10.95.0.1".parse().unwrap());
            let mut icmp = MutableIcmpPacket::new(ipv4.payload_mut()).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            icmp.set_checksum(pnet_packet::icmp::checksum(&icmp.to_immutable()));
            ipv4.set_checksum(pnet_packet::ipv4::checksum(&ipv4.to_immutable()));
        }
        let encrypted = match client.encapsulate(&ping, &mut output) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            result => panic!("unexpected encapsulation result: {result:?}"),
        };
        let roaming_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        roaming_socket
            .send_to(&encrypted, handle.local_addr())
            .await
            .unwrap();
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), roaming_socket.recv_from(&mut udp))
                .await
                .unwrap()
                .unwrap();
        let reply = match client.decapsulate(None, &udp[..length], &mut scratch) {
            TunnResult::WriteToTunnelV4(packet, _) => packet.to_vec(),
            result => panic!("unexpected reply result: {result:?}"),
        };
        let reply = checked_ipv4(&reply).unwrap();
        assert_eq!(reply.get_source(), "10.95.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            reply.get_destination(),
            "192.168.51.7".parse::<Ipv4Addr>().unwrap()
        );
        handle.shutdown().await;
    }
}
