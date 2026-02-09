use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
use crate::server::control_server::db;
use crate::server::control_server::db::{NetworkRecord, NetworkSource};
use crate::server::network_state_provider::{i64_to_system_time, NetworkState, NetworkStateProvider};
use anyhow::{Context, bail};
use bytes::Bytes;
use dashmap::DashMap;
use ipnet::Ipv4Net;
use parking_lot::RwLock;
use rand::RngCore;
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;
use time::OffsetDateTime;
use time::macros::format_description;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationStatus {
    Confirmed,
    PendingConfirmation,
}

#[derive(Clone, Copy)]
pub struct NetworkConfig {
    pub net: Ipv4Net,
    pub lease_duration: Duration,
    pub source: NetworkSource,
}

#[derive(Clone)]
pub struct ControlService {
    default_net: Ipv4Net,
    default_lease_duration: Duration,
    db_nets: Arc<RwLock<HashMap<String, NetworkConfig>>>,
    network_state_provider: NetworkStateProvider,
    network_init_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    peer_manager: Arc<RwLock<Option<Arc<crate::server::peer_server::PeerServerManager>>>>,
}

impl ControlService {
    pub async fn new(
        default_net: Ipv4Net,
        custom_nets: HashMap<String, Ipv4Net>,
        lease_duration: Duration,
    ) -> Self {
        let network_states = Arc::new(DashMap::new());

        Self::save_config_networks_to_db(&default_net, &custom_nets, lease_duration).await;
        let db_nets = Self::load_networks_from_db().await;

        let service = Self {
            default_net,
            default_lease_duration: lease_duration,
            db_nets: Arc::new(RwLock::new(db_nets)),
            network_state_provider: NetworkStateProvider::new(network_states),
            network_init_locks: Arc::new(DashMap::new()),
            peer_manager: Arc::new(RwLock::new(None)),
        };

        let cleanup_interval = Duration::from_secs(30 * 60);
        let cleanup_interval = cleanup_interval
            .min(lease_duration / 2)
            .max(Duration::from_secs(10));
        service.start_cleanup_task(cleanup_interval);

        service
    }

    async fn save_config_networks_to_db(
        _default_net: &Ipv4Net,
        custom_nets: &HashMap<String, Ipv4Net>,
        lease_duration: Duration,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let lease_secs = lease_duration.as_secs() as i64;

        for (code, net) in custom_nets {
            let gateway = Ipv4Addr::from(u32::from(net.network()) + 1);
            let record = NetworkRecord {
                network_code: code.clone(),
                gateway: gateway.to_string(),
                netmask: net.prefix_len(),
                lease_duration: lease_secs,
                source: NetworkSource::Config,
                created_at: now,
            };
            match db::save_network_if_not_exists(&record).await {
                Ok(true) => log::info!("Initialized network '{}' from config", code),
                Ok(false) => {}
                Err(e) => log::error!("Failed to save custom network {}: {}", code, e),
            }
        }
    }

    async fn load_networks_from_db() -> HashMap<String, NetworkConfig> {
        let mut nets = HashMap::new();
        match db::load_all_networks().await {
            Ok(records) => {
                for record in records {
                    if let Some(net) = record.to_ipv4_net() {
                        nets.insert(
                            record.network_code,
                            NetworkConfig {
                                net,
                                lease_duration: Duration::from_secs(record.lease_duration as u64),
                                source: record.source,
                            },
                        );
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to load networks from DB: {}", e);
            }
        }
        nets
    }

    pub async fn register(
        &self,
        reg_req: RegRequestMsg,
        sender: Sender<Bytes>,
    ) -> anyhow::Result<Session> {
        reg_req.check()?;
        let network_code = reg_req.network_code.clone();
        let registration_mode = reg_req.registration_mode;

        let is_new_network = !self.db_nets.read().contains_key(&reg_req.network_code);
        let config = self.network_config(&reg_req.network_code, reg_req.ip);

        if is_new_network {
            self.db_nets.write().insert(reg_req.network_code.clone(), config);
        }

        let state = self
            .get_or_create_network_state(reg_req.network_code.clone(), config)
            .await;

        let (session, entry) = {
            let random_id = rand::rng().next_u64();
            let device_id = reg_req.device_id.clone();

            let (ip, _old_ip, entry) = match state.allocate_ip_and_get_entry(reg_req, random_id, sender) {
                Ok(rs) => rs,
                Err(e) => {
                    log::warn!("network_code={network_code},device_id={device_id},e={e:?}");
                    return Err(e);
                }
            };

            (
                Session {
                    network_code: network_code.clone(),
                    device_id: device_id.clone(),
                    ip,
                    random_id,
                    network_state: state.clone(),
                    registration_status: match registration_mode {
                        RegistrationMode::Normal => RegistrationStatus::Confirmed,
                        RegistrationMode::PreRegister => RegistrationStatus::PendingConfirmation,
                    },
                    control_service: self.clone(),
                },
                entry,
            )
        };

        if is_new_network {
            let gateway = Ipv4Addr::from(u32::from(config.net.network()) + 1);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let record = NetworkRecord {
                network_code: network_code.clone(),
                gateway: gateway.to_string(),
                netmask: config.net.prefix_len(),
                lease_duration: config.lease_duration.as_secs() as i64,
                source: NetworkSource::DeviceRegister,
                created_at: now,
            };
            tokio::spawn(async move {
                if let Err(e) = db::save_network(&record).await {
                    log::error!("Failed to save new network: {:?}", e);
                }
            });
        }

        if matches!(registration_mode, RegistrationMode::Normal) {
            if let Some(entry) = entry {
                let nc = network_code.clone();
                tokio::spawn(async move {
                    let record = entry.to_record(&nc);
                    if let Err(e) = db::save_or_update_device(&record).await {
                        log::error!("Failed to save or update device record: {:?}", e);
                    }
                });
            }
        }

        Ok(session)
    }

    fn network_config(&self, network_code: &str, ip: Option<Ipv4Addr>) -> NetworkConfig {
        if let Some(config) = self.db_nets.read().get(network_code) {
            return *config;
        }
        let net = if let Some(ip) = ip {
            Ipv4Net::new_assert(Ipv4Net::new_assert(ip, 24).network(), 24)
        } else {
            self.default_net
        };
        NetworkConfig {
            net,
            lease_duration: self.default_lease_duration,
            source: NetworkSource::DeviceRegister,
        }
    }

    /// DCL: 获取或创建 NetworkState
    async fn get_or_create_network_state(
        &self,
        network_code: String,
        config: NetworkConfig,
    ) -> Arc<NetworkState> {
        if let Some(existing) = self.network_state_provider.get(&network_code) {
            existing.update_time();
            return existing.clone();
        }

        let init_lock = self
            .network_init_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();

        let _guard = init_lock.lock().await;

        if let Some(existing) = self.network_state_provider.get(&network_code) {
            existing.update_time();
            return existing.clone();
        }

        let new_state = Arc::new(
            NetworkState::new_from_db(network_code.clone(), config.net, config.lease_duration)
                .await,
        );

        self.network_state_provider
            .insert(network_code, new_state.clone());
        new_state
    }

    fn release_network(&self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(60 * 60);
        let keys: Vec<String> = self
            .network_state_provider
            .iter()
            .filter(|v| v.last_active_time() + timeout < now)
            .map(|v| v.key().clone())
            .collect();
        for network_code in keys {
            let option = self.network_state_provider.get(&network_code).map(|v| v.clone());
            if let Some(state) = option {
                if !state.is_empty() {
                    continue;
                }

                let time = state.last_active_time();
                if now < time + timeout {
                    continue;
                }
                self.network_state_provider.remove(&network_code);
            }
        }
    }

    async fn release_expired_ips(state: &Arc<NetworkState>) {
        let network_code = state.network_code();
        let expired_devices = state.collect_expired_devices();

        if expired_devices.is_empty() {
            return;
        }

        state.remove_devices(&expired_devices);

        for device_id in expired_devices {
            log::info!(
                "release IP for offline device network_code={},device_id={}",
                network_code,
                device_id
            );
            if let Err(e) = db::release_device_ip(&network_code, &device_id).await {
                log::error!("Error releasing device IP: {}", e);
            }
        }
    }

    fn start_cleanup_task(&self, interval: Duration) {
        let network_state_provider = self.network_state_provider.clone();
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                // 收集所有 state 的引用
                let state_list: Vec<Arc<NetworkState>> = network_state_provider
                    .iter()
                    .map(|entry| entry.value().clone())
                    .collect();

                for state in state_list {
                    ControlService::release_expired_ips(&state).await;
                }

                tokio::time::sleep(Duration::from_secs(3)).await;
                service.release_network();
            }
        });

        let service_clone = self.clone();
        tokio::spawn(async move {
            const CLIENT_PING_INTERVAL_SECS: u64 = 15;
            loop {
                tokio::time::sleep(Duration::from_secs(CLIENT_PING_INTERVAL_SECS)).await;
                service_clone.ping_local_clients().await;
            }
        });
    }

    async fn ping_local_clients(&self) {
        use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
        use bytes::BytesMut;

        let network_codes = self.get_network_codes();

        for network_code in network_codes {
            if let Some(state) = self.get_network_state(&network_code) {
                let timestamp = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;

                for entry in state.sender_map().iter() {
                    let _ip = *entry.key();
                    let sender = entry.value().clone();

                    let mut buf = BytesMut::zeroed(HEAD_LENGTH + 8);
                    if let Ok(mut packet) = NetPacket::new(&mut buf) {
                        packet.set_msg_type(MsgType::Ping);
                        packet.set_gateway_flag(true);
                        packet.set_ttl(1);

                        let timestamp_bytes = timestamp.to_be_bytes();
                        if packet.set_payload(&timestamp_bytes).is_ok() {
                            let _ = sender.try_send(buf.freeze());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }

    pub async fn add_network(
        &self,
        network_code: String,
        gateway: Ipv4Addr,
        netmask: u8,
        lease_duration: Option<Duration>,
    ) -> anyhow::Result<()> {
        if self.db_nets.read().contains_key(&network_code) {
            bail!("网络编号 '{}' 已存在", network_code);
        }

        let lease_duration = lease_duration.unwrap_or(self.default_lease_duration);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let record = NetworkRecord {
            network_code: network_code.clone(),
            gateway: gateway.to_string(),
            netmask,
            lease_duration: lease_duration.as_secs() as i64,
            source: NetworkSource::Manual,
            created_at: now,
        };

        db::save_network(&record).await?;

        let network_ip = Ipv4Addr::from(u32::from(gateway) - 1);
        let net = Ipv4Net::new(network_ip, netmask).context("Invalid network")?;
        self.db_nets.write().insert(
            network_code,
            NetworkConfig {
                net,
                lease_duration,
                source: NetworkSource::Manual,
            },
        );

        Ok(())
    }

    pub async fn update_network(
        &self,
        network_code: &str,
        gateway: Ipv4Addr,
        netmask: u8,
        lease_duration: Duration,
    ) -> anyhow::Result<()> {
        let original_source = self
            .db_nets
            .read()
            .get(network_code)
            .map(|c| c.source)
            .ok_or_else(|| anyhow::anyhow!("网络编号 '{}' 不存在", network_code))?;

        if db::network_has_devices(network_code).await? {
            bail!("网络下存在设备，无法编辑");
        }

        if let Some(state) = self.network_state_provider.get(network_code) {
            let (all, _) = state.count();
            if all > 0 {
                bail!("网络下存在设备，无法编辑");
            }
        }

        db::update_network(
            network_code,
            &gateway.to_string(),
            netmask,
            lease_duration.as_secs() as i64,
        )
        .await?;

        let network_ip = Ipv4Addr::from(u32::from(gateway) - 1);
        let net = Ipv4Net::new(network_ip, netmask).context("Invalid network")?;
        self.db_nets.write().insert(
            network_code.to_string(),
            NetworkConfig {
                net,
                lease_duration,
                source: original_source,
            },
        );

        self.network_state_provider.remove(network_code);

        Ok(())
    }

    pub async fn delete_network(&self, network_code: &str) -> anyhow::Result<()> {
        if !self.db_nets.read().contains_key(network_code) {
            bail!("网络编号 '{}' 不存在", network_code);
        }

        if db::network_has_devices(network_code).await? {
            bail!("网络下存在设备，无法删除");
        }

        if let Some(state) = self.network_state_provider.get(network_code) {
            let (all, _) = state.count();
            if all > 0 {
                bail!("网络下存在设备，无法删除");
            }
        }

        db::delete_network(network_code).await?;

        self.db_nets.write().remove(network_code);
        self.network_state_provider.remove(network_code);

        Ok(())
    }

    pub async fn delete_device(
        &self,
        network_code: &str,
        device_id: &str,
    ) -> anyhow::Result<()> {
        if let Some(state) = self.network_state_provider.get(network_code) {
            if state.is_device_online(device_id) {
                bail!("设备在线，无法删除");
            }
            state.remove_device_from_memory(device_id);
        }

        db::delete_device(network_code, device_id).await?;

        Ok(())
    }
}

impl ControlService {
    pub fn get_network_codes(&self) -> Vec<String> {
        self.db_nets.read().keys().cloned().collect()
    }

    pub fn get_network_state(&self, network_code: &str) -> Option<Arc<NetworkState>> {
        self.network_state_provider.get(network_code).map(|s| s.clone())
    }

    pub fn set_peer_manager(&self, manager: Arc<crate::server::peer_server::PeerServerManager>) {
        *self.peer_manager.write() = Some(manager);
    }

    pub fn get_peer_manager(&self) -> Option<Arc<crate::server::peer_server::PeerServerManager>> {
        self.peer_manager.read().clone()
    }


    pub fn get_network_state_provider(&self) -> &NetworkStateProvider {
        &self.network_state_provider
    }

    pub fn get_network_info(&self) -> Vec<NetworkInfoVO> {
        let db_nets = self.db_nets.read();
        db_nets
            .iter()
            .map(|(code, config)| {
                let gateway = Ipv4Addr::from(u32::from(config.net.network()) + 1);
                let (all_count, online_count) = self
                    .network_state_provider
                    .get(code)
                    .map(|s| s.count())
                    .unwrap_or((0, 0));

                NetworkInfoVO {
                    network_code: code.clone(),
                    gateway,
                    netmask: config.net.prefix_len(),
                    net: config.net,
                    lease_duration: config.lease_duration.as_secs(),
                    source: config.source,
                    all_count,
                    online_count,
                }
            })
            .collect()
    }

    pub async fn get_device_info(&self, network_code: &str) -> Option<Vec<DeviceInfoVO>> {
        let mut devices = if let Some(state) = self.network_state_provider.get(network_code) {
            state.get_device_infos()
        } else {
            match db::load_all_devices(network_code).await {
                Ok(records) => {
                    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
                    records
                        .into_iter()
                        .map(|r| {
                            let last_connect_time: OffsetDateTime =
                                i64_to_system_time(r.last_connect_time).into();
                            DeviceInfoVO {
                                device_id: r.device_id,
                                device_name: r.device_name,
                                device_version: r.device_version,
                                ip: r.ip.as_ref().and_then(|s| s.parse().ok()),
                                status: "Offline".to_string(),
                                last_connect_time: last_connect_time.format(&format).unwrap_or_default(),
                                disconnect_time: None,
                                latency_ms: None,
                                server_addr: None,
                                tx_bytes: r.tx_bytes as u64,
                                rx_bytes: r.rx_bytes as u64,
                            }
                        })
                        .collect()
                }
                Err(e) => {
                    log::error!("Failed to load devices from DB: {}", e);
                    return None;
                }
            }
        };

        if let Some(peer_manager) = self.peer_manager.read().as_ref() {
            let remote_devices = peer_manager.get_remote_devices(network_code);

            for (ip, server_addr, latency_ms) in remote_devices {
                devices.push(DeviceInfoVO {
                    device_id: format!("remote-{}", ip),
                    device_name: format!("Remote Device ({})", ip),
                    device_version: "Unknown".to_string(),
                    ip: Some(ip),
                    status: "Remote".to_string(),
                    last_connect_time: "-".to_string(),
                    disconnect_time: None,
                    latency_ms: Some(latency_ms),
                    server_addr: Some(server_addr),
                    tx_bytes: 0,
                    rx_bytes: 0,
                });
            }
        }

        Some(devices)
    }
}

pub struct Session {
    pub network_code: String,
    pub device_id: String,
    pub ip: Ipv4Addr,
    pub random_id: u64,
    pub network_state: Arc<NetworkState>,
    pub registration_status: RegistrationStatus,
    pub control_service: ControlService,
}

impl Drop for Session {
    fn drop(&mut self) {
        match self.registration_status {
            RegistrationStatus::Confirmed => {
                let record = self.network_state.offline_ip(&self.device_id, self.ip, self.random_id);
                if let Some(record) = record {
                    tokio::spawn(async move {
                        if let Err(e) = db::save_or_update_device(&record).await {
                            log::warn!("Failed to update device record on offline: {}", e);
                        }
                    });
                }
            }
            RegistrationStatus::PendingConfirmation => {
                log::info!(
                    "Releasing pre-registered IP for network_code={}, device_id={}, ip={}",
                    self.network_code,
                    self.device_id,
                    self.ip
                );
                self.network_state.release_pre_registered_ip(&self.device_id, self.ip, self.random_id);
            }
        }
    }
}

#[derive(Serialize)]
pub struct DeviceInfoVO {
    pub device_id: String,
    pub device_name: String,
    pub device_version: String,
    pub ip: Option<Ipv4Addr>,
    pub status: String,
    pub last_connect_time: String,
    pub disconnect_time: Option<String>,
    pub latency_ms: Option<u32>,
    pub server_addr: Option<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Serialize)]
pub struct NetworkInfoVO {
    pub network_code: String,
    pub gateway: Ipv4Addr,
    pub netmask: u8,
    pub net: Ipv4Net,
    pub lease_duration: u64,
    pub source: NetworkSource,
    pub all_count: u32,
    pub online_count: u32,
}
