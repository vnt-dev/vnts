use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
use crate::server::control_server::db;
use crate::server::control_server::db::{NetworkRecord, NetworkSource};
use crate::server::network_state_provider::{
    NetworkState, NetworkStateProvider, i64_to_system_time,
};
use crate::utils::config::{
    DEFAULT_NETWORK_CODE, validate_network_code_value, validate_network_secret_value,
};
use anyhow::{Context, bail};
use bytes::Bytes;
use dashmap::DashMap;
use ipnet::Ipv4Net;
use parking_lot::RwLock;
use rand::RngCore;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
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
struct ManagedNetwork {
    config: NetworkConfig,
    secret: String,
}

#[derive(Clone)]
pub struct ControlService {
    default_lease_duration: Duration,
    db_nets: Arc<RwLock<HashMap<String, ManagedNetwork>>>,
    white_list: Arc<HashSet<String>>,
    network_state_provider: NetworkStateProvider,
    network_init_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    peer_manager: Arc<RwLock<Option<Arc<crate::server::peer_server::PeerServerManager>>>>,
}

impl ControlService {
    pub async fn new(
        custom_nets: HashMap<String, Ipv4Net>,
        network_secrets: HashMap<String, String>,
        white_list: HashSet<String>,
        lease_duration: Duration,
    ) -> Self {
        let network_states = Arc::new(DashMap::new());
        let db_nets =
            Self::load_or_initialize_networks(custom_nets, network_secrets, lease_duration).await;

        let service = Self {
            default_lease_duration: lease_duration,
            white_list: Arc::new(white_list),
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

    async fn load_or_initialize_networks(
        custom_nets: HashMap<String, Ipv4Net>,
        network_secrets: HashMap<String, String>,
        lease_duration: Duration,
    ) -> HashMap<String, ManagedNetwork> {
        if !db::db_pool_initialized() {
            return Self::build_networks_from_config(custom_nets, network_secrets, lease_duration);
        }

        let mut records = Self::load_network_records_from_db().await;
        if records.is_empty() {
            Self::seed_config_networks_to_db(&custom_nets, &network_secrets, lease_duration).await;
            records = Self::load_network_records_from_db().await;
        } else if Self::backfill_missing_secrets_from_config(&records, &network_secrets).await {
            records = Self::load_network_records_from_db().await;
        }

        if records.is_empty() {
            log::warn!("No networks found in DB after initialization, falling back to config");
            return Self::build_networks_from_config(custom_nets, network_secrets, lease_duration);
        }

        Self::managed_networks_from_records(records)
    }

    fn build_networks_from_config(
        custom_nets: HashMap<String, Ipv4Net>,
        network_secrets: HashMap<String, String>,
        lease_duration: Duration,
    ) -> HashMap<String, ManagedNetwork> {
        custom_nets
            .into_iter()
            .filter_map(|(code, net)| {
                let Some(secret) = network_secrets.get(&code).cloned() else {
                    log::error!(
                        "Missing secret for network '{}' while building config fallback",
                        code
                    );
                    return None;
                };

                Some((
                    code,
                    ManagedNetwork {
                        config: NetworkConfig {
                            net,
                            lease_duration,
                            source: NetworkSource::Config,
                        },
                        secret,
                    },
                ))
            })
            .collect()
    }

    async fn seed_config_networks_to_db(
        custom_nets: &HashMap<String, Ipv4Net>,
        network_secrets: &HashMap<String, String>,
        lease_duration: Duration,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let lease_secs = lease_duration.as_secs() as i64;

        for (code, net) in custom_nets {
            let Some(secret) = network_secrets.get(code) else {
                log::error!(
                    "Skip seeding network '{}' because its secret is missing",
                    code
                );
                continue;
            };
            let gateway = Ipv4Addr::from(u32::from(net.network()) + 1);
            let record = NetworkRecord {
                network_code: code.clone(),
                gateway: gateway.to_string(),
                netmask: net.prefix_len(),
                secret: secret.clone(),
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

    async fn backfill_missing_secrets_from_config(
        records: &[NetworkRecord],
        network_secrets: &HashMap<String, String>,
    ) -> bool {
        let mut updated = false;

        for record in records {
            if !record.secret.trim().is_empty() {
                continue;
            }

            let Some(secret) = network_secrets.get(&record.network_code) else {
                continue;
            };

            let mut updated_record = record.clone();
            updated_record.secret = secret.clone();

            match db::save_network(&updated_record).await {
                Ok(()) => {
                    updated = true;
                    log::info!(
                        "Backfilled missing secret for network '{}' from config",
                        record.network_code
                    );
                }
                Err(e) => {
                    log::error!(
                        "Failed to backfill secret for network '{}': {}",
                        record.network_code,
                        e
                    );
                }
            }
        }

        updated
    }

    async fn load_network_records_from_db() -> Vec<NetworkRecord> {
        match db::load_all_networks().await {
            Ok(records) => records,
            Err(e) => {
                log::error!("Failed to load networks from DB: {}", e);
                Vec::new()
            }
        }
    }

    fn managed_networks_from_records(
        records: Vec<NetworkRecord>,
    ) -> HashMap<String, ManagedNetwork> {
        let mut nets = HashMap::new();

        for record in records {
            if let Some(net) = record.to_ipv4_net() {
                nets.insert(
                    record.network_code,
                    ManagedNetwork {
                        config: NetworkConfig {
                            net,
                            lease_duration: Duration::from_secs(record.lease_duration as u64),
                            source: record.source,
                        },
                        secret: record.secret,
                    },
                );
            } else {
                log::error!(
                    "Skip network '{}' because gateway/netmask in DB is invalid",
                    record.network_code
                );
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
        self.validate_registration(&reg_req)?;
        let network_code = reg_req.network_code.clone();
        let registration_mode = reg_req.registration_mode;
        let config = self.network_config(&reg_req.network_code)?;
        if !self.white_list.is_empty() && !self.white_list.contains(&network_code) {
            bail!("network_code '{}' is not in white_list", network_code);
        }

        let state = self
            .get_or_create_network_state(reg_req.network_code.clone(), config)
            .await;

        let (session, entry) = {
            let random_id = rand::rng().next_u64();
            let device_id = reg_req.device_id.clone();

            let (ip, _old_ip, entry) =
                match state.allocate_ip_and_get_entry(reg_req, random_id, sender) {
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

    fn network_config(&self, network_code: &str) -> anyhow::Result<NetworkConfig> {
        self.db_nets
            .read()
            .get(network_code)
            .map(|network| network.config)
            .ok_or_else(|| anyhow::anyhow!("network_code '{}' is not allowed", network_code))
    }

    fn build_network_from_gateway(gateway: Ipv4Addr, netmask: u8) -> anyhow::Result<Ipv4Net> {
        let network_ip = u32::from(gateway)
            .checked_sub(1)
            .context("gateway must be the first usable IP in the subnet")?;
        Ipv4Net::new(Ipv4Addr::from(network_ip), netmask).context("Invalid network")
    }

    fn validate_registration(&self, reg_req: &RegRequestMsg) -> anyhow::Result<()> {
        let networks = self.db_nets.read();
        let Some(network) = networks.get(&reg_req.network_code) else {
            bail!(
                "network_code '{}' is not allowed by server configuration or database",
                reg_req.network_code
            );
        };
        validate_network_secret_value(&reg_req.network_code, &network.secret)?;

        let Some(provided_secret) = reg_req.key_sign.as_deref() else {
            bail!(
                "network_code '{}' requires a network secret",
                reg_req.network_code
            );
        };

        if provided_secret != network.secret {
            bail!(
                "invalid network secret for network_code '{}'",
                reg_req.network_code
            );
        }

        Ok(())
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
            let option = self
                .network_state_provider
                .get(&network_code)
                .map(|v| v.clone());
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
        secret: String,
    ) -> anyhow::Result<()> {
        validate_network_code_value(&network_code, "network_code")?;
        validate_network_secret_value(&network_code, &secret)?;
        if self.db_nets.read().contains_key(&network_code) {
            bail!("network_code '{}' already exists", network_code);
        }

        if self.db_nets.read().contains_key(&network_code) {
            bail!("网络编号 '{}' 已存在", network_code);
        }

        let lease_duration = lease_duration.unwrap_or(self.default_lease_duration);
        let net = Self::build_network_from_gateway(gateway, netmask)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let record = NetworkRecord {
            network_code: network_code.clone(),
            gateway: gateway.to_string(),
            netmask,
            secret: secret.clone(),
            lease_duration: lease_duration.as_secs() as i64,
            source: NetworkSource::Manual,
            created_at: now,
        };

        db::save_network(&record).await?;

        self.db_nets.write().insert(
            network_code,
            ManagedNetwork {
                config: NetworkConfig {
                    net,
                    lease_duration,
                    source: NetworkSource::Manual,
                },
                secret,
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
        secret: String,
    ) -> anyhow::Result<()> {
        validate_network_secret_value(network_code, &secret)?;
        let original_source = self
            .db_nets
            .read()
            .get(network_code)
            .map(|c| c.config.source)
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
            &secret,
            lease_duration.as_secs() as i64,
        )
        .await?;

        let net = Self::build_network_from_gateway(gateway, netmask)?;
        self.db_nets.write().insert(
            network_code.to_string(),
            ManagedNetwork {
                config: NetworkConfig {
                    net,
                    lease_duration,
                    source: original_source,
                },
                secret,
            },
        );

        self.network_state_provider.remove(network_code);

        Ok(())
    }

    pub async fn delete_network(&self, network_code: &str) -> anyhow::Result<()> {
        if network_code == DEFAULT_NETWORK_CODE {
            bail!("the default network cannot be deleted");
        }

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

    pub async fn delete_device(&self, network_code: &str, device_id: &str) -> anyhow::Result<()> {
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
        let mut codes: Vec<String> = self.db_nets.read().keys().cloned().collect();
        codes.sort();
        codes
    }

    pub fn get_network_state(&self, network_code: &str) -> Option<Arc<NetworkState>> {
        self.network_state_provider
            .get(network_code)
            .map(|s| s.clone())
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
        let mut networks: Vec<NetworkInfoVO> = db_nets
            .iter()
            .map(|(code, network)| {
                let gateway = Ipv4Addr::from(u32::from(network.config.net.network()) + 1);
                let (all_count, online_count) = self
                    .network_state_provider
                    .get(code)
                    .map(|s| s.count())
                    .unwrap_or((0, 0));

                NetworkInfoVO {
                    network_code: code.clone(),
                    gateway,
                    netmask: network.config.net.prefix_len(),
                    net: network.config.net,
                    secret: network.secret.clone(),
                    lease_duration: network.config.lease_duration.as_secs(),
                    source: network.config.source,
                    is_default: code == DEFAULT_NETWORK_CODE,
                    can_delete: code != DEFAULT_NETWORK_CODE,
                    all_count,
                    online_count,
                }
            })
            .collect();
        networks.sort_by(|a, b| a.network_code.cmp(&b.network_code));
        networks
    }

    pub async fn get_device_info(&self, network_code: &str) -> Option<Vec<DeviceInfoVO>> {
        let mut devices = if let Some(state) = self.network_state_provider.get(network_code) {
            state.get_device_infos()
        } else {
            match db::load_all_devices(network_code).await {
                Ok(records) => {
                    let format =
                        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
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
                                last_connect_time: last_connect_time
                                    .format(&format)
                                    .unwrap_or_default(),
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
                let record =
                    self.network_state
                        .offline_ip(&self.device_id, self.ip, self.random_id);
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
                self.network_state.release_pre_registered_ip(
                    &self.device_id,
                    self.ip,
                    self.random_id,
                );
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
    pub secret: String,
    pub lease_duration: u64,
    pub source: NetworkSource,
    pub is_default: bool,
    pub can_delete: bool,
    pub all_count: u32,
    pub online_count: u32,
}
