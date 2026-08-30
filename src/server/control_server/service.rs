use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
use crate::server::control_server::db;
use crate::server::control_server::db::{DeviceIpType, NetworkRecord, NetworkSource, NetworkType};
use crate::server::network_state_provider::{
    NetworkState, NetworkStateProvider, i64_to_system_time,
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
    pub gateway: Ipv4Addr,
    pub lease_duration: Duration,
    pub source: NetworkSource,
    pub network_type: NetworkType,
}

fn validate_gateway(net: Ipv4Net, gateway: Ipv4Addr) -> anyhow::Result<()> {
    if net.prefix_len() > 30 {
        bail!("掩码 /{} 没有足够的可用主机地址", net.prefix_len());
    }
    if !net.contains(&gateway) || gateway == net.network() || gateway == net.broadcast() {
        bail!("网关 {} 必须是网段 {} 中的可用主机地址", gateway, net);
    }
    Ok(())
}

fn first_usable_ip(net: Ipv4Net) -> anyhow::Result<Ipv4Addr> {
    if net.prefix_len() > 30 {
        bail!("网段 {} 没有足够的可用主机地址", net);
    }
    let value = u32::from(net.network())
        .checked_add(1)
        .context("Network address overflow")?;
    let gateway = Ipv4Addr::from(value);
    validate_gateway(net, gateway)?;
    Ok(gateway)
}

fn network_from_gateway(gateway: Ipv4Addr, netmask: u8) -> anyhow::Result<Ipv4Net> {
    if netmask > 30 {
        bail!("无效的掩码 /{}，必须小于等于 30", netmask);
    }
    let net = Ipv4Net::new(gateway, netmask)
        .context("Invalid network")?
        .trunc();
    validate_gateway(net, gateway)?;
    Ok(net)
}

#[derive(Clone)]
pub struct ControlService {
    default_net: Ipv4Net,
    default_gateway: Ipv4Addr,
    default_lease_duration: Duration,
    white_list: Arc<HashSet<String>>,
    db_nets: Arc<RwLock<HashMap<String, NetworkConfig>>>,
    network_state_provider: NetworkStateProvider,
    network_init_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    device_mutation_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    peer_manager: Arc<RwLock<Option<Arc<crate::server::peer_server::PeerServerManager>>>>,
}

impl ControlService {
    pub async fn new(
        default_net: Ipv4Net,
        custom_nets: HashMap<String, Ipv4Net>,
        white_list: HashSet<String>,
        lease_duration: Duration,
    ) -> anyhow::Result<Self> {
        let default_net = default_net.trunc();
        let default_gateway = first_usable_ip(default_net)?;
        let network_states = Arc::new(DashMap::new());

        let config_nets = Self::build_config_networks(&custom_nets, lease_duration);
        Self::save_config_networks_to_db(&config_nets).await;
        let db_nets = Self::merge_network_configs(Self::load_networks_from_db().await, config_nets);

        let service = Self {
            default_net,
            default_gateway,
            default_lease_duration: lease_duration,
            white_list: Arc::new(white_list),
            db_nets: Arc::new(RwLock::new(db_nets)),
            network_state_provider: NetworkStateProvider::new(network_states),
            network_init_locks: Arc::new(DashMap::new()),
            device_mutation_locks: Arc::new(DashMap::new()),
            peer_manager: Arc::new(RwLock::new(None)),
        };

        let cleanup_interval = Duration::from_secs(30 * 60);
        let cleanup_interval = cleanup_interval
            .min(lease_duration / 2)
            .max(Duration::from_secs(10));
        service.start_cleanup_task(cleanup_interval);

        Ok(service)
    }

    fn build_config_networks(
        custom_nets: &HashMap<String, Ipv4Net>,
        lease_duration: Duration,
    ) -> HashMap<String, NetworkConfig> {
        let mut config_nets = HashMap::with_capacity(custom_nets.len());
        for (code, net) in custom_nets {
            let net = net.trunc();
            let gateway = match first_usable_ip(net) {
                Ok(gateway) => gateway,
                Err(e) => {
                    log::error!("Invalid custom network {} ({}): {}", code, net, e);
                    continue;
                }
            };
            config_nets.insert(
                code.clone(),
                NetworkConfig {
                    net,
                    gateway,
                    lease_duration,
                    source: NetworkSource::Config,
                    network_type: NetworkType::Public,
                },
            );
        }
        config_nets
    }

    async fn save_config_networks_to_db(config_nets: &HashMap<String, NetworkConfig>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        for (code, config) in config_nets {
            let record = NetworkRecord {
                network_code: code.clone(),
                gateway: config.gateway.to_string(),
                netmask: config.net.prefix_len(),
                lease_duration: config.lease_duration.as_secs() as i64,
                source: NetworkSource::Config,
                network_type: config.network_type,
                created_at: now,
            };
            match db::save_network_if_not_exists(&record).await {
                Ok(true) => log::info!("Initialized network '{}' from config", code),
                Ok(false) => {}
                Err(e) => log::error!("Failed to save custom network {}: {}", code, e),
            }
        }
    }

    fn merge_network_configs(
        db_nets: HashMap<String, NetworkConfig>,
        mut config_nets: HashMap<String, NetworkConfig>,
    ) -> HashMap<String, NetworkConfig> {
        // 配置用于首次初始化；持久化开启且数据库已有记录时，以数据库中的修改为准。
        // 持久化关闭时 db_nets 为空，因此 TOML 中的自定义网络仍会在内存中生效。
        config_nets.extend(db_nets);
        config_nets
    }

    fn network_code_allowed(&self, network_code: &str) -> bool {
        self.white_list.is_empty() || self.white_list.contains(network_code)
    }

    async fn load_networks_from_db() -> HashMap<String, NetworkConfig> {
        let mut nets = HashMap::new();
        match db::load_all_networks().await {
            Ok(records) => {
                for record in records {
                    let gateway = record.gateway.parse::<Ipv4Addr>();
                    if let (Some(net), Ok(gateway)) = (record.to_ipv4_net(), gateway)
                        && validate_gateway(net, gateway).is_ok()
                    {
                        nets.insert(
                            record.network_code,
                            NetworkConfig {
                                net,
                                gateway,
                                lease_duration: Duration::from_secs(record.lease_duration as u64),
                                source: record.source,
                                network_type: record.network_type,
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
        if !self.network_code_allowed(&network_code) {
            bail!("network_code '{}' is not in white_list", network_code);
        }

        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _mutation_guard = mutation_lock.lock().await;

        let is_new_network = !self.db_nets.read().contains_key(&reg_req.network_code);
        let config = self.network_config(&reg_req.network_code, reg_req.ip)?;

        if is_new_network {
            self.db_nets
                .write()
                .insert(reg_req.network_code.clone(), config);
        }

        let state = self
            .get_or_create_network_state(reg_req.network_code.clone(), config)
            .await;

        if config.network_type == NetworkType::Private && !state.has_device(&reg_req.device_id) {
            bail!("私有网络仅允许已添加的设备连接");
        }

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
                },
                entry,
            )
        };

        if is_new_network {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let record = NetworkRecord {
                network_code: network_code.clone(),
                gateway: config.gateway.to_string(),
                netmask: config.net.prefix_len(),
                lease_duration: config.lease_duration.as_secs() as i64,
                source: NetworkSource::DeviceRegister,
                network_type: NetworkType::Public,
                created_at: now,
            };
            tokio::spawn(async move {
                if let Err(e) = db::save_network(&record).await {
                    log::error!("Failed to save new network: {:?}", e);
                }
            });
        }

        if matches!(registration_mode, RegistrationMode::Normal)
            && let Some(entry) = entry
        {
            let nc = network_code.clone();
            let record = entry.to_record(&nc);
            db::save_or_update_device(&record).await?;
        }

        Ok(session)
    }

    fn network_config(
        &self,
        network_code: &str,
        ip: Option<Ipv4Addr>,
    ) -> anyhow::Result<NetworkConfig> {
        if let Some(config) = self.db_nets.read().get(network_code) {
            return Ok(*config);
        }
        let (net, gateway) = if let Some(ip) = ip {
            let net = Ipv4Net::new(ip, 24)
                .context("Invalid requested IP network")?
                .trunc();
            (net, first_usable_ip(net)?)
        } else {
            (self.default_net, self.default_gateway)
        };
        Ok(NetworkConfig {
            net,
            gateway,
            lease_duration: self.default_lease_duration,
            source: NetworkSource::DeviceRegister,
            network_type: NetworkType::Public,
        })
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
            NetworkState::new_from_db(
                network_code.clone(),
                config.net,
                config.gateway,
                config.lease_duration,
            )
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

    async fn release_expired_ips(&self, state: &Arc<NetworkState>) {
        let network_code = state.network_code();
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        let expired_devices = state.collect_expired_devices();

        if expired_devices.is_empty() {
            return;
        }

        let expired_devices = state.remove_devices(&expired_devices);

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
                    service.release_expired_ips(&state).await;
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
        network_type: NetworkType,
    ) -> anyhow::Result<()> {
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        if self.db_nets.read().contains_key(&network_code) {
            bail!("网络编号 '{}' 已存在", network_code);
        }

        let net = network_from_gateway(gateway, netmask)?;
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
            network_type,
            created_at: now,
        };

        db::save_network(&record).await?;

        self.db_nets.write().insert(
            network_code,
            NetworkConfig {
                net,
                gateway,
                lease_duration,
                source: NetworkSource::Manual,
                network_type,
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
        network_type: NetworkType,
    ) -> anyhow::Result<()> {
        let net = network_from_gateway(gateway, netmask)?;
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        let original_config = self
            .db_nets
            .read()
            .get(network_code)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("网络编号 '{}' 不存在", network_code))?;

        let topology_changed = original_config.net != net
            || original_config.gateway != gateway
            || original_config.lease_duration != lease_duration;
        if topology_changed && db::network_has_devices(network_code).await? {
            bail!("网络下存在设备，只能修改网络类型");
        }

        if topology_changed && let Some(state) = self.network_state_provider.get(network_code) {
            let (all, _) = state.count();
            if all > 0 {
                bail!("网络下存在设备，只能修改网络类型");
            }
        }

        db::update_network(
            network_code,
            &gateway.to_string(),
            netmask,
            lease_duration.as_secs() as i64,
            network_type,
        )
        .await?;

        self.db_nets.write().insert(
            network_code.to_string(),
            NetworkConfig {
                net,
                gateway,
                lease_duration,
                source: original_config.source,
                network_type,
            },
        );

        if topology_changed {
            self.network_state_provider.remove(network_code);
        }

        Ok(())
    }

    pub async fn delete_network(&self, network_code: &str) -> anyhow::Result<()> {
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
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

    fn validate_device_ip(config: NetworkConfig, ip: Ipv4Addr) -> anyhow::Result<()> {
        if !config.net.contains(&ip) {
            bail!("IP {} 不属于网段 {}", ip, config.net);
        }
        if ip == config.gateway {
            bail!("此IP为网关IP，不允许使用");
        }
        if ip == config.net.network() || ip == config.net.broadcast() {
            bail!("此IP为网段的网络地址或广播地址，不允许使用");
        }
        Ok(())
    }

    async fn upsert_device(
        &self,
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
        create: bool,
    ) -> anyhow::Result<()> {
        if device_id.is_empty()
            || device_id.trim() != device_id
            || device_id.len() > RegRequestMsg::MAX_DEVICE_ID_LEN
        {
            bail!("无效的设备 ID");
        }
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        let config = self
            .db_nets
            .read()
            .get(network_code)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("网络编号 '{}' 不存在", network_code))?;
        Self::validate_device_ip(config, ip)?;

        let state = self
            .get_or_create_network_state(network_code.to_string(), config)
            .await;

        if create && state.has_device(device_id) {
            bail!("设备 ID '{}' 已存在", device_id);
        }
        if !create && !state.has_device(device_id) {
            bail!("设备 ID '{}' 不存在", device_id);
        }

        let previous = state.upsert_device_config(device_id, ip, ip_type)?;
        let record = state
            .get_device_entry(device_id)
            .ok_or_else(|| anyhow::anyhow!("设备状态更新失败"))?
            .to_record(network_code);
        if let Err(error) = db::save_or_update_device(&record).await {
            state.restore_device_config(device_id, previous);
            return Err(error);
        }
        Ok(())
    }

    pub async fn add_device(
        &self,
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
    ) -> anyhow::Result<()> {
        self.upsert_device(network_code, device_id, ip, ip_type, true)
            .await
    }

    pub async fn update_device(
        &self,
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
    ) -> anyhow::Result<()> {
        self.upsert_device(network_code, device_id, ip, ip_type, false)
            .await
    }

    pub async fn fast_register(
        &self,
        session: &mut Session,
        new_ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
        let mutation_lock = self
            .device_mutation_locks
            .entry(session.network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        session.network_state.fast_register(
            &session.device_id,
            session.ip,
            new_ip,
            session.random_id,
        )?;
        session.ip = new_ip;
        Ok(())
    }

    pub async fn delete_device(&self, network_code: &str, device_id: &str) -> anyhow::Result<()> {
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
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
        self.network_state_provider
            .get(network_code)
            .map(|s| s.clone())
    }

    pub fn get_network_type(&self, network_code: &str) -> Option<NetworkType> {
        self.db_nets
            .read()
            .get(network_code)
            .map(|config| config.network_type)
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
                let (all_count, online_count) = self
                    .network_state_provider
                    .get(code)
                    .map(|s| s.count())
                    .unwrap_or((0, 0));

                NetworkInfoVO {
                    network_code: code.clone(),
                    gateway: config.gateway,
                    netmask: config.net.prefix_len(),
                    net: config.net,
                    lease_duration: config.lease_duration.as_secs(),
                    source: config.source,
                    network_type: config.network_type,
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
                                current_ip: None,
                                ip_type: Some(r.ip_type),
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
                    current_ip: None,
                    ip_type: None,
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
    pub current_ip: Option<Ipv4Addr>,
    pub ip_type: Option<DeviceIpType>,
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
    pub network_type: NetworkType,
    pub all_count: u32,
    pub online_count: u32,
}

#[cfg(test)]
mod tests {
    use super::{ControlService, NetworkConfig, first_usable_ip, network_from_gateway};
    use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
    use crate::server::control_server::db::{DeviceIpType, NetworkSource, NetworkType};
    use ipnet::Ipv4Net;
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn registration(network_code: &str, device_id: &str) -> RegRequestMsg {
        RegRequestMsg {
            network_code: network_code.to_string(),
            device_id: device_id.to_string(),
            ip: None,
            name: device_id.to_string(),
            version: "test".to_string(),
            key_sign: None,
            ip_variable: true,
            server_id: 0,
            registration_mode: RegistrationMode::Normal,
        }
    }

    #[test]
    fn network_from_gateway_preserves_non_default_gateway() {
        let gateway = Ipv4Addr::new(192, 168, 1, 100);
        let net = network_from_gateway(gateway, 24).expect("valid network");
        assert_eq!(net, "192.168.1.0/24".parse::<Ipv4Net>().unwrap());
        assert!(net.contains(&gateway));
    }

    #[test]
    fn network_from_gateway_rejects_reserved_and_too_small_networks() {
        assert!(network_from_gateway(Ipv4Addr::new(192, 168, 1, 0), 24).is_err());
        assert!(network_from_gateway(Ipv4Addr::new(192, 168, 1, 255), 24).is_err());
        assert!(network_from_gateway(Ipv4Addr::new(192, 168, 1, 1), 31).is_err());
        assert!(network_from_gateway(Ipv4Addr::UNSPECIFIED, 0).is_err());
    }

    #[test]
    fn first_usable_ip_uses_checked_host_address() {
        let net = "10.20.0.0/24".parse::<Ipv4Net>().unwrap();
        assert_eq!(first_usable_ip(net).unwrap(), Ipv4Addr::new(10, 20, 0, 1));
        assert!(first_usable_ip("255.255.255.255/32".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn custom_networks_work_without_database_persistence() {
        let mut custom_nets = HashMap::new();
        custom_nets.insert("net1".to_string(), "10.40.0.0/24".parse().unwrap());
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            custom_nets,
            HashSet::from(["net1".to_string()]),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

        let config = service.network_config("net1", None).unwrap();
        assert_eq!(config.net, "10.40.0.0/24".parse::<Ipv4Net>().unwrap());
        assert_eq!(config.gateway, Ipv4Addr::new(10, 40, 0, 1));
        assert_eq!(config.source, NetworkSource::Config);
    }

    #[test]
    fn persisted_network_overrides_configured_initial_value() {
        let persisted = NetworkConfig {
            net: "10.1.0.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(10, 1, 0, 1),
            lease_duration: Duration::from_secs(60),
            source: NetworkSource::Config,
            network_type: NetworkType::Public,
        };
        let configured = NetworkConfig {
            net: "10.2.0.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(10, 2, 0, 1),
            lease_duration: Duration::from_secs(120),
            source: NetworkSource::Config,
            network_type: NetworkType::Public,
        };
        let merged = ControlService::merge_network_configs(
            HashMap::from([("net1".to_string(), persisted)]),
            HashMap::from([("net1".to_string(), configured)]),
        );

        let actual = merged.get("net1").unwrap();
        assert_eq!(actual.net, persisted.net);
        assert_eq!(actual.gateway, persisted.gateway);
        assert_eq!(actual.lease_duration, persisted.lease_duration);
    }

    #[tokio::test]
    async fn white_list_is_exact_and_empty_list_allows_all() {
        let unrestricted = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        assert!(unrestricted.network_code_allowed("any-network"));

        let restricted = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::from(["net1".to_string()]),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        assert!(restricted.network_code_allowed("net1"));
        assert!(!restricted.network_code_allowed("NET1"));
        assert!(!restricted.network_code_allowed("net2"));
    }

    #[tokio::test]
    async fn private_network_only_accepts_existing_device_ids() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "private".to_string(),
                "10.50.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Private,
            )
            .await
            .unwrap();
        service
            .add_device(
                "private",
                "known",
                "10.50.0.3".parse().unwrap(),
                DeviceIpType::Static,
            )
            .await
            .unwrap();

        let (sender, _receiver) = mpsc::channel(8);
        assert!(
            service
                .register(registration("private", "unknown"), sender.clone())
                .await
                .is_err()
        );
        let session = service
            .register(registration("private", "known"), sender)
            .await
            .unwrap();
        assert_eq!(session.ip, "10.50.0.3".parse::<Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn configured_ip_waits_for_valid_fast_registration_before_switching_session() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "public".to_string(),
                "10.60.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();
        let (sender, _receiver) = mpsc::channel(8);
        let mut session = service
            .register(registration("public", "device-a"), sender)
            .await
            .unwrap();
        let old_ip = session.ip;
        let new_ip = "10.60.0.9".parse::<Ipv4Addr>().unwrap();

        service
            .update_device("public", "device-a", new_ip, DeviceIpType::Static)
            .await
            .unwrap();
        assert_eq!(session.ip, old_ip);
        assert_eq!(
            session.network_state.configured_ip("device-a"),
            Some(new_ip)
        );
        let device_info = session
            .network_state
            .get_device_infos()
            .into_iter()
            .find(|device| device.device_id == "device-a")
            .unwrap();
        assert_eq!(device_info.ip, Some(new_ip));
        assert_eq!(device_info.current_ip, Some(old_ip));
        assert!(session.network_state.sender_map().contains_key(&old_ip));
        assert!(!session.network_state.sender_map().contains_key(&new_ip));
        assert!(
            service
                .add_device("public", "device-b", old_ip, DeviceIpType::Static)
                .await
                .is_err(),
            "the active old IP must remain reserved"
        );

        assert!(
            service
                .fast_register(&mut session, "10.60.0.8".parse().unwrap())
                .await
                .is_err()
        );
        assert_eq!(session.ip, old_ip);
        service.fast_register(&mut session, new_ip).await.unwrap();
        assert_eq!(session.ip, new_ip);
        let device_info = session
            .network_state
            .get_device_infos()
            .into_iter()
            .find(|device| device.device_id == "device-a")
            .unwrap();
        assert_eq!(device_info.current_ip, Some(new_ip));
        assert!(!session.network_state.sender_map().contains_key(&old_ip));
        assert!(session.network_state.sender_map().contains_key(&new_ip));
    }

    #[tokio::test]
    async fn normal_reconnect_uses_latest_configured_ip_without_fast_registration() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "reconnect".to_string(),
                "10.70.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();
        let (sender, _receiver) = mpsc::channel(8);
        let session = service
            .register(registration("reconnect", "device-a"), sender.clone())
            .await
            .unwrap();
        let old_ip = session.ip;
        let new_ip = "10.70.0.20".parse::<Ipv4Addr>().unwrap();
        service
            .update_device("reconnect", "device-a", new_ip, DeviceIpType::Static)
            .await
            .unwrap();
        drop(session);

        let state = service.get_network_state("reconnect").unwrap();
        assert!(!state.sender_map().contains_key(&old_ip));
        let reconnected = service
            .register(registration("reconnect", "device-a"), sender)
            .await
            .unwrap();
        assert_eq!(reconnected.ip, new_ip);
        assert!(state.sender_map().contains_key(&new_ip));
    }

    #[tokio::test]
    async fn fixed_ip_uses_server_value_while_other_types_prefer_client_request() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "ip-types".to_string(),
                "10.80.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();
        service
            .add_device(
                "ip-types",
                "static-device",
                "10.80.0.3".parse().unwrap(),
                DeviceIpType::Static,
            )
            .await
            .unwrap();
        service
            .add_device(
                "ip-types",
                "fixed-device",
                "10.80.0.4".parse().unwrap(),
                DeviceIpType::Fixed,
            )
            .await
            .unwrap();
        let (sender, _receiver) = mpsc::channel(8);

        let mut static_request = registration("ip-types", "static-device");
        static_request.ip = Some("10.80.0.9".parse().unwrap());
        static_request.ip_variable = false;
        let static_session = service
            .register(static_request, sender.clone())
            .await
            .unwrap();
        assert_eq!(static_session.ip, "10.80.0.9".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            static_session
                .network_state
                .get_device_entry("static-device")
                .unwrap()
                .ip_type,
            DeviceIpType::Static
        );

        let mut fixed_request = registration("ip-types", "fixed-device");
        fixed_request.ip = Some("10.80.0.10".parse().unwrap());
        fixed_request.ip_variable = false;
        let fixed_session = service.register(fixed_request, sender).await.unwrap();
        assert_eq!(fixed_session.ip, "10.80.0.4".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            fixed_session
                .network_state
                .get_device_entry("fixed-device")
                .unwrap()
                .ip_type,
            DeviceIpType::Fixed
        );
    }

    #[tokio::test]
    async fn configured_and_active_ips_are_both_reserved_for_add_and_registration() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "unique-ips".to_string(),
                "10.90.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();

        let (sender, _receiver) = mpsc::channel(8);
        let first_session = service
            .register(registration("unique-ips", "device-a"), sender.clone())
            .await
            .unwrap();
        let active_ip = first_session.ip;
        let configured_ip = "10.90.0.9".parse::<Ipv4Addr>().unwrap();
        service
            .update_device(
                "unique-ips",
                "device-a",
                configured_ip,
                DeviceIpType::Static,
            )
            .await
            .unwrap();

        assert_eq!(first_session.ip, active_ip);
        assert_eq!(
            first_session.network_state.configured_ip("device-a"),
            Some(configured_ip)
        );

        for occupied_ip in [active_ip, configured_ip] {
            assert!(
                service
                    .add_device(
                        "unique-ips",
                        &format!("manual-{occupied_ip}"),
                        occupied_ip,
                        DeviceIpType::Dynamic,
                    )
                    .await
                    .is_err(),
                "manual add must reject occupied IP {occupied_ip}"
            );

            let mut strict_request = registration("unique-ips", &format!("strict-{occupied_ip}"));
            strict_request.ip = Some(occupied_ip);
            strict_request.ip_variable = false;
            assert!(
                service
                    .register(strict_request, sender.clone())
                    .await
                    .is_err(),
                "registration must reject occupied fixed request {occupied_ip}"
            );
        }

        let mut variable_request = registration("unique-ips", "variable-device");
        variable_request.ip = Some(active_ip);
        variable_request.ip_variable = true;
        let variable_session = service.register(variable_request, sender).await.unwrap();
        assert_ne!(variable_session.ip, active_ip);
        assert_ne!(variable_session.ip, configured_ip);
    }
}
