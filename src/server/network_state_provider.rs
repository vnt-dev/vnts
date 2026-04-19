use crate::protocol::control_message::RegRequestMsg;
use crate::server::control_server::db;
use crate::server::control_server::db::DeviceRecord;
use anyhow::bail;
use bytes::Bytes;
use dashmap::DashMap;
use ipnet::Ipv4Net;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, Instant};

#[derive(Debug)]
struct DirectionTraffic {
    total_bytes: u64,
}

impl DirectionTraffic {
    fn new() -> Self {
        Self { total_bytes: 0 }
    }

    fn add(&mut self, bytes: u64) {
        self.total_bytes += bytes;
    }

    fn set_bytes(&mut self, bytes: u64) {
        self.total_bytes = bytes;
    }
}

#[derive(Debug)]
pub struct TrafficStats {
    tx: Mutex<DirectionTraffic>,
    rx: Mutex<DirectionTraffic>,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            tx: Mutex::new(DirectionTraffic::new()),
            rx: Mutex::new(DirectionTraffic::new()),
        }
    }

    pub fn add_tx(&self, bytes: u64) {
        self.tx.lock().add(bytes);
    }

    pub fn add_rx(&self, bytes: u64) {
        self.rx.lock().add(bytes);
    }

    pub fn get_tx(&self) -> u64 {
        self.tx.lock().total_bytes
    }

    pub fn get_rx(&self) -> u64 {
        self.rx.lock().total_bytes
    }

    pub fn set_tx(&self, bytes: u64) {
        self.tx.lock().set_bytes(bytes);
    }

    pub fn set_rx(&self, bytes: u64) {
        self.rx.lock().set_bytes(bytes);
    }
}

impl Clone for TrafficStats {
    fn clone(&self) -> Self {
        let new = Self::new();
        new.set_tx(self.get_tx());
        new.set_rx(self.get_rx());
        new
    }
}

#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub device_id: String,
    pub ip: Option<Ipv4Addr>,
    pub random_id: u64,
    pub device_name: String,
    pub device_version: String,
    pub is_connected: bool,
    pub last_connect_time: SystemTime,
    pub disconnect_time: Option<SystemTime>,
    pub data_version: u64,
    pub key_sign: Option<String>,
    pub latency_ms: Option<u32>,
    pub traffic_stats: Arc<TrafficStats>,
}

pub fn system_time_to_i64(st: SystemTime) -> i64 {
    st.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::new(0, 0))
        .as_secs() as i64
}

pub fn i64_to_system_time(ts: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(ts as u64)
}

impl DeviceEntry {
    fn from_record(record: DeviceRecord) -> Self {
        let ip = record.ip.as_ref().and_then(|s| s.parse().ok());
        let traffic_stats = Arc::new(TrafficStats::new());
        traffic_stats.set_tx(record.tx_bytes as u64);
        traffic_stats.set_rx(record.rx_bytes as u64);

        DeviceEntry {
            device_id: record.device_id,
            ip,
            random_id: 0,
            device_name: record.device_name,
            device_version: record.device_version,
            is_connected: false,
            last_connect_time: i64_to_system_time(record.last_connect_time),
            disconnect_time: Some(SystemTime::now()),
            data_version: 0,
            key_sign: None,
            latency_ms: None,
            traffic_stats,
        }
    }

    pub fn to_record(&self, network_code: &str) -> DeviceRecord {
        DeviceRecord {
            device_id: self.device_id.clone(),
            network_code: network_code.to_string(),
            ip: self.ip.map(|ip| ip.to_string()),
            device_name: self.device_name.clone(),
            device_version: self.device_version.clone(),
            last_connect_time: system_time_to_i64(self.last_connect_time),
            tx_bytes: self.traffic_stats.get_tx() as i64,
            rx_bytes: self.traffic_stats.get_rx() as i64,
        }
    }
}

pub struct NetworkState {
    time: Mutex<Instant>,
    network_code: String,
    gateway: Ipv4Addr,
    net: Ipv4Net,
    lease_duration: Duration,
    sender_map: DashMap<Ipv4Addr, Sender<Bytes>>,
    lease_state: Mutex<NetworkStateInner>,
    traffic_stats_map: DashMap<Ipv4Addr, Arc<TrafficStats>>,
}

struct NetworkStateInner {
    data_version: u64,
    device_map: HashMap<String, DeviceEntry>,
    device_ip_map: HashMap<Ipv4Addr, String>,
}

impl NetworkState {
    pub fn network(&self) -> &Ipv4Net {
        &self.net
    }
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }
    pub fn net_prefix_len(&self) -> u8 {
        self.net.prefix_len()
    }

    pub fn sender_map(&self) -> &DashMap<Ipv4Addr, Sender<Bytes>> {
        &self.sender_map
    }

    pub fn record_tx_traffic(&self, ip: Ipv4Addr, bytes: usize) {
        if let Some(stats) = self.traffic_stats_map.get(&ip) {
            stats.add_tx(bytes as u64);
        }
    }

    pub fn record_rx_traffic(&self, ip: Ipv4Addr, bytes: usize) {
        if let Some(stats) = self.traffic_stats_map.get(&ip) {
            stats.add_rx(bytes as u64);
        }
    }

    /// 设备离线，返回需要持久化的记录。random_id 用于判断是否为当前会话。
    pub fn offline_ip(
        &self,
        device_id: &String,
        ip: Ipv4Addr,
        random_id: u64,
    ) -> Option<DeviceRecord> {
        let mut guard = self.lease_state.lock();
        let (success, record) = guard.offline_ip(&self.network_code, device_id, ip, random_id);
        if success {
            log::info!(
                "offline_ip network_code={},device_id={device_id},ip={ip}",
                self.network_code,
            );
            self.sender_map.remove(&ip);
            self.traffic_stats_map.remove(&ip);

            record
        } else {
            log::info!(
                "reconnect network_code={},device_id={device_id},ip={ip}",
                self.network_code,
            );
            None
        }
    }

    pub fn count(&self) -> (u32, u32) {
        let all_count = self.lease_state.lock().device_map.len() as u32;
        let online_count = self.sender_map.len() as u32;
        (all_count.max(online_count), online_count)
    }

    pub fn is_device_online(&self, device_id: &str) -> bool {
        let guard = self.lease_state.lock();
        guard
            .device_map
            .get(device_id)
            .map(|e| e.is_connected)
            .unwrap_or(false)
    }

    pub fn remove_device_from_memory(&self, device_id: &str) -> Option<Ipv4Addr> {
        let mut guard = self.lease_state.lock();
        if let Some(entry) = guard.device_map.remove(device_id) {
            if let Some(ip) = entry.ip {
                guard.device_ip_map.remove(&ip);
                self.sender_map.remove(&ip);
                self.traffic_stats_map.remove(&ip);
            }
            guard.data_version += 1;
            return entry.ip;
        }
        None
    }

    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    /// 释放预注册但未确认的 IP，通过 random_id 避免误删其他会话
    pub fn release_pre_registered_ip(&self, device_id: &String, ip: Ipv4Addr, random_id: u64) {
        let should_remove = {
            let mut guard = self.lease_state.lock();
            if let Some(device_entry) = guard.device_map.get(device_id) {
                if device_entry.random_id == random_id && device_entry.ip == Some(ip) {
                    guard.device_map.remove(device_id);
                    guard.device_ip_map.remove(&ip);
                    guard.data_version += 1;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };

        if should_remove {
            self.sender_map.remove(&ip);
            self.traffic_stats_map.remove(&ip);
            log::info!(
                "Released pre-registered IP device_id={}, ip={}",
                device_id,
                ip
            );
        }
    }

    pub fn get_device_entry(&self, device_id: &str) -> Option<DeviceEntry> {
        let guard = self.lease_state.lock();
        guard.device_map.get(device_id).cloned()
    }

    pub fn get_device_entry_by_ip(&self, ip: Ipv4Addr) -> Option<DeviceEntry> {
        let guard = self.lease_state.lock();
        guard
            .device_ip_map
            .get(&ip)
            .and_then(|device_id| guard.device_map.get(device_id).cloned())
    }

    /// 同步保存到 DB 后再确认，防止 Drop 时状态不一致
    pub async fn confirm_registration(
        &self,
        network_code: &str,
        device_id: &str,
    ) -> anyhow::Result<()> {
        if let Some(entry) = self.get_device_entry(device_id) {
            let record = entry.to_record(network_code);
            db::save_or_update_device(&record).await?;
        }
        Ok(())
    }

    /// 返回 (分配的IP, 旧IP, DeviceEntry克隆)
    pub fn allocate_ip_and_get_entry(
        &self,
        reg_req: RegRequestMsg,
        random_id: u64,
        sender: Sender<Bytes>,
    ) -> anyhow::Result<(Ipv4Addr, Option<Ipv4Addr>, Option<DeviceEntry>)> {
        let mut guard = self.lease_state.lock();
        let (ip, old_ip) =
            guard.allocate_ip(&self.net, self.gateway, reg_req.clone(), random_id)?;

        if let Some(old_ip) = old_ip {
            self.sender_map.remove(&old_ip);
            self.traffic_stats_map.remove(&old_ip);
        }

        let entry = guard.device_map.get(&reg_req.device_id).cloned();
        self.sender_map.insert(ip, sender);

        if let Some(entry) = &entry {
            self.traffic_stats_map
                .insert(ip, entry.traffic_stats.clone());
        }

        Ok((ip, old_ip, entry))
    }

    pub fn collect_expired_devices(&self) -> Vec<String> {
        let guard = self.lease_state.lock();
        guard.collect_expired_devices(self.lease_duration)
    }

    pub fn remove_devices(&self, device_ids: &[String]) {
        let mut guard = self.lease_state.lock();
        guard.remove_devices(device_ids);
    }

    pub fn data_version(&self) -> u64 {
        let guard = self.lease_state.lock();
        guard.data_version
    }

    pub fn get_all_device_simple_info(&self) -> Vec<(String, Option<Ipv4Addr>, bool, u64)> {
        let guard = self.lease_state.lock();
        guard
            .device_map
            .values()
            .map(|entry| {
                (
                    entry.device_id.clone(),
                    entry.ip,
                    entry.is_connected,
                    entry.data_version,
                )
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        let guard = self.lease_state.lock();
        guard.device_map.is_empty() && guard.device_ip_map.is_empty()
    }

    pub fn last_active_time(&self) -> Instant {
        *self.time.lock()
    }

    pub fn network_code(&self) -> String {
        self.network_code.clone()
    }

    pub fn get_device_infos(&self) -> Vec<crate::server::control_server::service::DeviceInfoVO> {
        use time::OffsetDateTime;
        use time::macros::format_description;

        let guard = self.lease_state.lock();
        let mut list = Vec::new();
        let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

        for (_device_id, entry) in &guard.device_map {
            let last_connect_time: OffsetDateTime = entry.last_connect_time.into();
            let disconnect_time: Option<OffsetDateTime> = entry.disconnect_time.map(|d| d.into());

            list.push(crate::server::control_server::service::DeviceInfoVO {
                device_id: entry.device_id.clone(),
                device_name: entry.device_name.clone(),
                device_version: entry.device_version.clone(),
                ip: entry.ip,
                status: if entry.is_connected {
                    "Online".to_string()
                } else {
                    "Offline".to_string()
                },
                last_connect_time: last_connect_time.format(&format).unwrap_or_default(),
                disconnect_time: disconnect_time.map(|d| d.format(&format).unwrap_or_default()),
                latency_ms: entry.latency_ms,
                server_addr: None,
                tx_bytes: entry.traffic_stats.get_tx(),
                rx_bytes: entry.traffic_stats.get_rx(),
            });
        }
        list
    }

    pub fn changed_client_simple_list(
        &self,
        exclude_ip: Ipv4Addr,
        data_version: u64,
    ) -> Option<crate::protocol::control_message::ClientSimpleInfoList> {
        use crate::protocol::control_message::ClientSimpleInfo;

        let guard = self.lease_state.lock();
        if data_version == guard.data_version {
            return None;
        }
        if data_version > guard.data_version {
            let list = guard
                .device_map
                .values()
                .filter(|v| v.ip.is_some() && v.ip != Some(exclude_ip))
                .map(|v| ClientSimpleInfo {
                    ip: v.ip.unwrap(),
                    online: v.is_connected,
                })
                .collect();
            return Some(crate::protocol::control_message::ClientSimpleInfoList {
                data_version: guard.data_version,
                list,
                is_all: true,
                time: 0,
            });
        }
        let list = guard
            .device_map
            .values()
            .filter(|v| v.data_version > data_version && v.ip.is_some() && v.ip != Some(exclude_ip))
            .map(|v| ClientSimpleInfo {
                ip: v.ip.unwrap(),
                online: v.is_connected,
            })
            .collect();
        Some(crate::protocol::control_message::ClientSimpleInfoList {
            data_version: guard.data_version,
            list,
            is_all: false,
            time: 0,
        })
    }

    pub fn client_info_list(
        &self,
        exclude_ip: Ipv4Addr,
    ) -> Vec<crate::protocol::rpc_message::ClientInfo> {
        use crate::protocol::rpc_message::ClientInfo;
        use time::OffsetDateTime;

        let guard = self.lease_state.lock();
        let mut list = Vec::new();

        for (_device_id, entry) in &guard.device_map {
            let Some(ip) = entry.ip else {
                continue;
            };
            if ip == exclude_ip {
                continue;
            }
            let last_connect_time: OffsetDateTime = entry.last_connect_time.into();
            list.push(ClientInfo {
                name: entry.device_name.clone(),
                version: entry.device_version.clone(),
                ip: ip.into(),
                key_sign: entry.key_sign.clone(),
                online: entry.is_connected,
                last_connected_time: last_connect_time.unix_timestamp(),
                id: entry.device_id.clone(),
            });
        }
        list
    }
}

impl NetworkStateInner {
    fn offline_ip(
        &mut self,
        network_code: &str,
        device_id: &String,
        ip: Ipv4Addr,
        random_id: u64,
    ) -> (bool, Option<DeviceRecord>) {
        let Some(device_entry) = self.device_map.get_mut(device_id) else {
            log::error!("unknown device_id {}", device_id);
            return (false, None);
        };
        if device_entry.random_id != random_id {
            return (false, None);
        }
        if device_entry.ip != Some(ip) {
            return (false, None);
        }
        self.data_version += 1;
        device_entry.data_version = self.data_version;
        device_entry.is_connected = false;
        device_entry.disconnect_time = Some(SystemTime::now());

        let record = device_entry.to_record(network_code);
        (true, Some(record))
    }

    fn collect_expired_devices(&self, lease_duration: Duration) -> Vec<String> {
        let now = SystemTime::now();
        self.device_map
            .iter()
            .filter_map(|(k, v)| {
                if v.is_connected {
                    return None;
                }
                if let Some(disconnect_time) = v.disconnect_time {
                    if disconnect_time + lease_duration > now {
                        return None;
                    }
                    return Some(k.clone());
                }
                None
            })
            .collect()
    }

    fn remove_devices(&mut self, device_ids: &[String]) {
        if device_ids.is_empty() {
            return;
        }
        self.data_version += 1;
        for device_id in device_ids {
            if let Some(entry) = self.device_map.remove(device_id) {
                if let Some(ip) = entry.ip {
                    self.device_ip_map.remove(&ip);
                }
            }
        }
    }

    fn add_device(&mut self, device_entry: DeviceEntry) {
        if let Some(ip) = device_entry.ip {
            self.device_ip_map
                .insert(ip, device_entry.device_id.clone());
        }
        self.device_map
            .insert(device_entry.device_id.clone(), device_entry);
    }

    #[allow(dead_code)]
    fn remove_device(&mut self, device_id: &String, ip: Option<Ipv4Addr>) {
        self.device_map.remove(device_id);
        if let Some(ip) = ip {
            self.device_ip_map.remove(&ip);
        }
    }

    fn allocate_ip(
        &mut self,
        net: &Ipv4Net,
        gateway: Ipv4Addr,
        reg_req: RegRequestMsg,
        random_id: u64,
    ) -> anyhow::Result<(Ipv4Addr, Option<Ipv4Addr>)> {
        let expect_ip = reg_req.ip;

        let existing_device_info = self
            .device_map
            .get(&reg_req.device_id)
            .map(|e| (e.ip, expect_ip.is_none() || e.ip == expect_ip));

        if let Some((current_ip, ip_matches)) = existing_device_info {
            if ip_matches {
                let new_ip = if current_ip.is_none() {
                    Some(self.find_available_ip(net, gateway)?)
                } else {
                    None
                };

                let device_entry = self.device_map.get_mut(&reg_req.device_id).unwrap();
                device_entry.is_connected = true;
                device_entry.disconnect_time = None;
                device_entry.random_id = random_id;
                device_entry.last_connect_time = SystemTime::now();
                self.data_version += 1;
                device_entry.data_version = self.data_version;
                device_entry.key_sign = reg_req.key_sign.clone();

                if let Some(ip) = new_ip {
                    device_entry.ip = Some(ip);
                    let device_id = device_entry.device_id.clone();
                    self.device_ip_map.insert(ip, device_id);
                    return Ok((ip, None));
                }
                return Ok((current_ip.unwrap(), None));
            }
        }

        let old = existing_device_info.and_then(|(ip, _)| ip);

        if let Some(ip) = expect_ip {
            loop {
                if ip == gateway {
                    if reg_req.ip_variable {
                        break;
                    }
                    bail!("此IP为网关IP，不允许使用")
                }
                if !net.contains(&ip) {
                    if reg_req.ip_variable {
                        break;
                    }
                    bail!("IP网段错误，应使用{}网段中的IP", net)
                }
                if let Some(id) = self.device_ip_map.get(&ip) {
                    if reg_req.ip_variable {
                        break;
                    }
                    if let Some(v) = self.device_map.get(id) {
                        bail!("IP重复，设备{}[{}]已使用此IP", v.device_name, v.device_id)
                    }
                    bail!("IP重复，服务端数据错误")
                }
                if let Some(old_ip) = old {
                    self.device_ip_map.remove(&old_ip);
                }
                self.data_version += 1;
                self.add_device(DeviceEntry {
                    device_id: reg_req.device_id,
                    ip: Some(ip),
                    random_id,
                    device_name: reg_req.name,
                    device_version: reg_req.version,
                    is_connected: true,
                    last_connect_time: SystemTime::now(),
                    disconnect_time: None,
                    data_version: self.data_version,
                    key_sign: reg_req.key_sign,
                    latency_ms: None,
                    traffic_stats: Arc::new(TrafficStats::new()),
                });

                return Ok((ip, old));
            }
        }

        let ip = self.find_available_ip(net, gateway)?;
        self.data_version += 1;
        self.add_device(DeviceEntry {
            device_id: reg_req.device_id,
            ip: Some(ip),
            random_id,
            device_name: reg_req.name,
            device_version: reg_req.version,
            is_connected: true,
            last_connect_time: SystemTime::now(),
            disconnect_time: None,
            data_version: self.data_version,
            key_sign: reg_req.key_sign,
            latency_ms: None,
            traffic_stats: Arc::new(TrafficStats::new()),
        });
        Ok((ip, old))
    }

    fn find_available_ip(&self, net: &Ipv4Net, gateway: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
        let start = u32::from(net.network()) + 1;
        let end = u32::from(net.broadcast());
        for i in start..end {
            let ip = Ipv4Addr::from(i);
            if ip == gateway {
                continue;
            }
            if self.device_ip_map.contains_key(&ip) {
                continue;
            }
            return Ok(ip);
        }
        bail!("IP exhaustion");
    }
}

impl NetworkState {
    async fn build_initial_inner_state(
        network_code: &str,
        net: Ipv4Net,
        gateway: Ipv4Addr,
    ) -> NetworkStateInner {
        match db::load_all_devices(network_code).await {
            Ok(records) => {
                let mut device_map = HashMap::new();
                let mut device_ip_map = HashMap::new();
                let mut max_version = 0u64;

                for record in records {
                    let entry = DeviceEntry::from_record(record);
                    if let Some(ip) = entry.ip {
                        if net.contains(&ip) && gateway != ip {
                            device_ip_map.insert(ip, entry.device_id.clone());
                        }
                    }
                    max_version = max_version.max(entry.data_version);
                    device_map.insert(entry.device_id.clone(), entry);
                }

                if !device_map.is_empty() {
                    log::info!(
                        "Loaded {} devices for network {}",
                        device_map.len(),
                        network_code
                    );
                }

                NetworkStateInner {
                    data_version: max_version,
                    device_map,
                    device_ip_map,
                }
            }
            Err(e) => {
                log::error!(
                    "Error loading all devices for network {}: {}",
                    network_code,
                    e
                );
                NetworkStateInner {
                    data_version: 0,
                    device_map: Default::default(),
                    device_ip_map: Default::default(),
                }
            }
        }
    }

    pub async fn new_from_db(
        network_code: String,
        net: Ipv4Net,
        lease_duration: Duration,
    ) -> NetworkState {
        let gateway = Ipv4Addr::from(u32::from(net.network()) + 1);
        let initial_inner_state =
            Self::build_initial_inner_state(&network_code, net, gateway).await;
        Self {
            time: Mutex::new(Instant::now()),
            network_code,
            gateway,
            net,
            lease_duration,
            sender_map: Default::default(),
            lease_state: Mutex::new(initial_inner_state),
            traffic_stats_map: Default::default(),
        }
    }

    pub fn update_time(&self) {
        *self.time.lock() = Instant::now();
    }

    pub fn update_client_latency(&self, ip: Ipv4Addr, latency_ms: u32) {
        let mut guard = self.lease_state.lock();
        if let Some(device_id) = guard.device_ip_map.get(&ip).cloned() {
            if let Some(entry) = guard.device_map.get_mut(&device_id) {
                entry.latency_ms = Some(latency_ms);
                log::debug!(
                    "Updated client latency: network_code={}, ip={}, latency={} ms",
                    self.network_code,
                    ip,
                    latency_ms
                );
            }
        }
    }
}

/// 网络状态的共享视图，供 PeerServerManager 等外部模块访问
#[derive(Clone)]
pub struct NetworkStateProvider {
    network_states: Arc<DashMap<String, Arc<NetworkState>>>,
}

impl NetworkStateProvider {
    pub fn new(network_states: Arc<DashMap<String, Arc<NetworkState>>>) -> Self {
        Self { network_states }
    }

    pub fn get_network_codes(&self) -> Vec<String> {
        self.network_states
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn get_network_state(&self, network_code: &str) -> Option<Arc<NetworkState>> {
        self.network_states.get(network_code).map(|s| s.clone())
    }

    pub fn update_client_latency(&self, network_code: &str, ip: Ipv4Addr, latency_ms: u32) {
        if let Some(state) = self.get_network_state(network_code) {
            state.update_client_latency(ip, latency_ms);
        }
    }
}

impl Deref for NetworkStateProvider {
    type Target = DashMap<String, Arc<NetworkState>>;

    fn deref(&self) -> &Self::Target {
        &self.network_states
    }
}
