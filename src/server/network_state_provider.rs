use crate::protocol::control_message::RegRequestMsg;
use crate::server::control_server::db;
use crate::server::control_server::db::DeviceIpType;
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
    pub ip_type: DeviceIpType,
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
    pub advertised_subnets: Vec<Ipv4Net>,
    pub subnet_advertisement_active: bool,
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
            ip_type: record.ip_type,
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
            advertised_subnets: Vec::new(),
            subnet_advertisement_active: false,
        }
    }

    pub fn to_record(&self, network_code: &str) -> DeviceRecord {
        DeviceRecord {
            device_id: self.device_id.clone(),
            network_code: network_code.to_string(),
            ip: self.ip.map(|ip| ip.to_string()),
            ip_type: self.ip_type,
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
    /// 最近一次无法用增量列表表达的设备列表变更版本。
    /// 客户端版本低于该值时必须下发全量列表以删除本地旧条目。
    full_sync_version: u64,
    device_map: HashMap<String, DeviceEntry>,
    device_ip_map: HashMap<Ipv4Addr, String>,
    active_ip_map: HashMap<Ipv4Addr, String>,
}

impl NetworkState {
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
            }
            let active_ips: Vec<Ipv4Addr> = guard
                .active_ip_map
                .iter()
                .filter_map(|(ip, id)| (id == device_id).then_some(*ip))
                .collect();
            for ip in active_ips {
                guard.active_ip_map.remove(&ip);
                self.sender_map.remove(&ip);
                self.traffic_stats_map.remove(&ip);
            }
            guard.data_version += 1;
            guard.full_sync_version = guard.data_version;
            return entry.ip;
        }
        None
    }

    /// 释放预注册但未确认的 IP，通过 random_id 避免误删其他会话
    pub fn release_pre_registered_ip(&self, device_id: &String, ip: Ipv4Addr, random_id: u64) {
        let should_remove = {
            let mut guard = self.lease_state.lock();
            if let Some(device_entry) = guard.device_map.get(device_id) {
                if device_entry.random_id == random_id && device_entry.ip == Some(ip) {
                    guard.device_map.remove(device_id);
                    guard.device_ip_map.remove(&ip);
                    guard.active_ip_map.remove(&ip);
                    guard.data_version += 1;
                    guard.full_sync_version = guard.data_version;
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

    pub fn configured_ip(&self, device_id: &str) -> Option<Ipv4Addr> {
        self.lease_state
            .lock()
            .device_map
            .get(device_id)
            .and_then(|entry| entry.ip)
    }

    pub fn has_device(&self, device_id: &str) -> bool {
        self.lease_state.lock().device_map.contains_key(device_id)
    }

    pub fn upsert_device_config(
        &self,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
    ) -> anyhow::Result<Option<DeviceEntry>> {
        let mut guard = self.lease_state.lock();
        guard.validate_ip_available(ip, Some(device_id))?;
        let previous = guard.device_map.get(device_id).cloned();
        let replaces_published_ip = previous
            .as_ref()
            .is_some_and(|entry| !entry.is_connected && entry.ip.is_some_and(|old| old != ip));

        if let Some(old_ip) = previous.as_ref().and_then(|entry| entry.ip)
            && old_ip != ip
        {
            guard.device_ip_map.remove(&old_ip);
        }

        let publish_now = previous
            .as_ref()
            .map(|entry| !entry.is_connected)
            .unwrap_or(true);
        if publish_now {
            guard.data_version += 1;
            if replaces_published_ip {
                guard.full_sync_version = guard.data_version;
            }
        }
        let data_version = previous
            .as_ref()
            .filter(|_| !publish_now)
            .map(|entry| entry.data_version)
            .unwrap_or(guard.data_version);
        if let Some(entry) = guard.device_map.get_mut(device_id) {
            entry.ip = Some(ip);
            entry.ip_type = ip_type;
            entry.data_version = data_version;
        } else {
            guard.device_map.insert(
                device_id.to_string(),
                DeviceEntry {
                    device_id: device_id.to_string(),
                    ip: Some(ip),
                    ip_type,
                    random_id: 0,
                    device_name: device_id.to_string(),
                    device_version: String::new(),
                    is_connected: false,
                    last_connect_time: SystemTime::now(),
                    disconnect_time: Some(SystemTime::now()),
                    data_version,
                    key_sign: None,
                    latency_ms: None,
                    traffic_stats: Arc::new(TrafficStats::new()),
                    advertised_subnets: Vec::new(),
                    subnet_advertisement_active: false,
                },
            );
        }
        guard.device_ip_map.insert(ip, device_id.to_string());
        Ok(previous)
    }

    pub fn restore_device_config(&self, device_id: &str, previous: Option<DeviceEntry>) {
        let mut guard = self.lease_state.lock();
        if let Some(current) = guard.device_map.get(device_id)
            && let Some(ip) = current.ip
        {
            guard.device_ip_map.remove(&ip);
        }
        match previous {
            Some(entry) => {
                if let Some(ip) = entry.ip {
                    guard.device_ip_map.insert(ip, device_id.to_string());
                }
                guard.device_map.insert(device_id.to_string(), entry);
            }
            None => {
                guard.device_map.remove(device_id);
            }
        }
        guard.data_version += 1;
        guard.full_sync_version = guard.data_version;
    }

    pub fn fast_register(
        &self,
        device_id: &str,
        old_ip: Ipv4Addr,
        new_ip: Ipv4Addr,
        random_id: u64,
    ) -> anyhow::Result<()> {
        let mut guard = self.lease_state.lock();
        let entry = guard
            .device_map
            .get(device_id)
            .ok_or_else(|| anyhow::anyhow!("设备不存在"))?;
        if entry.random_id != random_id || !entry.is_connected {
            bail!("会话已失效");
        }
        if entry.ip != Some(new_ip) {
            bail!("快速注册 IP 与设备最新 IP 不一致");
        }
        guard.validate_ip_available(new_ip, Some(device_id))?;
        if guard.active_ip_map.get(&old_ip).map(String::as_str) != Some(device_id) {
            bail!("当前会话 IP 不匹配");
        }

        let sender = self
            .sender_map
            .get(&old_ip)
            .map(|value| value.clone())
            .ok_or_else(|| anyhow::anyhow!("当前会话发送通道不存在"))?;
        let stats = self
            .traffic_stats_map
            .get(&old_ip)
            .map(|value| value.clone());

        guard.active_ip_map.remove(&old_ip);
        guard.active_ip_map.insert(new_ip, device_id.to_string());
        guard.data_version += 1;
        let data_version = guard.data_version;
        if old_ip != new_ip {
            guard.full_sync_version = data_version;
        }
        if let Some(entry) = guard.device_map.get_mut(device_id) {
            entry.data_version = data_version;
        }
        self.sender_map.remove(&old_ip);
        self.sender_map.insert(new_ip, sender);
        self.traffic_stats_map.remove(&old_ip);
        if let Some(stats) = stats {
            self.traffic_stats_map.insert(new_ip, stats);
        }
        Ok(())
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
        let mut guard = self.lease_state.lock();
        let next_version = guard.data_version + 1;
        if let Some(entry) = guard.device_map.get_mut(device_id)
            && !entry.subnet_advertisement_active
        {
            entry.subnet_advertisement_active = true;
            entry.data_version = next_version;
            guard.data_version = next_version;
        }
        Ok(())
    }

    pub fn online_advertised_subnets(&self) -> Vec<(Ipv4Addr, Vec<Ipv4Net>)> {
        self.lease_state
            .lock()
            .device_map
            .values()
            .filter(|entry| entry.is_connected && entry.subnet_advertisement_active)
            .filter_map(|entry| entry.ip.map(|ip| (ip, entry.advertised_subnets.clone())))
            .collect()
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

        // 普通重新注册以本次服务端分配结果为准，并淘汰同一设备的旧活动会话映射。
        let stale_active_ips: Vec<Ipv4Addr> = guard
            .active_ip_map
            .iter()
            .filter_map(|(active_ip, id)| {
                (id == &reg_req.device_id && *active_ip != ip).then_some(*active_ip)
            })
            .collect();
        if !stale_active_ips.is_empty() {
            guard.full_sync_version = guard.data_version;
        }
        for stale_ip in stale_active_ips {
            guard.active_ip_map.remove(&stale_ip);
            self.sender_map.remove(&stale_ip);
            self.traffic_stats_map.remove(&stale_ip);
        }

        let entry = guard.device_map.get(&reg_req.device_id).cloned();
        self.sender_map.insert(ip, sender);
        guard.active_ip_map.insert(ip, reg_req.device_id.clone());

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

    pub fn remove_devices(&self, device_ids: &[String]) -> Vec<String> {
        let mut guard = self.lease_state.lock();
        guard.remove_devices(device_ids)
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
        let active_ips: HashMap<&str, Ipv4Addr> = guard
            .active_ip_map
            .iter()
            .map(|(ip, device_id)| (device_id.as_str(), *ip))
            .collect();

        for entry in guard.device_map.values() {
            let last_connect_time: OffsetDateTime = entry.last_connect_time.into();
            let disconnect_time: Option<OffsetDateTime> = entry.disconnect_time.map(|d| d.into());

            list.push(crate::server::control_server::service::DeviceInfoVO {
                device_id: entry.device_id.clone(),
                device_name: entry.device_name.clone(),
                device_version: entry.device_version.clone(),
                ip: entry.ip,
                current_ip: active_ips.get(entry.device_id.as_str()).copied(),
                ip_type: Some(entry.ip_type),
                status: if entry.is_connected {
                    "Online".to_string()
                } else {
                    "Offline".to_string()
                },
                last_connect_time: last_connect_time.format(&format).unwrap_or_default(),
                disconnect_time: disconnect_time.map(|d| d.format(&format).unwrap_or_default()),
                latency_ms: entry.latency_ms,
                server_addr: None,
                advertised_subnets: if entry.subnet_advertisement_active {
                    entry.advertised_subnets.clone()
                } else {
                    Vec::new()
                },
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
        if data_version > guard.data_version || data_version < guard.full_sync_version {
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

        for entry in guard.device_map.values() {
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
        let removes_different_ip = device_entry.ip != Some(ip);
        self.data_version += 1;
        device_entry.data_version = self.data_version;
        device_entry.is_connected = false;
        device_entry.subnet_advertisement_active = false;
        device_entry.disconnect_time = Some(SystemTime::now());

        let record = device_entry.to_record(network_code);
        self.active_ip_map.remove(&ip);
        if removes_different_ip {
            self.full_sync_version = self.data_version;
        }
        (true, Some(record))
    }

    fn collect_expired_devices(&self, lease_duration: Duration) -> Vec<String> {
        let now = SystemTime::now();
        self.device_map
            .iter()
            .filter_map(|(k, v)| {
                if v.is_connected || v.ip_type != DeviceIpType::Dynamic {
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

    fn remove_devices(&mut self, device_ids: &[String]) -> Vec<String> {
        if device_ids.is_empty() {
            return Vec::new();
        }
        self.data_version += 1;
        let mut released = Vec::new();
        for device_id in device_ids {
            if let Some(entry) = self.device_map.get_mut(device_id) {
                if entry.is_connected || entry.ip_type != DeviceIpType::Dynamic {
                    continue;
                }
                if let Some(ip) = entry.ip.take() {
                    self.device_ip_map.remove(&ip);
                    released.push(device_id.clone());
                }
                entry.data_version = self.data_version;
            }
        }
        if !released.is_empty() {
            self.full_sync_version = self.data_version;
        }
        released
    }

    fn add_device(&mut self, device_entry: DeviceEntry) {
        if let Some(ip) = device_entry.ip {
            self.device_ip_map
                .insert(ip, device_entry.device_id.clone());
        }
        self.device_map
            .insert(device_entry.device_id.clone(), device_entry);
    }

    fn validate_ip_available(&self, ip: Ipv4Addr, device_id: Option<&str>) -> anyhow::Result<()> {
        if let Some(owner) = self.conflicting_ip_owner(ip, device_id) {
            bail!("IP重复，设备 {} 已使用此IP", owner);
        }
        Ok(())
    }

    /// 配置 IP 和活动会话 IP 都属于占用。必须分别检查两个集合，不能用
    /// `device_ip_map.get(...).or_else(...)`，否则配置集合中属于当前设备的记录
    /// 会掩盖活动集合中可能属于另一设备的冲突记录。
    fn conflicting_ip_owner(&self, ip: Ipv4Addr, device_id: Option<&str>) -> Option<String> {
        self.device_ip_map
            .get(&ip)
            .filter(|owner| Some(owner.as_str()) != device_id)
            .cloned()
            .or_else(|| {
                self.active_ip_map
                    .get(&ip)
                    .filter(|owner| Some(owner.as_str()) != device_id)
                    .cloned()
            })
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
        let advertised_subnets = reg_req.advertised_subnets.clone();
        let subnet_advertisement_active =
            reg_req.registration_mode == crate::protocol::control_message::RegistrationMode::Normal;
        let existing_entry = self.device_map.get(&reg_req.device_id).cloned();
        let fixed_ip = existing_entry
            .as_ref()
            .is_some_and(|entry| entry.ip_type == DeviceIpType::Fixed);
        // 固定 IP 始终服从服务端；静态/动态 IP 则优先采用客户端注册请求。
        let expect_ip = match existing_entry.as_ref() {
            Some(entry) if entry.ip_type == DeviceIpType::Fixed => Some(
                entry
                    .ip
                    .ok_or_else(|| anyhow::anyhow!("固定 IP 设备未配置 IP"))?,
            ),
            Some(entry) => reg_req.ip.or(entry.ip),
            None => reg_req.ip,
        };

        let existing_device_info = self
            .device_map
            .get(&reg_req.device_id)
            .map(|e| (e.ip, expect_ip.is_none() || e.ip == expect_ip));

        if let Some((current_ip, ip_matches)) = existing_device_info
            && ip_matches
        {
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
            device_entry.device_name = reg_req.name.clone();
            device_entry.device_version = reg_req.version.clone();
            device_entry.advertised_subnets = advertised_subnets.clone();
            device_entry.subnet_advertisement_active = subnet_advertisement_active;

            if let Some(ip) = new_ip {
                device_entry.ip = Some(ip);
                let device_id = device_entry.device_id.clone();
                self.device_ip_map.insert(ip, device_id);
                return Ok((ip, None));
            }
            let current_ip = current_ip.unwrap();
            self.validate_ip_available(current_ip, Some(&reg_req.device_id))?;
            return Ok((current_ip, None));
        }

        let old = existing_device_info.and_then(|(ip, _)| ip);

        if let Some(ip) = expect_ip {
            let can_use_expected_ip = if ip == gateway {
                if fixed_ip || !reg_req.ip_variable {
                    bail!("此IP为网关IP，不允许使用")
                }
                false
            } else if !net.contains(&ip) {
                if fixed_ip || !reg_req.ip_variable {
                    bail!("IP网段错误，应使用{}网段中的IP", net)
                }
                false
            } else if ip == net.network() || ip == net.broadcast() {
                if fixed_ip || !reg_req.ip_variable {
                    bail!("此IP为网段的网络地址或广播地址，不允许使用")
                }
                false
            } else if let Some(id) = self.conflicting_ip_owner(ip, Some(&reg_req.device_id)) {
                if fixed_ip || !reg_req.ip_variable {
                    if let Some(v) = self.device_map.get(&id) {
                        bail!("IP重复，设备{}[{}]已使用此IP", v.device_name, v.device_id)
                    }
                    bail!("IP重复，设备 {} 的活动会话已使用此IP", id)
                }
                false
            } else {
                true
            };

            if can_use_expected_ip {
                if let Some(old_ip) = old {
                    self.device_ip_map.remove(&old_ip);
                }
                self.data_version += 1;
                if old.is_some_and(|old_ip| old_ip != ip) {
                    self.full_sync_version = self.data_version;
                }
                let entry = if let Some(mut entry) = existing_entry.clone() {
                    entry.ip = Some(ip);
                    entry.random_id = random_id;
                    entry.device_name = reg_req.name;
                    entry.device_version = reg_req.version;
                    entry.is_connected = true;
                    entry.last_connect_time = SystemTime::now();
                    entry.disconnect_time = None;
                    entry.data_version = self.data_version;
                    entry.key_sign = reg_req.key_sign;
                    entry.latency_ms = None;
                    entry.advertised_subnets = advertised_subnets.clone();
                    entry.subnet_advertisement_active = subnet_advertisement_active;
                    entry
                } else {
                    DeviceEntry {
                        device_id: reg_req.device_id,
                        ip: Some(ip),
                        ip_type: DeviceIpType::Dynamic,
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
                        advertised_subnets: advertised_subnets.clone(),
                        subnet_advertisement_active,
                    }
                };
                self.add_device(entry);

                return Ok((ip, old));
            }
        }

        let ip = self.find_available_ip(net, gateway)?;
        self.data_version += 1;
        if old.is_some_and(|old_ip| old_ip != ip) {
            self.full_sync_version = self.data_version;
        }
        let entry = if let Some(mut entry) = existing_entry {
            if let Some(old_ip) = entry.ip {
                self.device_ip_map.remove(&old_ip);
            }
            entry.ip = Some(ip);
            entry.random_id = random_id;
            entry.device_name = reg_req.name;
            entry.device_version = reg_req.version;
            entry.is_connected = true;
            entry.last_connect_time = SystemTime::now();
            entry.disconnect_time = None;
            entry.data_version = self.data_version;
            entry.key_sign = reg_req.key_sign;
            entry.latency_ms = None;
            entry.advertised_subnets = advertised_subnets.clone();
            entry.subnet_advertisement_active = subnet_advertisement_active;
            entry
        } else {
            DeviceEntry {
                device_id: reg_req.device_id,
                ip: Some(ip),
                ip_type: DeviceIpType::Dynamic,
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
                advertised_subnets,
                subnet_advertisement_active,
            }
        };
        self.add_device(entry);
        Ok((ip, old))
    }

    fn find_available_ip(&self, net: &Ipv4Net, gateway: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
        let start = u32::from(net.network())
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Invalid network address"))?;
        let end = u32::from(net.broadcast());
        for i in start..end {
            let ip = Ipv4Addr::from(i);
            if ip == gateway {
                continue;
            }
            if self.device_ip_map.contains_key(&ip) {
                continue;
            }
            if self.active_ip_map.contains_key(&ip) {
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
                    if let Some(ip) = entry.ip
                        && net.contains(&ip)
                        && gateway != ip
                        && ip != net.network()
                        && ip != net.broadcast()
                    {
                        device_ip_map.insert(ip, entry.device_id.clone());
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
                    full_sync_version: 0,
                    device_map,
                    device_ip_map,
                    active_ip_map: HashMap::new(),
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
                    full_sync_version: 0,
                    device_map: Default::default(),
                    device_ip_map: Default::default(),
                    active_ip_map: Default::default(),
                }
            }
        }
    }

    pub async fn new_from_db(
        network_code: String,
        net: Ipv4Net,
        gateway: Ipv4Addr,
        lease_duration: Duration,
    ) -> NetworkState {
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
        if let Some(device_id) = guard.device_ip_map.get(&ip).cloned()
            && let Some(entry) = guard.device_map.get_mut(&device_id)
        {
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

#[cfg(test)]
mod tests {
    use super::NetworkStateInner;
    use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
    use crate::server::control_server::db::DeviceIpType;
    use ipnet::Ipv4Net;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    fn request(ip: Ipv4Addr, ip_variable: bool) -> RegRequestMsg {
        RegRequestMsg {
            network_code: "test-net".to_string(),
            device_id: format!("device-{ip}"),
            ip: Some(ip),
            name: "test".to_string(),
            version: "1".to_string(),
            key_sign: None,
            ip_variable,
            server_id: 0,
            registration_mode: RegistrationMode::Normal,
            advertised_subnets: Vec::new(),
        }
    }

    fn empty_state() -> NetworkStateInner {
        NetworkStateInner {
            data_version: 0,
            full_sync_version: 0,
            device_map: HashMap::new(),
            device_ip_map: HashMap::new(),
            active_ip_map: HashMap::new(),
        }
    }

    #[test]
    fn requested_network_and_broadcast_addresses_are_rejected() {
        let net = "10.26.0.0/24".parse::<Ipv4Net>().unwrap();
        let gateway = Ipv4Addr::new(10, 26, 0, 1);
        let mut state = empty_state();

        assert!(
            state
                .allocate_ip(
                    &net,
                    gateway,
                    request(Ipv4Addr::new(10, 26, 0, 0), false),
                    1,
                )
                .is_err()
        );
        assert!(
            state
                .allocate_ip(
                    &net,
                    gateway,
                    request(Ipv4Addr::new(10, 26, 0, 255), false),
                    2,
                )
                .is_err()
        );
    }

    #[test]
    fn reregister_replaces_subnets_and_stale_session_cannot_remove_them() {
        let net = "10.26.0.0/24".parse::<Ipv4Net>().unwrap();
        let gateway = Ipv4Addr::new(10, 26, 0, 1);
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        let mut state = empty_state();
        let mut first = request(ip, false);
        first.advertised_subnets = vec!["192.168.0.0/24".parse().unwrap()];
        state.allocate_ip(&net, gateway, first, 1).unwrap();

        let mut second = request(ip, false);
        second.advertised_subnets = vec!["172.16.0.0/16".parse().unwrap()];
        state.allocate_ip(&net, gateway, second, 2).unwrap();
        let entry = state.device_map.get(&format!("device-{ip}")).unwrap();
        assert_eq!(
            entry.advertised_subnets,
            vec!["172.16.0.0/16".parse().unwrap()]
        );

        let (removed, _) = state.offline_ip("test-net", &format!("device-{ip}"), ip, 1);
        assert!(!removed);
        assert!(
            state
                .device_map
                .get(&format!("device-{ip}"))
                .unwrap()
                .is_connected
        );
    }

    #[test]
    fn variable_invalid_ip_falls_back_to_available_host() {
        let net = "10.26.0.0/24".parse::<Ipv4Net>().unwrap();
        let gateway = Ipv4Addr::new(10, 26, 0, 1);
        let mut state = empty_state();

        let (ip, _) = state
            .allocate_ip(
                &net,
                gateway,
                request(Ipv4Addr::new(10, 26, 0, 255), true),
                1,
            )
            .expect("fallback allocation");
        assert_eq!(ip, Ipv4Addr::new(10, 26, 0, 2));
    }

    #[test]
    fn lease_cleanup_releases_only_dynamic_ip_and_keeps_device_membership() {
        let net = "10.26.0.0/24".parse::<Ipv4Net>().unwrap();
        let gateway = Ipv4Addr::new(10, 26, 0, 1);
        let mut state = empty_state();
        let dynamic_id = "device-10.26.0.2".to_string();
        let static_id = "device-10.26.0.3".to_string();

        state
            .allocate_ip(
                &net,
                gateway,
                request(Ipv4Addr::new(10, 26, 0, 2), false),
                1,
            )
            .unwrap();
        state
            .allocate_ip(
                &net,
                gateway,
                request(Ipv4Addr::new(10, 26, 0, 3), false),
                2,
            )
            .unwrap();
        for id in [&dynamic_id, &static_id] {
            let entry = state.device_map.get_mut(id).unwrap();
            entry.is_connected = false;
            entry.disconnect_time = Some(SystemTime::UNIX_EPOCH);
        }
        state.device_map.get_mut(&static_id).unwrap().ip_type = DeviceIpType::Static;
        assert_eq!(state.full_sync_version, 0);

        let expired = state.collect_expired_devices(Duration::from_secs(1));
        assert_eq!(expired, vec![dynamic_id.clone()]);
        assert_eq!(state.remove_devices(&expired), vec![dynamic_id.clone()]);
        assert_eq!(state.full_sync_version, state.data_version);
        assert!(state.device_map.contains_key(&dynamic_id));
        assert_eq!(state.device_map.get(&dynamic_id).unwrap().ip, None);
        assert_eq!(
            state.device_map.get(&static_id).unwrap().ip,
            Some(Ipv4Addr::new(10, 26, 0, 3))
        );
    }
}
