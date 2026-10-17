use crate::protocol::control_message::RegRequestMsg;
use crate::server::control_server::db;
use crate::server::control_server::db::DeviceRecord;
use crate::server::control_server::db::{ClientType, DeviceIpType, Ikev2InputRoute};
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
use tokio::sync::mpsc::error::TrySendError;
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

#[derive(Clone)]
pub struct DeviceSender {
    inner: Arc<Mutex<DeviceSenderInner>>,
}

struct DeviceSenderInner {
    client_instance_id: Vec<u8>,
    links: HashMap<u64, DeviceLink>,
}

struct DeviceLink {
    sender: Sender<Bytes>,
    latency_ms: Option<u32>,
}

impl DeviceSender {
    fn new(client_instance_id: Vec<u8>, random_id: u64, sender: Sender<Bytes>) -> Self {
        let mut links = HashMap::new();
        links.insert(
            random_id,
            DeviceLink {
                sender,
                latency_ms: None,
            },
        );
        Self {
            inner: Arc::new(Mutex::new(DeviceSenderInner {
                client_instance_id,
                links,
            })),
        }
    }

    fn same_instance(&self, client_instance_id: &[u8]) -> bool {
        !client_instance_id.is_empty()
            && self.inner.lock().client_instance_id.as_slice() == client_instance_id
    }

    fn owns_link(&self, client_instance_id: &[u8], random_id: u64) -> bool {
        let inner = self.inner.lock();
        inner.client_instance_id.as_slice() == client_instance_id
            && inner.links.contains_key(&random_id)
    }

    fn add_link(&self, random_id: u64, sender: Sender<Bytes>) {
        self.inner.lock().links.insert(
            random_id,
            DeviceLink {
                sender,
                latency_ms: None,
            },
        );
    }

    fn remove_link(&self, client_instance_id: &[u8], random_id: u64) -> Option<bool> {
        let mut inner = self.inner.lock();
        if inner.client_instance_id.as_slice() != client_instance_id
            || inner.links.remove(&random_id).is_none()
        {
            return None;
        }
        Some(inner.links.is_empty())
    }

    fn update_latency(&self, random_id: u64, latency_ms: u32) -> bool {
        let mut inner = self.inner.lock();
        let Some(link) = inner.links.get_mut(&random_id) else {
            return false;
        };
        link.latency_ms = Some(latency_ms);
        true
    }

    fn best_latency(&self) -> Option<u32> {
        self.inner
            .lock()
            .links
            .values()
            .filter_map(|link| link.latency_ms)
            .min()
    }

    fn links_empty(&self) -> bool {
        self.inner.lock().links.is_empty()
    }

    pub fn try_send(&self, payload: Bytes) -> Result<(), TrySendError<Bytes>> {
        let mut links = self
            .inner
            .lock()
            .links
            .values()
            .map(|link| (link.latency_ms.unwrap_or(u32::MAX), link.sender.clone()))
            .collect::<Vec<_>>();
        links.sort_by_key(|(latency, _)| *latency);
        let mut last_error = None;
        for (_, sender) in links {
            match sender.try_send(payload.clone()) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(TrySendError::Closed(payload)))
    }

    pub fn try_send_all(&self, payload: Bytes) -> usize {
        self.inner
            .lock()
            .links
            .values()
            .filter(|link| link.sender.try_send(payload.clone()).is_ok())
            .count()
    }
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
    pub client_type: ClientType,
    pub ikev2_password: Option<String>,
    pub wireguard_private_key: Option<String>,
    pub wireguard_public_key: Option<String>,
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub random_id: u64,
    /// Last name reported by a running VNT client. The configured name remains
    /// in `device_name` and is never overwritten by registration or ACK data.
    pub runtime_device_name: Option<String>,
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
    pub ikev2_input_routes: Vec<Ikev2InputRoute>,
    pub wireguard_input_routes: Vec<Ikev2InputRoute>,
    pub wireguard_dns: Vec<Ipv4Addr>,
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

/// Formats timestamps for the management UI in the server's local time zone.
///
/// Timestamps remain stored and transmitted as Unix timestamps (UTC); only their
/// human-readable representation is localized.
pub fn format_system_time_local(time: SystemTime) -> String {
    use time::macros::format_description;
    use time::{OffsetDateTime, UtcOffset};

    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    let datetime: OffsetDateTime = time.into();
    let local_offset = UtcOffset::local_offset_at(datetime).unwrap_or(UtcOffset::UTC);
    datetime
        .to_offset(local_offset)
        .format(&format)
        .unwrap_or_default()
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
            client_type: record.client_type,
            ikev2_password: record.ikev2_password,
            wireguard_private_key: record.wireguard_private_key,
            wireguard_public_key: record.wireguard_public_key,
            allow_ikev2: false,
            allow_wireguard: false,
            random_id: 0,
            runtime_device_name: None,
            device_name: record.device_name,
            device_version: record.device_version,
            is_connected: false,
            last_connect_time: i64_to_system_time(record.last_connect_time),
            disconnect_time: Some(SystemTime::now()),
            data_version: 0,
            key_sign: None,
            latency_ms: None,
            traffic_stats,
            advertised_subnets: match record.client_type {
                ClientType::Ikev2 => record.ikev2_output_subnets,
                ClientType::Wireguard => record.wireguard_output_subnets,
                ClientType::Vnt => Vec::new(),
            },
            ikev2_input_routes: record.ikev2_input_routes,
            wireguard_input_routes: record.wireguard_input_routes,
            wireguard_dns: record.wireguard_dns,
            subnet_advertisement_active: false,
        }
    }

    pub fn to_record(&self, network_code: &str) -> DeviceRecord {
        DeviceRecord {
            device_id: self.device_id.clone(),
            network_code: network_code.to_string(),
            ip: self.ip.map(|ip| ip.to_string()),
            ip_type: self.ip_type,
            client_type: self.client_type,
            ikev2_password: self.ikev2_password.clone(),
            ikev2_output_subnets: if self.client_type == ClientType::Ikev2 {
                self.advertised_subnets.clone()
            } else {
                Vec::new()
            },
            ikev2_input_routes: if self.client_type == ClientType::Ikev2 {
                self.ikev2_input_routes.clone()
            } else {
                Vec::new()
            },
            wireguard_output_subnets: if self.client_type == ClientType::Wireguard {
                self.advertised_subnets.clone()
            } else {
                Vec::new()
            },
            wireguard_input_routes: if self.client_type == ClientType::Wireguard {
                self.wireguard_input_routes.clone()
            } else {
                Vec::new()
            },
            wireguard_dns: if self.client_type == ClientType::Wireguard {
                self.wireguard_dns.clone()
            } else {
                Vec::new()
            },
            wireguard_private_key: self.wireguard_private_key.clone(),
            wireguard_public_key: self.wireguard_public_key.clone(),
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
    sender_map: DashMap<Ipv4Addr, DeviceSender>,
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
    pub fn network_contains(&self, ip: Ipv4Addr) -> bool {
        self.net.contains(&ip)
    }

    pub fn sender_map(&self) -> &DashMap<Ipv4Addr, DeviceSender> {
        &self.sender_map
    }

    pub fn active_link_ip(
        &self,
        expected_ip: Ipv4Addr,
        client_instance_id: &[u8],
        random_id: u64,
    ) -> Option<Ipv4Addr> {
        if self
            .sender_map
            .get(&expected_ip)
            .is_some_and(|sender| sender.owns_link(client_instance_id, random_id))
        {
            return Some(expected_ip);
        }
        self.sender_map.iter().find_map(|sender| {
            sender
                .owns_link(client_instance_id, random_id)
                .then_some(*sender.key())
        })
    }

    pub fn first_available_ip_excluding(
        &self,
        excluded: &std::collections::HashSet<Ipv4Addr>,
    ) -> anyhow::Result<Ipv4Addr> {
        let guard = self.lease_state.lock();
        let start = u32::from(self.net.network())
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Invalid network address"))?;
        let end = u32::from(self.net.broadcast());
        for raw in start..end {
            let ip = Ipv4Addr::from(raw);
            if ip != self.gateway
                && !excluded.contains(&ip)
                && !guard.device_ip_map.contains_key(&ip)
                && !guard.active_ip_map.contains_key(&ip)
            {
                return Ok(ip);
            }
        }
        bail!("IP exhaustion");
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
        client_instance_id: &[u8],
    ) -> Option<DeviceRecord> {
        let sender = self.sender_map.get(&ip)?.clone();
        match sender.remove_link(client_instance_id, random_id) {
            None => return None,
            Some(false) => {
                if let Some(latency) = sender.best_latency() {
                    let mut guard = self.lease_state.lock();
                    if let Some(entry) = guard.device_map.get_mut(device_id) {
                        entry.latency_ms = Some(latency);
                    }
                }
                return None;
            }
            Some(true) => {}
        }
        self.finalize_offline(device_id, ip, sender)
    }

    /// remove_link 在 lease_state 锁外执行，期间新实例注册可能已替换 sender_map[ip]，
    /// 或同实例会话经快速路径向同一 pool 追加新链接；此时必须放弃本次离线标记，
    /// 否则会把仍在线的新会话误标为离线并清掉其转发映射与流量统计。
    fn finalize_offline(
        &self,
        device_id: &String,
        ip: Ipv4Addr,
        sender: DeviceSender,
    ) -> Option<DeviceRecord> {
        let mut guard = self.lease_state.lock();
        let pool_drained = self
            .sender_map
            .get(&ip)
            .is_some_and(|current| Arc::ptr_eq(&current.inner, &sender.inner))
            && sender.links_empty();
        if !pool_drained {
            log::info!(
                "skip offline, session superseded network_code={},device_id={device_id},ip={ip}",
                self.network_code,
            );
            return None;
        }
        let (success, record) = guard.offline_ip(&self.network_code, device_id, ip, None);
        if success {
            log::info!(
                "offline_ip network_code={},device_id={device_id},ip={ip}",
                self.network_code,
            );
            if self
                .sender_map
                .remove_if(&ip, |_, current| Arc::ptr_eq(&current.inner, &sender.inner))
                .is_some()
            {
                self.traffic_stats_map.remove(&ip);
            }

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

    /// 释放预注册但未确认的 IP，通过 random_id 避免误删其他会话。
    /// 会话断开与其余链接的注册可能并发：必须先把该会话的链接从 pool 中移除，
    /// 且 pool 已排空才允许释放，否则会删掉仍在线链接的注册信息。
    pub fn release_pre_registered_ip(
        &self,
        device_id: &String,
        ip: Ipv4Addr,
        random_id: u64,
        client_instance_id: &[u8],
    ) {
        let should_remove = {
            let mut guard = self.lease_state.lock();
            let pool_drained = self
                .sender_map
                .get(&ip)
                .map(|pool| pool.remove_link(client_instance_id, random_id) == Some(true))
                .unwrap_or(true);
            if let Some(device_entry) = guard.device_map.get(device_id) {
                if pool_drained
                    && device_entry.random_id == random_id
                    && device_entry.ip == Some(ip)
                {
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

    /// Applies runtime metadata reported by the authenticated managed session.
    /// Session identity and IP remain authoritative; the acknowledgement is
    /// never allowed to retarget another device.
    pub fn update_managed_runtime_metadata(
        &self,
        device_id: &str,
        device_name: &str,
        advertised_subnets: Vec<Ipv4Net>,
        allow_ikev2: bool,
        allow_wireguard: bool,
    ) -> Option<DeviceRecord> {
        let mut guard = self.lease_state.lock();
        let valid = guard
            .device_map
            .get(device_id)
            .is_some_and(|entry| entry.is_connected && entry.client_type == ClientType::Vnt);
        if !valid {
            return None;
        }
        guard.data_version += 1;
        let data_version = guard.data_version;
        let entry = guard.device_map.get_mut(device_id)?;
        if !device_name.is_empty() {
            entry.runtime_device_name = Some(device_name.to_string());
        }
        entry.advertised_subnets = advertised_subnets;
        entry.allow_ikev2 = allow_ikev2;
        entry.allow_wireguard = allow_wireguard;
        entry.data_version = data_version;
        Some(entry.to_record(&self.network_code))
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

    pub fn ikev2_credentials(&self) -> Vec<(String, String)> {
        self.lease_state
            .lock()
            .device_map
            .values()
            .filter_map(|entry| {
                (entry.client_type == ClientType::Ikev2)
                    .then(|| {
                        entry
                            .ikev2_password
                            .as_ref()
                            .map(|password| (entry.device_id.clone(), password.clone()))
                    })
                    .flatten()
            })
            .collect()
    }

    pub fn device_records_by_type(&self, client_type: ClientType) -> Vec<DeviceRecord> {
        let network_code = self.network_code();
        self.lease_state
            .lock()
            .device_map
            .values()
            .filter(|entry| entry.client_type == client_type)
            .map(|entry| entry.to_record(&network_code))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_device_config(
        &self,
        device_id: &str,
        device_name: String,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
        client_type: ClientType,
        ikev2_password: Option<String>,
        wireguard_private_key: Option<String>,
        wireguard_public_key: Option<String>,
        ikev2_output_subnets: Vec<Ipv4Net>,
        ikev2_input_routes: Vec<Ikev2InputRoute>,
        wireguard_output_subnets: Vec<Ipv4Net>,
        wireguard_input_routes: Vec<Ikev2InputRoute>,
        wireguard_dns: Vec<Ipv4Addr>,
    ) -> anyhow::Result<Option<DeviceEntry>> {
        let mut guard = self.lease_state.lock();
        guard.validate_ip_available(ip, Some(device_id))?;
        let previous = guard.device_map.get(device_id).cloned();
        let replaces_published_ip = previous
            .as_ref()
            .is_some_and(|entry| !entry.is_connected && entry.ip.is_some_and(|old| old != ip));
        let live_wireguard_route_change = previous.as_ref().is_some_and(|entry| {
            entry.is_connected
                && entry.client_type == ClientType::Wireguard
                && (entry.advertised_subnets != wireguard_output_subnets
                    || entry.wireguard_input_routes != wireguard_input_routes)
        });

        if let Some(old_ip) = previous.as_ref().and_then(|entry| entry.ip)
            && old_ip != ip
        {
            guard.device_ip_map.remove(&old_ip);
        }

        let publish_now = previous
            .as_ref()
            .map(|entry| !entry.is_connected)
            .unwrap_or(true)
            || live_wireguard_route_change;
        if publish_now {
            guard.data_version += 1;
            if replaces_published_ip || live_wireguard_route_change {
                guard.full_sync_version = guard.data_version;
            }
        }
        let data_version = previous
            .as_ref()
            .filter(|_| !publish_now)
            .map(|entry| entry.data_version)
            .unwrap_or(guard.data_version);
        if let Some(entry) = guard.device_map.get_mut(device_id) {
            entry.device_name = device_name;
            entry.ip = Some(ip);
            entry.ip_type = ip_type;
            entry.client_type = client_type;
            if ikev2_password.is_some() {
                entry.ikev2_password = ikev2_password;
            }
            if wireguard_private_key.is_some() {
                entry.wireguard_private_key = wireguard_private_key;
                entry.wireguard_public_key = wireguard_public_key;
            }
            entry.advertised_subnets = match client_type {
                ClientType::Ikev2 => ikev2_output_subnets,
                ClientType::Wireguard => wireguard_output_subnets,
                ClientType::Vnt => Vec::new(),
            };
            entry.ikev2_input_routes = ikev2_input_routes;
            entry.wireguard_input_routes = wireguard_input_routes;
            entry.wireguard_dns = wireguard_dns;
            entry.data_version = data_version;
        } else {
            guard.device_map.insert(
                device_id.to_string(),
                DeviceEntry {
                    device_id: device_id.to_string(),
                    ip: Some(ip),
                    ip_type,
                    client_type,
                    ikev2_password,
                    wireguard_private_key,
                    wireguard_public_key,
                    allow_ikev2: false,
                    allow_wireguard: false,
                    random_id: 0,
                    runtime_device_name: None,
                    device_name,
                    device_version: String::new(),
                    is_connected: false,
                    last_connect_time: SystemTime::now(),
                    disconnect_time: Some(SystemTime::now()),
                    data_version,
                    key_sign: None,
                    latency_ms: None,
                    traffic_stats: Arc::new(TrafficStats::new()),
                    advertised_subnets: match client_type {
                        ClientType::Ikev2 => ikev2_output_subnets,
                        ClientType::Wireguard => wireguard_output_subnets,
                        ClientType::Vnt => Vec::new(),
                    },
                    ikev2_input_routes,
                    wireguard_input_routes,
                    wireguard_dns,
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

    pub fn restore_device_record(&self, record: DeviceRecord) {
        let device_id = record.device_id.clone();
        self.restore_device_config(&device_id, Some(DeviceEntry::from_record(record)));
    }

    pub fn fast_register(
        &self,
        device_id: &str,
        old_ip: Ipv4Addr,
        new_ip: Ipv4Addr,
        random_id: u64,
        client_instance_id: &[u8],
    ) -> anyhow::Result<()> {
        let mut guard = self.lease_state.lock();
        let entry = guard
            .device_map
            .get(device_id)
            .ok_or_else(|| anyhow::anyhow!("设备不存在"))?;
        if !entry.is_connected {
            bail!("会话已失效");
        }
        if let Some(pool) = self.sender_map.get(&new_ip)
            && pool.owns_link(client_instance_id, random_id)
        {
            return Ok(());
        }
        // A managed client can switch a Dynamic or Static address after
        // receiving a configuration revision from another VNTS endpoint. In
        // that multi-server case this endpoint has no need to have observed
        // the management write first: the authenticated, live session is the
        // authority for its active address. Fixed addresses remain server
        // enforced and therefore cannot be changed by FastReg.
        if entry.ip_type == DeviceIpType::Fixed && entry.ip != Some(new_ip) {
            bail!("快速注册 IP 与设备设置的固定 IP 不一致");
        }
        if !self.net.contains(&new_ip)
            || new_ip == self.gateway
            || new_ip == self.net.network()
            || new_ip == self.net.broadcast()
        {
            bail!("快速注册 IP 不在可用虚拟网段内");
        }
        guard.validate_ip_available(new_ip, Some(device_id))?;
        if guard.active_ip_map.get(&old_ip).map(String::as_str) != Some(device_id) {
            bail!("当前会话 IP 不匹配");
        }

        let sender = self
            .sender_map
            .get(&old_ip)
            .filter(|value| value.owns_link(client_instance_id, random_id))
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
        let configured_ip = guard.device_map.get(device_id).and_then(|entry| entry.ip);
        if configured_ip != Some(new_ip) {
            if let Some(configured_ip) = configured_ip {
                guard.device_ip_map.remove(&configured_ip);
            }
            guard.device_ip_map.insert(new_ip, device_id.to_string());
        }
        if let Some(entry) = guard.device_map.get_mut(device_id) {
            entry.ip = Some(new_ip);
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

    pub fn active_advertised_subnets(&self, ip: Ipv4Addr) -> Option<Vec<Ipv4Net>> {
        self.get_device_entry_by_ip(ip)
            .filter(|entry| entry.is_connected && entry.subnet_advertisement_active)
            .map(|entry| entry.advertised_subnets)
    }

    pub fn ikev2_input_target(&self, device_id: &str, destination: Ipv4Addr) -> Option<Ipv4Addr> {
        self.get_device_entry(device_id)?
            .ikev2_input_routes
            .into_iter()
            .filter(|route| route.subnet.contains(&destination))
            .max_by_key(|route| route.subnet.prefix_len())
            .map(|route| route.target_ip)
    }

    pub fn wireguard_input_target(
        &self,
        device_id: &str,
        destination: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        self.get_device_entry(device_id)?
            .wireguard_input_routes
            .into_iter()
            .filter(|route| route.subnet.contains(&destination))
            .max_by_key(|route| route.subnet.prefix_len())
            .map(|route| route.target_ip)
    }

    /// 返回 (分配的IP, 旧IP, DeviceEntry克隆)
    pub fn allocate_ip_and_get_entry_as(
        &self,
        reg_req: RegRequestMsg,
        random_id: u64,
        sender: Sender<Bytes>,
        client_type: ClientType,
        client_instance_id: Vec<u8>,
    ) -> anyhow::Result<(Ipv4Addr, Option<Ipv4Addr>, Option<DeviceEntry>)> {
        let mut guard = self.lease_state.lock();
        if !client_instance_id.is_empty()
            && let Some(existing) = guard.device_map.get(&reg_req.device_id).cloned()
            && let Some(ip) = existing.ip
            && reg_req.ip == Some(ip)
            && let Some(pool) = self.sender_map.get(&ip)
            && pool.same_instance(&client_instance_id)
        {
            pool.add_link(random_id, sender);
            return Ok((ip, None, Some(existing)));
        }
        let (ip, old_ip) = guard.allocate_ip_as(
            &self.net,
            self.gateway,
            reg_req.clone(),
            random_id,
            client_type,
        )?;

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
        self.sender_map
            .insert(ip, DeviceSender::new(client_instance_id, random_id, sender));
        guard.active_ip_map.insert(ip, reg_req.device_id.clone());

        if let Some(entry) = &entry {
            self.traffic_stats_map
                .insert(ip, entry.traffic_stats.clone());
        }

        Ok((ip, old_ip, entry))
    }

    #[cfg(test)]
    pub fn allocate_ip_and_get_entry(
        &self,
        reg_req: RegRequestMsg,
        random_id: u64,
        sender: Sender<Bytes>,
    ) -> anyhow::Result<(Ipv4Addr, Option<Ipv4Addr>, Option<DeviceEntry>)> {
        self.allocate_ip_and_get_entry_as(reg_req, random_id, sender, ClientType::Vnt, Vec::new())
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
        let guard = self.lease_state.lock();
        let mut list = Vec::new();
        let active_ips: HashMap<&str, Ipv4Addr> = guard
            .active_ip_map
            .iter()
            .map(|(ip, device_id)| (device_id.as_str(), *ip))
            .collect();

        for entry in guard.device_map.values() {
            list.push(crate::server::control_server::service::DeviceInfoVO {
                device_id: entry.device_id.clone(),
                device_name: entry.device_name.clone(),
                current_device_name: entry.is_connected.then(|| {
                    entry
                        .runtime_device_name
                        .as_deref()
                        .unwrap_or(&entry.device_name)
                        .to_string()
                }),
                device_version: entry.device_version.clone(),
                ip: entry.ip,
                current_ip: active_ips.get(entry.device_id.as_str()).copied(),
                ip_type: Some(entry.ip_type),
                status: if entry.is_connected {
                    "Online".to_string()
                } else {
                    "Offline".to_string()
                },
                last_connect_time: format_system_time_local(entry.last_connect_time),
                disconnect_time: entry.disconnect_time.map(format_system_time_local),
                latency_ms: entry.latency_ms,
                server_addr: None,
                advertised_subnets: if entry.subnet_advertisement_active {
                    entry.advertised_subnets.clone()
                } else {
                    Vec::new()
                },
                ikev2_output_subnets: if entry.client_type == ClientType::Ikev2 {
                    entry.advertised_subnets.clone()
                } else {
                    Vec::new()
                },
                ikev2_input_routes: if entry.client_type == ClientType::Ikev2 {
                    entry.ikev2_input_routes.clone()
                } else {
                    Vec::new()
                },
                wireguard_output_subnets: if entry.client_type == ClientType::Wireguard {
                    entry.advertised_subnets.clone()
                } else {
                    Vec::new()
                },
                wireguard_input_routes: if entry.client_type == ClientType::Wireguard {
                    entry.wireguard_input_routes.clone()
                } else {
                    Vec::new()
                },
                wireguard_dns: if entry.client_type == ClientType::Wireguard {
                    entry.wireguard_dns.clone()
                } else {
                    Vec::new()
                },
                tx_bytes: entry.traffic_stats.get_tx(),
                rx_bytes: entry.traffic_stats.get_rx(),
                client_type: entry.client_type,
                managed: false,
                relay_online: entry.is_connected,
                subscription_online: false,
                subscription_issued: false,
                subscription_target_revision: None,
                subscription_applied_revision: None,
                subscription_status: None,
                subscription_error: None,
            });
        }
        list
    }

    pub fn changed_client_simple_list(
        &self,
        exclude_ip: Ipv4Addr,
        data_version: u64,
        allow_ikev2: bool,
        allow_wireguard: bool,
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
                .filter(|v| {
                    v.ip.is_some()
                        && v.ip != Some(exclude_ip)
                        && (allow_ikev2 || v.client_type != ClientType::Ikev2)
                        && (allow_wireguard || v.client_type != ClientType::Wireguard)
                })
                .map(|v| ClientSimpleInfo {
                    ip: v.ip.unwrap(),
                    online: v.is_connected,
                    client_type: match v.client_type {
                        ClientType::Vnt => crate::protocol::control_message::ClientType::Vnt,
                        ClientType::Ikev2 => crate::protocol::control_message::ClientType::Ikev2,
                        ClientType::Wireguard => {
                            crate::protocol::control_message::ClientType::Wireguard
                        }
                    },
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
            .filter(|v| {
                v.data_version > data_version
                    && v.ip.is_some()
                    && v.ip != Some(exclude_ip)
                    && (allow_ikev2 || v.client_type != ClientType::Ikev2)
                    && (allow_wireguard || v.client_type != ClientType::Wireguard)
            })
            .map(|v| ClientSimpleInfo {
                ip: v.ip.unwrap(),
                online: v.is_connected,
                client_type: match v.client_type {
                    ClientType::Vnt => crate::protocol::control_message::ClientType::Vnt,
                    ClientType::Ikev2 => crate::protocol::control_message::ClientType::Ikev2,
                    ClientType::Wireguard => {
                        crate::protocol::control_message::ClientType::Wireguard
                    }
                },
            })
            .collect();
        Some(crate::protocol::control_message::ClientSimpleInfoList {
            data_version: guard.data_version,
            list,
            is_all: false,
            time: 0,
        })
    }

    pub fn full_client_simple_list(
        &self,
        exclude_ip: Ipv4Addr,
        allow_ikev2: bool,
        allow_wireguard: bool,
    ) -> crate::protocol::control_message::ClientSimpleInfoList {
        let guard = self.lease_state.lock();
        let list = guard
            .device_map
            .values()
            .filter(|entry| {
                entry.ip.is_some()
                    && entry.ip != Some(exclude_ip)
                    && (allow_ikev2 || entry.client_type != ClientType::Ikev2)
                    && (allow_wireguard || entry.client_type != ClientType::Wireguard)
            })
            .map(|entry| crate::protocol::control_message::ClientSimpleInfo {
                ip: entry.ip.unwrap(),
                online: entry.is_connected,
                client_type: match entry.client_type {
                    ClientType::Vnt => crate::protocol::control_message::ClientType::Vnt,
                    ClientType::Ikev2 => crate::protocol::control_message::ClientType::Ikev2,
                    ClientType::Wireguard => {
                        crate::protocol::control_message::ClientType::Wireguard
                    }
                },
            })
            .collect();
        crate::protocol::control_message::ClientSimpleInfoList {
            data_version: guard.data_version,
            list,
            is_all: true,
            time: 0,
        }
    }

    pub fn client_info_list(
        &self,
        exclude_ip: Ipv4Addr,
        allow_ikev2: bool,
        allow_wireguard: bool,
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
            if (entry.client_type == ClientType::Ikev2 && !allow_ikev2)
                || (entry.client_type == ClientType::Wireguard && !allow_wireguard)
            {
                continue;
            }
            let last_connect_time: OffsetDateTime = entry.last_connect_time.into();
            list.push(ClientInfo {
                name: entry
                    .runtime_device_name
                    .as_ref()
                    .unwrap_or(&entry.device_name)
                    .clone(),
                version: entry.device_version.clone(),
                ip: ip.into(),
                key_sign: entry.key_sign.clone(),
                online: entry.is_connected,
                last_connected_time: last_connect_time.unix_timestamp(),
                id: entry.device_id.clone(),
                client_type: match entry.client_type {
                    ClientType::Vnt => crate::protocol::rpc_message::ClientType::Vnt as i32,
                    ClientType::Ikev2 => crate::protocol::rpc_message::ClientType::Ikev2 as i32,
                    ClientType::Wireguard => {
                        crate::protocol::rpc_message::ClientType::Wireguard as i32
                    }
                },
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
        random_id: Option<u64>,
    ) -> (bool, Option<DeviceRecord>) {
        let Some(device_entry) = self.device_map.get_mut(device_id) else {
            log::error!("unknown device_id {}", device_id);
            return (false, None);
        };
        if random_id.is_some_and(|random_id| device_entry.random_id != random_id) {
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

    fn allocate_ip_as(
        &mut self,
        net: &Ipv4Net,
        gateway: Ipv4Addr,
        reg_req: RegRequestMsg,
        random_id: u64,
        client_type: ClientType,
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
            device_entry.client_type = client_type;
            device_entry.allow_ikev2 = reg_req.allow_ikev2;
            device_entry.allow_wireguard = reg_req.allow_wireguard;
            if client_type == ClientType::Vnt {
                device_entry.runtime_device_name = Some(reg_req.name.clone());
            } else {
                device_entry.device_name = reg_req.name.clone();
            }
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
                    if client_type == ClientType::Vnt {
                        entry.runtime_device_name = Some(reg_req.name);
                    } else {
                        entry.device_name = reg_req.name;
                    }
                    entry.device_version = reg_req.version;
                    entry.is_connected = true;
                    entry.last_connect_time = SystemTime::now();
                    entry.disconnect_time = None;
                    entry.data_version = self.data_version;
                    entry.key_sign = reg_req.key_sign;
                    entry.client_type = client_type;
                    entry.allow_ikev2 = reg_req.allow_ikev2;
                    entry.allow_wireguard = reg_req.allow_wireguard;
                    entry.latency_ms = None;
                    entry.advertised_subnets = advertised_subnets.clone();
                    entry.subnet_advertisement_active = subnet_advertisement_active;
                    entry
                } else {
                    DeviceEntry {
                        device_id: reg_req.device_id,
                        ip: Some(ip),
                        ip_type: DeviceIpType::Dynamic,
                        client_type,
                        ikev2_password: None,
                        wireguard_private_key: None,
                        wireguard_public_key: None,
                        allow_ikev2: reg_req.allow_ikev2,
                        allow_wireguard: reg_req.allow_wireguard,
                        random_id,
                        runtime_device_name: (client_type == ClientType::Vnt)
                            .then(|| reg_req.name.clone()),
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
                ikev2_input_routes: Vec::new(),
                wireguard_input_routes: Vec::new(),
                wireguard_dns: Vec::new(),
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
            if client_type == ClientType::Vnt {
                entry.runtime_device_name = Some(reg_req.name);
            } else {
                entry.device_name = reg_req.name;
            }
            entry.device_version = reg_req.version;
            entry.is_connected = true;
            entry.last_connect_time = SystemTime::now();
            entry.disconnect_time = None;
            entry.data_version = self.data_version;
            entry.key_sign = reg_req.key_sign;
            entry.client_type = client_type;
            entry.allow_ikev2 = reg_req.allow_ikev2;
            entry.allow_wireguard = reg_req.allow_wireguard;
            entry.latency_ms = None;
            entry.advertised_subnets = advertised_subnets.clone();
            entry.subnet_advertisement_active = subnet_advertisement_active;
            entry
        } else {
            DeviceEntry {
                device_id: reg_req.device_id,
                ip: Some(ip),
                ip_type: DeviceIpType::Dynamic,
                client_type,
                ikev2_password: None,
                wireguard_private_key: None,
                wireguard_public_key: None,
                allow_ikev2: reg_req.allow_ikev2,
                allow_wireguard: reg_req.allow_wireguard,
                random_id,
                runtime_device_name: (client_type == ClientType::Vnt).then(|| reg_req.name.clone()),
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
                ikev2_input_routes: Vec::new(),
                wireguard_input_routes: Vec::new(),
                wireguard_dns: Vec::new(),
                subnet_advertisement_active,
            }
        };
        self.add_device(entry);
        Ok((ip, old))
    }

    #[cfg(test)]
    fn allocate_ip(
        &mut self,
        net: &Ipv4Net,
        gateway: Ipv4Addr,
        reg_req: RegRequestMsg,
        random_id: u64,
    ) -> anyhow::Result<(Ipv4Addr, Option<Ipv4Addr>)> {
        self.allocate_ip_as(net, gateway, reg_req, random_id, ClientType::Vnt)
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

    pub fn update_client_latency(&self, ip: Ipv4Addr, random_id: u64, latency_ms: u32) {
        let Some(sender) = self.sender_map.get(&ip).map(|sender| sender.clone()) else {
            return;
        };
        if !sender.update_latency(random_id, latency_ms) {
            return;
        }
        let latency_ms = sender.best_latency().unwrap_or(latency_ms);
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

    pub fn update_client_latency(
        &self,
        network_code: &str,
        ip: Ipv4Addr,
        random_id: u64,
        latency_ms: u32,
    ) {
        if let Some(state) = self.get_network_state(network_code) {
            state.update_client_latency(ip, random_id, latency_ms);
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
    use super::{DeviceSender, NetworkState, NetworkStateInner};
    use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
    use crate::server::control_server::db::{ClientType, DeviceIpType};
    use bytes::Bytes;
    use ipnet::Ipv4Net;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};
    use tokio::sync::mpsc;
    use tokio::time::Instant;

    #[tokio::test]
    async fn device_sender_falls_back_when_the_lowest_latency_link_is_closed() {
        let (fallback_sender, mut fallback_receiver) = mpsc::channel(1);
        let (preferred_sender, mut preferred_receiver) = mpsc::channel(1);
        let sender = DeviceSender::new(vec![1; 32], 1, fallback_sender);
        sender.add_link(2, preferred_sender);
        assert!(sender.update_latency(1, 20));
        assert!(sender.update_latency(2, 5));

        sender.try_send(Bytes::from_static(b"preferred")).unwrap();
        assert_eq!(
            preferred_receiver.recv().await,
            Some(Bytes::from_static(b"preferred"))
        );
        assert!(fallback_receiver.try_recv().is_err());
        drop(preferred_receiver);

        sender.try_send(Bytes::from_static(b"fallback")).unwrap();
        assert_eq!(
            fallback_receiver.recv().await,
            Some(Bytes::from_static(b"fallback"))
        );
    }

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
            allow_ikev2: false,
            allow_wireguard: false,
            subscription: None,
            client_instance_id: Vec::new(),
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

    fn outer_state() -> NetworkState {
        NetworkState {
            time: Mutex::new(Instant::now()),
            network_code: "test-net".to_string(),
            gateway: Ipv4Addr::new(10, 26, 0, 1),
            net: "10.26.0.0/24".parse().unwrap(),
            lease_duration: Duration::from_secs(60),
            sender_map: Default::default(),
            lease_state: Mutex::new(empty_state()),
            traffic_stats_map: Default::default(),
        }
    }

    async fn register(
        state: &NetworkState,
        ip: Ipv4Addr,
        instance: u8,
        random_id: u64,
    ) -> tokio::sync::mpsc::Receiver<Bytes> {
        let (tx, rx) = mpsc::channel(1);
        let mut req = request(ip, false);
        req.client_instance_id = vec![instance; 32];
        state
            .allocate_ip_and_get_entry_as(req, random_id, tx, ClientType::Vnt, vec![instance; 32])
            .unwrap();
        rx
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

        let (removed, _) = state.offline_ip("test-net", &format!("device-{ip}"), ip, Some(1));
        assert!(!removed);
        assert!(
            state
                .device_map
                .get(&format!("device-{ip}"))
                .unwrap()
                .is_connected
        );
    }

    // 复现旧会话断开与新实例注册的竞态：remove_link 成功后、拿到 lease_state
    // 锁之前，新实例已完成注册并替换 sender_map[ip]，此时不得标记离线。
    #[tokio::test]
    async fn superseded_session_cannot_mark_newer_session_offline() {
        let state = outer_state();
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        let device_id = format!("device-{ip}");

        let _rx = register(&state, ip, 1, 11).await;
        let stale_pool = state.sender_map.get(&ip).unwrap().clone();
        let _rx_new = register(&state, ip, 2, 22).await;

        assert_eq!(stale_pool.remove_link(&[1; 32], 11), Some(true));
        assert!(state.finalize_offline(&device_id, ip, stale_pool).is_none());

        assert!(state.is_device_online(&device_id));
        let guard = state.lease_state.lock();
        assert_eq!(guard.active_ip_map.get(&ip), Some(&device_id));
        drop(guard);
        assert!(state.sender_map.get(&ip).unwrap().same_instance(&[2; 32]));
        assert!(state.traffic_stats_map.get(&ip).is_some());
    }

    // 同实例最后一个链接断开后、收尾加锁前，快速路径又注册了新链接：
    // pool 未排空，不得标记离线，新链接必须保留。
    #[tokio::test]
    async fn link_added_during_disconnect_window_keeps_device_online() {
        let state = outer_state();
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        let device_id = format!("device-{ip}");

        let _rx = register(&state, ip, 1, 11).await;
        let pool = state.sender_map.get(&ip).unwrap().clone();
        assert_eq!(pool.remove_link(&[1; 32], 11), Some(true));
        let _rx_new = register(&state, ip, 1, 33).await;

        assert!(state.finalize_offline(&device_id, ip, pool).is_none());
        assert!(state.is_device_online(&device_id));
        assert!(state.sender_map.get(&ip).unwrap().owns_link(&[1; 32], 33));
    }

    #[tokio::test]
    async fn last_link_offline_still_tears_down_session() {
        let state = outer_state();
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        let device_id = format!("device-{ip}");

        let _rx = register(&state, ip, 1, 11).await;
        state.record_tx_traffic(ip, 100);

        let record = state.offline_ip(&device_id, ip, 11, &[1; 32]);
        assert!(record.is_some());
        assert!(!state.is_device_online(&device_id));
        assert!(state.sender_map.get(&ip).is_none());
        assert!(state.traffic_stats_map.get(&ip).is_none());
        let guard = state.lease_state.lock();
        assert!(!guard.active_ip_map.contains_key(&ip));
    }

    #[test]
    fn managed_registration_updates_runtime_name_without_overwriting_configured_name() {
        let net = "10.26.0.0/24".parse::<Ipv4Net>().unwrap();
        let gateway = Ipv4Addr::new(10, 26, 0, 1);
        let ip = Ipv4Addr::new(10, 26, 0, 2);
        let device_id = format!("device-{ip}");
        let mut state = empty_state();
        state
            .allocate_ip(&net, gateway, request(ip, false), 1)
            .unwrap();
        state.device_map.get_mut(&device_id).unwrap().device_name = "configured".to_string();

        let mut registration = request(ip, false);
        registration.name = "runtime-name".to_string();
        state.allocate_ip(&net, gateway, registration, 2).unwrap();

        let entry = state.device_map.get(&device_id).unwrap();
        assert_eq!(entry.device_name, "configured");
        assert_eq!(entry.runtime_device_name.as_deref(), Some("runtime-name"));
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
