use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use toml_edit::DocumentMut;
use uuid::Uuid;

use crate::utils::config::ClientAccessConfig;

pub const SUBSCRIPTION_PREFIX: &str = "vnt2://join/2/";
/// 下限对齐客户端 P2P 栈（rustp2p-core IpStack）的 IPv6 MTU 要求：
/// 低于 1280 的配置能让客户端热应用，但会让后续实例创建失败
pub const MIN_MTU: u16 = 1280;
pub const MAX_MTU: u16 = 1500;

/// 生成设备唯一的订阅接入 ID（UUID v4）。创建设备时赋值；编辑时若为空则补赋。
pub fn new_join_id() -> String {
    Uuid::new_v4().to_string()
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionPayloadV2 {
    pub v: u8,
    pub server: String,
    pub cert_mode: String,
    pub join_id: String,
    pub credential_key: String,
}

#[derive(Clone)]
pub struct IssuedSubscription {
    pub subscription: String,
    pub credential_key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagedClientConfigForm {
    #[serde(default)]
    pub current_server: String,
    #[serde(default)]
    pub other_servers: Vec<String>,
    #[serde(default = "default_form_cert_mode")]
    pub cert_mode: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub peer_address: Vec<String>,
    #[serde(default)]
    pub turn: Vec<String>,
    #[serde(default)]
    pub punch_model: Vec<String>,
    #[serde(default)]
    pub device_mode: String,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub tun_name: String,
    #[serde(default)]
    pub outbound_interface: String,
    #[serde(default)]
    pub input: Vec<String>,
    #[serde(default)]
    pub output: Vec<String>,
    #[serde(default)]
    pub port_mapping: Vec<String>,
    #[serde(default)]
    pub subnet_mapping: Vec<String>,
    #[serde(default)]
    pub udp_stun: Vec<String>,
    #[serde(default)]
    pub tcp_stun: Vec<String>,
    #[serde(default)]
    pub tunnel_addr: Vec<String>,
    pub tunnel_port: Option<u16>,
    pub ctrl_port: Option<u16>,
    #[serde(default)]
    pub no_punch: Option<bool>,
    #[serde(default)]
    pub no_broadcast: Option<bool>,
    #[serde(default)]
    pub allow_ikev2: Option<bool>,
    #[serde(default)]
    pub allow_wireguard: Option<bool>,
    #[serde(default)]
    pub compress: Option<bool>,
    #[serde(default)]
    pub rtx: Option<bool>,
    #[serde(default)]
    pub fec: Option<bool>,
    #[serde(default)]
    pub auto_sync_subnet: Option<bool>,
    #[serde(default)]
    pub no_nat: Option<bool>,
    #[serde(default)]
    pub allow_mapping: Option<bool>,
}

fn default_form_cert_mode() -> String {
    "finger".to_string()
}

impl ManagedClientConfigForm {
    pub fn servers(&self) -> Vec<String> {
        std::iter::once(self.current_server.clone())
            .chain(self.other_servers.iter().cloned())
            .collect()
    }

    pub fn from_toml(source: &str) -> anyhow::Result<Self> {
        let table: toml::Table = toml::from_str(source)?;
        let string = |key: &str| {
            table
                .get(key)
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let strings = |key: &str| {
            table
                .get(key)
                .and_then(toml::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let boolean = |key: &str| table.get(key).and_then(toml::Value::as_bool);
        let cert_mode = string("cert_mode");
        let servers = strings("server");
        let current_server = servers.first().cloned().unwrap_or_default();
        Ok(Self {
            current_server,
            other_servers: servers.into_iter().skip(1).collect(),
            cert_mode: if cert_mode.starts_with("finger:") {
                "finger".to_string()
            } else if cert_mode.is_empty() {
                default_form_cert_mode()
            } else {
                cert_mode
            },
            password: string("password"),
            peer_address: strings("peer_address"),
            turn: strings("turn"),
            punch_model: strings("punch_model"),
            device_mode: string("device_mode"),
            mtu: table
                .get("mtu")
                .and_then(toml::Value::as_integer)
                .and_then(|v| u16::try_from(v).ok()),
            tun_name: string("tun_name"),
            outbound_interface: string("outbound_interface"),
            input: strings("input"),
            output: strings("output"),
            port_mapping: strings("port_mapping"),
            subnet_mapping: strings("subnet_mapping"),
            udp_stun: strings("udp_stun"),
            tcp_stun: strings("tcp_stun"),
            tunnel_addr: strings("tunnel_addr"),
            tunnel_port: table
                .get("tunnel_port")
                .and_then(toml::Value::as_integer)
                .and_then(|v| u16::try_from(v).ok()),
            ctrl_port: table
                .get("ctrl_port")
                .and_then(toml::Value::as_integer)
                .and_then(|v| u16::try_from(v).ok()),
            no_punch: boolean("no_punch"),
            no_broadcast: boolean("no_broadcast"),
            allow_ikev2: boolean("allow_ikev2"),
            allow_wireguard: boolean("allow_wireguard"),
            compress: boolean("compress"),
            rtx: boolean("rtx"),
            fec: boolean("fec"),
            auto_sync_subnet: boolean("auto_sync_subnet"),
            no_nat: boolean("no_nat"),
            allow_mapping: boolean("allow_mapping"),
        })
    }

    pub fn merge_into_toml(&self, source: &str) -> anyhow::Result<String> {
        let mut table: toml::Table = if source.trim().is_empty() {
            Default::default()
        } else {
            toml::from_str(source)?
        };
        const EDITABLE: &[&str] = &[
            "password",
            "peer_address",
            "turn",
            "punch_model",
            "device_mode",
            "mtu",
            "tun_name",
            "outbound_interface",
            "input",
            "output",
            "port_mapping",
            "subnet_mapping",
            "udp_stun",
            "tcp_stun",
            "tunnel_addr",
            "tunnel_port",
            "ctrl_port",
            "no_punch",
            "no_broadcast",
            "allow_ikev2",
            "allow_wireguard",
            "compress",
            "rtx",
            "fec",
            "auto_sync_subnet",
            "no_nat",
            "allow_mapping",
        ];
        for key in EDITABLE {
            table.remove(*key);
        }
        let put_string = |table: &mut toml::Table, key: &str, value: &str| {
            if !value.trim().is_empty() {
                table.insert(
                    key.to_string(),
                    toml::Value::String(value.trim().to_string()),
                );
            }
        };
        put_string(&mut table, "password", &self.password);
        if !self.device_mode.is_empty() {
            if !matches!(self.device_mode.as_str(), "tun" | "tap" | "no") {
                anyhow::bail!("运行模式只能是 tun、tap 或 no");
            }
            put_string(&mut table, "device_mode", &self.device_mode);
        }
        if let Some(mtu) = self.mtu {
            if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
                anyhow::bail!("mtu 必须是 {MIN_MTU} 到 {MAX_MTU} 的整数");
            }
            table.insert("mtu".to_string(), toml::Value::Integer(i64::from(mtu)));
        }
        put_string(&mut table, "tun_name", &self.tun_name);
        put_string(&mut table, "outbound_interface", &self.outbound_interface);
        for (key, values) in [
            ("peer_address", &self.peer_address),
            ("turn", &self.turn),
            ("punch_model", &self.punch_model),
            ("input", &self.input),
            ("output", &self.output),
            ("port_mapping", &self.port_mapping),
            ("subnet_mapping", &self.subnet_mapping),
            ("udp_stun", &self.udp_stun),
            ("tcp_stun", &self.tcp_stun),
            ("tunnel_addr", &self.tunnel_addr),
        ] {
            let values: Vec<_> = values
                .iter()
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .map(|v| toml::Value::String(v.to_string()))
                .collect();
            if !values.is_empty() {
                table.insert(key.to_string(), toml::Value::Array(values));
            }
        }
        if !self.tunnel_addr.is_empty() && self.tunnel_port.is_some() {
            anyhow::bail!("tunnel_addr 和 tunnel_port 不能同时配置");
        }
        if let Some(value) = self.tunnel_port {
            table.insert(
                "tunnel_port".to_string(),
                toml::Value::Integer(i64::from(value)),
            );
        }
        if let Some(value) = self.ctrl_port {
            table.insert(
                "ctrl_port".to_string(),
                toml::Value::Integer(i64::from(value)),
            );
        }
        for (key, enabled) in [
            ("no_punch", self.no_punch),
            ("no_broadcast", self.no_broadcast),
            ("allow_ikev2", self.allow_ikev2),
            ("allow_wireguard", self.allow_wireguard),
            ("compress", self.compress),
            ("rtx", self.rtx),
            ("fec", self.fec),
            ("auto_sync_subnet", self.auto_sync_subnet),
            ("no_nat", self.no_nat),
            ("allow_mapping", self.allow_mapping),
        ] {
            if let Some(enabled) = enabled {
                table.insert(key.to_string(), toml::Value::Boolean(enabled));
            }
        }
        Ok(toml::to_string_pretty(&table)?)
    }
}

pub fn issue_subscription(
    access: &ClientAccessConfig,
    certificate_fingerprint: Option<&str>,
    join_id: &str,
) -> anyhow::Result<IssuedSubscription> {
    access.validate()?;
    let cert_mode = resolve_cert_mode(certificate_fingerprint)?;

    let mut random = [0_u8; 32];
    rand::rng().fill(&mut random);
    let credential_key = sha256(&random);
    let credential_key = URL_SAFE_NO_PAD.encode(credential_key);
    let payload = SubscriptionPayloadV2 {
        v: 2,
        server: access.effective_subscription_server(),
        cert_mode,
        join_id: join_id.to_string(),
        credential_key: credential_key.clone(),
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    Ok(IssuedSubscription {
        subscription: format!("{SUBSCRIPTION_PREFIX}{encoded}"),
        credential_key,
    })
}

pub fn client_proof(credential_key: &[u8], client_nonce: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(credential_key);
    digest.update([0x01]);
    digest.update(client_nonce);
    digest.finalize().to_vec()
}

pub fn server_proof(credential_key: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(credential_key);
    digest.update([0x02]);
    digest.update(client_nonce);
    digest.update(server_nonce);
    digest.finalize().to_vec()
}

pub fn resolve_cert_mode(certificate_fingerprint: Option<&str>) -> anyhow::Result<String> {
    let fingerprint = certificate_fingerprint
        .filter(|value| value.len() == 64)
        .ok_or_else(|| anyhow::anyhow!("无法取得服务端证书 SHA-256 指纹"))?;
    Ok(format!("finger:{}", fingerprint.to_ascii_lowercase()))
}

/// Only transport policy is meaningful for remote connection groups.
pub fn validate_remote_advanced_config(source: &str) -> anyhow::Result<()> {
    let table: toml::Table = toml::from_str(source)?;
    for key in table.keys() {
        anyhow::ensure!(
            [
                "password",
                "peer_address",
                "turn",
                "punch_model",
                "outbound_interface",
                "udp_stun",
                "tcp_stun",
                "tunnel_addr",
                "tunnel_port",
                "no_punch",
                "compress",
                "rtx",
                "fec"
            ]
            .contains(&key.as_str()),
            "远程连接组不支持配置 {key}"
        );
    }
    for key in ["turn", "punch_model"] {
        for rule in table
            .get(key)
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let rule = rule
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("{key} 必须是字符串数组"))?;
            let mut parts = rule.split(',').map(str::trim);
            parts
                .next()
                .unwrap_or_default()
                .parse::<crate::connection_id::ConnectionId>()?;
            let rest = parts.collect::<Vec<_>>();
            anyhow::ensure!(!rest.is_empty(), "{key} 缺少规则参数");
            if key == "turn" {
                anyhow::ensure!(rest.len() == 1, "turn 格式为目标连接ID,中继连接ID");
                rest[0].parse::<crate::connection_id::ConnectionId>()?;
            } else {
                for mode in rest {
                    let normalized = mode.to_ascii_lowercase().replace(['-', '_'], "");
                    anyhow::ensure!(
                        ["ipv4tcp", "ipv4udp", "ipv6tcp", "ipv6udp"].contains(&normalized.as_str()),
                        "无效的打洞模式 {mode}"
                    );
                }
            }
        }
    }
    validate_managed_advanced_config(source)
}

pub fn validate_managed_advanced_config(source: &str) -> anyhow::Result<()> {
    let table: toml::Table = if source.trim().is_empty() {
        Default::default()
    } else {
        toml::from_str(source).map_err(|error| anyhow::anyhow!("高级配置 TOML 无效: {error}"))?
    };
    for field in ["server", "cert_mode", "device_name", "ip"] {
        if table.contains_key(field) {
            anyhow::bail!("{field} 由设备基础配置管理，不能写入高级配置");
        }
    }
    for field in ["subscription", "event_script", "no_tun", "config_name"] {
        if table.contains_key(field) {
            anyhow::bail!("{field} 不支持服务端下发");
        }
    }
    if let Some(mode) = table.get("device_mode") {
        let mode = mode
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("device_mode 必须是字符串"))?;
        if !matches!(mode, "tun" | "tap" | "no") {
            anyhow::bail!("device_mode 只能是 tun、tap 或 no");
        }
    }
    if table.contains_key("tunnel_addr") && table.contains_key("tunnel_port") {
        anyhow::bail!("tunnel_addr 和 tunnel_port 不能同时配置");
    }
    for field in [
        "peer_address",
        "turn",
        "punch_model",
        "input",
        "subnet_mapping",
        "output",
        "port_mapping",
        "udp_stun",
        "tcp_stun",
        "tunnel_addr",
    ] {
        if let Some(value) = table.get(field) {
            let values = value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("{field} 必须是字符串数组"))?;
            if values.iter().any(|value| value.as_str().is_none()) {
                anyhow::bail!("{field} 必须是字符串数组");
            }
        }
    }
    for field in [
        "no_punch",
        "no_broadcast",
        "allow_ikev2",
        "allow_wireguard",
        "rtx",
        "compress",
        "fec",
        "auto_sync_subnet",
        "no_nat",
        "allow_mapping",
    ] {
        if table
            .get(field)
            .is_some_and(|value| value.as_bool().is_none())
        {
            anyhow::bail!("{field} 必须是布尔值");
        }
    }
    if let Some(value) = table.get("mtu") {
        let value = value
            .as_integer()
            .ok_or_else(|| anyhow::anyhow!("mtu 必须是 {MIN_MTU} 到 {MAX_MTU} 的整数"))?;
        if !(i64::from(MIN_MTU)..=i64::from(MAX_MTU)).contains(&value) {
            anyhow::bail!("mtu 必须是 {MIN_MTU} 到 {MAX_MTU} 的整数");
        }
    }
    for field in ["ctrl_port", "tunnel_port"] {
        if let Some(value) = table.get(field) {
            let value = value
                .as_integer()
                .ok_or_else(|| anyhow::anyhow!("{field} 必须是 0 到 65535 的整数"))?;
            if !(0..=u16::MAX.into()).contains(&value) {
                anyhow::bail!("{field} 必须是 0 到 65535 的整数");
            }
        }
    }
    for field in ["device_name", "tun_name", "outbound_interface", "password"] {
        if table
            .get(field)
            .is_some_and(|value| value.as_str().is_none())
        {
            anyhow::bail!("{field} 必须是字符串");
        }
    }
    validate_network_fields(&table)?;
    Ok(())
}

fn validate_network_fields(table: &toml::Table) -> anyhow::Result<()> {
    let strings = |field: &str| {
        table
            .get(field)
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
    };
    let outputs = strings("output")
        .map(|value| {
            value
                .parse::<ipnet::Ipv4Net>()
                .map(|network| network.trunc())
                .map_err(|error| anyhow::anyhow!("output '{value}' 无效: {error}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    for value in strings("input") {
        let parts = value.split(',').map(str::trim).collect::<Vec<_>>();
        if parts.len() != 2
            || parts[0].parse::<ipnet::Ipv4Net>().is_err()
            || parts[1].parse::<Ipv4Addr>().is_err()
        {
            anyhow::bail!("input '{value}' 无效，应为 IPv4网段,下一跳IPv4地址");
        }
    }
    for value in strings("subnet_mapping") {
        let parts = value.split(',').map(str::trim).collect::<Vec<_>>();
        if parts.len() != 2 {
            anyhow::bail!("subnet_mapping '{value}' 无效，应为映射网段,实际网段");
        }
        let mapped = parts[0]
            .parse::<ipnet::Ipv4Net>()
            .map_err(|error| anyhow::anyhow!("subnet_mapping 映射网段无效: {error}"))?
            .trunc();
        let actual = parts[1]
            .parse::<ipnet::Ipv4Net>()
            .map_err(|error| anyhow::anyhow!("subnet_mapping 实际网段无效: {error}"))?
            .trunc();
        if mapped.prefix_len() != actual.prefix_len() {
            anyhow::bail!("subnet_mapping '{value}' 的两个掩码必须相同");
        }
        if mapped == actual {
            anyhow::bail!("subnet_mapping '{value}' 的映射网段和实际网段不能相同");
        }
        if !network_is_covered(actual, &outputs) {
            anyhow::bail!("subnet_mapping '{value}' 的实际网段未被 output 完整覆盖");
        }
    }
    let mut ipv4 = false;
    let mut ipv6 = false;
    let mut port = None;
    for value in strings("tunnel_addr") {
        let address = value
            .parse::<std::net::SocketAddr>()
            .map_err(|error| anyhow::anyhow!("tunnel_addr '{value}' 无效: {error}"))?;
        let seen = if address.is_ipv4() {
            &mut ipv4
        } else {
            &mut ipv6
        };
        if *seen {
            anyhow::bail!("tunnel_addr 每个 IP 地址族最多配置一个监听地址");
        }
        *seen = true;
        if port.is_some_and(|expected| expected != address.port()) {
            anyhow::bail!("tunnel_addr 的所有监听地址必须使用相同端口");
        }
        port = Some(address.port());
    }
    Ok(())
}

fn network_is_covered(network: ipnet::Ipv4Net, outputs: &[ipnet::Ipv4Net]) -> bool {
    let start = u32::from(network.network()) as u64;
    let end = u32::from(network.broadcast()) as u64 + 1;
    let mut intervals = outputs
        .iter()
        .map(|output| {
            (
                (u32::from(output.network()) as u64).max(start),
                (u32::from(output.broadcast()) as u64 + 1).min(end),
            )
        })
        .filter(|(left, right)| left < right)
        .collect::<Vec<_>>();
    intervals.sort_unstable();
    let mut cursor = start;
    for (left, right) in intervals {
        if left > cursor {
            return false;
        }
        cursor = cursor.max(right);
        if cursor >= end {
            return true;
        }
    }
    false
}

/// Return the canonical representation used for persistence and delivery.
/// Parsing through `toml::Table` deliberately removes comments and source
/// formatting. The subscription envelope, not this TOML, owns client identity.
pub fn canonicalize_client_config(
    config_toml: &str,
    access: &ClientAccessConfig,
    resolved_cert_mode: &str,
    _device_name: &str,
    _is_fixed_ip: bool,
) -> anyhow::Result<String> {
    // A server-side draft may exist before a public client endpoint is
    // configured. Issuing a subscription still calls `ClientAccessConfig::validate`
    // and therefore cannot publish an unusable draft.
    if !access.effective_subscription_server().is_empty() {
        access.validate()?;
    }
    if resolved_cert_mode == "skip" {
        anyhow::bail!("订阅链接接入禁止跳过证书校验");
    }
    let mut table: toml::Table = if config_toml.trim().is_empty() {
        Default::default()
    } else {
        toml::from_str(config_toml).map_err(|error| anyhow::anyhow!("配置 TOML 无效: {error}"))?
    };
    for field in [
        "network_code",
        "device_id",
        "subscription",
        "event_script",
        "no_tun",
        "config_name",
        "server",
        "cert_mode",
        "device_name",
        "ip",
    ] {
        table.remove(field);
    }
    validate_managed_advanced_config(&toml::to_string(&table)?)?;
    table.insert(
        "server".to_string(),
        toml::Value::Array(
            access
                .resolved_traffic_servers()
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    table.insert(
        "cert_mode".to_string(),
        toml::Value::String(resolved_cert_mode.to_string()),
    );
    Ok(toml::to_string_pretty(&table)?)
}

/// Canonicalize legacy or externally modified records at the delivery boundary.
pub fn canonicalize_stored_client_config(
    source: &str,
    device_name: &str,
    is_fixed_ip: bool,
    subscription_server: Option<&str>,
) -> anyhow::Result<String> {
    let mut table: toml::Table = if source.trim().is_empty() {
        Default::default()
    } else {
        toml::from_str(source).map_err(|error| anyhow::anyhow!("配置 TOML 无效: {error}"))?
    };
    for field in [
        "network_code",
        "device_id",
        "subscription",
        "event_script",
        "no_tun",
        "config_name",
        "device_name",
        "ip",
    ] {
        table.remove(field);
    }
    let servers = table
        .get("server")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("server 必须是字符串数组"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| anyhow::anyhow!("server 必须是字符串数组"))
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let cert_mode = table
        .get("cert_mode")
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow::anyhow!("cert_mode 必须是字符串"))
        })
        .transpose()?
        .unwrap_or_else(|| "standard".to_string());
    // 订阅端点在记录里单独保存时，存储的 server 列表就是完整流量列表
    // （create 写入的是 resolved_traffic_servers，可能包含订阅端点本身）；
    // 只有缺失该字段的旧记录才按旧约定把首项当作订阅端点剥离。
    let access = match subscription_server.filter(|value| !value.trim().is_empty()) {
        Some(subscription_server) => {
            ClientAccessConfig::new(subscription_server.to_string(), servers)
        }
        None => ClientAccessConfig::new(
            servers.first().cloned().unwrap_or_default(),
            servers.into_iter().skip(1).collect(),
        ),
    };
    if !access.effective_subscription_server().is_empty() {
        access.validate()?;
    }
    let mut advanced = table.clone();
    for field in ["server", "cert_mode", "device_name", "ip"] {
        advanced.remove(field);
    }
    validate_managed_advanced_config(&toml::to_string(&advanced)?)?;
    canonicalize_client_config(
        &toml::to_string(&advanced)?,
        &access,
        &cert_mode,
        device_name,
        is_fixed_ip,
    )
}

/// Compares the effective server-managed payload while ignoring fields that
/// never belong to that payload. Device-table identity and address changes are
/// compared separately by the caller because they travel in envelope metadata.
pub fn managed_config_semantically_equal(left: &str, right: &str) -> anyhow::Result<bool> {
    fn semantic_table(source: &str) -> anyhow::Result<toml::Table> {
        let mut table: toml::Table = if source.trim().is_empty() {
            Default::default()
        } else {
            toml::from_str(source).map_err(|error| anyhow::anyhow!("配置 TOML 无效: {error}"))?
        };
        for field in [
            "network_code",
            "device_id",
            "subscription",
            "event_script",
            "no_tun",
            "config_name",
            "device_name",
            "ip",
        ] {
            table.remove(field);
        }
        Ok(table)
    }

    Ok(semantic_table(left)? == semantic_table(right)?)
}

/// Removes base-editor fields without reserializing the rest of the
/// document, so comments and unknown fields remain intact in the advanced editor.
pub fn editable_client_config(config_toml: &str) -> anyhow::Result<String> {
    let mut document: DocumentMut = config_toml
        .parse()
        .map_err(|error| anyhow::anyhow!("配置 TOML 无效: {error}"))?;
    for field in ["server", "cert_mode", "device_name", "ip"] {
        document.as_table_mut().remove(field);
    }
    Ok(document.to_string())
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Constant-time for equal-length hashes; stored hashes and computed hashes are
/// always SHA-256. Length mismatch is still folded into the result.
pub fn constant_time_hash_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access() -> ClientAccessConfig {
        ClientAccessConfig::new("tcp://vpn.example.com:29872".to_string(), Vec::new())
    }

    #[test]
    fn subscription_contains_only_bootstrap_material() {
        let issued = issue_subscription(&access(), Some(&"a".repeat(64)), "join-id").unwrap();
        assert!(issued.subscription.starts_with(SUBSCRIPTION_PREFIX));
        let encoded = issued
            .subscription
            .strip_prefix(SUBSCRIPTION_PREFIX)
            .unwrap();
        let payload: SubscriptionPayloadV2 =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        assert_eq!(payload.v, 2);
        assert_eq!(payload.join_id, "join-id");
        assert_eq!(payload.credential_key.len(), 43);
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("network_code"));
        assert!(!encoded.contains("device_id"));
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&issued.credential_key)
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn subscription_and_traffic_servers_are_kept_separate() {
        let access = ClientAccessConfig::new(
            "tcp://vpn-a.example.com:29872".to_string(),
            vec!["quic://vpn-b.example.com:29872".to_string()],
        );
        let issued = issue_subscription(&access, Some(&"a".repeat(64)), "join-id").unwrap();
        let encoded = issued
            .subscription
            .strip_prefix(SUBSCRIPTION_PREFIX)
            .unwrap();
        let payload: SubscriptionPayloadV2 =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        assert_eq!(payload.server, access.effective_subscription_server());
        let dynamic = canonicalize_client_config("", &access, "standard", "node", false).unwrap();
        let fixed = canonicalize_client_config("", &access, "standard", "node", true).unwrap();
        assert_eq!(dynamic, fixed);
        assert!(!dynamic.contains("vpn-a.example.com"));
        assert!(dynamic.contains("vpn-b.example.com"));
    }

    #[test]
    fn canonicalizer_strips_identity_and_local_only_fields() {
        let rendered = canonicalize_client_config(
            "# discarded\nnetwork_code='bad'\ndevice_id='bad'\nevent_script='oops'\ndevice_name='spoofed'\nip='10.0.0.99'\nmtu=1400",
            &access(),
            "standard",
            "managed-name",
            true,
        )
        .unwrap();
        assert!(!rendered.contains("network_code"));
        assert!(!rendered.contains("device_id"));
        assert!(!rendered.contains("event_script"));
        assert!(!rendered.contains("# discarded"));
        assert!(!rendered.contains("device_name"));
        assert!(!rendered.lines().any(|line| line.starts_with("ip =")));
        assert!(!rendered.contains("spoofed"));
        assert!(!rendered.contains("10.0.0.99"));
    }

    #[test]
    fn structured_form_preserves_unknown_fields_and_omits_default_mode() {
        let form = ManagedClientConfigForm {
            current_server: "tcp://vpn.example.com:29872".into(),
            other_servers: Vec::new(),
            cert_mode: "finger".into(),
            compress: Some(true),
            ..Default::default()
        };
        let rendered = form
            .merge_into_toml("future_option = 42\ndevice_mode = 'tun'")
            .unwrap();
        assert!(rendered.contains("future_option = 42"));
        assert!(rendered.contains("compress = true"));
        assert!(!rendered.contains("device_mode"));
    }

    #[test]
    fn structured_form_rejects_mtu_outside_supported_range() {
        let form = ManagedClientConfigForm {
            mtu: Some(MIN_MTU - 1),
            ..Default::default()
        };
        assert!(form.merge_into_toml("").is_err());

        let form = ManagedClientConfigForm {
            mtu: Some(MAX_MTU + 1),
            ..Default::default()
        };
        assert!(form.merge_into_toml("").is_err());
    }

    #[test]
    fn advanced_config_rejects_base_and_local_only_fields() {
        assert!(validate_managed_advanced_config("server = ['tcp://x:1']").is_err());
        assert!(validate_managed_advanced_config("device_name = 'spoofed'").is_err());
        assert!(validate_managed_advanced_config("ip = '10.0.0.99'").is_err());
        assert!(validate_managed_advanced_config("event_script = 'danger'").is_err());
        assert!(
            validate_managed_advanced_config("tunnel_addr = ['0.0.0.0:1']\ntunnel_port = 1")
                .is_err()
        );
        assert!(validate_managed_advanced_config("mtu = 1280").is_ok());
        assert!(validate_managed_advanced_config("mtu = 1500").is_ok());
        assert!(validate_managed_advanced_config("mtu = 575").is_err());
        assert!(validate_managed_advanced_config("mtu = 1501").is_err());
        assert!(validate_managed_advanced_config("future_option = 42\ncompress = false").is_ok());
        assert!(
            validate_managed_advanced_config(
                "output=['192.168.1.0/25','192.168.1.128/25']\nsubnet_mapping=['192.168.2.0/24,192.168.1.0/24']"
            )
            .is_ok()
        );
        assert!(
            validate_managed_advanced_config(
                "output=['192.168.1.0/25']\nsubnet_mapping=['192.168.2.0/24,192.168.1.0/24']"
            )
            .is_err()
        );
        assert!(
            validate_managed_advanced_config("tunnel_addr=['192.0.2.1:1000','192.0.2.2:1000']")
                .is_err()
        );
    }

    #[test]
    fn semantic_comparison_ignores_identity_device_metadata_and_format() {
        assert!(
            managed_config_semantically_equal(
                "# old\nnetwork_code='ignored'\ndevice_name='node'\nip='10.0.0.2'\nmtu=1400",
                "mtu = 1400\nip = \"10.0.0.2\"\ndevice_name = \"node\"",
            )
            .unwrap()
        );
        assert!(
            managed_config_semantically_equal(
                "device_name='node'\nip='10.0.0.2'",
                "device_name='renamed'\nip='10.0.0.3'",
            )
            .unwrap()
        );
    }

    #[test]
    fn canonicalizer_removes_comments_and_stale_fixed_ip() {
        let rendered = canonicalize_client_config(
            "# 用户注释\nfuture_option = 42\nip = '10.0.0.2'\n",
            &access(),
            "standard",
            "managed-name",
            false,
        )
        .unwrap();
        assert!(!rendered.contains("# 用户注释"));
        assert!(rendered.contains("future_option = 42"));
        assert!(!rendered.lines().any(|line| line.starts_with("ip =")));
        assert!(!rendered.contains("device_name"));

        let editable = editable_client_config(&format!(
            "{rendered}network_code = 'ignored-network'\ndevice_id = 'ignored-device'\n"
        ))
        .unwrap();
        assert!(editable.contains("future_option = 42"));
        assert!(editable.contains("network_code"));
        assert!(editable.contains("device_id"));
    }

    #[test]
    fn canonical_semantics_ignore_format_comments_and_identity() {
        let first = canonicalize_client_config(
            "# first\ndevice_name='node'\nnetwork_code='forged'\ncompress=true\n",
            &access(),
            "standard",
            "managed-name",
            false,
        )
        .unwrap();
        let second = canonicalize_client_config(
            "compress = true\n\n# second\ndevice_id = \"forged\"\ndevice_name = \"node\"\n",
            &access(),
            "standard",
            "managed-name",
            false,
        )
        .unwrap();
        assert_eq!(first, second);
        assert!(!first.contains('#'));
        assert!(!first.contains("network_code"));
        assert!(!first.contains("device_id"));
    }

    #[test]
    fn invalid_historical_config_is_rejected_at_delivery_boundary() {
        assert!(
            canonicalize_stored_client_config("compress = 'yes'", "node", false, None).is_err()
        );
    }
}

#[cfg(test)]
mod remote_tests {
    #[test]
    fn remote_configuration_accepts_only_transport_settings_and_id_targets() {
        for source in [
            "",
            "compress=true",
            "turn=['001,0001']",
            "punch_model=['001,IPv4Tcp,IPv4Udp']",
            "tunnel_port=29873",
        ] {
            super::validate_remote_advanced_config(source).unwrap();
        }
        for source in [
            "mtu=1400",
            "device_mode='no'",
            "input=[]",
            "output=[]",
            "no_broadcast=true",
            "allow_ikev2=false",
            "allow_wireguard=false",
            "allow_mapping=false",
            "turn=['10.0.0.0/24,001']",
            "punch_model=['10.0.0.1,IPv4Tcp']",
        ] {
            assert!(
                super::validate_remote_advanced_config(source).is_err(),
                "{source}"
            );
        }
    }
}
