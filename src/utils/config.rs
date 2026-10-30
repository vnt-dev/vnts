use base64::Engine;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigFile {
    pub tcp_bind: Option<SocketAddr>,
    pub quic_bind: Option<SocketAddr>,
    pub ws_bind: Option<SocketAddr>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub network: Ipv4Net,
    #[serde(default)]
    pub custom_nets: HashMap<String, Ipv4Net>,
    #[serde(default)]
    pub group_types: HashMap<String, crate::server::control_server::db::GroupType>,
    #[serde(default)]
    pub white_list: HashSet<String>,
    pub lease_duration: u64,
    pub web_bind: Option<SocketAddr>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub persistence: bool,
    pub server_quic_bind: Option<SocketAddr>,
    #[serde(default)]
    pub peer_servers: Vec<String>,
    pub server_token: Option<String>,
    pub ikev2: Option<Ikev2Config>,
    pub wireguard: Option<WireGuardConfig>,
    #[serde(default)]
    pub client_access: ClientAccessConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct ClientAccessConfig {
    /// The one control endpoint embedded in newly issued subscriptions.
    #[serde(default)]
    pub subscription_server: String,
    /// Default data-plane endpoints. An empty list means the subscription endpoint.
    #[serde(default)]
    pub traffic_servers: Vec<String>,
}

impl ClientAccessConfig {
    pub fn new(subscription_server: String, traffic_servers: Vec<String>) -> Self {
        Self {
            subscription_server,
            traffic_servers,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.effective_subscription_server().is_empty() {
            anyhow::bail!("client_access.subscription_server 不能为空");
        }
        self.validate_optional()
    }

    pub fn validate_optional(&self) -> anyhow::Result<()> {
        let subscription_server = self.effective_subscription_server();
        if subscription_server.is_empty() && !self.effective_traffic_servers().is_empty() {
            anyhow::bail!("配置 client_access.traffic_servers 前必须先配置 subscription_server");
        }
        if !subscription_server.is_empty() {
            let trimmed = subscription_server.trim();
            if trimmed.is_empty() || subscription_server != trimmed {
                anyhow::bail!("client_access.subscription_server 包含无效地址");
            }
            validate_client_endpoint(trimmed)?;
        }
        let mut unique = HashSet::new();
        for endpoint in self.effective_traffic_servers() {
            let trimmed = endpoint.trim();
            if trimmed.is_empty() || endpoint != trimmed {
                anyhow::bail!("client_access 包含无效地址");
            }
            validate_client_endpoint(trimmed)?;
            if !unique.insert(trimmed.to_string()) {
                anyhow::bail!("client_access 包含重复地址");
            }
        }
        Ok(())
    }

    pub fn effective_subscription_server(&self) -> String {
        self.subscription_server.clone()
    }

    pub fn effective_traffic_servers(&self) -> Vec<String> {
        self.traffic_servers.clone()
    }

    pub fn resolved_traffic_servers(&self) -> Vec<String> {
        let servers = self.effective_traffic_servers();
        if servers.is_empty() {
            vec![self.effective_subscription_server()]
        } else {
            servers
        }
    }
}

fn validate_client_endpoint(endpoint: &str) -> anyhow::Result<()> {
    let authority = ["tcp://", "quic://", "wss://"]
        .into_iter()
        .find_map(|scheme| endpoint.strip_prefix(scheme))
        .ok_or_else(|| anyhow::anyhow!("客户端接入地址仅支持 tcp://、quic:// 或 wss://"))?;
    if authority.is_empty()
        || authority.bytes().any(|byte| byte.is_ascii_whitespace())
        || authority.contains(['/', '?', '#', '@'])
    {
        anyhow::bail!("客户端接入地址格式无效，必须包含主机和端口");
    }
    if let Ok(address) = authority.parse::<SocketAddr>() {
        if address.port() == 0 {
            anyhow::bail!("客户端接入端口不能为 0");
        }
        return Ok(());
    }
    // A bracketed IPv6 authority should have parsed as SocketAddr above.
    if authority.starts_with('[') || authority.contains(']') {
        anyhow::bail!("客户端接入 IPv6 地址格式无效");
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("客户端接入地址必须包含端口"))?;
    if host.is_empty()
        || host.contains(':')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        anyhow::bail!("客户端接入主机名无效");
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("客户端接入端口无效"))?;
    if port == 0 {
        anyhow::bail!("客户端接入端口不能为 0");
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WireGuardConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    #[serde(default)]
    pub endpoint: String,
    pub private_key: Option<String>,
    #[serde(default = "default_wireguard_keepalive")]
    pub persistent_keepalive: u16,
}

const fn default_wireguard_keepalive() -> u16 {
    25
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "[::]:51820".parse().unwrap(),
            endpoint: String::new(),
            private_key: None,
            persistent_keepalive: default_wireguard_keepalive(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Ikev2Config {
    pub enabled: bool,
    pub ike_bind: SocketAddr,
    pub natt_bind: SocketAddr,
    #[serde(default)]
    pub server_address: String,
    pub remote_id: String,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub dns: Vec<Ipv4Addr>,
}

impl Default for Ikev2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            ike_bind: "[::]:500".parse().expect("valid IKE bind default"),
            natt_bind: "[::]:4500".parse().expect("valid NAT-T bind default"),
            server_address: String::new(),
            remote_id: String::new(),
            cert: None,
            key: None,
            dns: Vec::new(),
        }
    }
}
impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            tcp_bind: Some("[::]:29872".parse().unwrap()),
            quic_bind: Some("[::]:29872".parse().unwrap()),
            ws_bind: Some("[::]:29872".parse().unwrap()),
            cert: None,
            key: None,
            network: Ipv4Net::new_assert(Ipv4Addr::new(10, 26, 0, 0), 24),
            custom_nets: Default::default(),
            group_types: Default::default(),
            white_list: Default::default(),
            lease_duration: 24 * 60 * 60,
            web_bind: Some("[::]:29871".parse().unwrap()),
            username: Some("admin".to_string()),
            password: Some("admin".to_string()),
            persistence: true,
            server_quic_bind: None,
            peer_servers: vec![],
            server_token: None,
            ikev2: None,
            wireguard: None,
            client_access: ClientAccessConfig::default(),
        }
    }
}

impl ConfigFile {
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        let s = toml::to_string_pretty(self)?;

        let mut file = std::fs::File::create(path)?;
        file.write_all(s.as_bytes())?;

        Ok(())
    }
    pub fn load_from(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let path = if let Some(path) = path {
            path
        } else {
            let path = Path::new("config.toml");
            if !path.exists() {
                let file = Self::default();
                _ = file.save_to(path);
                return Ok(file);
            }
            path.to_path_buf()
        };
        let content = std::fs::read_to_string(path)?;
        let cfg: ConfigFile = toml::from_str(&content)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        for network_code in self.white_list.iter().chain(self.custom_nets.keys()) {
            validate_network_code(network_code)?;
        }
        if let Some(ikev2) = &self.ikev2 {
            ikev2.validate()?;
        }
        if let Some(wireguard) = &self.wireguard {
            wireguard.validate()?;
        }
        // An empty endpoint list is allowed at process startup so existing
        // installations remain compatible. Managed-device creation validates it.
        self.client_access.validate_optional()?;
        Ok(())
    }
}

impl WireGuardConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.enabled {
            validate_wireguard_endpoint(&self.endpoint)?;
        }
        if let Some(private_key) = &self.private_key
            && !private_key.is_empty()
        {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(private_key)
                .map_err(|_| anyhow::anyhow!("wireguard.private_key must be valid base64"))?;
            if decoded.len() != 32 {
                anyhow::bail!("wireguard.private_key must decode to 32 bytes");
            }
        }
        Ok(())
    }
}

fn validate_wireguard_endpoint(endpoint: &str) -> anyhow::Result<()> {
    if endpoint.trim().is_empty() || endpoint.trim() != endpoint {
        anyhow::bail!("wireguard.endpoint cannot be empty or contain surrounding whitespace");
    }
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        if address.port() == 0 {
            anyhow::bail!("wireguard.endpoint port cannot be zero");
        }
        return Ok(());
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("wireguard.endpoint must use host:port syntax"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("wireguard.endpoint has an invalid port"))?;
    if port == 0 || host.is_empty() || host.starts_with('[') || host.ends_with(']') {
        anyhow::bail!("wireguard.endpoint is invalid");
    }
    validate_ikev2_host(host, "wireguard.endpoint host")
}

impl Ikev2Config {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.ike_bind == self.natt_bind {
            anyhow::bail!("ikev2.ike_bind and ikev2.natt_bind must be different");
        }
        if self.enabled {
            validate_ikev2_server_address(&self.server_address)?;
            validate_ikev2_remote_id(&self.remote_id)?;
        }
        if self.cert.is_some() != self.key.is_some() {
            anyhow::bail!("ikev2.cert and ikev2.key must both be set or both be empty");
        }
        // When both paths are empty the web/startup preparation layer generates a
        // locally managed CA and server certificate before starting the responder.
        Ok(())
    }
}

fn validate_ikev2_server_address(server_address: &str) -> anyhow::Result<()> {
    if server_address.trim().is_empty() {
        anyhow::bail!("ikev2.server_address cannot be empty");
    }
    if server_address.trim() != server_address {
        anyhow::bail!("ikev2.server_address cannot contain surrounding whitespace");
    }
    validate_ikev2_host(server_address, "ikev2.server_address")
}

fn validate_ikev2_remote_id(remote_id: &str) -> anyhow::Result<()> {
    if remote_id.trim().is_empty() {
        anyhow::bail!("ikev2.remote_id cannot be empty");
    }
    if remote_id.trim() != remote_id {
        anyhow::bail!("ikev2.remote_id cannot contain surrounding whitespace");
    }
    if remote_id.parse::<std::net::IpAddr>().is_ok() {
        return if remote_id.parse::<Ipv4Addr>().is_ok() {
            Ok(())
        } else {
            anyhow::bail!("ikev2.remote_id only supports a domain name or IPv4 address")
        };
    }
    validate_ikev2_host(remote_id, "ikev2.remote_id")
}

fn validate_ikev2_host(value: &str, field: &str) -> anyhow::Result<()> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if value.len() > 253
        || !value.is_ascii()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        anyhow::bail!("{field} must be a valid domain name or IP address");
    }
    Ok(())
}

pub fn validate_network_code(network_code: &str) -> anyhow::Result<()> {
    if network_code.is_empty() {
        anyhow::bail!("network_code cannot be empty");
    }
    if network_code.trim() != network_code {
        anyhow::bail!(
            "network_code '{}' cannot contain leading or trailing whitespace",
            network_code
        );
    }
    if network_code.len() > 32 {
        anyhow::bail!("network_code '{}' length exceeds 32 bytes", network_code);
    }
    Ok(())
}

pub fn update_white_list(path: &Path, network_codes: &[String]) -> anyhow::Result<()> {
    for network_code in network_codes {
        validate_network_code(network_code)?;
    }

    let content = std::fs::read_to_string(path)?;
    let mut document = content.parse::<DocumentMut>()?;
    if let Some(white_list) = document.get_mut("white_list").and_then(Item::as_array_mut) {
        white_list.clear();
        for network_code in network_codes {
            white_list.push(network_code.as_str());
        }
    } else {
        let mut white_list = Array::new();
        for network_code in network_codes {
            white_list.push(network_code.as_str());
        }
        document["white_list"] = Item::Value(Value::Array(white_list));
    }

    persist_document(path, document.to_string())
}

pub fn load_ikev2_config(path: &Path) -> anyhow::Result<Option<Ikev2Config>> {
    Ok(ConfigFile::load_from(Some(path.to_path_buf()))?.ikev2)
}

pub fn load_wireguard_config(path: &Path) -> anyhow::Result<Option<WireGuardConfig>> {
    Ok(ConfigFile::load_from(Some(path.to_path_buf()))?.wireguard)
}

pub fn update_client_access_config(
    path: &Path,
    config: &ClientAccessConfig,
) -> anyhow::Result<ClientAccessConfig> {
    config.validate_optional()?;
    let content = std::fs::read_to_string(path)?;
    let mut document = content.parse::<DocumentMut>()?;
    if !document.contains_key("client_access") {
        document["client_access"] = Item::Table(Table::new());
    }
    let table = document["client_access"]
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("client_access 必须是表"))?;
    table.remove("server");
    table.remove("cert_mode");
    insert_value(
        table,
        "subscription_server",
        Value::from(config.effective_subscription_server()),
    );
    let mut traffic_servers = Array::new();
    for endpoint in config.effective_traffic_servers() {
        traffic_servers.push(endpoint);
    }
    insert_value(table, "traffic_servers", Value::Array(traffic_servers));
    let rendered = document.to_string();
    let parsed: ConfigFile = toml::from_str(&rendered)?;
    parsed.client_access.validate_optional()?;
    persist_document(path, rendered)?;
    Ok(parsed.client_access)
}

pub fn update_wireguard_config(
    path: &Path,
    config: &WireGuardConfig,
) -> anyhow::Result<WireGuardConfig> {
    config.validate()?;
    let content = std::fs::read_to_string(path)?;
    let mut document = content.parse::<DocumentMut>()?;
    if !document.contains_key("wireguard") {
        document["wireguard"] = Item::Table(Table::new());
    }
    let table = document["wireguard"]
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("wireguard 必须是表"))?;
    insert_value(table, "enabled", Value::from(config.enabled));
    insert_value(table, "bind", Value::from(config.bind.to_string()));
    insert_value(table, "endpoint", Value::from(config.endpoint.clone()));
    match &config.private_key {
        Some(private_key) => insert_value(table, "private_key", Value::from(private_key.clone())),
        None => {
            table.remove("private_key");
        }
    }
    insert_value(
        table,
        "persistent_keepalive",
        Value::from(i64::from(config.persistent_keepalive)),
    );
    let rendered = document.to_string();
    let parsed: ConfigFile = toml::from_str(&rendered)?;
    let wireguard = parsed
        .wireguard
        .ok_or_else(|| anyhow::anyhow!("WireGuard 服务尚未配置"))?;
    persist_document(path, rendered)?;
    Ok(wireguard)
}

pub fn update_ikev2_config(path: &Path, config: &Ikev2Config) -> anyhow::Result<Ikev2Config> {
    config.validate()?;
    let content = std::fs::read_to_string(path)?;
    let mut document = content.parse::<DocumentMut>()?;
    if !document.contains_key("ikev2") {
        document["ikev2"] = Item::Table(Table::new());
    }
    let table = document["ikev2"]
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("ikev2 必须是表"))?;
    insert_value(table, "enabled", Value::from(config.enabled));
    insert_value(table, "ike_bind", Value::from(config.ike_bind.to_string()));
    insert_value(
        table,
        "natt_bind",
        Value::from(config.natt_bind.to_string()),
    );
    insert_value(
        table,
        "server_address",
        Value::from(config.server_address.clone()),
    );
    insert_value(table, "remote_id", Value::from(config.remote_id.clone()));
    match &config.cert {
        Some(path) => {
            insert_value(
                table,
                "cert",
                Value::from(path.to_string_lossy().to_string()),
            );
        }
        None => {
            table.remove("cert");
        }
    }
    match &config.key {
        Some(path) => {
            insert_value(
                table,
                "key",
                Value::from(path.to_string_lossy().to_string()),
            );
        }
        None => {
            table.remove("key");
        }
    }
    table.remove("public_ip");
    let mut dns = Array::new();
    for address in &config.dns {
        dns.push(address.to_string());
    }
    insert_value(table, "dns", Value::Array(dns));

    table.remove("networks");

    let rendered = document.to_string();
    let parsed: ConfigFile = toml::from_str(&rendered)?;
    let ikev2 = parsed
        .ikev2
        .ok_or_else(|| anyhow::anyhow!("IKEv2 服务尚未配置"))?;
    persist_document(path, rendered)?;
    Ok(ikev2)
}

fn insert_value(table: &mut Table, key: &str, value: Value) {
    let decor = table
        .get(key)
        .and_then(Item::as_value)
        .map(|value| value.decor().clone());
    table.insert(key, Item::Value(value));
    if let (Some(decor), Some(value)) = (decor, table.get_mut(key).and_then(Item::as_value_mut)) {
        *value.decor_mut() = decor;
    }
}

pub(crate) fn persist_config_text(path: &Path, content: String) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(std::fs::metadata(path)?.permissions())?;
    temporary.write_all(content.as_bytes())?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    Ok(())
}

fn persist_document(path: &Path, content: String) -> anyhow::Result<()> {
    persist_config_text(path, content)
}

pub fn print_example() {
    let str = r#"# 绑定tcp地址，不写则不启用tcp服务
tcp_bind = "[::]:29872"
# 绑定quic地址，不写则不启用quic服务
quic_bind = "[::]:29872"
# 绑定wss地址，不写则不启用wss服务
ws_bind = "[::]:29872"
# 默认虚拟网段
network = "10.26.0.0/24"
# 网络编号白名单
white_list = []
# IP租约时长，单位秒，默认24小时，离线超过这个时间IP就会被回收
lease_duration = 86400
# Web管理端绑定地址，不写则不启用web服务
web_bind = "[::]:29871"
# 管理端登录用户名密码
username = "admin"
# 管理端登录用户密码
password = "admin"
# 是否启用数据持久化
persistence = true

# tls证书不填时将自动生成
# 自定义tls证书路径
cert = "cert.pem"
# 自定义tls私钥路径
key = "key.pem"

# 服务端互联配置（可选）
# 服务端之间通信的UDP端口，不填则不启用服务端互联
# server_quic_bind = "[::]:29873"
# 其他服务器地址列表
# peer_servers = ["server1.example.com:29873", "192.168.1.100:29873"]
# 服务器验证码，用于服务器之间的身份验证
# server_token = "your-secret-token"

# IKEv2/IPsec 接入（可选；启用后通常需要管理员/root权限绑定 500/4500）
# [ikev2]
# enabled = true
# ike_bind = "[::]:500"
# natt_bind = "[::]:4500"
# server_address = "vpn.example.com" # 客户端实际连接地址
# remote_id = "vpn.example.com"
# cert = "ikev2-cert.pem"
# key = "ikev2-key.pem"
# dns = []
#
# WireGuard 接入（可选；使用独立 UDP 监听端口）
# [wireguard]
# enabled = true
# bind = "[::]:51820"
# endpoint = "vpn.example.com:51820"
# private_key = "" # 留空时首次启用自动生成
# persistent_keepalive = 25
#
# 自定义虚拟网段 格式：网络编号 = "网段"
[custom_nets]

# net1 = "10.25.0.0/24"
# net2 = "10.27.1.0/24"
"#;
    println!("{}", str);
}

#[cfg(test)]
mod tests {
    use super::{
        ClientAccessConfig, ConfigFile, Ikev2Config, load_ikev2_config, load_wireguard_config,
        update_ikev2_config, update_white_list, update_wireguard_config, validate_network_code,
    };
    use std::collections::HashSet;

    #[test]
    fn client_access_requires_a_supported_host_and_nonzero_port() {
        for endpoint in [
            "tcp://vpn.example.com:29872",
            "quic://192.0.2.10:443",
            "wss://[2001:db8::1]:29872",
        ] {
            assert!(
                ClientAccessConfig::new(endpoint.to_string(), Vec::new())
                    .validate()
                    .is_ok()
            );
        }
        for endpoint in [
            "http://vpn.example.com:29872",
            "tcp://vpn.example.com",
            "tcp://vpn.example.com:0",
            "tcp://2001:db8::1:29872",
            "tcp://vpn.example.com:29872/path",
        ] {
            assert!(
                ClientAccessConfig::new(endpoint.to_string(), Vec::new())
                    .validate()
                    .is_err()
            );
        }
    }

    #[test]
    fn client_access_serializes_only_subscription_and_traffic_servers() {
        let access: ClientAccessConfig = toml::from_str(
            r#"subscription_server = "tcp://control.example.com:29872"
traffic_servers = ["quic://traffic.example.com:29872"]
"#,
        )
        .unwrap();
        assert_eq!(
            access.effective_subscription_server(),
            "tcp://control.example.com:29872"
        );
        assert_eq!(
            access.effective_traffic_servers(),
            vec!["quic://traffic.example.com:29872"]
        );
        let rendered = toml::to_string(&ClientAccessConfig::new(
            access.effective_subscription_server(),
            access.effective_traffic_servers(),
        ))
        .unwrap();
        assert!(rendered.contains("subscription_server"));
        assert!(rendered.contains("traffic_servers"));
        assert!(!rendered.contains("cert_mode"));
    }

    #[test]
    fn missing_white_list_and_custom_nets_use_empty_defaults() {
        let config: ConfigFile = toml::from_str(
            r#"
network = "10.26.0.0/24"
lease_duration = 86400
"#,
        )
        .expect("config");

        assert!(config.white_list.is_empty());
        assert!(config.custom_nets.is_empty());
    }

    #[test]
    fn ikev2_disabled_drafts_allow_empty_identity() {
        let draft: ConfigFile = toml::from_str(
            r#"
network = "10.26.0.0/24"
lease_duration = 86400
[ikev2]
enabled = false
ike_bind = "0.0.0.0:500"
natt_bind = "0.0.0.0:4500"
remote_id = ""
"#,
        )
        .unwrap();
        assert!(draft.validate().is_ok());

        let mut identity = Ikev2Config {
            enabled: true,
            server_address: "vpn.example.com".to_string(),
            remote_id: "192.0.2.1".to_string(),
            ..Ikev2Config::default()
        };
        assert!(identity.validate().is_ok());
        identity.remote_id = "vpn.example.com".to_string();
        assert!(identity.validate().is_ok());
        identity.remote_id = "2001:db8::1".to_string();
        assert!(identity.validate().is_err());
        identity.remote_id = "not a host".to_string();
        assert!(identity.validate().is_err());

        identity.remote_id = "vpn.example.com".to_string();
        identity.server_address.clear();
        assert!(identity.validate().is_err());
        identity.server_address = "203.0.113.10".to_string();
        assert!(identity.validate().is_ok());
        identity.server_address = "2001:db8::1".to_string();
        assert!(identity.validate().is_ok());
        identity.server_address = "https://vpn.example.com".to_string();
        assert!(identity.validate().is_err());
    }

    #[test]
    fn network_codes_with_surrounding_whitespace_are_rejected() {
        let config: ConfigFile = toml::from_str(
            r#"
network = "10.26.0.0/24"
lease_duration = 86400
white_list = [" net1"]
"#,
        )
        .expect("config syntax");

        assert!(config.validate().is_err());
    }

    #[test]
    fn network_code_validation_matches_whitelist_rules() {
        assert!(validate_network_code("net1").is_ok());
        assert!(validate_network_code("").is_err());
        assert!(validate_network_code(" net1").is_err());
        assert!(validate_network_code(&"网".repeat(11)).is_err());
    }

    #[test]
    fn updating_white_list_preserves_other_config_and_comments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("custom.toml");
        std::fs::write(
            &path,
            r#"# keep this comment
network = "10.26.0.0/24"
white_list = ["old"] # whitelist comment
lease_duration = 86400
"#,
        )
        .unwrap();

        update_white_list(&path, &["alpha".to_string(), "beta".to_string()]).unwrap();

        let updated = std::fs::read_to_string(path).unwrap();
        assert!(updated.contains("# keep this comment"));
        assert!(updated.contains("# whitelist comment"));
        assert!(updated.contains("network = \"10.26.0.0/24\""));
        let config: ConfigFile = toml::from_str(&updated).unwrap();
        assert_eq!(
            config.white_list,
            HashSet::from(["alpha".to_string(), "beta".to_string()])
        );
    }

    #[test]
    fn ikev2_empty_certificate_paths_enable_auto_generation() {
        let config: ConfigFile = toml::from_str(
            r#"
network = "10.26.0.0/24"
lease_duration = 86400
[ikev2]
enabled = true
ike_bind = "0.0.0.0:500"
natt_bind = "0.0.0.0:4500"
server_address = "vpn.example.com"
remote_id = "vpn.example.com"
"#,
        )
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn updating_full_ikev2_config_preserves_comments_and_unknown_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            r#"# root comment
network = "10.26.0.0/24"
lease_duration = 86400
[ikev2]
enabled = true
ike_bind = "0.0.0.0:500" # bind comment
natt_bind = "0.0.0.0:4500"
server_address = "old-access.example.com"
remote_id = "old.example.com"
public_ip = "203.0.113.10"
future_global_option = "keep"
"#,
        )
        .unwrap();

        let mut config = load_ikev2_config(&path).unwrap().unwrap();
        config.server_address = "vpn-access.example.com".to_string();
        config.remote_id = "vpn.example.com".to_string();
        update_ikev2_config(&path, &config).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# root comment"));
        assert!(content.contains("# bind comment"));
        assert!(content.contains("future_global_option = \"keep\""));
        assert!(!content.contains("public_ip"));
        let updated = load_ikev2_config(&path).unwrap().unwrap();
        assert_eq!(updated.server_address, "vpn-access.example.com");
        assert_eq!(updated.remote_id, "vpn.example.com");
    }

    #[test]
    fn wireguard_config_validates_endpoint_and_key() {
        let config: ConfigFile = toml::from_str(
            r#"network = "10.26.0.0/24"
lease_duration = 86400
[wireguard]
enabled = true
bind = "0.0.0.0:51820"
endpoint = "vpn.example.com:51820"
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
persistent_keepalive = 25
"#,
        )
        .unwrap();
        assert!(config.validate().is_ok());

        let mut invalid = config.wireguard.unwrap();
        invalid.endpoint = "vpn.example.com".to_string();
        assert!(invalid.validate().is_err());
        invalid.endpoint = "vpn.example.com:51820".to_string();
        invalid.private_key = Some("not-a-key".to_string());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn updating_wireguard_preserves_comments_and_other_sections() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            r#"# root comment
network = "10.26.0.0/24"
lease_duration = 86400
[wireguard]
enabled = false
bind = "0.0.0.0:51820" # bind comment
endpoint = ""
persistent_keepalive = 25
future_option = "keep"
[custom_nets]
alpha = "10.27.0.0/24"
"#,
        )
        .unwrap();
        let mut config = load_wireguard_config(&path).unwrap().unwrap();
        config.endpoint = "vpn.example.com:51820".to_string();
        config.private_key = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
        update_wireguard_config(&path, &config).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# root comment"));
        assert!(content.contains("# bind comment"));
        assert!(content.contains("future_option = \"keep\""));
        assert!(content.contains("alpha = \"10.27.0.0/24\""));
    }
}
