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
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Ikev2Config {
    pub enabled: bool,
    pub ike_bind: SocketAddr,
    pub natt_bind: SocketAddr,
    pub remote_id: String,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub dns: Vec<Ipv4Addr>,
    pub public_ip: Option<std::net::IpAddr>,
}

impl Default for Ikev2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            ike_bind: "0.0.0.0:500".parse().expect("valid IKE bind default"),
            natt_bind: "0.0.0.0:4500".parse().expect("valid NAT-T bind default"),
            remote_id: String::new(),
            cert: None,
            key: None,
            dns: Vec::new(),
            public_ip: None,
        }
    }
}
impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            tcp_bind: Some("0.0.0.0:29872".parse().unwrap()),
            quic_bind: Some("0.0.0.0:29872".parse().unwrap()),
            ws_bind: Some("0.0.0.0:29872".parse().unwrap()),
            cert: None,
            key: None,
            network: Ipv4Net::new_assert(Ipv4Addr::new(10, 26, 0, 0), 24),
            custom_nets: Default::default(),
            white_list: Default::default(),
            lease_duration: 24 * 60 * 60,
            web_bind: Some("0.0.0.0:29871".parse().unwrap()),
            username: Some("admin".to_string()),
            password: Some("admin".to_string()),
            persistence: true,
            server_quic_bind: None,
            peer_servers: vec![],
            server_token: None,
            ikev2: None,
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
        Ok(())
    }
}

impl Ikev2Config {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.ike_bind == self.natt_bind {
            anyhow::bail!("ikev2.ike_bind and ikev2.natt_bind must be different");
        }
        if self.enabled {
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

fn validate_ikev2_remote_id(remote_id: &str) -> anyhow::Result<()> {
    if remote_id.trim().is_empty() {
        anyhow::bail!("ikev2.remote_id cannot be empty");
    }
    if remote_id.trim() != remote_id {
        anyhow::bail!("ikev2.remote_id cannot contain surrounding whitespace");
    }
    if remote_id.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if remote_id.parse::<std::net::IpAddr>().is_ok() {
        anyhow::bail!("ikev2.remote_id only supports a domain name or IPv4 address");
    }
    if remote_id.len() > 253
        || !remote_id.is_ascii()
        || remote_id.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        anyhow::bail!("ikev2.remote_id must be a valid domain name or IPv4 address");
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
    match config.public_ip {
        Some(ip) => {
            insert_value(table, "public_ip", Value::from(ip.to_string()));
        }
        None => {
            table.remove("public_ip");
        }
    }
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
tcp_bind = "0.0.0.0:29872"
# 绑定quic地址，不写则不启用quic服务
quic_bind = "0.0.0.0:29872"
# 绑定wss地址，不写则不启用wss服务
ws_bind = "0.0.0.0:29872"
# 默认虚拟网段
network = "10.26.0.0/24"
# 网络编号白名单
white_list = []
# IP租约时长，单位秒，默认24小时，离线超过这个时间IP就会被回收
lease_duration = 86400
# Web管理端绑定地址，不写则不启用web服务
web_bind = "0.0.0.0:29871"
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
# server_quic_bind = "0.0.0.0:29873"
# 其他服务器地址列表
# peer_servers = ["server1.example.com:29873", "192.168.1.100:29873"]
# 服务器验证码，用于服务器之间的身份验证
# server_token = "your-secret-token"

# IKEv2/IPsec 接入（可选；启用后通常需要管理员/root权限绑定 500/4500）
# [ikev2]
# enabled = true
# ike_bind = "0.0.0.0:500"
# natt_bind = "0.0.0.0:4500"
# remote_id = "vpn.example.com"
# public_ip = "203.0.113.10" # 可选；数据面始终使用 UDP/4500 NAT-T
# cert = "ikev2-cert.pem"
# key = "ikev2-key.pem"
# dns = []
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
        ConfigFile, Ikev2Config, load_ikev2_config, update_ikev2_config, update_white_list,
        validate_network_code,
    };
    use std::collections::HashSet;

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
remote_id = "old.example.com"
future_global_option = "keep"
"#,
        )
        .unwrap();

        let mut config = load_ikev2_config(&path).unwrap().unwrap();
        config.remote_id = "vpn.example.com".to_string();
        update_ikev2_config(&path, &config).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# root comment"));
        assert!(content.contains("# bind comment"));
        assert!(content.contains("future_global_option = \"keep\""));
        let updated = load_ikev2_config(&path).unwrap().unwrap();
        assert_eq!(updated.remote_id, "vpn.example.com");
    }
}
