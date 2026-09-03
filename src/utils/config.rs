use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, Item, Value};

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ikev2Config {
    pub ike_bind: SocketAddr,
    pub natt_bind: SocketAddr,
    pub remote_id: String,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub dns: Vec<Ipv4Addr>,
    pub public_ip: Option<std::net::IpAddr>,
    pub networks: Vec<Ikev2NetworkConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ikev2NetworkConfig {
    pub network_code: String,
    pub psk: Option<String>,
    #[serde(default)]
    pub eap_users: HashMap<String, String>,
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
        if self.remote_id.trim().is_empty() {
            anyhow::bail!("ikev2.remote_id cannot be empty");
        }
        if self.networks.is_empty() {
            anyhow::bail!("ikev2.networks cannot be empty");
        }
        let mut network_codes = HashSet::new();
        let mut psks = HashSet::new();
        let mut users = HashSet::new();
        let mut has_eap = false;
        for network in &self.networks {
            validate_network_code(&network.network_code)?;
            if !network_codes.insert(network.network_code.as_str()) {
                anyhow::bail!("duplicate IKEv2 network_code '{}'", network.network_code);
            }
            let psk = network
                .psk
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty());
            if let Some(psk) = psk
                && !psks.insert(psk)
            {
                anyhow::bail!("IKEv2 PSKs must be unique across networks");
            }
            for (user, password) in &network.eap_users {
                if user.trim().is_empty() || password.is_empty() {
                    anyhow::bail!("IKEv2 EAP username and password cannot be empty");
                }
                if !users.insert(user.as_str()) {
                    anyhow::bail!("IKEv2 EAP usernames must be unique across networks");
                }
                has_eap = true;
            }
            if psk.is_none() && network.eap_users.is_empty() {
                anyhow::bail!(
                    "IKEv2 network '{}' must configure psk or eap_users",
                    network.network_code
                );
            }
        }
        if has_eap && (self.cert.is_none() || self.key.is_none()) {
            anyhow::bail!("IKEv2 EAP authentication requires ikev2.cert and ikev2.key");
        }
        Ok(())
    }
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

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(std::fs::metadata(path)?.permissions())?;
    temporary.write_all(document.to_string().as_bytes())?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    Ok(())
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
# ike_bind = "0.0.0.0:500"
# natt_bind = "0.0.0.0:4500"
# remote_id = "vpn.example.com"
# public_ip = "203.0.113.10" # 可选；数据面始终使用 UDP/4500 NAT-T
# cert = "ikev2-cert.pem"
# key = "ikev2-key.pem"
# dns = []
#
# [[ikev2.networks]]
# network_code = "net1"
# psk = "network-secret"
# eap_users = { alice = "password1" }

# 自定义虚拟网段 格式：网络编号 = "网段"
[custom_nets]

# net1 = "10.25.0.0/24"
# net2 = "10.27.1.0/24"
"#;
    println!("{}", str);
}

#[cfg(test)]
mod tests {
    use super::{ConfigFile, update_white_list, validate_network_code};
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
    fn ikev2_credentials_are_unique_and_eap_requires_certificate() {
        let valid: ConfigFile = toml::from_str(
            r#"
network = "10.26.0.0/24"
lease_duration = 86400
[ikev2]
ike_bind = "0.0.0.0:500"
natt_bind = "0.0.0.0:4500"
remote_id = "vpn.example.com"
cert = "ike.pem"
key = "ike.key"
[[ikev2.networks]]
network_code = "alpha"
psk = "alpha-secret"
eap_users = { alice = "password" }
[[ikev2.networks]]
network_code = "beta"
psk = "beta-secret"
"#,
        )
        .unwrap();
        assert!(valid.validate().is_ok());

        let duplicate: ConfigFile = toml::from_str(
            r#"
network = "10.26.0.0/24"
lease_duration = 86400
[ikev2]
ike_bind = "0.0.0.0:500"
natt_bind = "0.0.0.0:4500"
remote_id = "vpn.example.com"
[[ikev2.networks]]
network_code = "alpha"
psk = "same"
[[ikev2.networks]]
network_code = "beta"
psk = "same"
"#,
        )
        .unwrap();
        assert!(duplicate.validate().is_err());

        let missing_certificate: ConfigFile = toml::from_str(
            r#"
network = "10.26.0.0/24"
lease_duration = 86400
[ikev2]
ike_bind = "0.0.0.0:500"
natt_bind = "0.0.0.0:4500"
remote_id = "vpn.example.com"
[[ikev2.networks]]
network_code = "alpha"
eap_users = { alice = "password" }
"#,
        )
        .unwrap();
        assert!(missing_certificate.validate().is_err());
    }
}
