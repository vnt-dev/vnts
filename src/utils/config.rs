use anyhow::{Context, bail};
use ipnet::Ipv4Net;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

pub const DEFAULT_NETWORK_CODE: &str = "default";

#[derive(Debug)]
pub struct LoadedConfig {
    pub path: PathBuf,
    pub config: ConfigFile,
    pub created_default: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigFile {
    pub tcp_bind: Option<SocketAddr>,
    pub quic_bind: Option<SocketAddr>,
    pub ws_bind: Option<SocketAddr>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
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
    #[serde(default)]
    pub custom_nets: HashMap<String, Ipv4Net>,
    #[serde(default)]
    pub network_secrets: HashMap<String, String>,
}

fn generate_strong_secret() -> String {
    const SECRET_CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!@#$%^&*+=:";

    let mut rng = rand::rng();
    let mut secret = String::with_capacity(32);
    secret.push('A');
    secret.push('a');
    secret.push('0');
    secret.push('!');
    for _ in 4..32 {
        let idx = rng.random_range(0..SECRET_CHARSET.len());
        secret.push(SECRET_CHARSET[idx] as char);
    }
    secret
}

impl Default for ConfigFile {
    fn default() -> Self {
        let mut custom_nets = HashMap::new();
        custom_nets.insert(
            DEFAULT_NETWORK_CODE.to_string(),
            Ipv4Net::new_assert(Ipv4Addr::new(10, 26, 0, 0), 24),
        );

        let mut network_secrets = HashMap::new();
        network_secrets.insert(DEFAULT_NETWORK_CODE.to_string(), generate_strong_secret());

        Self {
            tcp_bind: Some("0.0.0.0:29872".parse().unwrap()),
            quic_bind: Some("0.0.0.0:29872".parse().unwrap()),
            ws_bind: Some("0.0.0.0:29872".parse().unwrap()),
            cert: None,
            key: None,
            custom_nets,
            network_secrets,
            white_list: Default::default(),
            lease_duration: 24 * 60 * 60,
            web_bind: Some("0.0.0.0:29871".parse().unwrap()),
            username: Some("admin".to_string()),
            password: Some("admin".to_string()),
            persistence: true,
            server_quic_bind: None,
            peer_servers: vec![],
            server_token: None,
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
        Ok(Self::load_with_meta(path)?.config)
    }

    pub fn load_with_meta(path: Option<PathBuf>) -> anyhow::Result<LoadedConfig> {
        let path = path.unwrap_or_else(|| Path::new("config.toml").to_path_buf());
        if !path.exists() {
            let file = Self::default();
            file.validate()
                .with_context(|| "Generated default config is invalid".to_string())?;
            file.save_to(&path)?;
            return Ok(LoadedConfig {
                path,
                config: file,
                created_default: true,
            });
        }

        let content = std::fs::read_to_string(&path)?;
        let cfg: ConfigFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file {}", path.display()))?;
        cfg.validate()
            .with_context(|| format!("Invalid config file {}", path.display()))?;

        Ok(LoadedConfig {
            path,
            config: cfg,
            created_default: false,
        })
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.custom_nets.is_empty() {
            bail!(
                "custom_nets must contain at least one network, and it must include '{}'",
                DEFAULT_NETWORK_CODE
            );
        }

        if !self.custom_nets.contains_key(DEFAULT_NETWORK_CODE) {
            bail!(
                "custom_nets must contain '{}'. Clients must use network_code='{}' to join the default network",
                DEFAULT_NETWORK_CODE,
                DEFAULT_NETWORK_CODE
            );
        }

        for code in self.custom_nets.keys() {
            validate_network_code_value(code, "custom_nets")?;
        }

        for code in self.white_list.iter() {
            validate_network_code_value(code, "white_list")?;
        }

        for (code, secret) in self.network_secrets.iter() {
            validate_network_code_value(code, "network_secrets")?;
            validate_network_secret_value(code, secret)?;
        }

        for code in self.custom_nets.keys() {
            let Some(secret) = self.network_secrets.get(code) else {
                bail!(
                    "Missing secret for network_code '{}'. Add it under [network_secrets]",
                    code
                );
            };
            validate_network_secret_value(code, secret)?;
        }

        Ok(())
    }
}

pub fn validate_network_code_value(code: &str, field_name: &str) -> anyhow::Result<()> {
    if code.trim().is_empty() {
        bail!("{field_name} contains an empty network_code");
    }
    if code.len() > 32 {
        bail!(
            "{field_name} contains network_code '{}' longer than 32 characters",
            code
        );
    }
    Ok(())
}

pub fn validate_network_secret_value(network_code: &str, secret: &str) -> anyhow::Result<()> {
    if secret.len() < 24 {
        bail!(
            "Secret for network_code '{}' is too short. Use at least 24 characters",
            network_code
        );
    }
    if secret.chars().any(char::is_whitespace) {
        bail!(
            "Secret for network_code '{}' must not contain whitespace",
            network_code
        );
    }

    let has_lower = secret.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = secret.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = secret.chars().any(|c| c.is_ascii_digit());
    let has_symbol = secret.chars().any(|c| !c.is_ascii_alphanumeric());
    let category_count = [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|v| *v)
        .count();
    let is_hex = secret.chars().all(|c| c.is_ascii_hexdigit());

    if category_count < 3 && !(is_hex && secret.len() >= 32) {
        bail!(
            "Secret for network_code '{}' is too weak. Use a 24+ char mixed secret, or a 32+ char random hex secret",
            network_code
        );
    }

    Ok(())
}

pub fn print_example() {
    let str = r#"# Listener addresses. Remove a line to disable that protocol.
tcp_bind = "0.0.0.0:29872"
quic_bind = "0.0.0.0:29872"
ws_bind = "0.0.0.0:29872"

# Optional allow-list. Currently not enforced for registration.
white_list = []

# Lease duration in seconds.
lease_duration = 86400

# Web admin UI/API login.
web_bind = "0.0.0.0:29871"
username = "admin"
password = "admin"

# SQLite persistence.
persistence = true

# Leave these unset to auto-generate cert.pem and key.pem.
# cert = "cert.pem"
# key = "key.pem"

# Optional peer-server settings.
# server_quic_bind = "0.0.0.0:29873"
# peer_servers = ["server1.example.com:29873", "192.168.1.100:29873"]
# server_token = "your-secret-token"

# Bootstrap networks. When persistence is enabled and the database is empty,
# these entries are imported into the DB on first start.
[custom_nets]
default = "10.26.0.0/24"
# office = "10.25.0.0/24"
# dev = "10.27.1.0/24"

# Bootstrap secrets for the first import.
[network_secrets]
default = "Use-A-Long-Strong-Secret-At-Least-24-Chars!"
# office = "Replace-With-A-Different-Long-Strong-Secret!"
# dev = "Another-Different-Long-Strong-Secret!"
"#;
    println!("{}", str);
}
