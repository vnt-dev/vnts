use crate::utils::config::Ikev2Config;
use anyhow::{Context, bail};
use der::Decode;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use std::io::Cursor;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};
use x509_cert::ext::pkix::{SubjectAltName, name::GeneralName};

const CERT_FILE: &str = "ikev2-cert.pem";
const KEY_FILE: &str = "ikev2-key.pem";
const CA_CERT_FILE: &str = "ikev2-ca.pem";
const CA_KEY_FILE: &str = "ikev2-ca-key.pem";

#[derive(Debug)]
pub(crate) struct ManagedCertificateBackup {
    files: Vec<(PathBuf, Option<Vec<u8>>)>,
}

impl ManagedCertificateBackup {
    pub(crate) fn restore(self) -> anyhow::Result<()> {
        for (path, content) in self.files {
            match content {
                Some(content) => write_file(&path, &content, is_private_file(&path))?,
                None if path.exists() => std::fs::remove_file(&path)
                    .with_context(|| format!("无法删除回滚文件 {}", path.display()))?,
                None => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub managed: bool,
    pub ca_path: Option<PathBuf>,
    pub not_after: Option<u64>,
}

pub fn managed_ca_path(config_path: &Path) -> PathBuf {
    config_directory(config_path).join(CA_CERT_FILE)
}

pub(crate) fn backup_managed_certificate_files(
    config_path: &Path,
) -> anyhow::Result<ManagedCertificateBackup> {
    let directory = config_directory(config_path);
    let mut files = Vec::new();
    for name in [CERT_FILE, KEY_FILE, CA_CERT_FILE, CA_KEY_FILE] {
        let path = directory.join(name);
        let content = if path.exists() {
            Some(std::fs::read(&path).with_context(|| format!("无法备份 {}", path.display()))?)
        } else {
            None
        };
        files.push((path, content));
    }
    Ok(ManagedCertificateBackup { files })
}

pub fn is_managed_certificate(config: &Ikev2Config, config_path: &Path) -> bool {
    let directory = config_directory(config_path);
    match (&config.cert, &config.key) {
        (Some(cert), Some(key)) => {
            paths_equal(cert, &directory.join(CERT_FILE))
                && paths_equal(key, &directory.join(KEY_FILE))
        }
        _ => false,
    }
}

pub fn prepare_certificate(
    config: &mut Ikev2Config,
    config_path: &Path,
) -> anyhow::Result<CertificateInfo> {
    if !config.enabled {
        return Ok(CertificateInfo {
            managed: is_managed_certificate(config, config_path),
            ca_path: None,
            not_after: None,
        });
    }
    let directory = config_directory(config_path);
    let default_cert = directory.join(CERT_FILE);
    let default_key = directory.join(KEY_FILE);
    let managed = match (&config.cert, &config.key) {
        (None, None) => {
            config.cert = Some(default_cert.clone());
            config.key = Some(default_key.clone());
            true
        }
        (Some(cert), Some(key)) => {
            paths_equal(cert, &default_cert) && paths_equal(key, &default_key)
        }
        _ => bail!("cert 和 key 必须同时填写，或同时留空由系统自动生成"),
    };

    if managed {
        let ca_cert = directory.join(CA_CERT_FILE);
        let ca_key = directory.join(CA_KEY_FILE);
        let renew = !default_cert.exists()
            || !default_key.exists()
            || certificate_needs_renewal(&default_cert, &config.remote_id).unwrap_or(true);
        if renew {
            generate_managed_certificate(
                &config.remote_id,
                &default_cert,
                &default_key,
                &ca_cert,
                &ca_key,
            )?;
        }
        let not_after = certificate_expiry(&default_cert).ok();
        return Ok(CertificateInfo {
            managed: true,
            ca_path: Some(ca_cert),
            not_after,
        });
    }

    let cert = config.cert.as_ref().expect("custom cert checked above");
    Ok(CertificateInfo {
        managed: false,
        ca_path: None,
        not_after: certificate_expiry(cert).ok(),
    })
}

fn config_directory(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf())
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    let absolute_left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let absolute_right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    absolute_left == absolute_right
}

fn certificate_needs_renewal(path: &Path, remote_id: &str) -> anyhow::Result<bool> {
    let cert = leaf_der(path)?;
    if !certificate_matches_remote_id(&cert, remote_id)? {
        return Ok(true);
    }
    let (_, not_after) = ryke::ikev2::sign::cert_validity(&cert).map_err(anyhow::Error::msg)?;
    let renew_at = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64 + 30 * 24 * 60 * 60;
    Ok(not_after <= renew_at)
}

pub fn certificate_matches_remote_id(cert_der: &[u8], remote_id: &str) -> anyhow::Result<bool> {
    let cert = x509_cert::Certificate::from_der(cert_der).context("无法解析 IKEv2 证书")?;
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(false);
    };
    let parsed_ip = remote_id.parse::<IpAddr>().ok();
    for extension in extensions {
        if extension.extn_id.to_string() != "2.5.29.17" {
            continue;
        }
        let san = SubjectAltName::from_der(extension.extn_value.as_bytes())
            .context("无法解析 IKEv2 证书 SAN")?;
        for name in san.0 {
            match (parsed_ip, name) {
                (None, GeneralName::DnsName(dns))
                    if dns.as_str().eq_ignore_ascii_case(remote_id) =>
                {
                    return Ok(true);
                }
                (Some(expected), GeneralName::IpAddress(bytes))
                    if bytes.as_bytes() == ip_bytes(expected).as_slice() =>
                {
                    return Ok(true);
                }
                _ => {}
            }
        }
    }
    Ok(false)
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn certificate_expiry(path: &Path) -> anyhow::Result<u64> {
    let cert = leaf_der(path)?;
    let (_, not_after) = ryke::ikev2::sign::cert_validity(&cert).map_err(anyhow::Error::msg)?;
    Ok(not_after)
}

fn leaf_der(path: &Path) -> anyhow::Result<Vec<u8>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("无法读取 IKEv2 证书 {}", path.display()))?;
    rustls_pemfile::certs(&mut Cursor::new(bytes))
        .next()
        .transpose()?
        .map(|cert| cert.as_ref().to_vec())
        .context("IKEv2 证书链为空")
}

fn generate_managed_certificate(
    remote_id: &str,
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: &Path,
    ca_key_path: &Path,
) -> anyhow::Result<()> {
    if remote_id.trim().is_empty() {
        bail!("Remote ID 不能为空");
    }
    let (ca_pem, ca_key_pem) = if ca_cert_path.exists() && ca_key_path.exists() {
        (
            std::fs::read_to_string(ca_cert_path).context("无法读取自动生成的 IKEv2 CA")?,
            std::fs::read_to_string(ca_key_path).context("无法读取自动生成的 IKEv2 CA 私钥")?,
        )
    } else {
        create_ca()?
    };
    let ca_key = KeyPair::from_pem(&ca_key_pem).context("无法解析自动生成的 IKEv2 CA 私钥")?;
    let issuer =
        Issuer::from_ca_cert_pem(&ca_pem, ca_key).context("无法解析自动生成的 IKEv2 CA 证书")?;

    let server_key_pem = generate_rsa_key()?;
    let server_key = KeyPair::from_pem(&server_key_pem).context("无法解析 IKEv2 服务器私钥")?;
    let mut params = CertificateParams::new(vec![remote_id.to_string()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, remote_id);
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(825);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let server_cert = params
        .signed_by(&server_key, &issuer)
        .context("无法签发 IKEv2 服务器证书")?;
    let chain = format!("{}{}", server_cert.pem(), ca_pem);

    if !ca_cert_path.exists() || !ca_key_path.exists() {
        write_public(ca_cert_path, ca_pem.as_bytes())?;
        write_private(ca_key_path, ca_key_pem.as_bytes())?;
    }
    write_public(cert_path, chain.as_bytes())?;
    write_private(key_path, server_key_pem.as_bytes())?;
    Ok(())
}

fn create_ca() -> anyhow::Result<(String, String)> {
    let key_pem = generate_rsa_key()?;
    let key = KeyPair::from_pem(&key_pem).context("无法解析新生成的 IKEv2 CA 私钥")?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "VNT IKEv2 Local CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
    let cert = params.self_signed(&key).context("无法生成 IKEv2 CA 证书")?;
    Ok((cert.pem(), key_pem))
}

fn generate_rsa_key() -> anyhow::Result<String> {
    let key =
        RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).context("无法生成 RSA-2048 私钥")?;
    Ok(key.to_pkcs8_pem(LineEnding::LF)?.to_string())
}

fn write_public(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    write_file(path, bytes, false)
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    write_file(path, bytes, true)
}

fn write_file(path: &Path, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes).with_context(|| format!("无法写入 {}", path.display()))?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}

fn is_private_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(KEY_FILE) | Some(CA_KEY_FILE)
    )
}

#[cfg(test)]
mod tests {
    use super::{
        backup_managed_certificate_files, certificate_matches_remote_id, managed_ca_path,
        prepare_certificate,
    };
    use crate::utils::config::Ikev2Config;
    use std::io::Cursor;

    #[test]
    fn managed_ca_issues_and_reissues_domain_and_ip_certificates() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let mut config = Ikev2Config {
            enabled: true,
            remote_id: "vpn.example.com".to_string(),
            ..Ikev2Config::default()
        };
        let first = prepare_certificate(&mut config, &config_path).unwrap();
        assert!(first.managed);
        let ca_path = managed_ca_path(&config_path);
        let ca_before = std::fs::read(&ca_path).unwrap();
        let cert_path = config.cert.clone().unwrap();
        let first_leaf =
            rustls_pemfile::certs(&mut Cursor::new(std::fs::read(&cert_path).unwrap()))
                .next()
                .unwrap()
                .unwrap();
        assert!(certificate_matches_remote_id(first_leaf.as_ref(), "vpn.example.com").unwrap());

        config.remote_id = "192.0.2.10".to_string();
        prepare_certificate(&mut config, &config_path).unwrap();
        assert_eq!(ca_before, std::fs::read(ca_path).unwrap());
        let second_leaf =
            rustls_pemfile::certs(&mut Cursor::new(std::fs::read(cert_path).unwrap()))
                .next()
                .unwrap()
                .unwrap();
        assert!(certificate_matches_remote_id(second_leaf.as_ref(), "192.0.2.10").unwrap());

        let backup = backup_managed_certificate_files(&config_path).unwrap();
        let key_path = config.key.as_ref().unwrap();
        let key_before = std::fs::read(key_path).unwrap();
        std::fs::write(key_path, b"broken").unwrap();
        backup.restore().unwrap();
        assert_eq!(std::fs::read(key_path).unwrap(), key_before);
    }
}
