use crate::ControlService;
use crate::managed_config::{
    ManagedClientConfigForm, canonicalize_client_config, canonicalize_stored_client_config,
    editable_client_config, issue_subscription, managed_config_semantically_equal, new_join_id,
    resolve_cert_mode, validate_managed_advanced_config,
};
use crate::server::control_server::db::{
    self, ClientType, DeviceIpType, Ikev2InputRoute, ManagedConfigRecord, NetworkType,
};
use crate::server::control_server::service::{
    DeviceInfoVO, NetworkInfoVO, SubscriptionLiveState, SubscriptionPushStatus,
};
use crate::utils::config::{
    ClientAccessConfig, Ikev2Config, WireGuardConfig, load_ikev2_config, load_wireguard_config,
    update_client_access_config as persist_client_access_config,
    update_ikev2_config as persist_ikev2_config, update_white_list as persist_white_list,
    update_wireguard_config as persist_wireguard_config, validate_network_code,
};
use anyhow::Context;
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Request, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
use mime_guess::from_path;
use rand::Rng;
use rand::distr::Alphanumeric;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Component, Path as StdPath, PathBuf};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

#[derive(RustEmbed)]
#[folder = "static"]
struct Assets;

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub msg: String,
    pub data: Option<T>,
}

#[derive(Serialize)]
struct PeerServerInfoVO {
    addr: String,
    latency_ms: u32,
    connected: bool,
    is_outbound: bool,
}

#[derive(Serialize)]
struct PeerServersResponse {
    outbound: Vec<PeerServerInfoVO>,
    inbound: Vec<PeerServerInfoVO>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: 200,
            msg: "success".to_string(),
            data: Some(data),
        }
    }
    pub fn ok_msg(msg: impl Into<String>) -> Self {
        Self {
            code: 200,
            msg: msg.into(),
            data: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            code: 400,
            msg: msg.into(),
            data: None,
        }
    }
    pub fn err_code(code: i32, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
            data: None,
        }
    }
}

impl<T> IntoResponse for ApiResponse<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

#[derive(Clone)]
struct AppState {
    control_service: ControlService,
    auth_config: AuthConfig,
    config_path: Arc<PathBuf>,
    config_update_lock: Arc<tokio::sync::Mutex<()>>,
    managed_device_update_locks: Arc<dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    client_access: Arc<parking_lot::RwLock<ClientAccessConfig>>,
    certificate_fingerprint: Arc<String>,
    client_listener_ports: ClientListenerPorts,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct ClientListenerPorts {
    tcp: Option<u16>,
    quic: Option<u16>,
    wss: Option<u16>,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
    pub jwt_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

async fn list_network_code(State(state): State<AppState>) -> ApiResponse<Vec<String>> {
    let codes = state.control_service.get_network_codes();
    ApiResponse::ok(codes)
}

async fn list_networks(State(state): State<AppState>) -> ApiResponse<Vec<NetworkInfoVO>> {
    let info = state.control_service.get_network_info().await;
    ApiResponse::ok(info)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NetworkWhitelistSettings {
    network_codes: Vec<String>,
}

fn normalize_network_codes(network_codes: Vec<String>) -> anyhow::Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for network_code in network_codes {
        validate_network_code(&network_code)?;
        normalized.insert(network_code);
    }
    Ok(normalized.into_iter().collect())
}

async fn get_network_whitelist(
    State(state): State<AppState>,
) -> ApiResponse<NetworkWhitelistSettings> {
    ApiResponse::ok(NetworkWhitelistSettings {
        network_codes: state.control_service.get_white_list(),
    })
}

async fn update_network_whitelist(
    State(state): State<AppState>,
    Json(body): Json<NetworkWhitelistSettings>,
) -> Response {
    let network_codes = match normalize_network_codes(body.network_codes) {
        Ok(network_codes) => network_codes,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };

    let _guard = state.config_update_lock.lock().await;
    let config_path = state.config_path.as_ref().clone();
    let persisted_codes = network_codes.clone();
    match tokio::task::spawn_blocking(move || persist_white_list(&config_path, &persisted_codes))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return ApiResponse::<()>::err(format!("保存配置失败: {error}")).into_response();
        }
        Err(error) => {
            return ApiResponse::<()>::err(format!("保存配置任务失败: {error}")).into_response();
        }
    }

    state
        .control_service
        .replace_white_list(network_codes.iter().cloned().collect::<HashSet<_>>());
    ApiResponse::ok(NetworkWhitelistSettings { network_codes }).into_response()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct Ikev2ServiceInfo {
    configured: bool,
    enabled: bool,
    runtime_active: bool,
    ike_bind: String,
    natt_bind: String,
    server_address: String,
    remote_id: String,
    dns: Vec<String>,
    cert: Option<String>,
    key: Option<String>,
    certificate_configured: bool,
    certificate_managed: bool,
    certificate_not_after: Option<u64>,
    ca_download_available: bool,
    server_certificate_download_available: bool,
    runtime_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UpdateIkev2ServiceRequest {
    enabled: bool,
    ike_bind: String,
    natt_bind: String,
    server_address: String,
    remote_id: String,
    #[serde(default)]
    dns: Vec<String>,
    cert: Option<String>,
    key: Option<String>,
}

fn optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct WireGuardServiceInfo {
    configured: bool,
    enabled: bool,
    runtime_active: bool,
    bind: String,
    endpoint: String,
    persistent_keepalive: u16,
    public_key: Option<String>,
    runtime_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UpdateWireGuardServiceRequest {
    enabled: bool,
    bind: String,
    endpoint: String,
    persistent_keepalive: u16,
}

fn wireguard_service_info(
    configured: bool,
    config: &WireGuardConfig,
    runtime_active: bool,
    runtime_error: Option<String>,
) -> WireGuardServiceInfo {
    WireGuardServiceInfo {
        configured,
        enabled: config.enabled,
        runtime_active,
        bind: config.bind.to_string(),
        endpoint: config.endpoint.clone(),
        persistent_keepalive: config.persistent_keepalive,
        public_key: config
            .private_key
            .as_ref()
            .and_then(|_| crate::server::wireguard::server_public_key(config).ok()),
        runtime_error,
    }
}

async fn get_wireguard_settings(State(state): State<AppState>) -> Response {
    let _guard = state.config_update_lock.lock().await;
    match load_wireguard_config(state.config_path.as_ref()) {
        Ok(configured) => {
            let config = configured.clone().unwrap_or_default();
            ApiResponse::ok(wireguard_service_info(
                configured.is_some(),
                &config,
                state.control_service.get_wireguard_manager().is_some(),
                state.control_service.get_wireguard_runtime_error(),
            ))
            .into_response()
        }
        Err(error) => {
            ApiResponse::<()>::err(format!("读取 WireGuard 配置失败: {error}")).into_response()
        }
    }
}

async fn update_wireguard_settings(
    State(state): State<AppState>,
    Json(body): Json<UpdateWireGuardServiceRequest>,
) -> Response {
    let _guard = state.config_update_lock.lock().await;
    let path = state.config_path.as_ref();
    let previous = match load_wireguard_config(path) {
        Ok(value) => value,
        Err(error) => {
            return ApiResponse::<()>::err(format!("读取 WireGuard 配置失败: {error}"))
                .into_response();
        }
    };
    let previous_text = match std::fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) => {
            return ApiResponse::<()>::err(format!("读取配置文件失败: {error}")).into_response();
        }
    };
    let bind = match body.bind.trim().parse::<SocketAddr>() {
        Ok(value) => value,
        Err(_) => return ApiResponse::<()>::err("WireGuard 监听地址无效").into_response(),
    };
    let mut candidate = WireGuardConfig {
        enabled: body.enabled,
        bind,
        endpoint: body.endpoint.trim().to_string(),
        private_key: previous
            .as_ref()
            .and_then(|value| value.private_key.clone()),
        persistent_keepalive: body.persistent_keepalive,
    };
    if candidate.private_key.as_deref().is_none_or(str::is_empty) {
        candidate.private_key = Some(crate::server::wireguard::generate_private_key());
    }
    if let Err(error) = candidate.validate() {
        return ApiResponse::<()>::err(error.to_string()).into_response();
    }
    if let Err(error) = persist_wireguard_config(path, &candidate) {
        return ApiResponse::<()>::err(format!("保存 WireGuard 配置失败: {error}")).into_response();
    }
    let old_handle = state.control_service.replace_wireguard_manager(None);
    if let Some(handle) = &old_handle {
        handle.shutdown().await;
    }
    let apply_result = if candidate.enabled {
        crate::server::wireguard::start(candidate.clone(), state.control_service.clone())
            .await
            .map(|handle| state.control_service.set_wireguard_manager(handle))
    } else {
        Ok(())
    };
    if let Err(error) = apply_result {
        let _ = crate::utils::config::persist_config_text(path, previous_text);
        if let Some(previous) = previous.filter(|value| value.enabled)
            && let Ok(handle) =
                crate::server::wireguard::start(previous, state.control_service.clone()).await
        {
            state.control_service.set_wireguard_manager(handle);
        }
        state
            .control_service
            .set_wireguard_runtime_error(Some(error.to_string()));
        return ApiResponse::<()>::err(format!("应用 WireGuard 配置失败，已恢复旧服务: {error}"))
            .into_response();
    }
    state.control_service.set_wireguard_runtime_error(None);
    ApiResponse::ok(wireguard_service_info(
        true,
        &candidate,
        state.control_service.get_wireguard_manager().is_some(),
        None,
    ))
    .into_response()
}

#[derive(Serialize)]
struct WireGuardAccessInfo {
    service: WireGuardServiceInfo,
    network_code: String,
    network_net: String,
    device_id: String,
    private_key: String,
    public_key: String,
    config: String,
}

async fn get_device_wireguard_access(
    State(state): State<AppState>,
    Path((network_code, device_id)): Path<(String, String)>,
) -> Response {
    let device = match state
        .control_service
        .get_device_record(&network_code, &device_id)
        .await
    {
        Ok(Some(device)) if device.client_type == ClientType::Wireguard => device,
        Ok(_) => {
            return no_store(
                ApiResponse::<()>::err(format!("WireGuard 设备 '{device_id}' 不存在"))
                    .into_response(),
            );
        }
        Err(error) => return no_store(ApiResponse::<()>::err(error.to_string()).into_response()),
    };
    let Some(ip) = device.ip.as_deref() else {
        return no_store(ApiResponse::<()>::err("WireGuard 设备未配置 IP").into_response());
    };
    let wireguard_input_routes = device.wireguard_input_routes.clone();
    let wireguard_dns = device.wireguard_dns.clone();
    let (Some(private_key), Some(public_key)) =
        (device.wireguard_private_key, device.wireguard_public_key)
    else {
        return no_store(ApiResponse::<()>::err("WireGuard 设备未配置密钥").into_response());
    };
    let _guard = state.config_update_lock.lock().await;
    let configured = match load_wireguard_config(state.config_path.as_ref()) {
        Ok(value) => value,
        Err(error) => return no_store(ApiResponse::<()>::err(error.to_string()).into_response()),
    };
    let service_config = configured.clone().unwrap_or_default();
    let server_public_key = match crate::server::wireguard::server_public_key(&service_config) {
        Ok(value) => value,
        Err(error) => return no_store(ApiResponse::<()>::err(error.to_string()).into_response()),
    };
    let network = state
        .control_service
        .get_network_info()
        .await
        .into_iter()
        .find(|network| network.network_code == network_code);
    let Some(network) = network else {
        return no_store(ApiResponse::<()>::err("网络不存在").into_response());
    };
    let mut allowed_ips = vec![network.net.to_string()];
    for subnet in wireguard_input_routes
        .iter()
        .map(|route| route.subnet.to_string())
    {
        if !allowed_ips.contains(&subnet) {
            allowed_ips.push(subnet);
        }
    }
    let dns_line = if wireguard_dns.is_empty() {
        String::new()
    } else {
        format!(
            "\nDNS = {}",
            wireguard_dns
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let config_text = format!(
        "[Interface]\nPrivateKey = {private_key}\nAddress = {ip}/{}{dns_line}\n\n[Peer]\nPublicKey = {server_public_key}\nAllowedIPs = {}\nEndpoint = {}\nPersistentKeepalive = {}\n",
        network.netmask,
        allowed_ips.join(", "),
        service_config.endpoint,
        service_config.persistent_keepalive,
    );
    no_store(
        ApiResponse::ok(WireGuardAccessInfo {
            service: wireguard_service_info(
                configured.is_some(),
                &service_config,
                state.control_service.get_wireguard_manager().is_some(),
                state.control_service.get_wireguard_runtime_error(),
            ),
            network_code,
            network_net: network.net.to_string(),
            device_id,
            private_key,
            public_key,
            config: config_text,
        })
        .into_response(),
    )
}

fn ikev2_service_info(
    configured: bool,
    config: &Ikev2Config,
    runtime_active: bool,
    runtime_error: Option<String>,
    config_path: &StdPath,
) -> Ikev2ServiceInfo {
    let ca_path = crate::utils::ikev2_cert::managed_ca_path(config_path);
    let certificate_managed =
        crate::utils::ikev2_cert::is_managed_certificate(config, config_path) && ca_path.exists();
    Ikev2ServiceInfo {
        configured,
        enabled: config.enabled,
        runtime_active,
        ike_bind: config.ike_bind.to_string(),
        natt_bind: config.natt_bind.to_string(),
        server_address: config.server_address.clone(),
        remote_id: config.remote_id.clone(),
        dns: config.dns.iter().map(ToString::to_string).collect(),
        cert: config
            .cert
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        key: config
            .key
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        certificate_configured: config.cert.is_some() && config.key.is_some(),
        certificate_managed,
        certificate_not_after: config.cert.as_ref().and_then(|path| {
            let bytes = std::fs::read(path).ok()?;
            let leaf = rustls_pemfile::certs(&mut std::io::Cursor::new(bytes))
                .next()?
                .ok()?;
            ryke::ikev2::sign::cert_validity(leaf.as_ref())
                .ok()
                .map(|(_, expiry)| expiry)
        }),
        ca_download_available: certificate_managed,
        server_certificate_download_available: config.cert.as_ref().is_some_and(|path| {
            std::fs::read(path).is_ok_and(|pem| {
                rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
                    .next()
                    .is_some_and(|certificate| certificate.is_ok())
            })
        }),
        runtime_error,
    }
}

async fn network_net(state: &AppState, network_code: &str) -> Option<String> {
    state
        .control_service
        .get_network_info()
        .await
        .into_iter()
        .find(|network| network.network_code == network_code)
        .map(|network| network.net.to_string())
}

async fn get_ikev2_settings(State(state): State<AppState>) -> Response {
    let _guard = state.config_update_lock.lock().await;
    let config_path = state.config_path.as_ref();
    let configured = match load_ikev2_config(config_path) {
        Ok(config) => config,
        Err(error) => {
            return ApiResponse::<()>::err(format!("读取 IKEv2 配置失败: {error}")).into_response();
        }
    };
    let config = configured.clone().unwrap_or_default();
    ApiResponse::ok(ikev2_service_info(
        configured.is_some(),
        &config,
        state.control_service.get_ikev2_manager().is_some(),
        state.control_service.get_ikev2_runtime_error(),
        config_path,
    ))
    .into_response()
}

async fn update_ikev2_settings(
    State(state): State<AppState>,
    Json(body): Json<UpdateIkev2ServiceRequest>,
) -> Response {
    let _guard = state.config_update_lock.lock().await;
    let config_path = state.config_path.as_ref();
    let previous = match load_ikev2_config(config_path) {
        Ok(config) => config,
        Err(error) => {
            log::error!("读取 IKEv2 配置失败: {error:#}");
            return ApiResponse::<()>::err(format!("读取 IKEv2 配置失败: {error}")).into_response();
        }
    };
    let mut candidate = match merge_ikev2_service(body) {
        Ok(config) => config,
        Err(error) => {
            log::error!("IKEv2 配置格式错误: {error:#}");
            return ApiResponse::<()>::err(format!("基础配置格式错误: {error}")).into_response();
        }
    };
    if !candidate.enabled
        && candidate.cert.is_none()
        && previous.as_ref().is_some_and(|config| {
            crate::utils::ikev2_cert::is_managed_certificate(config, config_path)
        })
    {
        candidate.cert = previous.as_ref().and_then(|config| config.cert.clone());
        candidate.key = previous.as_ref().and_then(|config| config.key.clone());
    }
    let (candidate, certificate) =
        match persist_and_apply_ikev2(&state, previous.as_ref(), candidate, None).await {
            Ok(result) => result,
            Err(error) => return ApiResponse::<()>::err(format!("{error:?}")).into_response(),
        };
    let mut info = ikev2_service_info(
        true,
        &candidate,
        state.control_service.get_ikev2_manager().is_some(),
        None,
        config_path,
    );
    info.certificate_managed = certificate.managed;
    info.ca_download_available = certificate.ca_path.is_some();
    info.certificate_not_after = certificate.not_after;
    ApiResponse::ok(info).into_response()
}

fn merge_ikev2_service(request: UpdateIkev2ServiceRequest) -> anyhow::Result<Ikev2Config> {
    let dns = request
        .dns
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().parse::<Ipv4Addr>())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Ikev2Config {
        enabled: request.enabled,
        ike_bind: request.ike_bind.trim().parse()?,
        natt_bind: request.natt_bind.trim().parse()?,
        server_address: request.server_address.trim().to_string(),
        remote_id: request.remote_id.trim().to_string(),
        cert: optional_text(request.cert).map(PathBuf::from),
        key: optional_text(request.key).map(PathBuf::from),
        dns,
    })
}

fn base_config_changed(old: &Ikev2Config, new: &Ikev2Config) -> bool {
    old.enabled != new.enabled
        || old.ike_bind != new.ike_bind
        || old.natt_bind != new.natt_bind
        || old.remote_id != new.remote_id
        || old.cert != new.cert
        || old.key != new.key
        || old.dns != new.dns
}

async fn apply_ikev2_runtime(
    state: &AppState,
    previous: Option<&Ikev2Config>,
    config: &Ikev2Config,
    changed_network: Option<&str>,
) -> anyhow::Result<()> {
    if changed_network.is_none() && previous.is_some_and(|old| !base_config_changed(old, config)) {
        return Ok(());
    }
    let existing = state.control_service.get_ikev2_manager();
    if !config.enabled {
        if let Some(old) = state.control_service.replace_ikev2_manager(None) {
            old.shutdown().await;
        }
        return Ok(());
    }
    if let Some(existing) = existing {
        let bind_changed = previous.is_some_and(|old| {
            old.ike_bind != config.ike_bind || old.natt_bind != config.natt_bind
        });
        if bind_changed {
            let old = state.control_service.replace_ikev2_manager(None);
            if let Some(old) = &old {
                old.shutdown().await;
                tokio::task::yield_now().await;
            }
            match crate::server::ikev2::start(config.clone(), state.control_service.clone()).await {
                Ok(replacement) => state.control_service.set_ikev2_manager(replacement),
                Err(error) => {
                    if let Some(previous) = previous
                        && let Ok(restored) = crate::server::ikev2::start(
                            previous.clone(),
                            state.control_service.clone(),
                        )
                        .await
                    {
                        state.control_service.set_ikev2_manager(restored);
                    }
                    return Err(error);
                }
            }
        } else {
            let changed_network = previous
                .filter(|old| !base_config_changed(old, config))
                .and_then(|_| changed_network.map(str::to_string));
            if let Err(error) = existing
                .reload_network_config(config.clone(), changed_network)
                .await
            {
                state.control_service.replace_ikev2_manager(None);
                if let Some(previous) = previous
                    && previous.enabled
                    && let Ok(restored) =
                        crate::server::ikev2::start(previous.clone(), state.control_service.clone())
                            .await
                {
                    state.control_service.set_ikev2_manager(restored);
                }
                return Err(error);
            }
        }
    } else {
        let manager =
            crate::server::ikev2::start(config.clone(), state.control_service.clone()).await?;
        state.control_service.set_ikev2_manager(manager);
    }
    Ok(())
}

fn restore_certificate_backup(
    backup: &mut Option<crate::utils::ikev2_cert::ManagedCertificateBackup>,
) {
    if let Some(backup) = backup.take()
        && let Err(error) = backup.restore()
    {
        log::error!("IKEv2 证书回滚失败: {error:#}");
    }
}

async fn persist_and_apply_ikev2(
    state: &AppState,
    previous: Option<&Ikev2Config>,
    mut candidate: Ikev2Config,
    changed_network: Option<&str>,
) -> anyhow::Result<(Ikev2Config, crate::utils::ikev2_cert::CertificateInfo)> {
    let config_path = state.config_path.as_ref();
    let previous_text = std::fs::read_to_string(config_path).context("读取配置文件失败")?;
    let mut certificate_backup = Some(
        crate::utils::ikev2_cert::backup_managed_certificate_files(config_path)
            .context("备份 IKEv2 证书失败")?,
    );
    let certificate =
        match crate::utils::ikev2_cert::prepare_certificate(&mut candidate, config_path) {
            Ok(certificate) => certificate,
            Err(error) => {
                log::error!(
                    "准备 IKEv2 证书失败: enabled={}, remote_id={:?}, error={error:#}",
                    candidate.enabled,
                    candidate.remote_id
                );
                restore_certificate_backup(&mut certificate_backup);
                return Err(error).context("准备 IKEv2 证书失败");
            }
        };
    if let Err(error) = crate::server::ikev2::validate_runtime_config(&candidate) {
        log::error!(
            "IKEv2 配置校验失败: enabled={}, ike_bind={}, natt_bind={}, remote_id={:?}, error={error:#}",
            candidate.enabled,
            candidate.ike_bind,
            candidate.natt_bind,
            candidate.remote_id
        );
        restore_certificate_backup(&mut certificate_backup);
        return Err(error).context("IKEv2 配置无效");
    }
    if let Err(error) = persist_ikev2_config(config_path, &candidate) {
        log::error!(
            "保存 IKEv2 配置失败: enabled={}, ike_bind={}, natt_bind={}, remote_id={:?}, error={error:#}",
            candidate.enabled,
            candidate.ike_bind,
            candidate.natt_bind,
            candidate.remote_id
        );
        restore_certificate_backup(&mut certificate_backup);
        return Err(error).context("保存 IKEv2 配置失败");
    }
    if let Err(error) = apply_ikev2_runtime(state, previous, &candidate, changed_network).await {
        log::error!(
            "IKEv2 服务启动或应用配置失败: enabled={}, ike_bind={}, natt_bind={}, remote_id={:?}, error={error:#}",
            candidate.enabled,
            candidate.ike_bind,
            candidate.natt_bind,
            candidate.remote_id
        );
        if let Err(rollback_error) =
            crate::utils::config::persist_config_text(config_path, previous_text)
        {
            log::error!("IKEv2 配置回滚失败: {rollback_error:#}");
        }
        restore_certificate_backup(&mut certificate_backup);
        state
            .control_service
            .set_ikev2_runtime_error(Some(error.to_string()));
        return Err(error).context("应用 IKEv2 配置失败，已保留旧服务");
    }
    state.control_service.set_ikev2_runtime_error(None);
    Ok((candidate, certificate))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct Ikev2AccessInfo {
    service: Ikev2ServiceInfo,
    network_code: String,
    network_net: String,
    username: String,
    password: String,
}

async fn get_device_ikev2_access(
    State(state): State<AppState>,
    Path((network_code, device_id)): Path<(String, String)>,
) -> Response {
    let Some(network_net) = network_net(&state, &network_code).await else {
        return no_store(
            ApiResponse::<()>::err(format!("网络编号 '{network_code}' 不存在")).into_response(),
        );
    };
    let device = match state
        .control_service
        .get_device_record(&network_code, &device_id)
        .await
    {
        Ok(Some(device)) if device.client_type == ClientType::Ikev2 => device,
        Ok(_) => {
            return no_store(
                ApiResponse::<()>::err(format!("IKEv2 设备 '{device_id}' 不存在")).into_response(),
            );
        }
        Err(error) => return no_store(ApiResponse::<()>::err(error.to_string()).into_response()),
    };
    let Some(password) = device.ikev2_password else {
        return no_store(ApiResponse::<()>::err("IKEv2 设备未配置密码").into_response());
    };
    let _guard = state.config_update_lock.lock().await;
    let configured = match load_ikev2_config(state.config_path.as_ref()) {
        Ok(config) => config,
        Err(error) => {
            return no_store(
                ApiResponse::<()>::err(format!("读取 IKEv2 配置失败: {error}")).into_response(),
            );
        }
    };
    let config = configured.clone().unwrap_or_default();
    no_store(
        ApiResponse::ok(Ikev2AccessInfo {
            service: ikev2_service_info(
                configured.is_some(),
                &config,
                state.control_service.get_ikev2_manager().is_some(),
                state.control_service.get_ikev2_runtime_error(),
                state.config_path.as_ref(),
            ),
            network_code,
            network_net,
            username: device_id,
            password,
        })
        .into_response(),
    )
}

#[derive(Deserialize)]
struct CertificateDownloadQuery {
    #[serde(default = "default_certificate_format")]
    format: String,
}

fn default_certificate_format() -> String {
    "der".to_string()
}

async fn download_ikev2_ca(
    State(state): State<AppState>,
    Query(query): Query<CertificateDownloadQuery>,
) -> Response {
    let _guard = state.config_update_lock.lock().await;
    match load_ikev2_config(state.config_path.as_ref()) {
        Ok(Some(config))
            if crate::utils::ikev2_cert::is_managed_certificate(
                &config,
                state.config_path.as_ref(),
            ) => {}
        Ok(_) => {
            return no_store(
                ApiResponse::<()>::err("当前未使用自动管理的 IKEv2 证书").into_response(),
            );
        }
        Err(error) => {
            return no_store(
                ApiResponse::<()>::err(format!("读取 IKEv2 配置失败: {error}")).into_response(),
            );
        }
    }
    let path = crate::utils::ikev2_cert::managed_ca_path(state.config_path.as_ref());
    let pem = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return no_store(
                ApiResponse::<()>::err("尚未生成可下载的 IKEv2 CA 证书").into_response(),
            );
        }
    };
    let (body, content_type, filename) = if query.format.eq_ignore_ascii_case("pem") {
        (pem, "application/x-pem-file", "vnt-ikev2-ca.pem")
    } else {
        let der = match rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
            .next()
            .transpose()
        {
            Ok(Some(cert)) => cert.as_ref().to_vec(),
            _ => {
                return no_store(
                    ApiResponse::<()>::err("自动生成的 IKEv2 CA 证书无效").into_response(),
                );
            }
        };
        (der, "application/pkix-cert", "vnt-ikev2-ca.cer")
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{filename}\""),
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

fn first_pem_certificate(pem: &[u8]) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(pem).ok()?;
    let start = text.find(BEGIN)?;
    let end = start + text[start..].find(END)? + END.len();
    let mut certificate = text.as_bytes()[start..end].to_vec();
    certificate.push(b'\n');
    Some(certificate)
}

async fn download_ikev2_server_certificate(
    State(state): State<AppState>,
    Query(query): Query<CertificateDownloadQuery>,
) -> Response {
    let _guard = state.config_update_lock.lock().await;
    let config = match load_ikev2_config(state.config_path.as_ref()) {
        Ok(Some(config)) => config,
        Ok(None) => {
            return no_store(ApiResponse::<()>::err("尚未配置 IKEv2 服务器证书").into_response());
        }
        Err(error) => {
            return no_store(
                ApiResponse::<()>::err(format!("读取 IKEv2 配置失败: {error}")).into_response(),
            );
        }
    };
    let Some(path) = config.cert else {
        return no_store(ApiResponse::<()>::err("尚未配置 IKEv2 服务器证书").into_response());
    };
    let pem = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return no_store(
                ApiResponse::<()>::err(format!("读取 IKEv2 服务器证书失败: {error}"))
                    .into_response(),
            );
        }
    };
    let der = match rustls_pemfile::certs(&mut std::io::Cursor::new(&pem))
        .next()
        .transpose()
    {
        Ok(Some(cert)) => cert.as_ref().to_vec(),
        _ => {
            return no_store(ApiResponse::<()>::err("IKEv2 服务器证书无效").into_response());
        }
    };
    let (body, content_type, filename) = if query.format.eq_ignore_ascii_case("pem") {
        let Some(leaf_pem) = first_pem_certificate(&pem) else {
            return no_store(ApiResponse::<()>::err("IKEv2 服务器证书 PEM 无效").into_response());
        };
        (leaf_pem, "application/x-pem-file", "vnt-ikev2-server.pem")
    } else {
        (der, "application/pkix-cert", "vnt-ikev2-server.cer")
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{filename}\""),
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

#[derive(Debug, Clone, Serialize)]
struct ManagedConfigVO {
    network_code: String,
    device_id: String,
    revision: i64,
    config_toml: String,
    advanced_config_toml: String,
    applied_revision: i64,
    status: String,
    error: Option<String>,
    overridden_fields: Vec<String>,
    updated_at: i64,
    subscription_issued: bool,
    subscription_server: String,
    traffic_servers_override: Option<Vec<String>>,
    inherits_traffic_servers: bool,
    effective_traffic_servers: Vec<String>,
    client_config: ManagedClientConfigForm,
}

impl ManagedConfigVO {
    /// Sync state comes from the live subscription session when there is one;
    /// without a session the server cannot know what the client runs and only
    /// reports that it is (or is not) waiting for one.
    fn from_record(
        value: ManagedConfigRecord,
        live: Option<SubscriptionLiveState>,
        default_subscription_server: String,
    ) -> Self {
        let subscription_issued = value.credential_key.is_some();
        let client_config =
            ManagedClientConfigForm::from_toml(&value.config_toml).unwrap_or_default();
        let advanced_config_toml = editable_client_config(&value.config_toml).unwrap_or_default();
        let (applied_revision, status, error, overridden_fields) = match live {
            Some(live) => (
                live.applied_revision as i64,
                live.status(value.revision).to_string(),
                live.apply_error(value.revision).map(str::to_string),
                live.overridden_fields,
            ),
            None => (
                0,
                if subscription_issued {
                    "awaiting_client"
                } else {
                    "not_connected_with_subscription"
                }
                .to_string(),
                None,
                Vec::new(),
            ),
        };
        let effective_traffic_servers = client_config.servers();
        let traffic_servers_override = value.traffic_servers_override.clone();
        let subscription_server = if value.subscription_server.is_empty() {
            default_subscription_server
        } else {
            value.subscription_server.clone()
        };
        Self {
            network_code: value.network_code,
            device_id: value.device_id,
            revision: value.revision,
            config_toml: value.config_toml,
            advanced_config_toml,
            applied_revision,
            status,
            error,
            overridden_fields,
            updated_at: value.updated_at,
            subscription_issued,
            subscription_server,
            inherits_traffic_servers: traffic_servers_override.is_none(),
            traffic_servers_override,
            effective_traffic_servers,
            client_config,
        }
    }
}

#[derive(Debug, Serialize)]
struct ManagedConfigMutationResponse {
    config: ManagedConfigVO,
    push_status: SubscriptionPushStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    subscription: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubscriptionResponse {
    subscription: String,
}

#[derive(Debug, Deserialize)]
struct ManagedConfigRequest {
    config_toml: Option<String>,
    subscription_server: Option<String>,
    current_server: Option<String>,
    other_servers: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_present_traffic_override")]
    traffic_servers_override: Option<Option<Vec<String>>>,
    client_config: Option<ManagedClientConfigForm>,
    device_name: Option<String>,
    ip: Option<String>,
    ip_type: Option<DeviceIpType>,
}

fn deserialize_present_traffic_override<'de, D>(
    deserializer: D,
) -> Result<Option<Option<Vec<String>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Vec<String>>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
struct CreateManagedDeviceRequest {
    network_code: String,
    device_id: String,
    device_name: String,
    ip: String,
    ip_type: Option<DeviceIpType>,
    #[serde(default)]
    config_toml: String,
    subscription_server: Option<String>,
    current_server: Option<String>,
    other_servers: Option<Vec<String>>,
    traffic_servers_override: Option<Vec<String>>,
    client_config: Option<ManagedClientConfigForm>,
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn resolve_managed_device_ips(
    current_ip: Option<&str>,
    requested_ip: Option<&str>,
) -> anyhow::Result<(Option<Ipv4Addr>, Ipv4Addr)> {
    let current_ip = current_ip
        .map(str::parse)
        .transpose()
        .map_err(|_| anyhow::anyhow!("设备当前 IP 无效"))?;
    let target_ip = requested_ip
        .map(str::parse)
        .transpose()
        .map_err(|_| anyhow::anyhow!("无效的 IP 地址"))?
        .or(current_ip)
        .ok_or_else(|| anyhow::anyhow!("请提供设备 IP 地址"))?;
    Ok((current_ip, target_ip))
}

fn requested_servers(
    current_server: Option<String>,
    other_servers: Option<Vec<String>>,
) -> anyhow::Result<Option<Vec<String>>> {
    match current_server {
        Some(current) => Ok(Some(
            std::iter::once(current)
                .chain(other_servers.unwrap_or_default())
                .collect(),
        )),
        None if other_servers
            .as_ref()
            .is_some_and(|servers| !servers.is_empty()) =>
        {
            anyhow::bail!("填写其他服务器地址时必须同时填写当前服务器地址")
        }
        None => Ok(None),
    }
}

fn requested_client_access(
    state: &AppState,
    subscription_server: Option<String>,
    traffic_servers: Vec<String>,
) -> anyhow::Result<ClientAccessConfig> {
    let defaults = state.client_access.read().clone();
    let subscription_server = subscription_server
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| defaults.effective_subscription_server());
    let access = ClientAccessConfig::new(subscription_server, traffic_servers);
    access.validate()?;
    Ok(access)
}

fn new_draft_record(
    state: &AppState,
    network_code: &str,
    device_id: &str,
    device_name: &str,
    configured_ip: Option<Ipv4Addr>,
    is_fixed_ip: bool,
    join_id: &str,
) -> anyhow::Result<ManagedConfigRecord> {
    let defaults = state.client_access.read().clone();
    let access = ClientAccessConfig::new(
        defaults.effective_subscription_server(),
        defaults.effective_traffic_servers(),
    );
    let resolved = "finger".to_string();
    let config_toml = canonicalize_client_config("", &access, &resolved, device_name, is_fixed_ip)?;
    let issued = if access.effective_subscription_server().is_empty() {
        None
    } else {
        Some(issue_subscription(
            &access,
            Some(state.certificate_fingerprint.as_str()),
            join_id,
        )?)
    };
    Ok(ManagedConfigRecord {
        network_code: network_code.to_string(),
        device_id: device_id.to_string(),
        revision: 1,
        config_toml,
        subscription_server: access.effective_subscription_server(),
        traffic_servers_override: None,
        credential_key: issued.as_ref().map(|issued| issued.credential_key.clone()),
        subscription: issued.as_ref().map(|issued| issued.subscription.clone()),
        join_id: join_id.to_string(),
        updated_at: unix_timestamp(),
        configured_device_name: device_name.to_string(),
        configured_ip,
        fixed_ip: is_fixed_ip.then_some(configured_ip).flatten(),
    })
}

#[derive(Serialize)]
struct ClientAccessSettingsVO {
    subscription_server: String,
    traffic_servers: Vec<String>,
    listener_ports: ClientListenerPorts,
}

fn client_access_settings(state: &AppState) -> ClientAccessSettingsVO {
    let config = state.client_access.read();
    ClientAccessSettingsVO {
        subscription_server: config.effective_subscription_server(),
        traffic_servers: config.effective_traffic_servers(),
        listener_ports: state.client_listener_ports,
    }
}

async fn get_client_access(State(state): State<AppState>) -> ApiResponse<ClientAccessSettingsVO> {
    ApiResponse::ok(client_access_settings(&state))
}

async fn update_client_access(
    State(state): State<AppState>,
    Json(body): Json<ClientAccessConfig>,
) -> Response {
    if let Err(error) = body.validate_optional() {
        return ApiResponse::<()>::err(error.to_string()).into_response();
    }
    let _guard = state.config_update_lock.lock().await;
    let previous = state.client_access.read().clone();
    let path = state.config_path.as_ref().clone();
    let persisted = body.clone();
    match tokio::task::spawn_blocking(move || persist_client_access_config(&path, &persisted)).await
    {
        Ok(Ok(config)) => {
            *state.client_access.write() = config.clone();
            if previous.effective_traffic_servers() != config.effective_traffic_servers() {
                match db::update_inherited_traffic_servers(
                    &config.effective_traffic_servers(),
                    &config.effective_subscription_server(),
                    unix_timestamp(),
                )
                .await
                {
                    Ok(records) => {
                        for record in records {
                            if let Err(error) = state
                                .control_service
                                .push_subscription_config(&record)
                                .await
                            {
                                log::warn!(
                                    "推送继承流量服务器的设备 {}/{} 失败: {error:#}",
                                    record.network_code,
                                    record.device_id
                                );
                            }
                        }
                    }
                    Err(error) => {
                        *state.client_access.write() = previous.clone();
                        let rollback_path = state.config_path.as_ref().clone();
                        let rollback = previous.clone();
                        if let Err(rollback_error) = tokio::task::spawn_blocking(move || {
                            persist_client_access_config(&rollback_path, &rollback)
                        })
                        .await
                        .unwrap_or_else(|join_error| Err(join_error.into()))
                        {
                            log::error!(
                                "继承设备事务失败后恢复 client_access 配置也失败: {rollback_error:#}"
                            );
                        }
                        return ApiResponse::<()>::err(format!("更新继承设备失败: {error}"))
                            .into_response();
                    }
                }
            }
            ApiResponse::ok(client_access_settings(&state)).into_response()
        }
        Ok(Err(error)) => ApiResponse::<()>::err(format!("保存配置失败: {error}")).into_response(),
        Err(error) => ApiResponse::<()>::err(format!("保存配置任务失败: {error}")).into_response(),
    }
}

async fn create_managed_device(
    State(state): State<AppState>,
    Json(body): Json<CreateManagedDeviceRequest>,
) -> Response {
    let ip: Ipv4Addr = match body.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return ApiResponse::<()>::err("无效的 IP 地址").into_response(),
    };
    let ip_type = body.ip_type.unwrap_or(DeviceIpType::Dynamic);
    let form_traffic_servers = body
        .client_config
        .as_ref()
        .map(ManagedClientConfigForm::servers);
    let request_traffic_servers = match requested_servers(body.current_server, body.other_servers) {
        Ok(value) => value.or(form_traffic_servers),
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let traffic_override = body
        .traffic_servers_override
        .clone()
        .or(request_traffic_servers);
    let effective_traffic_servers = traffic_override
        .clone()
        .unwrap_or_else(|| state.client_access.read().effective_traffic_servers());
    let access = match requested_client_access(
        &state,
        body.subscription_server.clone(),
        effective_traffic_servers,
    ) {
        Ok(access) => access,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let resolved_cert_mode = match resolve_cert_mode(Some(state.certificate_fingerprint.as_str())) {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let editable_toml = match body.client_config.as_ref() {
        Some(form) => match form.merge_into_toml(&body.config_toml) {
            Ok(value) => value,
            Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
        },
        None => body.config_toml.clone(),
    };
    if body.client_config.is_none()
        && let Err(error) = validate_managed_advanced_config(&editable_toml)
    {
        return ApiResponse::<()>::err(error.to_string()).into_response();
    }
    let config_toml = match canonicalize_client_config(
        &editable_toml,
        &access,
        &resolved_cert_mode,
        &body.device_name,
        ip_type == DeviceIpType::Fixed,
    ) {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let join_id = new_join_id();
    let issued = match issue_subscription(
        &access,
        Some(state.certificate_fingerprint.as_str()),
        &join_id,
    ) {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    if let Err(error) = state
        .control_service
        .add_device_typed(
            &body.network_code,
            &body.device_id,
            ip,
            ip_type,
            ClientType::Vnt,
            None,
            Some(body.device_name.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    {
        return ApiResponse::<()>::err(error.to_string()).into_response();
    }
    let record = ManagedConfigRecord {
        network_code: body.network_code.clone(),
        device_id: body.device_id.clone(),
        revision: 1,
        config_toml,
        subscription_server: access.effective_subscription_server(),
        traffic_servers_override: traffic_override,
        credential_key: Some(issued.credential_key.clone()),
        subscription: Some(issued.subscription.clone()),
        join_id,
        updated_at: unix_timestamp(),
        configured_device_name: body.device_name,
        configured_ip: Some(ip),
        fixed_ip: (ip_type == DeviceIpType::Fixed).then_some(ip),
    };
    if let Err(error) = db::create_managed_config(&record).await {
        // Keep the operation externally atomic even though the in-memory device
        // registry and SQLite are maintained by separate components.
        let _ = state
            .control_service
            .delete_device(&body.network_code, &body.device_id)
            .await;
        return ApiResponse::<()>::err(error.to_string()).into_response();
    }
    no_store(
        ApiResponse::ok(ManagedConfigMutationResponse {
            config: managed_config_vo_for(&state, &record).await,
            push_status: SubscriptionPushStatus::NotConnected,
            subscription: Some(issued.subscription),
        })
        .into_response(),
    )
}

/// Builds the editor VO, attaching the device's live subscription sync state.
async fn managed_config_vo_for(state: &AppState, record: &ManagedConfigRecord) -> ManagedConfigVO {
    let live = state
        .control_service
        .subscription_live_state(&record.network_code, &record.device_id);
    ManagedConfigVO::from_record(
        record.clone(),
        live,
        state.client_access.read().effective_subscription_server(),
    )
}

async fn get_managed_device_config(
    State(state): State<AppState>,
    Path((network_code, device_id)): Path<(String, String)>,
) -> Response {
    match db::get_managed_config(&network_code, &device_id).await {
        Ok(Some(record)) => {
            ApiResponse::ok(managed_config_vo_for(&state, &record).await).into_response()
        }
        Ok(None) => {
            let device = match state
                .control_service
                .get_device_record(&network_code, &device_id)
                .await
            {
                Ok(Some(value)) if value.client_type == ClientType::Vnt => value,
                Ok(Some(_)) => {
                    return ApiResponse::<()>::err("只有 VNT 设备支持客户端配置").into_response();
                }
                Ok(None) => {
                    return ApiResponse::<()>::err_code(404, "设备不存在").into_response();
                }
                Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
            };
            let record = match new_draft_record(
                &state,
                &network_code,
                &device_id,
                &device.device_name,
                device.ip.as_deref().and_then(|ip| ip.parse().ok()),
                device.ip_type == DeviceIpType::Fixed,
                &new_join_id(),
            ) {
                Ok(value) => value,
                Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
            };
            match db::create_managed_config(&record).await {
                Ok(()) => {
                    ApiResponse::ok(managed_config_vo_for(&state, &record).await).into_response()
                }
                Err(error) => ApiResponse::<()>::err(error.to_string()).into_response(),
            }
        }
        Err(error) => ApiResponse::<()>::err(error.to_string()).into_response(),
    }
}

async fn put_managed_device_config(
    State(state): State<AppState>,
    Path((network_code, device_id)): Path<(String, String)>,
    Json(body): Json<ManagedConfigRequest>,
) -> Response {
    let mutation_lock = state
        .managed_device_update_locks
        .entry(format!("{network_code}\0{device_id}"))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _mutation_guard = mutation_lock.lock().await;

    let device = match state
        .control_service
        .get_device_record(&network_code, &device_id)
        .await
    {
        Ok(Some(device)) if device.client_type == ClientType::Vnt => device,
        Ok(Some(_)) => {
            return ApiResponse::<()>::err("只有 VNT 设备支持客户端配置").into_response();
        }
        Ok(None) => return ApiResponse::<()>::err_code(404, "设备不存在").into_response(),
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let current = match db::get_managed_config(&network_code, &device_id).await {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let (old_ip, target_ip) =
        match resolve_managed_device_ips(device.ip.as_deref(), body.ip.as_deref()) {
            Ok(value) => value,
            Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
        };
    let target_ip_type = body.ip_type.unwrap_or(device.ip_type);
    let target_device_name = body
        .device_name
        .clone()
        .unwrap_or_else(|| device.device_name.clone());
    let base_changed = Some(target_ip) != old_ip
        || target_ip_type != device.ip_type
        || target_device_name != device.device_name;
    let form_traffic_servers = body
        .client_config
        .as_ref()
        .map(ManagedClientConfigForm::servers);
    let request_traffic_servers = match requested_servers(body.current_server, body.other_servers) {
        Ok(value) => value.or(form_traffic_servers),
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let traffic_servers_override = body.traffic_servers_override.clone().unwrap_or_else(|| {
        request_traffic_servers.map(Some).unwrap_or_else(|| {
            current
                .as_ref()
                .and_then(|record| record.traffic_servers_override.clone())
        })
    });
    let defaults = state.client_access.read().clone();
    let effective_traffic_servers = traffic_servers_override
        .clone()
        .unwrap_or_else(|| defaults.effective_traffic_servers());
    let requested_subscription_server = match body.subscription_server.as_deref() {
        Some(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        Some(_) => None,
        None => current
            .as_ref()
            .map(|record| record.subscription_server.clone())
            .filter(|value| !value.is_empty()),
    };
    let access = ClientAccessConfig::new(
        requested_subscription_server.unwrap_or_else(|| defaults.effective_subscription_server()),
        effective_traffic_servers,
    );
    if let Err(error) = access.validate() {
        return ApiResponse::<()>::err(error.to_string()).into_response();
    };
    let resolved = if access.effective_subscription_server().is_empty() {
        "standard".to_string()
    } else {
        match resolve_cert_mode(Some(state.certificate_fingerprint.as_str())) {
            Ok(value) => value,
            Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
        }
    };
    let base_source = body.config_toml.as_deref().unwrap_or_else(|| {
        current
            .as_ref()
            .map(|value| value.config_toml.as_str())
            .unwrap_or("")
    });
    if body.client_config.is_none()
        && body.config_toml.is_some()
        && let Err(error) = validate_managed_advanced_config(base_source)
    {
        return ApiResponse::<()>::err(error.to_string()).into_response();
    }
    let structured_source;
    let source = if let Some(form) = body.client_config.as_ref() {
        structured_source = match form.merge_into_toml(base_source) {
            Ok(value) => value,
            Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
        };
        structured_source.as_str()
    } else {
        base_source
    };
    let fixed_ip = (target_ip_type == DeviceIpType::Fixed).then_some(target_ip);
    let normalized = match canonicalize_client_config(
        source,
        &access,
        &resolved,
        &target_device_name,
        fixed_ip.is_some(),
    ) {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let previous = if let Some(current) = current.as_ref() {
        let previous = match canonicalize_stored_client_config(
            &current.config_toml,
            &current.configured_device_name,
            current.fixed_ip.is_some(),
            Some(current.subscription_server.as_str()).filter(|value| !value.trim().is_empty()),
        ) {
            Ok(value) => value,
            Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
        };
        Some(previous)
    } else {
        None
    };

    // Validation above is side-effect free. Only after the complete candidate
    // is known to be valid do we change the authoritative device-table fields.
    if base_changed
        && let Err(error) = state
            .control_service
            .update_device_with_password(
                &network_code,
                &device_id,
                target_ip,
                target_ip_type,
                None,
                Some(target_device_name.clone()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
    {
        return ApiResponse::<()>::err(error.to_string()).into_response();
    }

    let persist_result: anyhow::Result<(ManagedConfigRecord, bool)> = async {
        // 编辑时为空的设备补赋 join_id；已赋值则原样沿用
        let join_id = current
            .as_ref()
            .map(|record| record.join_id.clone())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(new_join_id);
        if let Some(current) = current.as_ref() {
            let semantic_equal = managed_config_semantically_equal(
                previous.as_deref().unwrap_or_default(),
                &normalized,
            )?;
            // Device-table IP is envelope metadata rather than TOML. It still
            // changes the effective managed configuration and therefore must
            // advance the revision for every allocation type.
            let traffic_changed = current.traffic_servers_override != traffic_servers_override;
            let subscription_changed =
                current.subscription_server != access.effective_subscription_server();
            if semantic_equal && !base_changed && !traffic_changed && !subscription_changed {
                if current.config_toml == normalized {
                    Ok((current.clone(), false))
                } else {
                    db::rewrite_managed_config(
                        &network_code,
                        &device_id,
                        &normalized,
                        &join_id,
                        unix_timestamp(),
                    )
                    .await?
                    .map(|record| (record, false))
                    .ok_or_else(|| anyhow::anyhow!("设备未启用服务端管理"))
                }
            } else {
                db::update_managed_config_with_endpoints(
                    &network_code,
                    &device_id,
                    &normalized,
                    &access.effective_subscription_server(),
                    traffic_servers_override.as_deref(),
                    &join_id,
                    unix_timestamp(),
                )
                .await?
                .map(|record| (record, true))
                .ok_or_else(|| anyhow::anyhow!("设备未启用服务端管理"))
            }
        } else {
            let record = ManagedConfigRecord {
                network_code: network_code.clone(),
                device_id: device_id.clone(),
                revision: 1,
                config_toml: normalized.clone(),
                subscription_server: access.effective_subscription_server(),
                traffic_servers_override: traffic_servers_override.clone(),
                credential_key: None,
                subscription: None,
                join_id,
                updated_at: unix_timestamp(),
                configured_device_name: target_device_name.clone(),
                configured_ip: Some(target_ip),
                fixed_ip,
            };
            db::create_managed_config(&record).await?;
            Ok((record, false))
        }
    }
    .await;

    let (record, should_push) = match persist_result {
        Ok(result) => result,
        Err(error) => {
            if base_changed
                && let Err(rollback_error) = state
                    .control_service
                    .restore_device_record(device.clone())
                    .await
            {
                return ApiResponse::<()>::err(format!(
                    "保存客户端配置失败: {error}; 恢复设备基础配置也失败: {rollback_error}"
                ))
                .into_response();
            }
            return ApiResponse::<()>::err(error.to_string()).into_response();
        }
    };
    let push_status = if should_push {
        match state
            .control_service
            .push_subscription_config(&record)
            .await
        {
            Ok(status) => status,
            Err(error) => {
                // The revision is already durable. A malformed historical
                // record must not be rolled back merely because it cannot be
                // packaged for this connection; registration catch-up remains
                // the recovery path after the record is repaired.
                log::error!(
                    "设备 {network_code}/{device_id} revision {} 的配置直推封包失败: {error:#}",
                    record.revision
                );
                SubscriptionPushStatus::Closed
            }
        }
    } else if current.is_some() {
        SubscriptionPushStatus::Unchanged
    } else {
        SubscriptionPushStatus::NotConnected
    };
    ApiResponse::ok(ManagedConfigMutationResponse {
        config: managed_config_vo_for(&state, &record).await,
        push_status,
        subscription: None,
    })
    .into_response()
}

async fn issue_missing_subscription(
    State(state): State<AppState>,
    Path((network_code, device_id)): Path<(String, String)>,
) -> Response {
    let device = match state
        .control_service
        .get_device_record(&network_code, &device_id)
        .await
    {
        Ok(Some(value)) if value.client_type == ClientType::Vnt => value,
        Ok(Some(_)) => return ApiResponse::<()>::err("只有 VNT 设备支持订阅链接").into_response(),
        Ok(None) => return ApiResponse::<()>::err_code(404, "设备不存在").into_response(),
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    // 老设备可能没有 join_id：签发前补齐（已赋值则原样沿用）
    let join_id = match db::ensure_join_id(&network_code, &device_id).await {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let (mut record, record_exists) = match db::get_managed_config(&network_code, &device_id).await
    {
        Ok(Some(value)) => (value, true),
        Ok(None) => match new_draft_record(
            &state,
            &network_code,
            &device_id,
            &device.device_name,
            device.ip.as_deref().and_then(|ip| ip.parse().ok()),
            device.ip_type == DeviceIpType::Fixed,
            &join_id,
        ) {
            Ok(value) => (value, false),
            Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
        },
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let defaults = state.client_access.read().clone();
    let access = ClientAccessConfig::new(
        if record.subscription_server.is_empty() {
            defaults.effective_subscription_server()
        } else {
            record.subscription_server.clone()
        },
        record
            .traffic_servers_override
            .clone()
            .unwrap_or_else(|| defaults.effective_traffic_servers()),
    );
    if access.effective_subscription_server().is_empty() {
        return ApiResponse::<()>::err("请先配置订阅服务器地址").into_response();
    }
    let resolved = match resolve_cert_mode(Some(state.certificate_fingerprint.as_str())) {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let normalized = match canonicalize_client_config(
        &record.config_toml,
        &access,
        &resolved,
        &device.device_name,
        device.ip_type == DeviceIpType::Fixed,
    ) {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let semantic_changed = match managed_config_semantically_equal(&record.config_toml, &normalized)
    {
        Ok(equal) => !equal,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let representation_changed = normalized != record.config_toml;
    record.config_toml = normalized;
    if !record_exists {
        if let Err(error) = db::create_managed_config(&record).await {
            return ApiResponse::<()>::err(error.to_string()).into_response();
        }
    } else if semantic_changed {
        match db::update_managed_config(
            &network_code,
            &device_id,
            &record.config_toml,
            &join_id,
            unix_timestamp(),
        )
        .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return ApiResponse::<()>::err_code(404, "设备配置不存在").into_response();
            }
            Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
        }
    } else if representation_changed {
        match db::rewrite_managed_config(
            &network_code,
            &device_id,
            &record.config_toml,
            &join_id,
            unix_timestamp(),
        )
        .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return ApiResponse::<()>::err_code(404, "设备配置不存在").into_response();
            }
            Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
        }
    }
    let issued = match issue_subscription(
        &access,
        Some(state.certificate_fingerprint.as_str()),
        &join_id,
    ) {
        Ok(value) => value,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    match db::rotate_subscription_credentials(
        &network_code,
        &device_id,
        &issued.credential_key,
        &issued.subscription,
        &join_id,
        unix_timestamp(),
    )
    .await
    {
        Ok(true) => {
            state
                .control_service
                .disconnect_subscription_session(&network_code, &device_id);
            no_store(
                ApiResponse::ok(SubscriptionResponse {
                    subscription: issued.subscription,
                })
                .into_response(),
            )
        }
        Ok(false) => ApiResponse::<()>::err_code(404, "设备未启用服务端管理").into_response(),
        Err(error) => ApiResponse::<()>::err(error.to_string()).into_response(),
    }
}

async fn get_subscription(
    State(state): State<AppState>,
    Path((network_code, device_id)): Path<(String, String)>,
) -> Response {
    let record = match db::get_managed_config(&network_code, &device_id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            let device = match state
                .control_service
                .get_device_record(&network_code, &device_id)
                .await
            {
                Ok(Some(device)) if device.client_type == ClientType::Vnt => device,
                Ok(Some(_)) => {
                    return ApiResponse::<()>::err("只有 VNT 设备支持订阅链接").into_response();
                }
                Ok(None) => return ApiResponse::<()>::err_code(404, "设备不存在").into_response(),
                Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
            };
            let record = match new_draft_record(
                &state,
                &network_code,
                &device_id,
                &device.device_name,
                device.ip.as_deref().and_then(|ip| ip.parse().ok()),
                device.ip_type == DeviceIpType::Fixed,
                &new_join_id(),
            ) {
                Ok(record) => record,
                Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
            };
            if let Err(error) = db::create_managed_config(&record).await {
                return ApiResponse::<()>::err(error.to_string()).into_response();
            }
            record
        }
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    if let Some(subscription) = record.subscription {
        return no_store(ApiResponse::ok(SubscriptionResponse { subscription }).into_response());
    }
    // A VNT device imported from the previous release receives its link on
    // the first copy. That release had no vnt_device_configs table.
    issue_missing_subscription(State(state), Path((network_code, device_id))).await
}

async fn disconnect_managed_device(
    State(state): State<AppState>,
    Path((network_code, device_id)): Path<(String, String)>,
) -> ApiResponse<()> {
    if state
        .control_service
        .disconnect_subscription_session(&network_code, &device_id)
    {
        ApiResponse::ok_msg("已断开订阅链接同步会话")
    } else {
        ApiResponse::ok_msg("设备当前没有订阅链接同步会话")
    }
}

#[derive(Deserialize)]
struct DeviceQueryParams {
    code: String,
}

async fn list_devices(
    State(state): State<AppState>,
    Query(params): Query<DeviceQueryParams>,
) -> ApiResponse<Vec<DeviceInfoVO>> {
    match state.control_service.get_device_info(&params.code).await {
        Some(devices) => ApiResponse::ok(devices),
        None => ApiResponse::err(format!("Network code '{}' not found", params.code)),
    }
}

async fn list_peer_servers(State(state): State<AppState>) -> ApiResponse<PeerServersResponse> {
    let peer_manager = match state.control_service.get_peer_manager() {
        Some(manager) => manager,
        None => {
            return ApiResponse::ok(PeerServersResponse {
                outbound: vec![],
                inbound: vec![],
            });
        }
    };

    let peer_servers = peer_manager.get_peer_servers();
    let mut outbound = Vec::new();
    let mut inbound = Vec::new();

    for peer_info in peer_servers {
        let info = PeerServerInfoVO {
            addr: peer_info.get_addr(),
            latency_ms: peer_info.get_latency(),
            connected: peer_info.is_connected(),
            is_outbound: peer_info.is_outbound(),
        };

        if info.is_outbound {
            outbound.push(info);
        } else {
            inbound.push(info);
        }
    }

    ApiResponse::ok(PeerServersResponse { outbound, inbound })
}

#[derive(Deserialize)]
struct AddPeerServerRequest {
    server_addr: String,
}

async fn add_peer_server(
    State(state): State<AppState>,
    Json(body): Json<AddPeerServerRequest>,
) -> Response {
    let peer_manager = match state.control_service.get_peer_manager() {
        Some(manager) => manager,
        None => {
            return ApiResponse::<()>::err("服务器互联功能未启用").into_response();
        }
    };

    match peer_manager.add_peer_server(body.server_addr).await {
        Ok(()) => ApiResponse::<()>::ok_msg("添加成功").into_response(),
        Err(e) => ApiResponse::<()>::err(e.to_string()).into_response(),
    }
}

async fn delete_peer_server(
    State(state): State<AppState>,
    Path(server_addr): Path<String>,
) -> Response {
    let peer_manager = match state.control_service.get_peer_manager() {
        Some(manager) => manager,
        None => {
            return ApiResponse::<()>::err("服务器互联功能未启用").into_response();
        }
    };

    match peer_manager.remove_peer_server(&server_addr).await {
        Ok(()) => ApiResponse::<()>::ok_msg("删除成功").into_response(),
        Err(e) => ApiResponse::<()>::err(e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateNetworkRequest {
    network_code: String,
    gateway: String,
    netmask: u8,
    lease_duration: Option<u64>,
    network_type: Option<NetworkType>,
}

async fn create_network(
    State(state): State<AppState>,
    Json(body): Json<CreateNetworkRequest>,
) -> Response {
    let gateway: Ipv4Addr = match body.gateway.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return ApiResponse::<()>::err("无效的网关地址").into_response();
        }
    };

    if body.netmask > 30 {
        return ApiResponse::<()>::err("无效的掩码").into_response();
    }

    let lease_duration = body.lease_duration.map(std::time::Duration::from_secs);

    match state
        .control_service
        .add_network(
            body.network_code,
            gateway,
            body.netmask,
            lease_duration,
            body.network_type.unwrap_or(NetworkType::Public),
        )
        .await
    {
        Ok(()) => ApiResponse::<()>::ok_msg("创建成功").into_response(),
        Err(e) => ApiResponse::<()>::err(e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct UpdateNetworkRequest {
    gateway: String,
    netmask: u8,
    lease_duration: u64,
    network_type: Option<NetworkType>,
}

async fn update_network(
    State(state): State<AppState>,
    Path(network_code): Path<String>,
    Json(body): Json<UpdateNetworkRequest>,
) -> Response {
    let gateway: Ipv4Addr = match body.gateway.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return ApiResponse::<()>::err("无效的网关地址").into_response();
        }
    };

    if body.netmask > 30 {
        return ApiResponse::<()>::err("无效的掩码").into_response();
    }

    let lease_duration = std::time::Duration::from_secs(body.lease_duration);
    let network_type = body.network_type.unwrap_or_else(|| {
        state
            .control_service
            .get_network_type(&network_code)
            .unwrap_or(NetworkType::Public)
    });

    match state
        .control_service
        .update_network(
            &network_code,
            gateway,
            body.netmask,
            lease_duration,
            network_type,
        )
        .await
    {
        Ok(()) => ApiResponse::<()>::ok_msg("更新成功").into_response(),
        Err(e) => ApiResponse::<()>::err(e.to_string()).into_response(),
    }
}

async fn delete_network(
    State(state): State<AppState>,
    Path(network_code): Path<String>,
) -> Response {
    match state.control_service.delete_network(&network_code).await {
        Ok(()) => ApiResponse::<()>::ok_msg("删除成功").into_response(),
        Err(e) => ApiResponse::<()>::err(e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct DeleteDeviceParams {
    code: String,
    device_id: String,
}

async fn delete_device(
    State(state): State<AppState>,
    Query(params): Query<DeleteDeviceParams>,
) -> Response {
    match state
        .control_service
        .delete_device(&params.code, &params.device_id)
        .await
    {
        Ok(()) => ApiResponse::<()>::ok_msg("删除成功").into_response(),
        Err(e) => ApiResponse::<()>::err(e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateDeviceRequest {
    network_code: String,
    device_id: String,
    device_name: Option<String>,
    ip: String,
    ip_type: Option<DeviceIpType>,
    #[serde(default)]
    client_type: ClientType,
    ikev2_password: Option<String>,
    #[serde(default)]
    ikev2_output_subnets: Vec<ipnet::Ipv4Net>,
    #[serde(default)]
    ikev2_input_routes: Vec<Ikev2InputRoute>,
    #[serde(default)]
    wireguard_output_subnets: Vec<ipnet::Ipv4Net>,
    #[serde(default)]
    wireguard_input_routes: Vec<Ikev2InputRoute>,
    #[serde(default)]
    wireguard_dns: Vec<Ipv4Addr>,
    wireguard_private_key: Option<String>,
    #[serde(default)]
    config_toml: String,
    subscription_server: Option<String>,
    current_server: Option<String>,
    other_servers: Option<Vec<String>>,
    traffic_servers_override: Option<Vec<String>>,
}

async fn create_device(
    State(state): State<AppState>,
    Json(body): Json<CreateDeviceRequest>,
) -> Response {
    let ip: Ipv4Addr = match body.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return ApiResponse::<()>::err("无效的 IP 地址").into_response(),
    };
    let client_type = body.client_type;
    let ip_type = body.ip_type.unwrap_or(DeviceIpType::Dynamic);
    if client_type == ClientType::Vnt {
        let device_name = body.device_name.unwrap_or_else(|| body.device_id.clone());
        return create_managed_device(
            State(state),
            Json(CreateManagedDeviceRequest {
                network_code: body.network_code,
                device_id: body.device_id,
                device_name,
                ip: body.ip,
                ip_type: Some(ip_type),
                config_toml: body.config_toml,
                subscription_server: body.subscription_server,
                current_server: body.current_server,
                other_servers: body.other_servers,
                traffic_servers_override: body.traffic_servers_override,
                client_config: None,
            }),
        )
        .await;
    }
    match state
        .control_service
        .add_device_typed(
            &body.network_code,
            &body.device_id,
            ip,
            ip_type,
            client_type,
            body.ikev2_password,
            body.device_name,
            Some(body.ikev2_output_subnets),
            Some(body.ikev2_input_routes),
            Some(body.wireguard_output_subnets),
            Some(body.wireguard_input_routes),
            Some(body.wireguard_dns),
            optional_text(body.wireguard_private_key),
        )
        .await
    {
        Ok(()) => ApiResponse::<()>::ok_msg("添加成功").into_response(),
        Err(error) => ApiResponse::<()>::err(error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct UpdateDeviceRequest {
    network_code: String,
    device_name: Option<String>,
    ip: String,
    ip_type: DeviceIpType,
    ikev2_password: Option<String>,
    ikev2_output_subnets: Option<Vec<ipnet::Ipv4Net>>,
    ikev2_input_routes: Option<Vec<Ikev2InputRoute>>,
    wireguard_output_subnets: Option<Vec<ipnet::Ipv4Net>>,
    wireguard_input_routes: Option<Vec<Ikev2InputRoute>>,
    wireguard_dns: Option<Vec<Ipv4Addr>>,
    wireguard_private_key: Option<String>,
}

async fn update_device(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    Json(body): Json<UpdateDeviceRequest>,
) -> Response {
    match state
        .control_service
        .get_device_record(&body.network_code, &device_id)
        .await
    {
        Ok(Some(device)) if device.client_type == ClientType::Vnt => {
            return ApiResponse::<()>::err("VNT 设备的名称和 IP 由客户端配置接口统一更新")
                .into_response();
        }
        Ok(Some(_)) => {}
        Ok(None) => return ApiResponse::<()>::err_code(404, "设备不存在").into_response(),
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    }
    let ip: Ipv4Addr = match body.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return ApiResponse::<()>::err("无效的 IP 地址").into_response(),
    };
    match state
        .control_service
        .update_device_with_password(
            &body.network_code,
            &device_id,
            ip,
            body.ip_type,
            body.ikev2_password,
            body.device_name,
            body.ikev2_output_subnets,
            body.ikev2_input_routes,
            body.wireguard_output_subnets,
            body.wireguard_input_routes,
            body.wireguard_dns,
            optional_text(body.wireguard_private_key),
        )
        .await
    {
        Ok(()) => ApiResponse::<()>::ok_msg("更新成功").into_response(),
        Err(error) => ApiResponse::<()>::err(error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

async fn login(State(state): State<AppState>, Json(body): Json<LoginRequest>) -> Response {
    let auth_cfg = &state.auth_config;

    if body.username == auth_cfg.username && body.password == auth_cfg.password {
        let exp = time::OffsetDateTime::now_utc() + time::Duration::days(1);
        let claims = Claims {
            sub: body.username,
            exp: exp.unix_timestamp(),
        };

        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &EncodingKey::from_secret(auth_cfg.jwt_secret.as_bytes()),
        )
        .unwrap();

        ApiResponse::ok(LoginResponse { token }).into_response()
    } else {
        let resp = ApiResponse::<()>::err_code(401, "invalid username or password");
        (StatusCode::UNAUTHORIZED, Json(resp)).into_response()
    }
}

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    let Some(token) = token else {
        let resp = ApiResponse::<()>::err_code(401, "missing token");
        return (StatusCode::UNAUTHORIZED, Json(resp)).into_response();
    };

    let validation = Validation::default();
    match jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.auth_config.jwt_secret.as_bytes()),
        &validation,
    ) {
        Ok(_) => next.run(request).await,
        Err(e) => {
            let resp = ApiResponse::<()>::err_code(401, format!("invalid token: {e}"));
            (StatusCode::UNAUTHORIZED, Json(resp)).into_response()
        }
    }
}

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/').to_string();

    if path.is_empty() {
        path = "index.html".to_string();
    }

    // 优先从本地文件系统加载，fallback 到内嵌资源。
    // 只接受普通相对路径组件，避免通过 `..`、绝对路径或 Windows 盘符逃逸 static 目录。
    if let Some(local_path) = safe_static_path(&path)
        && let Ok(static_root) = tokio::fs::canonicalize("static").await
        && let Ok(canonical_path) = tokio::fs::canonicalize(&local_path).await
        && canonical_path.starts_with(static_root)
        && canonical_path.is_file()
        && let Ok(content) = tokio::fs::read(&canonical_path).await
    {
        log::debug!("Serving file from local filesystem: {:?}", canonical_path);
        let mime = from_path(&canonical_path).first_or_octet_stream();
        return (
            [
                (header::CONTENT_TYPE, mime.as_ref()),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            content,
        )
            .into_response();
    }

    if let Some(content) = Assets::get(&path) {
        log::debug!("Serving file from embedded assets: {}", path);
        let mime = from_path(&path).first_or_octet_stream();
        return (
            [
                (header::CONTENT_TYPE, mime.as_ref()),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            Body::from(content.data),
        )
            .into_response();
    }

    (StatusCode::NOT_FOUND, "404 Not Found").into_response()
}

fn safe_static_path(path: &str) -> Option<PathBuf> {
    if path.contains('\\') || path.contains(':') {
        return None;
    }
    let relative = StdPath::new(path);
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }

    Some(StdPath::new("static").join(relative))
}

#[allow(clippy::too_many_arguments)]
pub async fn start_http_server(
    control_service: ControlService,
    username: String,
    password: String,
    web_bind: SocketAddr,
    config_path: PathBuf,
    client_access: ClientAccessConfig,
    certificate_fingerprint: String,
    client_listener_ports: (Option<u16>, Option<u16>, Option<u16>),
) -> anyhow::Result<()> {
    let jwt_secret: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let auth_config = AuthConfig {
        username,
        password,
        jwt_secret,
    };

    let app_state = AppState {
        control_service,
        auth_config,
        config_path: Arc::new(config_path),
        config_update_lock: Arc::new(tokio::sync::Mutex::new(())),
        managed_device_update_locks: Arc::new(dashmap::DashMap::new()),
        client_access: Arc::new(parking_lot::RwLock::new(client_access)),
        certificate_fingerprint: Arc::new(certificate_fingerprint),
        client_listener_ports: ClientListenerPorts {
            tcp: client_listener_ports.0,
            quic: client_listener_ports.1,
            wss: client_listener_ports.2,
        },
    };

    let app = build_app(app_state);

    log::info!("HTTP Server running at http://{}", web_bind);

    let listener =
        tokio::net::TcpListener::from_std(crate::utils::net::bind_tcp_listener(web_bind)?)?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_app(app_state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api_routes = Router::new()
        .route("/network_codes", get(list_network_code))
        .route("/networks", get(list_networks))
        .route("/networks", post(create_network))
        .route("/networks/{network_code}", put(update_network))
        .route("/networks/{network_code}", delete(delete_network))
        .route(
            "/networks/{network_code}/devices/{device_id}/ikev2-access",
            get(get_device_ikev2_access),
        )
        .route(
            "/networks/{network_code}/devices/{device_id}/wireguard-access",
            get(get_device_wireguard_access),
        )
        .route("/ikev2/ca-certificate", get(download_ikev2_ca))
        .route(
            "/ikev2/server-certificate",
            get(download_ikev2_server_certificate),
        )
        .route("/devices", get(list_devices))
        .route("/devices", post(create_device))
        .route("/devices", delete(delete_device))
        .route("/devices/{device_id}", put(update_device))
        .route(
            "/networks/{network_code}/devices/{device_id}/client-config",
            get(get_managed_device_config).put(put_managed_device_config),
        )
        .route(
            "/networks/{network_code}/devices/{device_id}/subscription",
            get(get_subscription),
        )
        .route(
            "/networks/{network_code}/devices/{device_id}/disconnect",
            post(disconnect_managed_device),
        )
        .route("/peer_servers", get(list_peer_servers))
        .route("/peer_servers", post(add_peer_server))
        .route("/peer_servers/{server_addr}", delete(delete_peer_server))
        .route(
            "/settings/network-whitelist",
            get(get_network_whitelist).put(update_network_whitelist),
        )
        .route(
            "/settings/ikev2",
            get(get_ikev2_settings).put(update_ikev2_settings),
        )
        .route(
            "/settings/wireguard",
            get(get_wireguard_settings).put(update_wireguard_settings),
        )
        .route(
            "/settings/client-access",
            get(get_client_access).put(update_client_access),
        )
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    Router::new()
        .nest("/api", api_routes)
        .route("/api/login", post(login))
        .fallback(static_handler)
        .layer(cors)
        .with_state(app_state)
}

#[cfg(test)]
mod tests {
    use super::{
        AppState, AuthConfig, Claims, ClientListenerPorts, build_app, normalize_network_codes,
        requested_servers, resolve_managed_device_ips, safe_static_path,
    };
    use crate::server::control_server::db::{ClientType, DeviceIpType, Ikev2InputRoute};
    use crate::server::control_server::service::ControlService;
    use crate::utils::config::{ClientAccessConfig, Ikev2Config, update_ikev2_config};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use jsonwebtoken::{EncodingKey, Header};
    use std::collections::{HashMap, HashSet};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    #[test]
    fn safe_static_path_accepts_normal_relative_paths() {
        assert_eq!(
            safe_static_path("assets/app.js").as_deref(),
            Some(Path::new("static").join("assets/app.js").as_path())
        );
        assert_eq!(
            safe_static_path("index.html").as_deref(),
            Some(Path::new("static").join("index.html").as_path())
        );
    }

    #[test]
    fn safe_static_path_rejects_paths_outside_static_root() {
        assert!(safe_static_path("../key.pem").is_none());
        assert!(safe_static_path("assets/../../config.toml").is_none());
        assert!(safe_static_path("/etc/passwd").is_none());
        assert!(safe_static_path(r"C:\Windows\win.ini").is_none());
    }

    #[test]
    fn whitelist_codes_are_validated_deduplicated_and_sorted() {
        assert_eq!(
            normalize_network_codes(vec![
                "zeta".to_string(),
                "alpha".to_string(),
                "zeta".to_string(),
            ])
            .unwrap(),
            vec!["alpha".to_string(), "zeta".to_string()]
        );
        assert!(normalize_network_codes(vec![" alpha".to_string()]).is_err());
    }

    #[test]
    fn managed_endpoints_keep_current_first_and_require_it_for_other_addresses() {
        assert_eq!(
            requested_servers(
                Some("tcp://vpn.example.com:29872".to_string()),
                Some(vec![
                    "quic://vpn.example.com:29872".to_string(),
                    "wss://vpn.example.com:443".to_string(),
                ]),
            )
            .unwrap()
            .unwrap(),
            vec![
                "tcp://vpn.example.com:29872".to_string(),
                "quic://vpn.example.com:29872".to_string(),
                "wss://vpn.example.com:443".to_string(),
            ]
        );
        assert!(
            requested_servers(None, Some(vec!["quic://vpn.example.com:29872".to_string()]))
                .is_err()
        );
    }

    #[test]
    fn unconfigured_client_access_has_no_subscription_server() {
        let access = ClientAccessConfig::default();
        assert!(access.effective_subscription_server().is_empty());
    }

    #[test]
    fn managed_device_update_accepts_a_requested_ip_after_dynamic_lease_expiry() {
        let (current_ip, target_ip) = resolve_managed_device_ips(None, Some("10.26.0.33")).unwrap();
        assert_eq!(current_ip, None);
        assert_eq!(target_ip.to_string(), "10.26.0.33");
        assert!(resolve_managed_device_ips(None, None).is_err());
    }

    #[tokio::test]
    async fn whitelist_settings_routes_require_auth_and_update_config_and_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("custom.toml");
        std::fs::write(
            &config_path,
            "network = \"10.26.0.0/24\"\nwhite_list = []\nlease_duration = 86400\n",
        )
        .unwrap();
        let control_service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let jwt_secret = "test-secret".to_string();
        let app = build_app(AppState {
            control_service: control_service.clone(),
            auth_config: AuthConfig {
                username: "admin".to_string(),
                password: "admin".to_string(),
                jwt_secret: jwt_secret.clone(),
            },
            config_path: Arc::new(config_path.clone()),
            config_update_lock: Arc::new(tokio::sync::Mutex::new(())),
            managed_device_update_locks: Arc::new(dashmap::DashMap::new()),
            client_access: Arc::new(parking_lot::RwLock::new(ClientAccessConfig::default())),
            certificate_fingerprint: Arc::new("0".repeat(64)),
            client_listener_ports: ClientListenerPorts::default(),
        });

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/settings/network-whitelist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let token = jsonwebtoken::encode(
            &Header::default(),
            &Claims {
                sub: "admin".to_string(),
                exp: (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
                    .unix_timestamp(),
            },
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap();
        let authorization = format!("Bearer {token}");

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/settings/network-whitelist")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);

        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/settings/network-whitelist")
                    .header(header::AUTHORIZATION, &authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"network_codes":["zeta","alpha","zeta"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::OK);
        assert_eq!(
            control_service.get_white_list(),
            vec!["alpha".to_string(), "zeta".to_string()]
        );
        let persisted = std::fs::read_to_string(config_path).unwrap();
        assert!(persisted.contains("white_list = [\"alpha\", \"zeta\"]"));

        let app_with_unwritable_config = build_app(AppState {
            control_service: control_service.clone(),
            auth_config: AuthConfig {
                username: "admin".to_string(),
                password: "admin".to_string(),
                jwt_secret,
            },
            config_path: Arc::new(directory.path().join("missing/config.toml")),
            config_update_lock: Arc::new(tokio::sync::Mutex::new(())),
            managed_device_update_locks: Arc::new(dashmap::DashMap::new()),
            client_access: Arc::new(parking_lot::RwLock::new(ClientAccessConfig::default())),
            certificate_fingerprint: Arc::new("0".repeat(64)),
            client_listener_ports: ClientListenerPorts::default(),
        });
        let failed_update = app_with_unwritable_config
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/settings/network-whitelist")
                    .header(header::AUTHORIZATION, authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"network_codes":["beta"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(failed_update.status(), StatusCode::OK);
        assert_eq!(
            control_service.get_white_list(),
            vec!["alpha".to_string(), "zeta".to_string()]
        );
    }

    #[tokio::test]
    async fn ikev2_access_is_device_scoped_no_store_and_hidden_from_device_list() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(
            &config_path,
            "network = \"10.26.0.0/24\"\nlease_duration = 86400\n",
        )
        .unwrap();
        let control_service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::from([("alpha".to_string(), "10.60.0.0/24".parse().unwrap())]),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        control_service
            .add_device_typed(
                "alpha",
                "alice",
                "10.60.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Ikev2,
                Some("private-password".to_string()),
                Some("Alice's device".to_string()),
                Some(vec!["192.168.88.0/24".parse().unwrap()]),
                Some(vec![Ikev2InputRoute {
                    subnet: "172.20.0.0/16".parse().unwrap(),
                    target_ip: "10.60.0.20".parse().unwrap(),
                }]),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let jwt_secret = "ike-access-test".to_string();
        let app = build_app(AppState {
            control_service,
            auth_config: AuthConfig {
                username: "admin".to_string(),
                password: "admin".to_string(),
                jwt_secret: jwt_secret.clone(),
            },
            config_path: Arc::new(config_path),
            config_update_lock: Arc::new(tokio::sync::Mutex::new(())),
            managed_device_update_locks: Arc::new(dashmap::DashMap::new()),
            client_access: Arc::new(parking_lot::RwLock::new(ClientAccessConfig::default())),
            certificate_fingerprint: Arc::new("0".repeat(64)),
            client_listener_ports: ClientListenerPorts::default(),
        });
        let token = jsonwebtoken::encode(
            &Header::default(),
            &Claims {
                sub: "admin".to_string(),
                exp: (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
                    .unix_timestamp(),
            },
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap();
        let authorization = format!("Bearer {token}");

        let list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/devices?code=alpha")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let list_body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let list_body = String::from_utf8(list_body.to_vec()).unwrap();
        assert!(!list_body.contains("private-password"));
        assert!(list_body.contains("\"ikev2_output_subnets\":[\"192.168.88.0/24\"]"));
        assert!(list_body.contains(
            "\"ikev2_input_routes\":[{\"subnet\":\"172.20.0.0/16\",\"target_ip\":\"10.60.0.20\"}]"
        ));

        let access = app
            .oneshot(
                Request::builder()
                    .uri("/api/networks/alpha/devices/alice/ikev2-access")
                    .header(header::AUTHORIZATION, authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            access.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let access_body = to_bytes(access.into_body(), usize::MAX).await.unwrap();
        let access_body = String::from_utf8(access_body.to_vec()).unwrap();
        assert!(access_body.contains("private-password"));
        assert!(access_body.contains("\"username\":\"alice\""));
    }

    #[tokio::test]
    async fn wireguard_access_is_device_scoped_no_store_and_private_key_is_hidden_from_list() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"network = "10.26.0.0/24"
lease_duration = 86400
[wireguard]
enabled = false
bind = "127.0.0.1:51820"
endpoint = "vpn.example.com:51820"
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
persistent_keepalive = 25
"#,
        )
        .unwrap();
        let control_service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::from([("alpha-wg".to_string(), "10.61.0.0/24".parse().unwrap())]),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        control_service
            .add_device_typed(
                "alpha-wg",
                "wg-alice",
                "10.61.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Wireguard,
                None,
                Some("Alice WG".to_string()),
                None,
                None,
                Some(vec!["192.168.90.7/24".parse().unwrap()]),
                Some(vec![Ikev2InputRoute {
                    subnet: "172.30.0.9/16".parse().unwrap(),
                    target_ip: "10.61.0.20".parse().unwrap(),
                }]),
                Some(vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()]),
                None,
            )
            .await
            .unwrap();
        let private_key = control_service
            .get_device_record("alpha-wg", "wg-alice")
            .await
            .unwrap()
            .unwrap()
            .wireguard_private_key
            .unwrap();
        let jwt_secret = "wg-access-test".to_string();
        let app = build_app(AppState {
            control_service,
            auth_config: AuthConfig {
                username: "admin".into(),
                password: "admin".into(),
                jwt_secret: jwt_secret.clone(),
            },
            config_path: Arc::new(config_path),
            config_update_lock: Arc::new(tokio::sync::Mutex::new(())),
            managed_device_update_locks: Arc::new(dashmap::DashMap::new()),
            client_access: Arc::new(parking_lot::RwLock::new(ClientAccessConfig::default())),
            certificate_fingerprint: Arc::new("0".repeat(64)),
            client_listener_ports: ClientListenerPorts::default(),
        });
        let token = jsonwebtoken::encode(
            &Header::default(),
            &Claims {
                sub: "admin".into(),
                exp: (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
                    .unix_timestamp(),
            },
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap();
        let authorization = format!("Bearer {token}");
        let list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/devices?code=alpha-wg")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let list_body = String::from_utf8(
            to_bytes(list.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!list_body.contains(&private_key));
        assert!(list_body.contains("\"wireguard_output_subnets\":[\"192.168.90.0/24\"]"));
        assert!(list_body.contains(
            "\"wireguard_input_routes\":[{\"subnet\":\"172.30.0.0/16\",\"target_ip\":\"10.61.0.20\"}]"
        ));
        let access = app
            .oneshot(
                Request::builder()
                    .uri("/api/networks/alpha-wg/devices/wg-alice/wireguard-access")
                    .header(header::AUTHORIZATION, authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            access.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = String::from_utf8(
            to_bytes(access.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains(&private_key));
        assert!(body.contains("[Interface]\\nPrivateKey"));
        assert!(body.contains("Address = 10.61.0.8/24\\nDNS = 1.1.1.1, 8.8.8.8\\n\\n[Peer]"));
        assert!(body.contains("AllowedIPs = 10.61.0.0/24, 172.30.0.0/16"));
    }

    #[tokio::test]
    async fn ikev2_server_certificate_download_returns_only_the_leaf() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(
            &config_path,
            "network = \"10.26.0.0/24\"\nlease_duration = 86400\n",
        )
        .unwrap();
        let mut ikev2 = Ikev2Config {
            enabled: true,
            server_address: "192.0.2.10".to_string(),
            remote_id: "192.0.2.10".to_string(),
            ..Ikev2Config::default()
        };
        crate::utils::ikev2_cert::prepare_certificate(&mut ikev2, &config_path).unwrap();
        update_ikev2_config(&config_path, &ikev2).unwrap();
        let certificate_path = ikev2.cert.as_ref().unwrap();
        let certificate_file = std::fs::read(certificate_path).unwrap();
        let expected_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&certificate_file))
            .next()
            .unwrap()
            .unwrap()
            .as_ref()
            .to_vec();

        let control_service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let jwt_secret = "ike-server-cert-download".to_string();
        let app = build_app(AppState {
            control_service,
            auth_config: AuthConfig {
                username: "admin".to_string(),
                password: "admin".to_string(),
                jwt_secret: jwt_secret.clone(),
            },
            config_path: Arc::new(config_path),
            config_update_lock: Arc::new(tokio::sync::Mutex::new(())),
            managed_device_update_locks: Arc::new(dashmap::DashMap::new()),
            client_access: Arc::new(parking_lot::RwLock::new(ClientAccessConfig::default())),
            certificate_fingerprint: Arc::new("0".repeat(64)),
            client_listener_ports: ClientListenerPorts::default(),
        });
        let token = jsonwebtoken::encode(
            &Header::default(),
            &Claims {
                sub: "admin".to_string(),
                exp: (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
                    .unix_timestamp(),
            },
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap();
        let authorization = format!("Bearer {token}");

        let der_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/ikev2/server-certificate?format=der")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(der_response.status(), StatusCode::OK);
        assert_eq!(
            der_response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/pkix-cert"
        );
        assert_eq!(
            der_response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap(),
            "attachment; filename=\"vnt-ikev2-server.cer\""
        );
        assert_eq!(
            to_bytes(der_response.into_body(), usize::MAX)
                .await
                .unwrap()
                .as_ref(),
            expected_der
        );

        let pem_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/ikev2/server-certificate?format=pem")
                    .header(header::AUTHORIZATION, authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pem_response.status(), StatusCode::OK);
        let pem = to_bytes(pem_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let pem = std::str::from_utf8(&pem).unwrap();
        assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        assert_eq!(pem.matches("-----END CERTIFICATE-----").count(), 1);
        let downloaded_der = rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(downloaded_der.as_ref(), expected_der);
    }

    #[tokio::test]
    async fn ikev2_start_failure_rolls_back_config_and_generated_certificates() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        let original = "network = \"10.26.0.0/24\"\nlease_duration = 86400\n";
        std::fs::write(&config_path, original).unwrap();
        let control_service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::from([("alpha".to_string(), "10.62.0.0/24".parse().unwrap())]),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let jwt_secret = "ike-rollback".to_string();
        let app = build_app(AppState {
            control_service: control_service.clone(),
            auth_config: AuthConfig {
                username: "admin".to_string(),
                password: "admin".to_string(),
                jwt_secret: jwt_secret.clone(),
            },
            config_path: Arc::new(config_path.clone()),
            config_update_lock: Arc::new(tokio::sync::Mutex::new(())),
            managed_device_update_locks: Arc::new(dashmap::DashMap::new()),
            client_access: Arc::new(parking_lot::RwLock::new(ClientAccessConfig::default())),
            certificate_fingerprint: Arc::new("0".repeat(64)),
            client_listener_ports: ClientListenerPorts::default(),
        });
        let token = jsonwebtoken::encode(
            &Header::default(),
            &Claims {
                sub: "admin".to_string(),
                exp: (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
                    .unix_timestamp(),
            },
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap();
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let natt_port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let body = format!(
            r#"{{"enabled":true,"ike_bind":"127.0.0.1:{occupied_port}","natt_bind":"127.0.0.1:{natt_port}","server_address":"127.0.0.1","remote_id":"vpn.example.com","dns":[]}}"#
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/settings/ikev2")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let response_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_body = String::from_utf8(response_body.to_vec()).unwrap();
        assert!(response_body.contains("应用 IKEv2 配置失败"));
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), original);
        assert!(!config_path.with_file_name("ikev2-cert.pem").exists());
        assert!(!config_path.with_file_name("ikev2-key.pem").exists());
        assert!(!config_path.with_file_name("ikev2-ca.pem").exists());
        assert!(control_service.get_ikev2_manager().is_none());

        let status = app
            .oneshot(
                Request::builder()
                    .uri("/api/settings/ikev2")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status_body = to_bytes(status.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8(status_body.to_vec())
                .unwrap()
                .contains("\"runtime_error\":")
        );
    }
}
