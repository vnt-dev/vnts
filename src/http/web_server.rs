use crate::ControlService;
use crate::server::control_server::db::{DeviceIpType, NetworkType};
use crate::server::control_server::service::{DeviceInfoVO, NetworkInfoVO};
use crate::utils::config::{
    Ikev2Config, Ikev2NetworkConfig, load_ikev2_config,
    update_ikev2_network as persist_ikev2_network, update_white_list as persist_white_list,
    validate_network_code,
};
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
use std::collections::{BTreeSet, HashMap, HashSet};
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
struct NetworkIkev2Info {
    service_configured: bool,
    runtime_active: bool,
    enabled: bool,
    ike_bind: Option<String>,
    natt_bind: Option<String>,
    remote_id: Option<String>,
    public_ip: Option<String>,
    dns: Vec<String>,
    certificate_configured: bool,
    psk_configured: bool,
    eap_users: Vec<String>,
    restart_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct EapUserUpdate {
    username: String,
    password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UpdateNetworkIkev2Request {
    enabled: bool,
    psk: Option<String>,
    #[serde(default)]
    clear_psk: bool,
    #[serde(default)]
    eap_users: Vec<EapUserUpdate>,
}

fn network_ikev2_info(
    config: Option<&Ikev2Config>,
    network_code: &str,
    runtime_active: bool,
    restart_required: bool,
) -> NetworkIkev2Info {
    let network = config.and_then(|config| {
        config
            .networks
            .iter()
            .find(|network| network.network_code == network_code)
    });
    let mut eap_users = network
        .map(|network| network.eap_users.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    eap_users.sort();
    NetworkIkev2Info {
        service_configured: config.is_some(),
        runtime_active,
        enabled: network.is_some(),
        ike_bind: config.map(|config| config.ike_bind.to_string()),
        natt_bind: config.map(|config| config.natt_bind.to_string()),
        remote_id: config.map(|config| config.remote_id.clone()),
        public_ip: config.and_then(|config| config.public_ip.map(|ip| ip.to_string())),
        dns: config
            .map(|config| config.dns.iter().map(ToString::to_string).collect())
            .unwrap_or_default(),
        certificate_configured: config
            .is_some_and(|config| config.cert.is_some() && config.key.is_some()),
        psk_configured: network.is_some_and(|network| network.psk.is_some()),
        eap_users,
        restart_required,
    }
}

async fn get_network_ikev2(
    State(state): State<AppState>,
    Path(network_code): Path<String>,
) -> Response {
    if !state
        .control_service
        .get_network_codes()
        .contains(&network_code)
    {
        return ApiResponse::<()>::err(format!("网络编号 '{network_code}' 不存在")).into_response();
    }
    let _guard = state.config_update_lock.lock().await;
    let config_path = state.config_path.as_ref().clone();
    let config = match tokio::task::spawn_blocking(move || load_ikev2_config(&config_path)).await {
        Ok(Ok(config)) => config,
        Ok(Err(error)) => {
            return ApiResponse::<()>::err(format!("读取 IKEv2 配置失败: {error}")).into_response();
        }
        Err(error) => {
            return ApiResponse::<()>::err(format!("读取 IKEv2 配置任务失败: {error}"))
                .into_response();
        }
    };
    let runtime_active = state.control_service.get_ikev2_manager().is_some();
    ApiResponse::ok(network_ikev2_info(
        config.as_ref(),
        &network_code,
        runtime_active,
        config.is_some() && !runtime_active,
    ))
    .into_response()
}

fn merge_network_ikev2_update(
    config: &Ikev2Config,
    network_code: &str,
    request: UpdateNetworkIkev2Request,
) -> anyhow::Result<Option<Ikev2NetworkConfig>> {
    if !request.enabled {
        return Ok(None);
    }
    let current = config
        .networks
        .iter()
        .find(|network| network.network_code == network_code);
    let psk = if let Some(psk) = request.psk {
        if psk.is_empty() {
            anyhow::bail!("PSK 不能为空；留空字段表示保留原值");
        }
        Some(psk)
    } else if request.clear_psk {
        None
    } else {
        current.and_then(|network| network.psk.clone())
    };

    let mut usernames = HashSet::new();
    let mut eap_users = HashMap::new();
    for user in request.eap_users {
        let username = user.username.trim().to_string();
        if username.is_empty() || !usernames.insert(username.clone()) {
            anyhow::bail!("EAP 用户名不能为空或重复");
        }
        let password = match user.password {
            Some(password) if !password.is_empty() => password,
            _ => current
                .and_then(|network| network.eap_users.get(&username))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("新增 EAP 用户 '{username}' 必须填写密码"))?,
        };
        eap_users.insert(username, password);
    }
    if psk.is_none() && eap_users.is_empty() {
        anyhow::bail!("启用 IKEv2 时至少配置 PSK 或一个 EAP 用户");
    }
    Ok(Some(Ikev2NetworkConfig {
        network_code: network_code.to_string(),
        psk,
        eap_users,
    }))
}

async fn update_network_ikev2(
    State(state): State<AppState>,
    Path(network_code): Path<String>,
    Json(body): Json<UpdateNetworkIkev2Request>,
) -> Response {
    if !state
        .control_service
        .get_network_codes()
        .contains(&network_code)
    {
        return ApiResponse::<()>::err(format!("网络编号 '{network_code}' 不存在")).into_response();
    }
    let _guard = state.config_update_lock.lock().await;
    let config_path = state.config_path.as_ref().clone();
    let current = match tokio::task::spawn_blocking({
        let config_path = config_path.clone();
        move || load_ikev2_config(&config_path)
    })
    .await
    {
        Ok(Ok(Some(config))) => config,
        Ok(Ok(None)) => {
            return ApiResponse::<()>::err(
                "IKEv2 服务尚未配置，请先在 config.toml 添加全局 [ikev2] 配置并重启",
            )
            .into_response();
        }
        Ok(Err(error)) => {
            return ApiResponse::<()>::err(format!("读取 IKEv2 配置失败: {error}")).into_response();
        }
        Err(error) => {
            return ApiResponse::<()>::err(format!("读取 IKEv2 配置任务失败: {error}"))
                .into_response();
        }
    };
    let network = match merge_network_ikev2_update(&current, &network_code, body) {
        Ok(network) => network,
        Err(error) => return ApiResponse::<()>::err(error.to_string()).into_response(),
    };
    let mut prospective = current.clone();
    prospective
        .networks
        .retain(|network| network.network_code != network_code);
    if let Some(network) = network.clone() {
        prospective.networks.push(network);
    }
    let validation = tokio::task::spawn_blocking({
        let prospective = prospective.clone();
        move || crate::server::ikev2::validate_runtime_config(&prospective)
    })
    .await;
    match validation {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return ApiResponse::<()>::err(format!("IKEv2 配置无效: {error}")).into_response();
        }
        Err(error) => {
            return ApiResponse::<()>::err(format!("IKEv2 配置校验任务失败: {error}"))
                .into_response();
        }
    }

    let updated = match tokio::task::spawn_blocking({
        let config_path = config_path.clone();
        let network_code = network_code.clone();
        move || persist_ikev2_network(&config_path, &network_code, network)
    })
    .await
    {
        Ok(Ok(config)) => config,
        Ok(Err(error)) => {
            return ApiResponse::<()>::err(format!("保存 IKEv2 配置失败: {error}")).into_response();
        }
        Err(error) => {
            return ApiResponse::<()>::err(format!("保存 IKEv2 配置任务失败: {error}"))
                .into_response();
        }
    };

    let runtime_active = state.control_service.get_ikev2_manager().is_some();
    let mut restart_required = !runtime_active;
    if let Some(manager) = state.control_service.get_ikev2_manager()
        && let Err(error) = manager
            .reload_network_config(updated.clone(), network_code.clone())
            .await
    {
        log::error!("IKEv2 runtime reload failed after saving config: {error:#}");
        restart_required = true;
    }
    ApiResponse::ok(network_ikev2_info(
        Some(&updated),
        &network_code,
        runtime_active && !restart_required,
        restart_required,
    ))
    .into_response()
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
    ip: String,
    ip_type: Option<DeviceIpType>,
}

async fn create_device(
    State(state): State<AppState>,
    Json(body): Json<CreateDeviceRequest>,
) -> Response {
    let ip: Ipv4Addr = match body.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return ApiResponse::<()>::err("无效的 IP 地址").into_response(),
    };
    match state
        .control_service
        .add_device(
            &body.network_code,
            &body.device_id,
            ip,
            body.ip_type.unwrap_or(DeviceIpType::Dynamic),
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
    ip: String,
    ip_type: DeviceIpType,
}

async fn update_device(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    Json(body): Json<UpdateDeviceRequest>,
) -> Response {
    let ip: Ipv4Addr = match body.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return ApiResponse::<()>::err("无效的 IP 地址").into_response(),
    };
    match state
        .control_service
        .update_device(&body.network_code, &device_id, ip, body.ip_type)
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
) -> Result<Response, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    let Some(token) = token else {
        let resp = ApiResponse::<()>::err_code(401, "missing token");
        return Err((StatusCode::UNAUTHORIZED, Json(resp)).into_response());
    };

    let validation = Validation::default();
    match jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.auth_config.jwt_secret.as_bytes()),
        &validation,
    ) {
        Ok(_) => Ok(next.run(request).await),
        Err(e) => {
            let resp = ApiResponse::<()>::err_code(401, format!("invalid token: {e}"));
            Err((StatusCode::UNAUTHORIZED, Json(resp)).into_response())
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
        return ([(header::CONTENT_TYPE, mime.as_ref())], content).into_response();
    }

    if let Some(content) = Assets::get(&path) {
        log::debug!("Serving file from embedded assets: {}", path);
        let mime = from_path(&path).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref())],
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

pub async fn start_http_server(
    control_service: ControlService,
    username: String,
    password: String,
    web_bind: SocketAddr,
    config_path: PathBuf,
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
    };

    let app = build_app(app_state);

    log::info!("HTTP Server running at http://{}", web_bind);

    let listener = tokio::net::TcpListener::bind(web_bind).await?;
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
            "/networks/{network_code}/ikev2",
            get(get_network_ikev2).put(update_network_ikev2),
        )
        .route("/devices", get(list_devices))
        .route("/devices", post(create_device))
        .route("/devices", delete(delete_device))
        .route("/devices/{device_id}", put(update_device))
        .route("/peer_servers", get(list_peer_servers))
        .route("/peer_servers", post(add_peer_server))
        .route("/peer_servers/{server_addr}", delete(delete_peer_server))
        .route(
            "/settings/network-whitelist",
            get(get_network_whitelist).put(update_network_whitelist),
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
        AppState, AuthConfig, Claims, EapUserUpdate, UpdateNetworkIkev2Request, build_app,
        merge_network_ikev2_update, normalize_network_codes, safe_static_path,
    };
    use crate::server::control_server::service::ControlService;
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
    fn ikev2_update_keeps_redacted_passwords_and_removes_omitted_users() {
        let config = crate::utils::config::Ikev2Config {
            ike_bind: "127.0.0.1:500".parse().unwrap(),
            natt_bind: "127.0.0.1:4500".parse().unwrap(),
            remote_id: "vpn.example.com".to_string(),
            cert: None,
            key: None,
            dns: Vec::new(),
            public_ip: None,
            networks: vec![crate::utils::config::Ikev2NetworkConfig {
                network_code: "alpha".to_string(),
                psk: Some("secret".to_string()),
                eap_users: HashMap::from([("alice".to_string(), "old-password".to_string())]),
            }],
        };
        let merged = merge_network_ikev2_update(
            &config,
            "alpha",
            UpdateNetworkIkev2Request {
                enabled: true,
                psk: None,
                clear_psk: false,
                eap_users: vec![
                    EapUserUpdate {
                        username: "alice".to_string(),
                        password: None,
                    },
                    EapUserUpdate {
                        username: "bob".to_string(),
                        password: Some("new-password".to_string()),
                    },
                ],
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(merged.psk.as_deref(), Some("secret"));
        assert_eq!(
            merged.eap_users.get("alice").map(String::as_str),
            Some("old-password")
        );
        assert_eq!(
            merged.eap_users.get("bob").map(String::as_str),
            Some("new-password")
        );
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
    async fn network_ikev2_routes_redact_secrets_and_persist_updates() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"network = "10.26.0.0/24"
lease_duration = 86400
[ikev2]
ike_bind = "127.0.0.1:500"
natt_bind = "127.0.0.1:4500"
remote_id = "vpn.example.com"
[[ikev2.networks]]
network_code = "alpha"
psk = "old-secret"
"#,
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
        let jwt_secret = "ike-test-secret".to_string();
        let app = build_app(AppState {
            control_service,
            auth_config: AuthConfig {
                username: "admin".to_string(),
                password: "admin".to_string(),
                jwt_secret: jwt_secret.clone(),
            },
            config_path: Arc::new(config_path.clone()),
            config_update_lock: Arc::new(tokio::sync::Mutex::new(())),
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

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/networks/alpha/ikev2")
                    .header(header::AUTHORIZATION, &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let get_body = to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let get_body = String::from_utf8(get_body.to_vec()).unwrap();
        assert!(get_body.contains("\"psk_configured\":true"));
        assert!(!get_body.contains("old-secret"));

        let put_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/networks/alpha/ikev2")
                    .header(header::AUTHORIZATION, authorization)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"enabled":true,"psk":"new-secret","eap_users":[]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let put_body = to_bytes(put_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let put_body = String::from_utf8(put_body.to_vec()).unwrap();
        assert!(put_body.contains("\"restart_required\":true"));
        assert!(!put_body.contains("new-secret"));
        let persisted = std::fs::read_to_string(config_path).unwrap();
        assert!(persisted.contains("psk = \"new-secret\""));
        assert!(!persisted.contains("old-secret"));
    }
}
