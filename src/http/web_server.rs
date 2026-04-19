use crate::ControlService;
use crate::server::control_server::service::{DeviceInfoVO, NetworkInfoVO};
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
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path as StdPath;
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
    let info = state.control_service.get_network_info();
    ApiResponse::ok(info)
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
    secret: String,
    lease_duration: Option<u64>,
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

    if body.netmask > 32 {
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
            body.secret,
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
    secret: String,
    lease_duration: u64,
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

    if body.netmask > 32 {
        return ApiResponse::<()>::err("无效的掩码").into_response();
    }

    let lease_duration = std::time::Duration::from_secs(body.lease_duration);

    match state
        .control_service
        .update_network(
            &network_code,
            gateway,
            body.netmask,
            lease_duration,
            body.secret,
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

    // 优先从本地文件系统加载，fallback 到内嵌资源
    let local_path = StdPath::new("static").join(&path);
    if local_path.exists()
        && local_path.is_file()
        && let Ok(content) = tokio::fs::read(&local_path).await
    {
        log::debug!("Serving file from local filesystem: {:?}", local_path);
        let mime = from_path(&local_path).first_or_octet_stream();
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

pub async fn start_http_server(
    control_service: ControlService,
    username: String,
    password: String,
    web_bind: SocketAddr,
) {
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
    };

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
        .route("/devices", get(list_devices))
        .route("/devices", delete(delete_device))
        .route("/peer_servers", get(list_peer_servers))
        .route("/peer_servers", post(add_peer_server))
        .route("/peer_servers/{server_addr}", delete(delete_peer_server))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        .nest("/api", api_routes)
        .route("/api/login", post(login))
        .fallback(static_handler)
        .layer(cors)
        .with_state(app_state);

    log::info!("HTTP Server running at http://{}", web_bind);

    let listener = tokio::net::TcpListener::bind(web_bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
