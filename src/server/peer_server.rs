use crate::protocol::ProtoToBytesMut;
use crate::protocol::server_message::{Payload, *};
use crate::server::control_server::db::{self, PeerServerRecord, PeerServerSource};
use crate::server::network_state_provider::NetworkStateProvider;
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use prost::Message;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

const DEFAULT_CLIENT_LATENCY_MS: u32 = 10;
const DEFAULT_SERVER_LATENCY_MS: u32 = 10;
const PING_INTERVAL_SECS: u64 = 30;
const NETWORK_SYNC_INTERVAL_SECS: u64 = 30;
const MAX_ROUTES_PER_IP: usize = 5;

#[derive(Clone)]
pub struct PeerServerInfo {
    inner: Arc<parking_lot::RwLock<PeerServerInfoInner>>,
}

struct PeerServerInfoInner {
    addr: String,
    latency_ms: u32,
    sender: Option<tokio::sync::mpsc::Sender<Bytes>>,
    connection: Option<quinn::Connection>,
    connected: bool,
    is_outbound: bool,
}

impl PeerServerInfo {
    pub fn new(addr: String, is_outbound: bool) -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(PeerServerInfoInner {
                addr,
                latency_ms: DEFAULT_SERVER_LATENCY_MS,
                sender: None,
                connection: None,
                connected: false,
                is_outbound,
            })),
        }
    }

    pub fn set_connected(
        &self,
        sender: tokio::sync::mpsc::Sender<Bytes>,
        connection: quinn::Connection,
    ) {
        let mut inner = self.inner.write();
        inner.sender = Some(sender);
        inner.connection = Some(connection);
        inner.connected = true;
    }

    pub fn set_disconnected(&self) {
        let mut inner = self.inner.write();
        inner.sender = None;
        inner.connection = None;
        inner.connected = false;
    }

    pub fn update_latency(&self, latency: u32) {
        self.inner.write().latency_ms = latency;
    }

    pub fn get_latency(&self) -> u32 {
        self.inner.read().latency_ms
    }

    pub fn is_connected(&self) -> bool {
        self.inner.read().connected
    }

    pub fn get_addr(&self) -> String {
        self.inner.read().addr.clone()
    }

    pub fn is_outbound(&self) -> bool {
        self.inner.read().is_outbound
    }

    pub async fn send(&self, data: Bytes) -> Result<()> {
        let sender = {
            let guard = self.inner.read();
            guard.sender.clone()
        };

        if let Some(sender) = sender {
            sender.send(data).await?;
            Ok(())
        } else {
            bail!("Not connected")
        }
    }

    pub fn send_datagram(&self, data: Bytes) -> Result<()> {
        let conn = {
            let guard = self.inner.read();
            guard.connection.clone()
        };

        if let Some(conn) = conn {
            conn.send_datagram(data)?;
            Ok(())
        } else {
            bail!("Not connected")
        }
    }
}

#[derive(Clone)]
pub struct IpRouteInfo {
    pub peer_info: Arc<PeerServerInfo>,
    pub client_latency_ms: u32,
}

impl IpRouteInfo {
    /// 服务器间延迟 + 客户端延迟
    pub fn total_latency(&self) -> u32 {
        self.peer_info.get_latency() + self.client_latency_ms + 2
    }
}

pub struct PeerServerManager {
    token_hash: String,
    network_state_provider: NetworkStateProvider,
    peer_servers: Arc<parking_lot::RwLock<Vec<Arc<PeerServerInfo>>>>,
    // network_code -> (ip -> 路由列表)，按延迟排序取 top N
    ip_to_routes: Arc<DashMap<String, Arc<DashMap<Ipv4Addr, Vec<IpRouteInfo>>>>>,
    outbound_tasks: Arc<DashMap<String, (JoinHandle<()>, tokio::sync::oneshot::Sender<()>)>>,
}

impl PeerServerManager {
    pub fn new(token: String, network_state_provider: NetworkStateProvider) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        Self {
            token_hash,
            network_state_provider,
            peer_servers: Arc::new(parking_lot::RwLock::new(Vec::new())),
            ip_to_routes: Arc::new(DashMap::new()),
            outbound_tasks: Arc::new(DashMap::new()),
        }
    }

    pub async fn start_server(
        self: Arc<Self>,
        bind_addr: SocketAddr,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<()> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("TLS config error")?;

        let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .map_err(|e| anyhow::anyhow!("QUIC TLS config error: {:?}", e))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        let endpoint = quinn::Endpoint::server(server_config, bind_addr)
            .context(format!("peer server error:{}", bind_addr))?;

        log::info!("Peer server listening on: {}", bind_addr);

        tokio::spawn(async move {
            if let Err(e) = self.accept_loop(endpoint).await {
                log::error!("peer server accept_loop error: {:?}", e);
            }
        });

        Ok(())
    }

    async fn accept_loop(self: Arc<Self>, endpoint: Endpoint) -> Result<()> {
        loop {
            let connecting = endpoint.accept().await.context("peer accept error")?;
            let remote_addr = connecting.remote_address();
            let manager = self.clone();

            tokio::spawn(async move {
                match connecting.await {
                    Ok(connection) => {
                        log::info!("Peer connection from: {}", remote_addr);
                        match tokio::time::timeout(Duration::from_secs(10), connection.accept_bi())
                            .await
                        {
                            Ok(Ok((send_stream, recv_stream))) => {
                                if let Err(e) = manager
                                    .handle_peer_connection(
                                        connection,
                                        send_stream,
                                        recv_stream,
                                        remote_addr,
                                    )
                                    .await
                                {
                                    log::error!(
                                        "handle_peer_connection error: {:?}, addr={}",
                                        e,
                                        remote_addr
                                    );
                                }
                            }
                            Ok(Err(e)) => {
                                log::info!("peer connection closed: {}, {:?}", remote_addr, e);
                            }
                            Err(_) => {
                                log::error!("peer accept_bi timeout: {}", remote_addr);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("peer connect error: {:?}, addr={}", e, remote_addr);
                    }
                }
            });
        }
    }

    async fn run_peer_communication_loop(
        &self,
        peer_info: Arc<PeerServerInfo>,
        mut framed_write: FramedWrite<SendStream, LengthDelimitedCodec>,
        mut framed_read: FramedRead<RecvStream, LengthDelimitedCodec>,
        mut rx: tokio::sync::mpsc::Receiver<Bytes>,
    ) {
        let manager = self.clone();
        let mut network_codes = std::collections::HashSet::<String>::new();

        let mut network_sync_interval =
            tokio::time::interval(Duration::from_secs(NETWORK_SYNC_INTERVAL_SECS));
        network_sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                Some(data) = rx.recv() => {
                    if let Err(e) = framed_write.send(data).await {
                        log::warn!("peer send error: {}", e);
                        break;
                    }
                }
                Some(rs) = framed_read.next() => {
                    match rs {
                        Ok(bytes) => {
                            if let Err(e) = manager.handle_peer_message(&peer_info, &mut network_codes, bytes.freeze()).await {
                                log::error!("handle_peer_message error: {:?}", e);
                            }
                        }
                        Err(e) => {
                            log::warn!("peer recv error: {}", e);
                            break;
                        }
                    }
                }
                _ = network_sync_interval.tick() => {
                    if let Err(e) = manager.pull_client_info_from_peer(&peer_info).await {
                        log::warn!("Failed to pull client info from peer {}: {:?}", peer_info.get_addr(), e);
                    }
                }
                _ = ping_interval.tick() => {
                    if let Err(e) = manager.ping_peer(&peer_info).await {
                        log::warn!("Failed to ping peer {}: {:?}", peer_info.get_addr(), e);
                    }
                }
                else => break,
            }
        }

        peer_info.set_disconnected();
        manager.cleanup_routes(&peer_info, &network_codes);
        manager
            .peer_servers
            .write()
            .retain(|p| !Arc::ptr_eq(p, &peer_info));

        log::info!("Peer connection closed: {}", peer_info.get_addr());
    }

    async fn handle_peer_connection(
        &self,
        connection: quinn::Connection,
        send_stream: SendStream,
        recv_stream: RecvStream,
        addr: SocketAddr,
    ) -> Result<()> {
        let mut framed_write = FramedWrite::new(send_stream, LengthDelimitedCodec::new());
        let mut framed_read = FramedRead::new(recv_stream, LengthDelimitedCodec::new());

        let first = tokio::time::timeout(Duration::from_secs(5), framed_read.next()).await;
        let Ok(first) = first else {
            bail!("peer auth timeout");
        };
        let Some(first) = first else {
            bail!("peer connection closed");
        };
        let buf = first?;

        let msg = ServerMessage::decode(&buf[..])?;
        let ServerMessage {
            payload: Some(Payload::AuthReq(auth_req)),
        } = msg
        else {
            bail!("expected auth request");
        };

        if auth_req.token_hash != self.token_hash {
            let response = ServerMessage {
                payload: Some(Payload::AuthRes(ServerAuthResponse {
                    success: false,
                    message: "Invalid token".to_string(),
                })),
            };
            let _ = framed_write
                .send(response.encode_bytes_mut().freeze())
                .await;
            bail!("Invalid token from peer");
        }

        log::info!("Peer server authenticated from: {}", addr);

        let response = ServerMessage {
            payload: Some(Payload::AuthRes(ServerAuthResponse {
                success: true,
                message: "OK".to_string(),
            })),
        };
        framed_write
            .send(response.encode_bytes_mut().freeze())
            .await?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1024);
        let peer_info = Arc::new(PeerServerInfo::new(addr.to_string(), false));
        peer_info.set_connected(tx, connection.clone());
        self.peer_servers.write().push(peer_info.clone());

        let manager = self.clone();
        tokio::spawn(async move {
            manager
                .run_peer_communication_loop(peer_info, framed_write, framed_read, rx)
                .await;
        });

        Ok(())
    }

    /// 连接到对端，断线后自动重连
    pub fn connect_to_peer(
        self: Arc<Self>,
        peer_addr: String,
    ) -> (JoinHandle<()>, tokio::sync::oneshot::Sender<()>) {
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            loop {
                log::info!("Connecting to peer server: {}", peer_addr);

                tokio::select! {
                    result = self.clone().connect_to_peer_once(peer_addr.clone()) => {
                        match result {
                            Ok(_) => {
                                log::info!("Peer connection closed: {}, will reconnect...", peer_addr);
                            }
                            Err(e) => {
                                log::warn!(
                                    "Failed to connect to peer {}: {:?}, will retry...",
                                    peer_addr,
                                    e
                                );
                            }
                        }
                    }
                    _ = &mut stop_rx => {
                        log::info!("Stop signal received for peer: {}", peer_addr);
                        break;
                    }
                }

                let delay_secs = rand::random::<u64>() % 8 + 3;
                log::info!("Reconnecting to {} in {} seconds...", peer_addr, delay_secs);

                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(delay_secs)) => {}
                    _ = &mut stop_rx => {
                        log::info!("Stop signal received during reconnect delay for peer: {}", peer_addr);
                        break;
                    }
                }
            }
            log::info!("Connection task stopped for peer: {}", peer_addr);
        });

        (handle, stop_tx)
    }

    async fn connect_to_peer_once(self: Arc<Self>, peer_addr: String) -> Result<()> {
        let client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto)
                .map_err(|e| anyhow::anyhow!("QUIC client config error: {:?}", e))?,
        ));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        let addr: SocketAddr = peer_addr.parse()?;
        let connection = endpoint.connect(addr, "localhost")?.await?;
        let (send_stream, recv_stream) = connection.open_bi().await?;

        let mut framed_write = FramedWrite::new(send_stream, LengthDelimitedCodec::new());
        let mut framed_read = FramedRead::new(recv_stream, LengthDelimitedCodec::new());

        let auth_req = ServerMessage {
            payload: Some(Payload::AuthReq(ServerAuthRequest {
                token_hash: self.token_hash.clone(),
            })),
        };
        framed_write
            .send(auth_req.encode_bytes_mut().freeze())
            .await?;

        let response = tokio::time::timeout(Duration::from_secs(5), framed_read.next()).await;
        let Ok(Some(Ok(buf))) = response else {
            bail!("auth response timeout or error");
        };

        let msg = ServerMessage::decode(&buf[..])?;
        let ServerMessage {
            payload: Some(Payload::AuthRes(auth_res)),
        } = msg
        else {
            bail!("expected auth response");
        };

        if !auth_res.success {
            bail!("auth failed: {}", auth_res.message);
        }

        log::info!("Connected to peer server: {}", peer_addr);

        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1024);
        let peer_info = Arc::new(PeerServerInfo::new(peer_addr.clone(), true));
        peer_info.set_connected(tx, connection.clone());
        self.peer_servers.write().push(peer_info.clone());

        self.run_peer_communication_loop(peer_info, framed_write, framed_read, rx)
            .await;

        Ok(())
    }

    async fn handle_peer_message(
        &self,
        peer_info: &Arc<PeerServerInfo>,
        network_codes: &mut std::collections::HashSet<String>,
        data: Bytes,
    ) -> Result<()> {
        let msg = ServerMessage::decode(&data[..])?;

        match msg.payload {
            Some(Payload::PingReq(ping)) => {
                self.handle_ping_request(peer_info, ping).await?;
            }
            Some(Payload::PingRes(pong)) => {
                self.handle_ping_response(peer_info, pong).await;
            }
            Some(Payload::ForwardData(forward)) => {
                self.handle_forward_data(forward).await;
            }
            Some(Payload::ClientInfoReq(req)) => {
                self.handle_client_info_request_msg(peer_info, req).await?;
            }
            Some(Payload::ClientInfoRes(res)) => {
                self.handle_client_info_response(peer_info, network_codes, res)
                    .await;
            }
            _ => {
                log::warn!("unexpected message from peer: {}", peer_info.get_addr());
            }
        }

        Ok(())
    }

    async fn handle_forward_data(&self, forward: ServerForwardData) {
        if let Some(state) = self
            .network_state_provider
            .get_network_state(&forward.network_code)
        {
            use crate::protocol::ip_packet_protocol::NetPacket;
            if let Ok(packet) = NetPacket::new(forward.data) {
                let dest = Ipv4Addr::from(packet.dest_id());
                if let Some(sender) = state.sender_map().get(&dest) {
                    _ = sender.try_send(Bytes::from(packet.into_buffer()));
                    log::debug!("Forwarded data to local client: {}", dest);
                }
            }
        }
    }

    async fn handle_ping_request(
        &self,
        peer_info: &Arc<PeerServerInfo>,
        ping: ServerPingRequest,
    ) -> Result<()> {
        let response = ServerMessage {
            payload: Some(Payload::PingRes(ServerPingResponse {
                request_timestamp: ping.timestamp,
                response_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
                    as u64,
            })),
        };
        peer_info.send(response.encode_bytes_mut().freeze()).await?;
        Ok(())
    }

    async fn handle_ping_response(
        &self,
        peer_info: &Arc<PeerServerInfo>,
        pong: ServerPingResponse,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let rtt = now.saturating_sub(pong.request_timestamp);

        let latency = (rtt / 2) as u32; // 单向延迟
        peer_info.update_latency(latency);
        log::debug!("Peer {} latency: {} ms", peer_info.get_addr(), latency);
    }

    async fn handle_client_info_request_msg(
        &self,
        peer_info: &Arc<PeerServerInfo>,
        req: ServerClientInfoRequest,
    ) -> Result<()> {
        let response = self.handle_client_info_request(req.network_codes).await;

        let response_msg = ServerMessage {
            payload: Some(Payload::ClientInfoRes(response)),
        };

        peer_info
            .send(response_msg.encode_bytes_mut().freeze())
            .await?;
        Ok(())
    }

    /// 收到对端的客户端列表后更新路由表
    async fn handle_client_info_response(
        &self,
        peer_info: &Arc<PeerServerInfo>,
        network_codes: &mut std::collections::HashSet<String>,
        res: ServerClientInfoResponse,
    ) {
        for net_info in res.networks {
            let network_code = net_info.network_code.clone();
            network_codes.insert(network_code.clone());

            let ip_map = self
                .ip_to_routes
                .entry(network_code.clone())
                .or_insert_with(Default::default)
                .value()
                .clone();

            let mut synced_ips = std::collections::HashSet::new();

            for client in net_info.clients {
                let ip = Ipv4Addr::from(client.ip);
                synced_ips.insert(ip);

                let route_info = IpRouteInfo {
                    peer_info: peer_info.clone(),
                    client_latency_ms: client.latency_ms,
                };

                ip_map
                    .entry(ip)
                    .and_modify(|routes| {
                        if let Some(existing) = routes
                            .iter_mut()
                            .find(|r| Arc::ptr_eq(&r.peer_info, peer_info))
                        {
                            existing.client_latency_ms = client.latency_ms;
                        } else {
                            routes.push(route_info.clone());
                        }
                        routes.sort_by_key(|r| r.total_latency());
                        routes.truncate(MAX_ROUTES_PER_IP);
                    })
                    .or_insert_with(|| vec![route_info]);
            }

            // 不在同步列表中的 IP，移除该 peer 的路由
            ip_map.retain(|ip, routes| {
                if !synced_ips.contains(ip) {
                    routes.retain(|route| !Arc::ptr_eq(&route.peer_info, peer_info));
                }
                !routes.is_empty()
            });
        }

        log::debug!("Updated network routes from peer: {}", peer_info.get_addr());
    }

    fn cleanup_routes(
        &self,
        peer_info: &Arc<PeerServerInfo>,
        network_codes: &std::collections::HashSet<String>,
    ) {
        for network_code in network_codes {
            if let Some(ip_map) = self
                .ip_to_routes
                .get(network_code)
                .map(|v| v.value().clone())
            {
                ip_map.retain(|_ip, routes| {
                    routes.retain(|route| !Arc::ptr_eq(&route.peer_info, peer_info));
                    !routes.is_empty()
                });
            }
        }
        log::debug!("Cleaned up routes for peer: {}", peer_info.get_addr());
    }

    async fn pull_client_info_from_peer(&self, peer_info: &Arc<PeerServerInfo>) -> Result<()> {
        let network_codes = self.network_state_provider.get_network_codes();

        if network_codes.is_empty() {
            return Ok(());
        }

        let request_msg = ServerMessage {
            payload: Some(Payload::ClientInfoReq(ServerClientInfoRequest {
                network_codes,
            })),
        };
        let data = request_msg.encode_bytes_mut().freeze();

        peer_info.send(data).await?;
        Ok(())
    }

    pub async fn handle_client_info_request(
        &self,
        network_codes: Vec<String>,
    ) -> ServerClientInfoResponse {
        let mut networks = Vec::new();

        for network_code in network_codes {
            let clients =
                if let Some(state) = self.network_state_provider.get_network_state(&network_code) {
                    let clients: Vec<ClientLatencyInfo> = state
                        .sender_map()
                        .iter()
                        .map(|entry| {
                            let ip = *entry.key();
                            let latency_ms = state
                                .get_device_entry_by_ip(ip)
                                .and_then(|device| device.latency_ms)
                                .unwrap_or(DEFAULT_CLIENT_LATENCY_MS);

                            ClientLatencyInfo {
                                ip: u32::from(ip),
                                latency_ms,
                            }
                        })
                        .collect();
                    clients
                } else {
                    Vec::new()
                };
            networks.push(NetworkInfo {
                network_code,
                clients,
            });
        }

        ServerClientInfoResponse { networks }
    }

    async fn ping_peer(&self, peer_info: &Arc<PeerServerInfo>) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ping_msg = ServerMessage {
            payload: Some(Payload::PingReq(ServerPingRequest { timestamp })),
        };
        let data = ping_msg.encode_bytes_mut().freeze();

        peer_info.send(data).await?;
        Ok(())
    }

    /// 返回 (最优peer, 远程总延迟, 本地延迟)，None 表示不可达
    pub fn find_best_route(
        &self,
        network_code: &str,
        target_ip: Ipv4Addr,
    ) -> Option<(Arc<PeerServerInfo>, u32, Option<u32>)> {
        let local_latency = self
            .network_state_provider
            .get_network_state(network_code)
            .and_then(|state| state.get_device_entry_by_ip(target_ip))
            .and_then(|device| device.latency_ms);

        if let Some(ip_map) = self.ip_to_routes.get(network_code) {
            if let Some(routes) = ip_map.get(&target_ip) {
                let mut best_route: Option<(Arc<PeerServerInfo>, u32)> = None;

                for route in routes.value() {
                    if !route.peer_info.is_connected() {
                        continue;
                    }

                    let total_latency = route.total_latency();

                    match &best_route {
                        None => {
                            best_route = Some((route.peer_info.clone(), total_latency));
                        }
                        Some((_, current_best)) => {
                            if total_latency < *current_best {
                                best_route = Some((route.peer_info.clone(), total_latency));
                            }
                        }
                    }
                }

                if let Some((peer_info, total_latency)) = best_route {
                    return Some((peer_info, total_latency, local_latency));
                }
            }
        }

        None
    }

    pub fn get_peer_servers(&self) -> Vec<Arc<PeerServerInfo>> {
        self.peer_servers.read().clone()
    }

    pub async fn load_and_start_outbound_peers(self: Arc<Self>) -> Result<()> {
        let records = db::load_all_peer_servers().await?;

        for record in records {
            let peer_addr = record.server_addr.clone();
            log::info!(
                "Starting outbound connection to: {} (source: {:?})",
                peer_addr,
                record.source
            );

            let (handle, stop_tx) = self.clone().connect_to_peer(peer_addr.clone());
            self.outbound_tasks.insert(peer_addr, (handle, stop_tx));
        }

        Ok(())
    }

    pub async fn add_outbound_peer(self: Arc<Self>, server_addr: String) -> Result<()> {
        if self.outbound_tasks.contains_key(&server_addr) {
            bail!("服务器 '{}' 已存在", server_addr);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let record = PeerServerRecord {
            server_addr: server_addr.clone(),
            source: PeerServerSource::Manual,
            created_at: now,
        };

        db::save_peer_server(&record).await?;

        let (handle, stop_tx) = self.clone().connect_to_peer(server_addr.clone());
        self.outbound_tasks
            .insert(server_addr.clone(), (handle, stop_tx));

        log::info!("Added outbound peer: {}", server_addr);
        Ok(())
    }

    pub async fn remove_outbound_peer(self: Arc<Self>, server_addr: &str) -> Result<()> {
        if let Some((_, (handle, stop_tx))) = self.outbound_tasks.remove(server_addr) {
            let _ = stop_tx.send(());
            let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
            log::info!("Stopped connection task for: {}", server_addr);
        }

        let mut to_remove = Vec::new();
        {
            let peers = self.peer_servers.read();
            for peer in peers.iter() {
                if peer.get_addr() == server_addr && peer.is_outbound() {
                    peer.set_disconnected();
                    to_remove.push(peer.clone());
                }
            }
        }

        if !to_remove.is_empty() {
            let mut peers = self.peer_servers.write();
            for peer in &to_remove {
                peers.retain(|p| !Arc::ptr_eq(p, peer));
            }
        }

        db::delete_peer_server(server_addr).await?;

        log::info!("Removed outbound peer: {}", server_addr);
        Ok(())
    }

    pub async fn add_peer_server(self: Arc<Self>, server_addr: String) -> Result<()> {
        self.add_outbound_peer(server_addr).await
    }

    pub async fn remove_peer_server(self: Arc<Self>, server_addr: &str) -> Result<()> {
        self.remove_outbound_peer(server_addr).await
    }

    pub fn get_remote_devices(&self, network_code: &str) -> Vec<(Ipv4Addr, String, u32)> {
        let mut result = Vec::new();

        if let Some(network_routes) = self.ip_to_routes.get(network_code) {
            for entry in network_routes.iter() {
                let ip = *entry.key();
                let routes = entry.value();
                for route in routes {
                    let server_addr = route.peer_info.get_addr();
                    let total_latency = route.total_latency();
                    result.push((ip, server_addr, total_latency));
                }
            }
        }

        result
    }

    /// 通过 QUIC datagram 转发到指定 peer
    pub async fn forward_to_peer(
        &self,
        peer_info: &Arc<PeerServerInfo>,
        network_code: String,
        data: Bytes,
    ) -> bool {
        let forward_msg = ServerMessage {
            payload: Some(Payload::ForwardData(ServerForwardData {
                network_code,
                data: data.to_vec(),
            })),
        };

        let msg_bytes = forward_msg.encode_bytes_mut().freeze();

        if let Err(e) = peer_info.send_datagram(msg_bytes) {
            log::warn!("Failed to send datagram to peer: {:?}", e);
            false
        } else {
            log::debug!("Forwarded data to peer server: {}", peer_info.get_addr());
            true
        }
    }

    /// 找到最优路径并转发，返回 true 表示已转发到远端
    pub async fn forward_with_best_route(
        &self,
        network_code: &str,
        target_ip: Ipv4Addr,
        data: Bytes,
    ) -> bool {
        let local_has_client =
            if let Some(state) = self.network_state_provider.get_network_state(network_code) {
                state.sender_map().contains_key(&target_ip)
            } else {
                false
            };

        if let Some((peer_info, remote_latency, local_latency)) =
            self.find_best_route(network_code, target_ip)
        {
            let should_forward = if let Some(local_lat) = local_latency {
                if remote_latency < local_lat {
                    log::debug!(
                        "Remote path is faster: local={} ms, remote={} ms, forwarding to {}",
                        local_lat,
                        remote_latency,
                        peer_info.get_addr()
                    );
                    true
                } else {
                    log::debug!(
                        "Local path is faster: local={} ms, remote={} ms, using local",
                        local_lat,
                        remote_latency
                    );
                    false
                }
            } else if local_has_client {
                if remote_latency < DEFAULT_CLIENT_LATENCY_MS {
                    log::debug!(
                        "Remote path may be faster: local={}(default) ms, remote={} ms, forwarding to {}",
                        DEFAULT_CLIENT_LATENCY_MS,
                        remote_latency,
                        peer_info.get_addr()
                    );
                    true
                } else {
                    false
                }
            } else {
                true
            };

            if should_forward {
                log::debug!(
                    "Forwarding to peer server {} for {}, total latency: {} ms",
                    peer_info.get_addr(),
                    target_ip,
                    remote_latency
                );
                return self
                    .forward_to_peer(&peer_info, network_code.to_string(), data)
                    .await;
            }
        }

        false
    }
}

impl Clone for PeerServerManager {
    fn clone(&self) -> Self {
        Self {
            token_hash: self.token_hash.clone(),
            network_state_provider: self.network_state_provider.clone(),
            peer_servers: self.peer_servers.clone(),
            ip_to_routes: self.ip_to_routes.clone(),
            outbound_tasks: self.outbound_tasks.clone(),
        }
    }
}

// 自签名证书，跳过验证
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
