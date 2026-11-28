use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::reverse_proxy::{self as wire, Offer, Protocol, TOKEN_LEN};
use crate::server::network_state_provider::NetworkState;
use anyhow::{Context, Result, ensure};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::{Sink, SinkExt, Stream, StreamExt};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SETUP: Duration = Duration::from_secs(10);
const UDP_IDLE: Duration = Duration::from_secs(60);
const UDP_QUEUE_BYTES: usize = 128 * 1024;
const CLIENT_FLOWS: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct MappingConfig {
    pub protocol: Protocol,
    #[serde(default = "wildcard")]
    pub listen_ip: Ipv4Addr,
    pub listen_port: u16,
    pub network_code: String,
    pub virtual_ip: Ipv4Addr,
    pub lan_ip: Option<Ipv4Addr>,
    pub target_port: u16,
    #[serde(default = "enabled")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct MappingRule {
    pub id: String,
    #[serde(flatten)]
    pub config: MappingConfig,
}

#[derive(Serialize)]
pub(crate) struct MappingStatus {
    #[serde(flatten)]
    rule: MappingRule,
    listening: bool,
    bind_error: Option<String>,
    target_ready: bool,
}

fn wildcard() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

fn enabled() -> bool {
    true
}

impl MappingConfig {
    fn validate(&self) -> Result<()> {
        crate::utils::config::validate_network_code(&self.network_code)?;
        ensure!(
            self.listen_port != 0 && self.target_port != 0,
            "端口必须在 1–65535 范围内"
        );
        ensure!(
            !self.listen_ip.is_broadcast() && !self.listen_ip.is_multicast(),
            "监听地址无效"
        );
        ensure!(wire::valid_target(self.virtual_ip), "虚拟 IPv4 无效");
        ensure!(self.lan_ip.is_none_or(wire::valid_target), "内网 IPv4 无效");
        Ok(())
    }

    fn binding(&self) -> (Protocol, SocketAddr) {
        (
            self.protocol,
            SocketAddr::from((self.listen_ip, self.listen_port)),
        )
    }

    fn target(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.lan_ip.unwrap_or(Ipv4Addr::LOCALHOST), self.target_port)
    }
}

type FrameSink = Pin<Box<dyn Sink<Bytes, Error = anyhow::Error> + Send>>;
type FrameStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;
type Frames = (FrameSink, FrameStream);

pub(crate) struct ProxyLink {
    pub network: String,
    pub ip: Ipv4Addr,
    pub device_id: String,
    pub state: Arc<NetworkState>,
    pub instance: Vec<u8>,
    pub id: u64,
    pub sender: mpsc::WeakSender<Bytes>,
    pub stop: CancellationToken,
}

impl Drop for ProxyLink {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl ProxyLink {
    fn active(&self) -> bool {
        !self.stop.is_cancelled()
            && self.state.active_link_ip(self.ip, &self.instance, self.id) == Some(self.ip)
    }
}

struct Pending {
    link: Arc<ProxyLink>,
    stop: CancellationToken,
    expires: Instant,
    frames: oneshot::Sender<Frames>,
}

#[derive(Clone)]
struct Revision {
    config: MappingConfig,
    stop: CancellationToken,
}

enum Listener {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

impl Listener {
    fn bind(config: &MappingConfig) -> Result<Self> {
        let (protocol, addr) = config.binding();
        Ok(match protocol {
            Protocol::Tcp => Self::Tcp(TcpListener::from_std(
                crate::utils::net::bind_tcp_listener(addr)?,
            )?),
            Protocol::Udp => Self::Udp(UdpSocket::from_std(crate::utils::net::bind_udp_socket(
                addr,
            )?)?),
        })
    }
}

struct Running {
    updates: watch::Sender<Revision>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn stop(mut self) {
        self.updates.borrow().stop.cancel();
        self.shutdown.cancel();
        let _ = (&mut self.task).await;
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.updates.borrow().stop.cancel();
        self.task.abort();
    }
}

struct Entry {
    rule: MappingRule,
    running: Option<Running>,
    error: Option<String>,
}

pub(crate) enum Change {
    Create(MappingConfig),
    Update(String, MappingConfig),
    Delete(String),
}

pub(crate) struct ReverseProxy {
    rules: RwLock<Vec<Entry>>,
    links: DashMap<(String, Ipv4Addr), HashMap<u64, Arc<ProxyLink>>>,
    pending: DashMap<[u8; TOKEN_LEN], Pending>,
    capacity: Arc<Semaphore>,
    devices: DashMap<(String, String), Arc<Semaphore>>,
}

impl Default for ReverseProxy {
    fn default() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            links: DashMap::new(),
            pending: DashMap::new(),
            capacity: Arc::new(Semaphore::new(1024)),
            devices: DashMap::new(),
        }
    }
}

impl ReverseProxy {
    pub fn set_link(&self, link: ProxyLink) -> Arc<ProxyLink> {
        let link = Arc::new(link);
        self.links
            .entry((link.network.clone(), link.ip))
            .or_default()
            .insert(link.id, link.clone());
        link
    }

    pub fn clear_link(&self, link: &ProxyLink) {
        link.stop.cancel();
        let key = (link.network.clone(), link.ip);
        if let dashmap::mapref::entry::Entry::Occupied(mut entry) = self.links.entry(key) {
            entry.get_mut().remove(&link.id);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
    }

    fn target_link(&self, config: &MappingConfig) -> Option<Arc<ProxyLink>> {
        let links = self
            .links
            .get(&(config.network_code.clone(), config.virtual_ip))?;
        links.values().find(|link| link.active()).cloned()
    }

    pub fn list(&self) -> Vec<MappingStatus> {
        self.rules
            .read()
            .iter()
            .map(|entry| MappingStatus {
                rule: entry.rule.clone(),
                listening: entry
                    .running
                    .as_ref()
                    .is_some_and(|running| !running.task.is_finished()),
                bind_error: entry.error.clone(),
                target_ready: self.target_link(&entry.rule.config).is_some(),
            })
            .collect()
    }

    pub fn start(self: &Arc<Self>, rules: Vec<MappingRule>) {
        let mut entries = self.rules.write();
        for rule in rules {
            let binding = rule
                .config
                .enabled
                .then(|| Listener::bind(&rule.config))
                .transpose();
            let (running, error) = match binding {
                Ok(listener) => (
                    listener.map(|listener| self.listen(listener, rule.config.clone())),
                    None,
                ),
                Err(error) => {
                    log::warn!("端口映射 {} 监听失败: {error:#}", rule.id);
                    (None, Some(error.to_string()))
                }
            };
            entries.push(Entry {
                rule,
                running,
                error,
            });
        }
    }

    pub fn validate(rules: &[MappingRule]) -> Result<()> {
        let mut ids = HashSet::new();
        let mut ports = HashSet::new();
        for rule in rules {
            rule.config.validate()?;
            ensure!(
                !rule.id.is_empty() && ids.insert(&rule.id),
                "端口映射 ID 重复或为空"
            );
            ensure!(
                ports.insert((rule.config.protocol, rule.config.listen_port)),
                "同一协议的监听端口已存在"
            );
        }
        Ok(())
    }

    pub async fn change(self: &Arc<Self>, path: &Path, change: Change) -> Result<()> {
        let (rules, old_index, candidate, reuse) = {
            let entries = self.rules.read();
            let mut rules: Vec<_> = entries.iter().map(|entry| entry.rule.clone()).collect();
            let find = |id: &str| {
                entries
                    .iter()
                    .position(|entry| entry.rule.id == id)
                    .context("端口映射不存在")
            };
            let (old_index, candidate) = match change {
                Change::Create(config) => (
                    None,
                    Some(MappingRule {
                        id: Uuid::new_v4().to_string(),
                        config,
                    }),
                ),
                Change::Update(id, config) => (Some(find(&id)?), Some(MappingRule { id, config })),
                Change::Delete(id) => (Some(find(&id)?), None),
            };
            match (old_index, candidate.as_ref()) {
                (Some(index), Some(rule)) => rules[index] = rule.clone(),
                (Some(index), None) => {
                    rules.remove(index);
                }
                (None, Some(rule)) => rules.push(rule.clone()),
                (None, None) => unreachable!(),
            }
            Self::validate(&rules)?;
            let reuse = old_index
                .zip(candidate.as_ref())
                .is_some_and(|(index, next)| {
                    let old = &entries[index];
                    next.config.enabled
                        && old.rule.config.binding() == next.config.binding()
                        && old
                            .running
                            .as_ref()
                            .is_some_and(|running| !running.task.is_finished())
                });
            if let Some((index, next)) = old_index.zip(candidate.as_ref()) {
                let old = &entries[index];
                let a = &old.rule.config;
                let b = &next.config;
                if old.running.is_some()
                    && b.enabled
                    && !reuse
                    && a.protocol == b.protocol
                    && a.listen_port == b.listen_port
                    && a.listen_ip != b.listen_ip
                    && (a.listen_ip.is_unspecified() || b.listen_ip.is_unspecified())
                {
                    anyhow::bail!("新旧监听地址重叠，请先停用映射再更改监听地址");
                }
            }
            (rules, old_index, candidate, reuse)
        };
        let listener = candidate
            .as_ref()
            .filter(|rule| rule.config.enabled && !reuse)
            .map(|rule| Listener::bind(&rule.config))
            .transpose()?;
        // The HTTP caller holds the shared configuration lock through this commit.
        crate::utils::config::update_port_mappings(path, &rules)?;
        let retired = {
            let mut entries = self.rules.write();
            match (old_index, candidate) {
                (Some(index), Some(rule)) if reuse => {
                    let entry = &mut entries[index];
                    if entry.rule != rule {
                        let updates = &entry.running.as_ref().unwrap().updates;
                        updates
                            .send_replace(Revision {
                                config: rule.config.clone(),
                                stop: CancellationToken::new(),
                            })
                            .stop
                            .cancel();
                        entry.rule = rule;
                    }
                    None
                }
                (Some(index), Some(rule)) => {
                    let running =
                        listener.map(|listener| self.listen(listener, rule.config.clone()));
                    std::mem::replace(
                        &mut entries[index],
                        Entry {
                            rule,
                            running,
                            error: None,
                        },
                    )
                    .running
                }
                (Some(index), None) => entries.remove(index).running,
                (None, Some(rule)) => {
                    let running =
                        listener.map(|listener| self.listen(listener, rule.config.clone()));
                    entries.push(Entry {
                        rule,
                        running,
                        error: None,
                    });
                    None
                }
                (None, None) => unreachable!(),
            }
        };
        if let Some(retired) = retired {
            retired.stop().await;
        }
        Ok(())
    }

    fn listen(self: &Arc<Self>, listener: Listener, config: MappingConfig) -> Running {
        let (updates, read) = watch::channel(Revision {
            config,
            stop: CancellationToken::new(),
        });
        let manager = Arc::downgrade(self);
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let task = tokio::spawn(async move {
            match listener {
                Listener::Tcp(listener) => Self::listen_tcp(manager, listener, read, stop).await,
                Listener::Udp(socket) => Self::listen_udp(manager, socket, read, stop).await,
            }
        });
        Running {
            updates,
            shutdown,
            task,
        }
    }

    fn begin(self: &Arc<Self>, revision: &Revision, protocol: Protocol) -> Result<Flow> {
        let global = self.capacity.clone().try_acquire_owned()?;
        let link = self
            .target_link(&revision.config)
            .context("reverse proxy target unavailable")?;
        let device_key = (link.network.clone(), link.device_id.clone());
        let permit = self
            .devices
            .entry(device_key.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(CLIENT_FLOWS)))
            .clone()
            .try_acquire_owned()?;
        let device = DevicePermit {
            manager: Arc::downgrade(self),
            key: device_key,
            permit: Some(permit),
        };
        let expires = Instant::now() + SETUP;
        let mut token = [0; TOKEN_LEN];
        rand::rng().fill_bytes(&mut token);
        let offer = Offer {
            protocol,
            target: revision.config.target(),
            token,
        }
        .encode();
        let mut packet = NetPacket::new(BytesMut::zeroed(HEAD_LENGTH + offer.len()))?;
        packet.set_msg_type(MsgType::ReverseProxy);
        packet.set_gateway_flag(true);
        packet.set_ttl(1);
        packet.set_src_id(u32::from(link.state.gateway()));
        packet.set_dest_id(u32::from(link.ip));
        packet.payload_mut().copy_from_slice(&offer);
        let (frames, recv) = oneshot::channel();
        let stop = revision.stop.clone();
        self.pending.insert(
            token,
            Pending {
                link: link.clone(),
                stop: stop.clone(),
                expires,
                frames,
            },
        );
        let flow = Flow {
            manager: Arc::downgrade(self),
            token,
            link,
            stop,
            expires,
            recv: Some(recv),
            _global: global,
            _device: device,
        };
        let sender = flow
            .link
            .sender
            .upgrade()
            .context("reverse proxy client disconnected")?;
        sender.try_send(packet.into_buffer().freeze())?;
        Ok(flow)
    }

    pub fn attach<S, R, B, E>(&self, token: [u8; TOKEN_LEN], send: S, recv: R) -> Result<()>
    where
        S: Sink<Bytes> + Send + 'static,
        S::Error: Into<anyhow::Error>,
        R: Stream<Item = std::result::Result<B, E>> + Send + 'static,
        B: Into<Bytes>,
        E: Into<anyhow::Error>,
    {
        let (_, pending) = self
            .pending
            .remove(&token)
            .context("unknown reverse proxy attachment")?;
        ensure!(
            Instant::now() < pending.expires
                && !pending.stop.is_cancelled()
                && pending.link.active(),
            "expired reverse proxy attachment"
        );
        let frames: Frames = (
            Box::pin(send.sink_map_err(Into::into)),
            Box::pin(recv.map(|frame| frame.map(Into::into).map_err(Into::into))),
        );
        pending
            .frames
            .send(frames)
            .map_err(|_| anyhow::anyhow!("reverse proxy flow closed"))
    }

    async fn listen_tcp(
        manager: Weak<Self>,
        listener: TcpListener,
        config: watch::Receiver<Revision>,
        shutdown: CancellationToken,
    ) {
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (socket, _) = match accepted {
                Ok(value) => value,
                Err(error) => {
                    log::warn!("端口映射 TCP accept: {error}");
                    tokio::time::sleep(super::ACCEPT_ERROR_RETRY_DELAY).await;
                    continue;
                }
            };
            let revision = config.borrow().clone();
            let Some(manager) = manager.upgrade() else {
                break;
            };
            if let Ok(mut flow) = manager.begin(&revision, Protocol::Tcp) {
                tokio::spawn(async move {
                    let _ = flow
                        .run(|(send, recv): Frames| wire::relay_tcp(socket, send, recv))
                        .await;
                });
            }
        }
    }

    async fn listen_udp(
        manager: Weak<Self>,
        socket: UdpSocket,
        mut config: watch::Receiver<Revision>,
        shutdown: CancellationToken,
    ) {
        let socket = Arc::new(socket);
        let mut sources = HashMap::<SocketAddr, UdpSource>::new();
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; wire::MAX_DATAGRAM];
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                updated = config.changed() => {
                    if updated.is_err() { break; }
                    sources.clear();
                    tasks.abort_all();
                }
                Some(Ok((peer, token))) = tasks.join_next(), if !tasks.is_empty() => {
                    if sources.get(&peer).is_some_and(|source| source.token == token) {
                        sources.remove(&peer);
                    }
                }
                datagram = socket.recv_from(&mut buffer) => {
                    let (len, peer) = match datagram {
                        Ok(value) => value,
                        Err(error) => {
                            log::warn!("端口映射 UDP recv: {error}");
                            tokio::time::sleep(super::ACCEPT_ERROR_RETRY_DELAY).await;
                            continue;
                        }
                    };
                    if sources.get(&peer).is_some_and(|source| source.send.is_closed()) {
                        sources.remove(&peer);
                    }
                    let source = match sources.entry(peer) {
                        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            let revision = config.borrow().clone();
                            let Some(manager) = manager.upgrade() else { break; };
                            let Ok(mut flow) = manager.begin(&revision, Protocol::Udp) else { continue };
                            let token = flow.token;
                            let (send, recv) = mpsc::channel(8);
                            let socket = socket.clone();
                            tasks.spawn(async move {
                                let _ = flow.run(|frames: Frames| relay_udp(socket, peer, recv, frames)).await;
                                (peer, token)
                            });
                            entry.insert(UdpSource { token, send, budget: Arc::new(Semaphore::new(UDP_QUEUE_BYTES)) })
                        }
                    };
                    if let Ok(permit) = source.budget.clone().try_acquire_many_owned(len as u32) {
                        let _ = source.send.try_send((wire::data_frame(&buffer[..len]), permit));
                    }
                }
            }
        }
        tasks.shutdown().await;
    }
}

type QueuedDatagram = (Bytes, OwnedSemaphorePermit);

struct UdpSource {
    token: [u8; TOKEN_LEN],
    send: mpsc::Sender<QueuedDatagram>,
    budget: Arc<Semaphore>,
}

async fn relay_udp(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut incoming: mpsc::Receiver<QueuedDatagram>,
    (mut send, mut recv): Frames,
) -> Result<()> {
    let deadline = tokio::time::sleep(UDP_IDLE);
    tokio::pin!(deadline);
    // Sending and receiving progress independently even under backpressure.
    let (activity, mut changes) = watch::channel(Instant::now());
    let received = activity.clone();
    tokio::try_join!(
        async {
            while let Some((frame, _permit)) = incoming.recv().await {
                send.send(frame).await?;
                activity.send_replace(Instant::now());
            }
            Err::<(), _>(anyhow::anyhow!("UDP listener closed"))
        },
        async {
            while let Some(frame) = recv.next().await {
                let frame = frame?;
                socket.send_to(wire::datagram(&frame)?, peer).await?;
                received.send_replace(Instant::now());
            }
            Err::<(), _>(anyhow::anyhow!("UDP client disconnected"))
        },
        async {
            loop {
                tokio::select! {
                    _ = &mut deadline => return Err::<(), _>(anyhow::anyhow!("UDP mapping idle")),
                    Ok(()) = changes.changed() => deadline.as_mut().reset(*changes.borrow_and_update() + UDP_IDLE),
                }
            }
        },
    )?;
    Ok(())
}

struct DevicePermit {
    manager: Weak<ReverseProxy>,
    key: (String, String),
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for DevicePermit {
    fn drop(&mut self) {
        self.permit.take();
        if let Some(manager) = self.manager.upgrade() {
            manager.devices.remove_if(&self.key, |_, value| {
                value.available_permits() == CLIENT_FLOWS && Arc::strong_count(value) == 1
            });
        }
    }
}

struct Flow {
    manager: Weak<ReverseProxy>,
    token: [u8; TOKEN_LEN],
    link: Arc<ProxyLink>,
    stop: CancellationToken,
    expires: Instant,
    recv: Option<oneshot::Receiver<Frames>>,
    _global: OwnedSemaphorePermit,
    _device: DevicePermit,
}

impl Flow {
    async fn run<F, Fut>(&mut self, relay: F) -> Result<()>
    where
        F: FnOnce(Frames) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => Ok(()),
            _ = self.link.stop.cancelled() => Ok(()),
            _ = async {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                while self.link.active() {
                    interval.tick().await;
                }
            } => Ok(()),
            result = async {
                let frames = timeout_at(self.expires, async {
                    let (mut send, mut recv) = self.recv.take().unwrap().await?;
                    send.send(Bytes::from_static(wire::ACCEPT)).await?;
                    let ready = recv.next().await.context("reverse proxy setup disconnected")??;
                    ensure!(ready == wire::READY, "reverse proxy endpoint not ready");
                    Ok::<_, anyhow::Error>((send, recv))
                }).await??;
                relay(frames).await
            } => result,
        }
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            manager.pending.remove(&self.token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::ConfigFile;

    fn mapping(port: u16) -> MappingConfig {
        MappingConfig {
            protocol: Protocol::Tcp,
            listen_ip: Ipv4Addr::LOCALHOST,
            listen_port: port,
            network_code: "test-net".into(),
            virtual_ip: Ipv4Addr::new(10, 26, 0, 2),
            lan_ip: None,
            target_port: 8080,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn config_and_listener_change_together() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        ConfigFile::default().save_to(&path)?;
        let original = std::fs::read_to_string(&path)?;
        std::fs::write(&path, format!("# keep this comment\n{original}"))?;
        let proxy = Arc::new(ReverseProxy::default());

        let occupied = TcpListener::bind("127.0.0.1:0").await?;
        let occupied_port = occupied.local_addr()?.port();
        assert!(
            proxy
                .change(&path, Change::Create(mapping(occupied_port)))
                .await
                .is_err()
        );
        assert!(proxy.list().is_empty());
        drop(occupied);

        let config = mapping(occupied_port);
        proxy.change(&path, Change::Create(config.clone())).await?;
        let status = proxy.list().pop().unwrap();
        assert!(status.listening);
        let id = status.rule.id;
        let updated = MappingConfig {
            target_port: 9999,
            ..config.clone()
        };
        assert!(
            proxy
                .change(
                    &dir.path().join("unwritable"),
                    Change::Update(id.clone(), updated.clone())
                )
                .await
                .is_err()
        );
        assert_eq!(proxy.list()[0].rule.config, config);
        assert!(TcpListener::bind(config.binding().1).await.is_err());

        proxy
            .change(&path, Change::Update(id.clone(), updated.clone()))
            .await?;
        let mut udp = updated.clone();
        udp.protocol = Protocol::Udp;
        proxy.change(&path, Change::Create(udp)).await?;
        let persisted = ConfigFile::load_from(Some(path.clone()))?;
        assert_eq!(persisted.port_mappings[0].config, updated);
        assert_eq!(persisted.port_mappings.len(), 2);
        assert!(std::fs::read_to_string(&path)?.starts_with("# keep this comment"));

        proxy.change(&path, Change::Delete(id)).await?;
        assert!(TcpListener::bind(config.binding().1).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn startup_keeps_bind_errors_visible() -> Result<()> {
        let occupied = TcpListener::bind("127.0.0.1:0").await?;
        let config = mapping(occupied.local_addr()?.port());
        let proxy = Arc::new(ReverseProxy::default());
        proxy.start(vec![MappingRule {
            id: "blocked".into(),
            config,
        }]);
        let list = proxy.list();
        assert!(!list[0].listening);
        assert!(list[0].bind_error.is_some());
        assert!(!list[0].target_ready);
        Ok(())
    }
}
