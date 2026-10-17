use crate::managed_config::{
    canonicalize_stored_client_config, client_proof, constant_time_hash_eq,
    managed_config_semantically_equal, server_proof,
};
use crate::protocol::control_message::{
    RegRequestMsg, RegistrationMode, SubscriptionConfigAck, SubscriptionConfigApplyStatus,
    SubscriptionConfigEnvelope, SubscriptionConfigFetchRequest, SubscriptionRegisterRequest,
    SubscriptionRegistration, SubscriptionServerProof,
};
use crate::server::control_server::db;
use crate::server::control_server::db::{
    ClientType, DeviceIpType, Ikev2InputRoute, NetworkRecord, NetworkSource, NetworkType,
};
use crate::server::network_state_provider::{
    NetworkState, NetworkStateProvider, format_system_time_local, i64_to_system_time,
};
use anyhow::{Context, bail};
use base64::Engine;
use bytes::Bytes;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::Ipv4Net;
use parking_lot::RwLock;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, Instant, timeout};

const SUBSCRIPTION_PUSH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationStatus {
    Confirmed,
    PendingConfirmation,
}

/// Result of attempting to place a managed-configuration revision on the
/// currently connected subscription session's outbound queue. `Queued` is a
/// transport boundary only: the client still reports actual application by
/// sending a configuration acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionPushStatus {
    Queued,
    NotConnected,
    Registering,
    Timeout,
    Closed,
    Unchanged,
}

#[derive(Clone, Copy)]
pub struct NetworkConfig {
    pub net: Ipv4Net,
    pub gateway: Ipv4Addr,
    pub lease_duration: Duration,
    pub source: NetworkSource,
    pub network_type: NetworkType,
}

#[derive(Clone, Copy)]
enum DeviceMutation {
    Create(ClientType),
    Update,
}

fn validate_gateway(net: Ipv4Net, gateway: Ipv4Addr) -> anyhow::Result<()> {
    if net.prefix_len() > 30 {
        bail!("掩码 /{} 没有足够的可用主机地址", net.prefix_len());
    }
    if !net.contains(&gateway) || gateway == net.network() || gateway == net.broadcast() {
        bail!("网关 {} 必须是网段 {} 中的可用主机地址", gateway, net);
    }
    Ok(())
}

fn first_usable_ip(net: Ipv4Net) -> anyhow::Result<Ipv4Addr> {
    if net.prefix_len() > 30 {
        bail!("网段 {} 没有足够的可用主机地址", net);
    }
    let value = u32::from(net.network())
        .checked_add(1)
        .context("Network address overflow")?;
    let gateway = Ipv4Addr::from(value);
    validate_gateway(net, gateway)?;
    Ok(gateway)
}

fn network_from_gateway(gateway: Ipv4Addr, netmask: u8) -> anyhow::Result<Ipv4Net> {
    if netmask > 30 {
        bail!("无效的掩码 /{}，必须小于等于 30", netmask);
    }
    let net = Ipv4Net::new(gateway, netmask)
        .context("Invalid network")?
        .trunc();
    validate_gateway(net, gateway)?;
    Ok(net)
}

fn authenticate_managed_access(
    config: Option<&db::ManagedConfigRecord>,
    registration: Option<&SubscriptionRegistration>,
) -> Option<SubscriptionServerProof> {
    let registration = registration?;
    let encoded = config?.credential_key.as_deref()?;
    let credential_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .filter(|value| value.len() == 32)?;
    if registration.client_nonce.len() != 32
        || registration.client_proof.len() != 32
        || registration.instance_id.len() != 32
    {
        return None;
    }
    let expected = client_proof(&credential_key, &registration.client_nonce);
    if !constant_time_hash_eq(&expected, &registration.client_proof) {
        return None;
    };
    let mut server_nonce = vec![0_u8; 32];
    rand::rng().fill_bytes(&mut server_nonce);
    Some(SubscriptionServerProof {
        server_proof: server_proof(&credential_key, &registration.client_nonce, &server_nonce),
        server_nonce,
        target_revision: config?.revision as u64,
    })
}

fn validate_subscription_identity(
    reg_req: &RegRequestMsg,
    registration: Option<&SubscriptionRegistration>,
) -> anyhow::Result<Option<(String, String)>> {
    let Some(registration) = registration else {
        return Ok(None);
    };
    if registration.network_code != reg_req.network_code
        || registration.device_id != reg_req.device_id
    {
        bail!(
            "订阅身份与注册身份不一致: subscription={}/{}, registration={}/{}",
            registration.network_code,
            registration.device_id,
            reg_req.network_code,
            reg_req.device_id
        );
    }
    Ok(Some((
        registration.network_code.clone(),
        registration.device_id.clone(),
    )))
}

fn validate_registered_revision(applied_revision: u64, server_revision: i64) -> anyhow::Result<()> {
    if applied_revision > server_revision as u64 {
        bail!(
            "客户端受管配置 revision {} 超过服务端 revision {}",
            applied_revision,
            server_revision
        );
    }
    Ok(())
}

fn ack_can_update_live_state(
    ack_revision: u64,
    target_revision: u64,
    applied_revision: u64,
) -> bool {
    ack_revision == target_revision && ack_revision >= applied_revision
}

#[derive(Clone)]
struct SubscriptionSessionEntry {
    instance_id: Vec<u8>,
    client_instance_id: Vec<u8>,
    runtime_network_code: String,
    ip: Ipv4Addr,
    /// Device-scoped sync state reported by this client run. Registration
    /// seeds it and config ACKs keep it current. It deliberately dies with
    /// the session: the durable record only stores the server-authored
    /// revision, never a snapshot of what the client last ran.
    applied_revision: u64,
    apply_error: Option<(u64, String)>,
    overridden_fields: Vec<String>,
    links: HashMap<u64, SubscriptionSessionLink>,
}

#[derive(Clone)]
struct SubscriptionSessionLink {
    sender: Sender<Bytes>,
    server_proof: SubscriptionServerProof,
    /// False only until RegResponse has entered the same reliable outbound
    /// queue. It protects protocol ordering and is never controlled by an ACK.
    registration_complete: bool,
    control_connection: bool,
}

/// Sync state observed on a device's live subscription session.
#[derive(Clone, Debug)]
pub struct SubscriptionLiveState {
    pub applied_revision: u64,
    apply_error: Option<(u64, String)>,
    pub overridden_fields: Vec<String>,
}

impl SubscriptionLiveState {
    /// Failure reason reported for `target_revision`. It is hidden once the
    /// durable record advances past the revision the client failed to apply.
    pub fn apply_error(&self, target_revision: i64) -> Option<&str> {
        let (revision, error) = self.apply_error.as_ref()?;
        (*revision == target_revision as u64).then_some(error.as_str())
    }

    pub fn status(&self, target_revision: i64) -> &'static str {
        if self.applied_revision >= target_revision as u64 {
            "applied"
        } else if self.apply_error(target_revision).is_some() {
            "error"
        } else {
            "pending"
        }
    }
}

#[derive(Clone)]
struct SubscriptionSessionTarget {
    runtime_network_code: String,
    ip: Ipv4Addr,
    sender: Sender<Bytes>,
    server_proof: SubscriptionServerProof,
    applied_revision: u64,
    control_connection: bool,
}

impl SubscriptionSessionEntry {
    fn target(&self, require_complete: bool) -> Option<SubscriptionSessionTarget> {
        self.targets(require_complete).into_iter().next()
    }

    fn targets(&self, require_complete: bool) -> Vec<SubscriptionSessionTarget> {
        self.links
            .iter()
            .filter(|(_, link)| !require_complete || link.registration_complete)
            .map(|(_, link)| SubscriptionSessionTarget {
                runtime_network_code: self.runtime_network_code.clone(),
                ip: self.ip,
                sender: link.sender.clone(),
                server_proof: link.server_proof.clone(),
                applied_revision: self.applied_revision,
                control_connection: link.control_connection,
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct ControlService {
    server_instance_id: Arc<Vec<u8>>,
    default_net: Ipv4Net,
    default_gateway: Ipv4Addr,
    default_lease_duration: Duration,
    white_list: Arc<RwLock<HashSet<String>>>,
    db_nets: Arc<RwLock<HashMap<String, NetworkConfig>>>,
    network_state_provider: NetworkStateProvider,
    network_init_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    device_mutation_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    subscription_sessions: Arc<DashMap<(String, String), SubscriptionSessionEntry>>,
    ikev2_device_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    wireguard_device_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    peer_manager: Arc<RwLock<Option<Arc<crate::server::peer_server::PeerServerManager>>>>,
    ikev2_manager: Arc<RwLock<Option<crate::server::ikev2::Ikev2Handle>>>,
    ikev2_runtime_error: Arc<RwLock<Option<String>>>,
    wireguard_manager: Arc<RwLock<Option<crate::server::wireguard::WireGuardHandle>>>,
    wireguard_runtime_error: Arc<RwLock<Option<String>>>,
}

impl ControlService {
    pub async fn new(
        default_net: Ipv4Net,
        custom_nets: HashMap<String, Ipv4Net>,
        white_list: HashSet<String>,
        lease_duration: Duration,
    ) -> anyhow::Result<Self> {
        let default_net = default_net.trunc();
        let default_gateway = first_usable_ip(default_net)?;
        let network_states = Arc::new(DashMap::new());

        let config_nets = Self::build_config_networks(&custom_nets, lease_duration);
        Self::save_config_networks_to_db(&config_nets).await;
        let db_nets = Self::merge_network_configs(Self::load_networks_from_db().await, config_nets);

        let service = Self {
            server_instance_id: Arc::new({
                let mut value = vec![0_u8; 32];
                rand::rng().fill_bytes(&mut value);
                value
            }),
            default_net,
            default_gateway,
            default_lease_duration: lease_duration,
            white_list: Arc::new(RwLock::new(white_list)),
            db_nets: Arc::new(RwLock::new(db_nets)),
            network_state_provider: NetworkStateProvider::new(network_states),
            network_init_locks: Arc::new(DashMap::new()),
            device_mutation_locks: Arc::new(DashMap::new()),
            subscription_sessions: Arc::new(DashMap::new()),
            ikev2_device_mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            wireguard_device_mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            peer_manager: Arc::new(RwLock::new(None)),
            ikev2_manager: Arc::new(RwLock::new(None)),
            ikev2_runtime_error: Arc::new(RwLock::new(None)),
            wireguard_manager: Arc::new(RwLock::new(None)),
            wireguard_runtime_error: Arc::new(RwLock::new(None)),
        };

        let cleanup_interval = Duration::from_secs(30 * 60);
        let cleanup_interval = cleanup_interval
            .min(lease_duration / 2)
            .max(Duration::from_secs(10));
        service.start_cleanup_task(cleanup_interval);
        service.migrate_managed_config_representation().await;

        Ok(service)
    }

    pub fn server_instance_id(&self) -> Vec<u8> {
        self.server_instance_id.as_ref().clone()
    }

    async fn migrate_managed_config_representation(&self) {
        let records = match db::list_managed_configs().await {
            Ok(records) => records,
            Err(error) => {
                log::error!("读取历史受管配置以执行规范化迁移失败: {error:#}");
                return;
            }
        };
        for record in records {
            let canonical = match canonicalize_stored_client_config(
                &record.config_toml,
                &record.configured_device_name,
                record.fixed_ip.is_some(),
                Some(record.subscription_server.as_str()).filter(|value| !value.trim().is_empty()),
            ) {
                Ok(value) => value,
                Err(error) => {
                    log::error!(
                        "设备 {}/{} revision {} 的历史受管配置无效，未迁移且不会下发: {error:#}",
                        record.network_code,
                        record.device_id,
                        record.revision
                    );
                    continue;
                }
            };
            if canonical == record.config_toml {
                continue;
            }
            let semantic_equal =
                match managed_config_semantically_equal(&record.config_toml, &canonical) {
                    Ok(value) => value,
                    Err(error) => {
                        log::error!(
                            "设备 {}/{} revision {} 的历史受管配置无法比较: {error:#}",
                            record.network_code,
                            record.device_id,
                            record.revision
                        );
                        continue;
                    }
                };
            let result = if semantic_equal {
                db::rewrite_managed_config(
                    &record.network_code,
                    &record.device_id,
                    &canonical,
                    // 迁移不初始化 join_id：历史记录留空，编辑或签发时再补赋
                    &record.join_id,
                    record.updated_at,
                )
                .await
            } else {
                db::update_managed_config(
                    &record.network_code,
                    &record.device_id,
                    &canonical,
                    &record.join_id,
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                )
                .await
            };
            if let Err(error) = result {
                log::error!(
                    "设备 {}/{} revision {} 的历史受管配置规范化写回失败: {error:#}",
                    record.network_code,
                    record.device_id,
                    record.revision
                );
            }
        }
    }

    fn build_config_networks(
        custom_nets: &HashMap<String, Ipv4Net>,
        lease_duration: Duration,
    ) -> HashMap<String, NetworkConfig> {
        let mut config_nets = HashMap::with_capacity(custom_nets.len());
        for (code, net) in custom_nets {
            let net = net.trunc();
            let gateway = match first_usable_ip(net) {
                Ok(gateway) => gateway,
                Err(e) => {
                    log::error!("Invalid custom network {} ({}): {}", code, net, e);
                    continue;
                }
            };
            config_nets.insert(
                code.clone(),
                NetworkConfig {
                    net,
                    gateway,
                    lease_duration,
                    source: NetworkSource::Config,
                    network_type: NetworkType::Public,
                },
            );
        }
        config_nets
    }

    async fn save_config_networks_to_db(config_nets: &HashMap<String, NetworkConfig>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        for (code, config) in config_nets {
            let record = NetworkRecord {
                network_code: code.clone(),
                gateway: config.gateway.to_string(),
                netmask: config.net.prefix_len(),
                lease_duration: config.lease_duration.as_secs() as i64,
                source: NetworkSource::Config,
                network_type: config.network_type,
                created_at: now,
            };
            match db::save_network_if_not_exists(&record).await {
                Ok(true) => log::info!("Initialized network '{}' from config", code),
                Ok(false) => {}
                Err(e) => log::error!("Failed to save custom network {}: {}", code, e),
            }
        }
    }

    fn merge_network_configs(
        db_nets: HashMap<String, NetworkConfig>,
        mut config_nets: HashMap<String, NetworkConfig>,
    ) -> HashMap<String, NetworkConfig> {
        // 配置用于首次初始化；持久化开启且数据库已有记录时，以数据库中的修改为准。
        // 持久化关闭时 db_nets 为空，因此 TOML 中的自定义网络仍会在内存中生效。
        config_nets.extend(db_nets);
        config_nets
    }

    fn network_code_allowed(&self, network_code: &str) -> bool {
        let white_list = self.white_list.read();
        white_list.is_empty() || white_list.contains(network_code)
    }

    pub fn get_white_list(&self) -> Vec<String> {
        let mut white_list = self.white_list.read().iter().cloned().collect::<Vec<_>>();
        white_list.sort();
        white_list
    }

    pub fn replace_white_list(&self, white_list: HashSet<String>) {
        *self.white_list.write() = white_list;
    }

    async fn load_networks_from_db() -> HashMap<String, NetworkConfig> {
        let mut nets = HashMap::new();
        match db::load_all_networks().await {
            Ok(records) => {
                for record in records {
                    let gateway = record.gateway.parse::<Ipv4Addr>();
                    if let (Some(net), Ok(gateway)) = (record.to_ipv4_net(), gateway)
                        && validate_gateway(net, gateway).is_ok()
                    {
                        nets.insert(
                            record.network_code,
                            NetworkConfig {
                                net,
                                gateway,
                                lease_duration: Duration::from_secs(record.lease_duration as u64),
                                source: record.source,
                                network_type: record.network_type,
                            },
                        );
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to load networks from DB: {}", e);
            }
        }
        nets
    }

    pub async fn register(
        &self,
        reg_req: RegRequestMsg,
        sender: Sender<Bytes>,
    ) -> anyhow::Result<Session> {
        self.register_inner(reg_req, sender, ClientType::Vnt).await
    }

    async fn register_inner(
        &self,
        reg_req: RegRequestMsg,
        sender: Sender<Bytes>,
        client_type: ClientType,
    ) -> anyhow::Result<Session> {
        reg_req.check()?;
        let network_code = reg_req.network_code.clone();
        let registration_mode = reg_req.registration_mode;
        let allow_ikev2 = reg_req.allow_ikev2;
        let allow_wireguard = reg_req.allow_wireguard;
        // The experimental subscription extension on ordinary registration is
        // intentionally ignored. Managed synchronization is authenticated only
        // by SubscriptionRegister on its dedicated control connection.
        let subscription_registration = None;
        let claimed_subscription_identity =
            validate_subscription_identity(&reg_req, subscription_registration.as_ref())?;
        let managed_config =
            if let Some((managed_network, managed_device)) = &claimed_subscription_identity {
                db::get_managed_config(managed_network, managed_device).await?
            } else {
                None
            };
        let mut subscription_server_proof = authenticate_managed_access(
            managed_config.as_ref(),
            subscription_registration.as_ref(),
        );
        if !self.network_code_allowed(&network_code) {
            bail!("network_code '{}' is not in white_list", network_code);
        }

        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _mutation_guard = mutation_lock.lock().await;

        let is_new_network = !self.db_nets.read().contains_key(&reg_req.network_code);
        let config = self.network_config(&reg_req.network_code, reg_req.ip)?;

        if is_new_network {
            self.db_nets
                .write()
                .insert(reg_req.network_code.clone(), config);
        }

        let state = self
            .get_or_create_network_state(reg_req.network_code.clone(), config)
            .await;

        if let (Some(identity), Some(registration)) = (
            claimed_subscription_identity.as_ref(),
            subscription_registration.as_ref(),
        ) && self
            .subscription_sessions
            .get(identity)
            .is_some_and(|session| {
                session.instance_id.as_slice() != registration.instance_id.as_slice()
            })
        {
            subscription_server_proof = None;
        }
        // Presence of an unverified subscription extension must not change
        // ordinary session behaviour before subscription authentication.
        let subscription_identity = subscription_server_proof
            .as_ref()
            .and_then(|_| claimed_subscription_identity.clone());
        if subscription_identity.is_some()
            && let (Some(record), Some(registration)) =
                (managed_config.as_ref(), subscription_registration.as_ref())
        {
            validate_registered_revision(registration.applied_revision, record.revision)?;
        }

        let existing = state.get_device_entry(&reg_req.device_id);
        if existing
            .as_ref()
            .is_some_and(|entry| entry.client_type != client_type)
        {
            bail!("设备 ID '{}' 已被其他设备类型占用", reg_req.device_id);
        }
        if client_type != ClientType::Vnt && existing.is_none() {
            bail!("外部接入设备 '{}' 未由管理员预先创建", reg_req.device_id);
        }

        if config.network_type == NetworkType::Private
            && client_type == ClientType::Vnt
            && !state.has_device(&reg_req.device_id)
        {
            bail!("私有网络仅允许已添加的设备连接");
        }

        let (session, entry) = {
            let random_id = rand::rng().next_u64();
            let device_id = reg_req.device_id.clone();
            let client_instance_id = reg_req.client_instance_id.clone();

            let managed_sender = sender.clone();
            let (ip, _old_ip, entry) = match state.allocate_ip_and_get_entry_as(
                reg_req,
                random_id,
                sender,
                client_type,
                client_instance_id.clone(),
            ) {
                Ok(rs) => rs,
                Err(e) => {
                    log::warn!("network_code={network_code},device_id={device_id},e={e:?}");
                    return Err(e);
                }
            };

            if let (Some(identity), Some(registration), Some(_)) = (
                subscription_identity.clone(),
                subscription_registration.as_ref(),
                subscription_server_proof.as_ref(),
            ) {
                let link = SubscriptionSessionLink {
                    sender: managed_sender,
                    server_proof: subscription_server_proof.clone().expect("checked proof"),
                    registration_complete: false,
                    control_connection: false,
                };
                let appended = if !client_instance_id.is_empty() {
                    self.subscription_sessions
                        .get_mut(&identity)
                        .is_some_and(|mut current| {
                            if current.instance_id == registration.instance_id
                                && current.client_instance_id == client_instance_id
                            {
                                current.ip = ip;
                                current.applied_revision =
                                    current.applied_revision.max(registration.applied_revision);
                                current.links.insert(random_id, link.clone());
                                true
                            } else {
                                false
                            }
                        })
                } else {
                    false
                };
                if !appended {
                    self.subscription_sessions.insert(
                        identity,
                        SubscriptionSessionEntry {
                            instance_id: registration.instance_id.clone(),
                            client_instance_id: client_instance_id.clone(),
                            runtime_network_code: network_code.clone(),
                            ip,
                            applied_revision: registration.applied_revision,
                            apply_error: None,
                            overridden_fields: Vec::new(),
                            links: HashMap::from([(random_id, link)]),
                        },
                    );
                }
            }

            (
                Session {
                    network_code: network_code.clone(),
                    device_id: device_id.clone(),
                    ip,
                    random_id,
                    client_instance_id,
                    network_state: state.clone(),
                    registration_status: match registration_mode {
                        RegistrationMode::Normal => RegistrationStatus::Confirmed,
                        RegistrationMode::PreRegister => RegistrationStatus::PendingConfirmation,
                    },
                    allow_ikev2,
                    allow_wireguard,
                    subscription_identity,
                    subscription_server_proof,
                    subscription_sessions: self.subscription_sessions.clone(),
                },
                entry,
            )
        };

        if is_new_network {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let record = NetworkRecord {
                network_code: network_code.clone(),
                gateway: config.gateway.to_string(),
                netmask: config.net.prefix_len(),
                lease_duration: config.lease_duration.as_secs() as i64,
                source: NetworkSource::DeviceRegister,
                network_type: NetworkType::Public,
                created_at: now,
            };
            tokio::spawn(async move {
                if let Err(e) = db::save_network(&record).await {
                    log::error!("Failed to save new network: {:?}", e);
                }
            });
        }

        if matches!(registration_mode, RegistrationMode::Normal)
            && let Some(entry) = entry
        {
            let nc = network_code.clone();
            let record = entry.to_record(&nc);
            db::save_or_update_device(&record).await?;
        }

        Ok(session)
    }

    pub async fn fetch_subscription_config(
        &self,
        request: SubscriptionConfigFetchRequest,
    ) -> anyhow::Result<SubscriptionConfigEnvelope> {
        let record = db::get_managed_config_by_join_id(&request.join_id)
            .await?
            .filter(|record| record.credential_key.is_some())
            .ok_or_else(|| anyhow::anyhow!("订阅链接无效，或设备已被删除"))?;
        if request.client_nonce.len() != 32 || request.client_proof.len() != 32 {
            bail!("订阅链接客户端证明无效");
        }
        let credential_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                record
                    .credential_key
                    .as_deref()
                    .context("订阅链接凭据不存在")?,
            )
            .context("订阅链接凭据无效")?;
        if credential_key.len() != 32 {
            bail!("订阅链接凭据长度无效");
        }
        let expected = client_proof(&credential_key, &request.client_nonce);
        if !constant_time_hash_eq(&expected, &request.client_proof) {
            bail!("订阅链接凭据无效或已被重新签发");
        }
        let mut server_nonce = vec![0_u8; 32];
        rand::rng().fill_bytes(&mut server_nonce);
        let proof = SubscriptionServerProof {
            server_proof: server_proof(&credential_key, &request.client_nonce, &server_nonce),
            server_nonce,
            target_revision: record.revision as u64,
        };
        self.subscription_envelope(&record, proof)
    }

    /// Registers a long-lived subscription control connection without
    /// allocating an address or joining the traffic network.
    pub async fn register_subscription_connection(
        &self,
        request: SubscriptionRegisterRequest,
        sender: Sender<Bytes>,
    ) -> anyhow::Result<(SubscriptionConfigEnvelope, SubscriptionControlSession)> {
        // The link only carries the join id; the device identity comes from the
        // authenticated record, never from the request itself.
        let record = db::get_managed_config_by_join_id(&request.join_id)
            .await?
            .filter(|record| record.credential_key.is_some())
            .context("订阅链接无效，或设备已被删除")?;
        let registration = SubscriptionRegistration {
            network_code: record.network_code.clone(),
            device_id: record.device_id.clone(),
            client_nonce: request.client_nonce,
            client_proof: request.client_proof,
            instance_id: request.instance_id,
            applied_revision: request.applied_revision,
        };
        let proof = authenticate_managed_access(Some(&record), Some(&registration))
            .context("订阅链接凭据无效或已被重新签发")?;
        validate_registered_revision(registration.applied_revision, record.revision)?;

        let identity = (record.network_code.clone(), record.device_id.clone());
        if self
            .subscription_sessions
            .get(&identity)
            .is_some_and(|session| session.instance_id != registration.instance_id)
        {
            bail!("该设备已有另一个订阅任务保持连接");
        }
        let random_id = rand::random::<u64>();
        let ip = record.configured_ip.context("受管设备未配置目标 IP")?;
        self.subscription_sessions.insert(
            identity.clone(),
            SubscriptionSessionEntry {
                instance_id: registration.instance_id,
                client_instance_id: Vec::new(),
                runtime_network_code: record.network_code.clone(),
                ip,
                applied_revision: registration.applied_revision,
                apply_error: None,
                overridden_fields: Vec::new(),
                links: HashMap::from([(
                    random_id,
                    SubscriptionSessionLink {
                        sender,
                        server_proof: proof.clone(),
                        registration_complete: true,
                        control_connection: true,
                    },
                )]),
            },
        );
        let envelope = self.subscription_envelope(&record, proof)?;
        Ok((
            envelope,
            SubscriptionControlSession {
                identity,
                random_id,
                subscription_sessions: self.subscription_sessions.clone(),
            },
        ))
    }

    pub fn subscription_envelope(
        &self,
        record: &db::ManagedConfigRecord,
        proof: SubscriptionServerProof,
    ) -> anyhow::Result<SubscriptionConfigEnvelope> {
        let toml = canonicalize_stored_client_config(
            &record.config_toml,
            &record.configured_device_name,
            record.fixed_ip.is_some(),
            Some(record.subscription_server.as_str()).filter(|value| !value.trim().is_empty()),
        )
        .with_context(|| {
            format!(
                "设备 {}/{} revision {} 的配置无法规范化",
                record.network_code, record.device_id, record.revision
            )
        })?;
        let managed_ip = record.configured_ip.context("受管设备未配置目标 IP")?;
        let managed_prefix_len = self
            .db_nets
            .read()
            .get(&record.network_code)
            .copied()
            .context("受管设备所属网络不存在")?
            .net
            .prefix_len();
        let source_server_id = hex::encode(self.server_instance_id.as_ref());
        let mut content = Sha256::new();
        content.update(toml.as_bytes());
        content.update(managed_ip.octets());
        content.update([managed_prefix_len]);
        content.update(record.configured_device_name.as_bytes());
        let content_sha256 = content.finalize().to_vec();
        Ok(SubscriptionConfigEnvelope {
            revision: record.revision as u64,
            toml,
            managed_ip,
            managed_prefix_len,
            managed_device_name: record.configured_device_name.clone(),
            server_proof: proof,
            network_code: record.network_code.clone(),
            device_id: record.device_id.clone(),
            source_server_id,
            content_sha256,
        })
    }

    pub async fn acknowledge_subscription_config(
        &self,
        network_code: &str,
        device_id: &str,
        random_id: u64,
        ack: SubscriptionConfigAck,
    ) -> anyhow::Result<Option<(bool, bool)>> {
        let identity = (network_code.to_string(), device_id.to_string());
        // ACKs may arrive concurrently through multiple links. Serialize the
        // complete state-and-database update with registration and other device
        // mutations so a delayed revision cannot commit after a newer one.
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _mutation_guard = mutation_lock.lock().await;
        if !self
            .subscription_sessions
            .get(&identity)
            .is_some_and(|entry| entry.links.contains_key(&random_id))
        {
            bail!("订阅配置回执会话已失效");
        }
        if ack.status == SubscriptionConfigApplyStatus::SubscriptionConfigSuperseded {
            log::debug!(
                "设备 {network_code}/{device_id} 跳过已被更高版本替代的 revision {}",
                ack.revision
            );
            return Ok(None);
        }
        // Older clients sent APPLIED without the extended runtime fields. Protobuf decodes those
        // absent fields as empty/false, so only a hashed effective snapshot may replace live state.
        let has_runtime_metadata = has_effective_runtime_metadata(&ack);
        if ack.status == SubscriptionConfigApplyStatus::SubscriptionConfigApplied
            && has_runtime_metadata
            && (ack.effective_config_sha256.len() != 32
                || ack.effective_device_name.is_empty()
                || ack.effective_device_name.trim() != ack.effective_device_name
                || ack.effective_device_name.len() > RegRequestMsg::MAX_NAME_LEN
                || ack.effective_output.len() > 256)
        {
            bail!("订阅配置回执中的运行时元数据无效");
        }
        // The durable record stores only the server-authored revision; the
        // reported sync state lives in the session entry below.
        let Some(record) = db::get_managed_config(network_code, device_id).await? else {
            bail!("订阅链接配置确认的设备未启用服务端管理");
        };
        let target_revision =
            u64::try_from(record.revision).context("服务端订阅配置 revision 不能为负数")?;
        if ack.revision > target_revision {
            bail!("订阅链接配置确认的 revision {} 无效", ack.revision);
        }
        let mut applied_session = None;
        if let Some(mut entry) = self.subscription_sessions.get_mut(&identity)
            && ack_can_update_live_state(ack.revision, target_revision, entry.applied_revision)
        {
            if ack.status == SubscriptionConfigApplyStatus::SubscriptionConfigApplied {
                entry.applied_revision = ack.revision;
                if has_runtime_metadata {
                    applied_session = entry.target(false);
                }
            }
            entry.apply_error = (!ack.error.is_empty()).then(|| (ack.revision, ack.error.clone()));
            entry.overridden_fields = ack.overridden_fields.clone();
        } else {
            log::debug!(
                "忽略设备 {network_code}/{device_id} 的过期配置 ACK revision {}，当前目标 revision {}",
                ack.revision,
                target_revision
            );
        }
        let mut runtime_capabilities = None;
        if let Some(session) = applied_session {
            if !ack.effective_ip.is_unspecified() && ack.effective_ip != session.ip {
                log::warn!(
                    "忽略设备 {network_code}/{device_id} 回执中的不匹配 IP {}，会话 IP 为 {}",
                    ack.effective_ip,
                    session.ip
                );
            }
            if let Some(state) = self.get_network_state(&session.runtime_network_code)
                && let Some(record) = state.update_managed_runtime_metadata(
                    device_id,
                    &ack.effective_device_name,
                    ack.effective_output.clone(),
                    ack.allow_ikev2,
                    ack.allow_wireguard,
                )
                && let Err(error) = db::save_or_update_device(&record).await
            {
                log::error!(
                    "持久化设备 {network_code}/{device_id} 的受管运行时元数据失败: {error:#}"
                );
            }
            runtime_capabilities = Some((ack.allow_ikev2, ack.allow_wireguard));
        }
        Ok(runtime_capabilities)
    }

    /// Marks a managed session ready only after RegResponse has entered the
    /// reliable outbound queue, then catches it up from the durable record.
    pub async fn activate_subscription_session(
        &self,
        network_code: &str,
        device_id: &str,
        random_id: u64,
    ) -> anyhow::Result<()> {
        let identity = (network_code.to_string(), device_id.to_string());
        let sessions = {
            let Some(mut entry) = self.subscription_sessions.get_mut(&identity) else {
                return Ok(());
            };
            let Some(link) = entry.links.get_mut(&random_id) else {
                return Ok(());
            };
            link.registration_complete = true;
            entry.targets(true)
        };
        let Some(record) = db::get_managed_config(network_code, device_id).await? else {
            return Ok(());
        };
        if sessions
            .first()
            .is_none_or(|session| record.revision as u64 <= session.applied_revision)
        {
            return Ok(());
        }
        let status = self.enqueue_subscription_config(&record, &sessions).await?;
        if status != SubscriptionPushStatus::Queued {
            log::debug!("设备 {network_code}/{device_id} 的注册配置补发未入队: {status:?}");
        }
        Ok(())
    }

    pub async fn push_subscription_config(
        &self,
        record: &db::ManagedConfigRecord,
    ) -> anyhow::Result<SubscriptionPushStatus> {
        let identity = (record.network_code.clone(), record.device_id.clone());
        let sessions = {
            let Some(entry) = self.subscription_sessions.get(&identity) else {
                return Ok(SubscriptionPushStatus::NotConnected);
            };
            let targets = entry.targets(true);
            if targets.is_empty() {
                return Ok(SubscriptionPushStatus::Registering);
            }
            targets
        };
        self.enqueue_subscription_config(record, &sessions).await
    }

    async fn enqueue_subscription_config(
        &self,
        record: &db::ManagedConfigRecord,
        sessions: &[SubscriptionSessionTarget],
    ) -> anyhow::Result<SubscriptionPushStatus> {
        use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
        let mut deliveries = Vec::with_capacity(sessions.len());
        for session in sessions {
            let mut proof = session.server_proof.clone();
            proof.target_revision = record.revision as u64;
            let envelope = self.subscription_envelope(record, proof)?;
            let bytes = if session.control_connection {
                crate::protocol::control_message::ResponseMessage::SubscriptionPush(envelope)
                    .encode()
                    .freeze()
            } else {
                let payload = envelope.encode();
                let mut bytes = BytesMut::zeroed(HEAD_LENGTH + payload.len());
                let mut packet = NetPacket::new(&mut bytes)?;
                packet.set_msg_type(MsgType::SubscriptionConfigPush);
                packet.set_gateway_flag(true);
                packet.set_ttl(1);
                packet.set_payload(&payload)?;
                bytes.freeze()
            };
            deliveries.push((session.sender.clone(), bytes));
        }
        Ok(Self::enqueue_subscription_payloads(deliveries, SUBSCRIPTION_PUSH_TIMEOUT).await)
    }

    #[cfg(test)]
    async fn enqueue_subscription_payload(
        sender: &Sender<Bytes>,
        payload: Bytes,
        wait: Duration,
    ) -> SubscriptionPushStatus {
        Self::enqueue_subscription_payloads(vec![(sender.clone(), payload)], wait).await
    }

    async fn enqueue_subscription_payloads(
        deliveries: Vec<(Sender<Bytes>, Bytes)>,
        wait: Duration,
    ) -> SubscriptionPushStatus {
        let mut reservations = FuturesUnordered::new();
        for (sender, payload) in deliveries {
            reservations.push(async move { (sender.reserve_owned().await, payload) });
        }
        let delivery = async {
            while let Some((reservation, payload)) = reservations.next().await {
                if let Ok(permit) = reservation {
                    permit.send(payload);
                    return SubscriptionPushStatus::Queued;
                }
            }
            SubscriptionPushStatus::Closed
        };
        match timeout(wait, delivery).await {
            Ok(SubscriptionPushStatus::Closed) => {
                log::debug!("订阅配置推送的所有连接均已关闭，将在客户端重连后补发");
                SubscriptionPushStatus::Closed
            }
            Ok(status) => status,
            Err(_) => {
                // The durable revision is not rolled back. Registration catch-up
                // will retry it if every live link stays backpressured.
                log::debug!(
                    "订阅配置推送等待所有发送队列超过 {} 秒，将在客户端重连后补发",
                    wait.as_secs()
                );
                SubscriptionPushStatus::Timeout
            }
        }
    }

    pub fn disconnect_subscription_session(&self, network_code: &str, device_id: &str) -> bool {
        let Some((_, session)) = self
            .subscription_sessions
            .remove(&(network_code.to_string(), device_id.to_string()))
        else {
            return false;
        };
        let Some(state) = self.get_network_state(&session.runtime_network_code) else {
            return false;
        };
        state.sender_map().remove(&session.ip).is_some()
    }

    /// Live sync observation for a device's subscription session, if any.
    pub fn subscription_live_state(
        &self,
        network_code: &str,
        device_id: &str,
    ) -> Option<SubscriptionLiveState> {
        self.subscription_sessions
            .get(&(network_code.to_string(), device_id.to_string()))
            .map(|entry| SubscriptionLiveState {
                applied_revision: entry.applied_revision,
                apply_error: entry.apply_error.clone(),
                overridden_fields: entry.overridden_fields.clone(),
            })
    }

    pub async fn register_ikev2(
        &self,
        network_code: String,
        device_id: String,
        sender: Sender<Bytes>,
    ) -> anyhow::Result<Session> {
        let config = self.network_config(&network_code, None)?;
        let state = self
            .get_or_create_network_state(network_code.clone(), config)
            .await;
        let device = state
            .get_device_entry(&device_id)
            .filter(|entry| entry.client_type == ClientType::Ikev2)
            .with_context(|| format!("IKEv2 设备 '{}' 未由管理员预先创建", device_id))?;
        let remote_ips = self
            .get_peer_manager()
            .map(|manager| manager.remote_online_ips(&network_code))
            .unwrap_or_default();
        let requested_ip = state
            .configured_ip(&device_id)
            .filter(|ip| !remote_ips.contains(ip))
            .or_else(|| state.first_available_ip_excluding(&remote_ips).ok())
            .context("IKEv2 address pool is exhausted")?;
        let request = RegRequestMsg {
            network_code: network_code.clone(),
            device_id,
            ip: Some(requested_ip),
            name: device.device_name,
            version: "IKEv2".to_string(),
            key_sign: None,
            ip_variable: false,
            server_id: 0,
            registration_mode: RegistrationMode::Normal,
            advertised_subnets: device.advertised_subnets,
            allow_ikev2: true,
            allow_wireguard: true,
            subscription: None,
            client_instance_id: Vec::new(),
        };
        self.register_inner(request, sender, ClientType::Ikev2)
            .await
    }

    pub async fn register_wireguard(
        &self,
        network_code: String,
        device_id: String,
        sender: Sender<Bytes>,
    ) -> anyhow::Result<Session> {
        let config = self.network_config(&network_code, None)?;
        let state = self
            .get_or_create_network_state(network_code.clone(), config)
            .await;
        let entry = state
            .get_device_entry(&device_id)
            .filter(|entry| entry.client_type == ClientType::Wireguard)
            .with_context(|| format!("WireGuard 设备 '{}' 未由管理员预先创建", device_id))?;
        let remote_ips = self
            .get_peer_manager()
            .map(|manager| manager.remote_online_ips(&network_code))
            .unwrap_or_default();
        let requested_ip = entry
            .ip
            .filter(|ip| !remote_ips.contains(ip))
            .context("WireGuard 设备没有可用的固定地址")?;
        let request = RegRequestMsg {
            network_code: network_code.clone(),
            device_id,
            ip: Some(requested_ip),
            name: entry.device_name,
            version: "WireGuard".to_string(),
            key_sign: None,
            ip_variable: false,
            server_id: 0,
            registration_mode: RegistrationMode::Normal,
            advertised_subnets: entry.advertised_subnets,
            allow_ikev2: true,
            allow_wireguard: true,
            subscription: None,
            client_instance_id: Vec::new(),
        };
        self.register_inner(request, sender, ClientType::Wireguard)
            .await
    }

    fn network_config(
        &self,
        network_code: &str,
        ip: Option<Ipv4Addr>,
    ) -> anyhow::Result<NetworkConfig> {
        if let Some(config) = self.db_nets.read().get(network_code) {
            return Ok(*config);
        }
        let (net, gateway) = if let Some(ip) = ip {
            let net = Ipv4Net::new(ip, 24)
                .context("Invalid requested IP network")?
                .trunc();
            (net, first_usable_ip(net)?)
        } else {
            (self.default_net, self.default_gateway)
        };
        Ok(NetworkConfig {
            net,
            gateway,
            lease_duration: self.default_lease_duration,
            source: NetworkSource::DeviceRegister,
            network_type: NetworkType::Public,
        })
    }

    /// DCL: 获取或创建 NetworkState
    async fn get_or_create_network_state(
        &self,
        network_code: String,
        config: NetworkConfig,
    ) -> Arc<NetworkState> {
        if let Some(existing) = self.network_state_provider.get(&network_code) {
            existing.update_time();
            return existing.clone();
        }

        let init_lock = self
            .network_init_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();

        let _guard = init_lock.lock().await;

        if let Some(existing) = self.network_state_provider.get(&network_code) {
            existing.update_time();
            return existing.clone();
        }

        let new_state = Arc::new(
            NetworkState::new_from_db(
                network_code.clone(),
                config.net,
                config.gateway,
                config.lease_duration,
            )
            .await,
        );

        self.network_state_provider
            .insert(network_code, new_state.clone());
        new_state
    }

    fn release_network(&self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(60 * 60);
        let keys: Vec<String> = self
            .network_state_provider
            .iter()
            .filter(|v| v.last_active_time() + timeout < now)
            .map(|v| v.key().clone())
            .collect();
        for network_code in keys {
            let option = self
                .network_state_provider
                .get(&network_code)
                .map(|v| v.clone());
            if let Some(state) = option {
                if !state.is_empty() {
                    continue;
                }

                let time = state.last_active_time();
                if now < time + timeout {
                    continue;
                }
                self.network_state_provider.remove(&network_code);
            }
        }
    }

    async fn release_expired_ips(&self, state: &Arc<NetworkState>) {
        let network_code = state.network_code();
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        let expired_devices = state.collect_expired_devices();

        if expired_devices.is_empty() {
            return;
        }

        let expired_devices = state.remove_devices(&expired_devices);

        for device_id in expired_devices {
            log::info!(
                "release IP for offline device network_code={},device_id={}",
                network_code,
                device_id
            );
            if let Err(e) = db::release_device_ip(&network_code, &device_id).await {
                log::error!("Error releasing device IP: {}", e);
            }
        }
    }

    fn start_cleanup_task(&self, interval: Duration) {
        let network_state_provider = self.network_state_provider.clone();
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                // 收集所有 state 的引用
                let state_list: Vec<Arc<NetworkState>> = network_state_provider
                    .iter()
                    .map(|entry| entry.value().clone())
                    .collect();

                for state in state_list {
                    service.release_expired_ips(&state).await;
                }

                tokio::time::sleep(Duration::from_secs(3)).await;
                service.release_network();
            }
        });

        let service_clone = self.clone();
        tokio::spawn(async move {
            const CLIENT_PING_INTERVAL_SECS: u64 = 15;
            loop {
                tokio::time::sleep(Duration::from_secs(CLIENT_PING_INTERVAL_SECS)).await;
                service_clone.ping_local_clients().await;
            }
        });
    }

    async fn ping_local_clients(&self) {
        use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
        use bytes::BytesMut;

        let network_codes = self.get_network_codes();

        for network_code in network_codes {
            if let Some(state) = self.get_network_state(&network_code) {
                let timestamp = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;

                for entry in state.sender_map().iter() {
                    let ip = *entry.key();
                    if state
                        .get_device_entry_by_ip(ip)
                        .is_some_and(|device| device.client_type != ClientType::Vnt)
                    {
                        continue;
                    }
                    let sender = entry.value().clone();

                    let mut buf = BytesMut::zeroed(HEAD_LENGTH + 8);
                    if let Ok(mut packet) = NetPacket::new(&mut buf) {
                        packet.set_msg_type(MsgType::Ping);
                        packet.set_gateway_flag(true);
                        packet.set_ttl(1);

                        let timestamp_bytes = timestamp.to_be_bytes();
                        if packet.set_payload(&timestamp_bytes).is_ok() {
                            sender.try_send_all(buf.freeze());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }

    pub async fn add_network(
        &self,
        network_code: String,
        gateway: Ipv4Addr,
        netmask: u8,
        lease_duration: Option<Duration>,
        network_type: NetworkType,
    ) -> anyhow::Result<()> {
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        if self.db_nets.read().contains_key(&network_code) {
            bail!("网络编号 '{}' 已存在", network_code);
        }

        let net = network_from_gateway(gateway, netmask)?;
        let lease_duration = lease_duration.unwrap_or(self.default_lease_duration);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let record = NetworkRecord {
            network_code: network_code.clone(),
            gateway: gateway.to_string(),
            netmask,
            lease_duration: lease_duration.as_secs() as i64,
            source: NetworkSource::Manual,
            network_type,
            created_at: now,
        };

        db::save_network(&record).await?;

        self.db_nets.write().insert(
            network_code,
            NetworkConfig {
                net,
                gateway,
                lease_duration,
                source: NetworkSource::Manual,
                network_type,
            },
        );

        Ok(())
    }

    pub async fn update_network(
        &self,
        network_code: &str,
        gateway: Ipv4Addr,
        netmask: u8,
        lease_duration: Duration,
        network_type: NetworkType,
    ) -> anyhow::Result<()> {
        let net = network_from_gateway(gateway, netmask)?;
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        let original_config = self
            .db_nets
            .read()
            .get(network_code)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("网络编号 '{}' 不存在", network_code))?;

        let topology_changed = original_config.net != net
            || original_config.gateway != gateway
            || original_config.lease_duration != lease_duration;
        if topology_changed && db::network_has_devices(network_code).await? {
            bail!("网络下存在设备，只能修改网络类型");
        }

        if topology_changed && let Some(state) = self.network_state_provider.get(network_code) {
            let (all, _) = state.count();
            if all > 0 {
                bail!("网络下存在设备，只能修改网络类型");
            }
        }

        db::update_network(
            network_code,
            &gateway.to_string(),
            netmask,
            lease_duration.as_secs() as i64,
            network_type,
        )
        .await?;

        self.db_nets.write().insert(
            network_code.to_string(),
            NetworkConfig {
                net,
                gateway,
                lease_duration,
                source: original_config.source,
                network_type,
            },
        );

        if topology_changed {
            self.network_state_provider.remove(network_code);
        }

        Ok(())
    }

    pub async fn delete_network(&self, network_code: &str) -> anyhow::Result<()> {
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        if !self.db_nets.read().contains_key(network_code) {
            bail!("网络编号 '{}' 不存在", network_code);
        }

        if db::network_has_devices(network_code).await? {
            bail!("网络下存在设备，无法删除");
        }

        if let Some(state) = self.network_state_provider.get(network_code) {
            let (all, _) = state.count();
            if all > 0 {
                bail!("网络下存在设备，无法删除");
            }
        }

        db::delete_network(network_code).await?;

        self.db_nets.write().remove(network_code);
        self.network_state_provider.remove(network_code);

        Ok(())
    }

    fn validate_device_ip(config: NetworkConfig, ip: Ipv4Addr) -> anyhow::Result<()> {
        if !config.net.contains(&ip) {
            bail!("IP {} 不属于网段 {}", ip, config.net);
        }
        if ip == config.gateway {
            bail!("此IP为网关IP，不允许使用");
        }
        if ip == config.net.network() || ip == config.net.broadcast() {
            bail!("此IP为网段的网络地址或广播地址，不允许使用");
        }
        Ok(())
    }

    fn normalize_subnet_config(
        config: NetworkConfig,
        device_ip: Ipv4Addr,
        mut output_subnets: Vec<Ipv4Net>,
        mut input_routes: Vec<Ikev2InputRoute>,
        protocol: &str,
    ) -> anyhow::Result<(Vec<Ipv4Net>, Vec<Ikev2InputRoute>)> {
        output_subnets = output_subnets
            .into_iter()
            .map(|subnet| subnet.trunc())
            .collect();
        output_subnets.sort_by_key(|net| (u32::from(net.network()), net.prefix_len()));
        output_subnets.dedup();
        if output_subnets.len() > 254 {
            bail!("{protocol} 出口子网不能超过 254 条");
        }
        for route in &mut input_routes {
            route.subnet = route.subnet.trunc();
            Self::validate_device_ip(config, route.target_ip)?;
            if route.target_ip == device_ip {
                bail!("{protocol} 入口路由的目标 IP 不能是设备自身 IP");
            }
        }
        input_routes.sort_by_key(|route| {
            (
                std::cmp::Reverse(route.subnet.prefix_len()),
                u32::from(route.subnet.network()),
            )
        });
        if input_routes
            .windows(2)
            .any(|routes| routes[0].subnet == routes[1].subnet)
        {
            bail!("同一 {protocol} 设备不能为相同入口子网配置多个目标 IP");
        }
        if input_routes.len() > 254 {
            bail!("{protocol} 入口路由不能超过 254 条");
        }
        Ok((output_subnets, input_routes))
    }

    #[allow(clippy::too_many_arguments)]
    async fn upsert_device(
        &self,
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
        ikev2_password: Option<String>,
        device_name: Option<String>,
        ikev2_output_subnets: Option<Vec<Ipv4Net>>,
        ikev2_input_routes: Option<Vec<Ikev2InputRoute>>,
        wireguard_output_subnets: Option<Vec<Ipv4Net>>,
        wireguard_input_routes: Option<Vec<Ikev2InputRoute>>,
        wireguard_dns: Option<Vec<Ipv4Addr>>,
        wireguard_private_key: Option<String>,
        mutation: DeviceMutation,
    ) -> anyhow::Result<()> {
        if device_id.is_empty()
            || device_id.trim() != device_id
            || device_id.len() > RegRequestMsg::MAX_DEVICE_ID_LEN
        {
            bail!("无效的设备 ID");
        }
        let _ikev2_guard = self.ikev2_device_mutation_lock.lock().await;
        let _wireguard_guard = self.wireguard_device_mutation_lock.lock().await;
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        let config = self
            .db_nets
            .read()
            .get(network_code)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("网络编号 '{}' 不存在", network_code))?;
        Self::validate_device_ip(config, ip)?;

        let state = self
            .get_or_create_network_state(network_code.to_string(), config)
            .await;

        if matches!(mutation, DeviceMutation::Create(_)) && state.has_device(device_id) {
            bail!("设备 ID '{}' 已存在", device_id);
        }
        if matches!(mutation, DeviceMutation::Update) && !state.has_device(device_id) {
            bail!("设备 ID '{}' 不存在", device_id);
        }

        let existing = state.get_device_entry(device_id);
        let client_type = match mutation {
            DeviceMutation::Create(client_type) => client_type,
            DeviceMutation::Update => existing
                .as_ref()
                .map(|entry| entry.client_type)
                .context("设备不存在")?,
        };
        // WireGuard peers are provisioned by the server with a stable tunnel address. Keep the
        // persisted/API IP type consistent even when an older client submits Dynamic or Fixed.
        let ip_type = if client_type == ClientType::Wireguard {
            DeviceIpType::Static
        } else {
            ip_type
        };
        let (
            ikev2_output_subnets,
            ikev2_input_routes,
            wireguard_output_subnets,
            wireguard_input_routes,
        ) = match client_type {
            ClientType::Ikev2 => {
                if wireguard_output_subnets
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                    || wireguard_input_routes
                        .as_ref()
                        .is_some_and(|value| !value.is_empty())
                {
                    bail!("IKEv2 设备不能配置 WireGuard 入口或出口子网");
                }
                let output_subnets = ikev2_output_subnets
                    .or_else(|| {
                        existing
                            .as_ref()
                            .map(|entry| entry.advertised_subnets.clone())
                    })
                    .unwrap_or_default();
                let input_routes = ikev2_input_routes
                    .or_else(|| {
                        existing
                            .as_ref()
                            .map(|entry| entry.ikev2_input_routes.clone())
                    })
                    .unwrap_or_default();
                let (outputs, routes) = Self::normalize_subnet_config(
                    config,
                    ip,
                    output_subnets,
                    input_routes,
                    "IKEv2",
                )?;
                (outputs, routes, Vec::new(), Vec::new())
            }
            ClientType::Wireguard => {
                if ikev2_output_subnets
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                    || ikev2_input_routes
                        .as_ref()
                        .is_some_and(|value| !value.is_empty())
                {
                    bail!("WireGuard 设备不能配置 IKEv2 入口或出口子网");
                }
                let output_subnets = wireguard_output_subnets
                    .or_else(|| {
                        existing
                            .as_ref()
                            .map(|entry| entry.advertised_subnets.clone())
                    })
                    .unwrap_or_default();
                let input_routes = wireguard_input_routes
                    .or_else(|| {
                        existing
                            .as_ref()
                            .map(|entry| entry.wireguard_input_routes.clone())
                    })
                    .unwrap_or_default();
                let (outputs, routes) = Self::normalize_subnet_config(
                    config,
                    ip,
                    output_subnets,
                    input_routes,
                    "WireGuard",
                )?;
                (Vec::new(), Vec::new(), outputs, routes)
            }
            ClientType::Vnt => {
                if ikev2_output_subnets
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                    || ikev2_input_routes
                        .as_ref()
                        .is_some_and(|value| !value.is_empty())
                    || wireguard_output_subnets
                        .as_ref()
                        .is_some_and(|value| !value.is_empty())
                    || wireguard_input_routes
                        .as_ref()
                        .is_some_and(|value| !value.is_empty())
                {
                    bail!("只有 IKEv2 或 WireGuard 设备可以配置入口或出口子网");
                }
                (Vec::new(), Vec::new(), Vec::new(), Vec::new())
            }
        };
        if wireguard_dns
            .as_ref()
            .is_some_and(|value| !value.is_empty())
            && client_type != ClientType::Wireguard
        {
            bail!("只有 WireGuard 设备可以配置 DNS");
        }
        if wireguard_private_key
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            && client_type != ClientType::Wireguard
        {
            bail!("只有 WireGuard 设备可以配置 WireGuard 私钥");
        }
        let wireguard_dns = wireguard_dns
            .or_else(|| existing.as_ref().map(|entry| entry.wireguard_dns.clone()))
            .unwrap_or_default();
        let password = match client_type {
            ClientType::Vnt => {
                if ikev2_password.is_some() {
                    bail!("VNT 设备不能配置 IKEv2 密码");
                }
                None
            }
            ClientType::Ikev2 => {
                if device_id.len() > 48 {
                    bail!("IKEv2 用户名长度必须为 1..=48 字节");
                }
                let password = ikev2_password.or_else(|| {
                    existing
                        .as_ref()
                        .and_then(|entry| entry.ikev2_password.clone())
                });
                if password.as_ref().is_none_or(String::is_empty) {
                    bail!("IKEv2 密码不能为空");
                }
                if matches!(mutation, DeviceMutation::Create(_))
                    && self.ikev2_username_exists(device_id).await?
                {
                    bail!("IKEv2 用户名 '{}' 已存在", device_id);
                }
                password
            }
            ClientType::Wireguard => {
                if ikev2_password.is_some() {
                    bail!("WireGuard 设备不能配置 IKEv2 密码");
                }
                None
            }
        };
        let provided_wireguard_private_key = wireguard_private_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let (wireguard_private_key, wireguard_public_key, wireguard_keys_changed) =
            if client_type == ClientType::Wireguard {
                match provided_wireguard_private_key {
                    Some(private_key) => {
                        let bytes = crate::server::wireguard::decode_key(private_key)
                            .map_err(|error| anyhow::anyhow!("无效的 WireGuard 私钥：{error}"))?;
                        let secret = boringtun::x25519::StaticSecret::from(bytes);
                        let public = boringtun::x25519::PublicKey::from(&secret);
                        let public_key =
                            base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
                        let unchanged = existing.as_ref().is_some_and(|entry| {
                            entry.wireguard_private_key.as_deref() == Some(private_key)
                                && entry.wireguard_public_key.as_deref()
                                    == Some(public_key.as_str())
                        });
                        if !unchanged
                            && self
                                .wireguard_public_key_exists(&public_key, network_code, device_id)
                                .await?
                        {
                            bail!("该 WireGuard 私钥已绑定其他设备，不能重复使用");
                        }
                        (
                            Some(private_key.to_string()),
                            Some(public_key),
                            !unchanged,
                        )
                    }
                    None => {
                        match existing.as_ref().and_then(|entry| {
                            Some((
                                entry.wireguard_private_key.clone()?,
                                entry.wireguard_public_key.clone()?,
                            ))
                        }) {
                            Some(keys) => (Some(keys.0), Some(keys.1), false),
                            None => {
                                let mut bytes = [0u8; 32];
                                rand::rng().fill_bytes(&mut bytes);
                                let secret = boringtun::x25519::StaticSecret::from(bytes);
                                let public = boringtun::x25519::PublicKey::from(&secret);
                                (
                                    Some(
                                        base64::engine::general_purpose::STANDARD.encode(bytes),
                                    ),
                                    Some(
                                        base64::engine::general_purpose::STANDARD
                                            .encode(public.as_bytes()),
                                    ),
                                    true,
                                )
                            }
                        }
                    }
                }
            } else {
                (None, None, false)
            };
        let device_name = match client_type {
            ClientType::Vnt => device_name
                .or_else(|| existing.as_ref().map(|entry| entry.device_name.clone()))
                .unwrap_or_else(|| device_id.to_string()),
            ClientType::Ikev2 | ClientType::Wireguard => device_name
                .or_else(|| existing.as_ref().map(|entry| entry.device_name.clone()))
                .unwrap_or_else(|| device_id.to_string()),
        };
        if device_name.is_empty()
            || device_name.trim() != device_name
            || device_name.len() > RegRequestMsg::MAX_NAME_LEN
        {
            bail!("无效的设备名称");
        }

        if matches!(mutation, DeviceMutation::Update)
            && existing
                .as_ref()
                .is_some_and(|entry| entry.client_type == ClientType::Ikev2)
            && let Some(manager) = self.get_ikev2_manager()
        {
            manager.disconnect_device(network_code, device_id).await;
        }
        if matches!(mutation, DeviceMutation::Update)
            && existing.as_ref().is_some_and(|entry| {
                entry.client_type == ClientType::Wireguard
                    && (entry.ip != Some(ip) || wireguard_keys_changed)
            })
            && let Some(manager) = self.get_wireguard_manager()
        {
            manager.disconnect_device(network_code, device_id).await;
        }

        let previous = state.upsert_device_config(
            device_id,
            device_name,
            ip,
            ip_type,
            client_type,
            password,
            wireguard_private_key,
            wireguard_public_key,
            ikev2_output_subnets,
            ikev2_input_routes,
            wireguard_output_subnets,
            wireguard_input_routes,
            wireguard_dns,
        )?;
        let record = state
            .get_device_entry(device_id)
            .ok_or_else(|| anyhow::anyhow!("设备状态更新失败"))?
            .to_record(network_code);
        if let Err(error) = db::save_or_update_device(&record).await {
            state.restore_device_config(device_id, previous);
            return Err(error);
        }
        if client_type == ClientType::Ikev2 {
            self.refresh_ikev2_credentials().await;
        }
        if client_type == ClientType::Wireguard {
            self.refresh_wireguard_peers().await;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_device_typed(
        &self,
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
        client_type: ClientType,
        ikev2_password: Option<String>,
        device_name: Option<String>,
        ikev2_output_subnets: Option<Vec<Ipv4Net>>,
        ikev2_input_routes: Option<Vec<Ikev2InputRoute>>,
        wireguard_output_subnets: Option<Vec<Ipv4Net>>,
        wireguard_input_routes: Option<Vec<Ikev2InputRoute>>,
        wireguard_dns: Option<Vec<Ipv4Addr>>,
        wireguard_private_key: Option<String>,
    ) -> anyhow::Result<()> {
        self.upsert_device(
            network_code,
            device_id,
            ip,
            ip_type,
            ikev2_password,
            device_name,
            ikev2_output_subnets,
            ikev2_input_routes,
            wireguard_output_subnets,
            wireguard_input_routes,
            wireguard_dns,
            wireguard_private_key,
            DeviceMutation::Create(client_type),
        )
        .await
    }

    #[cfg(test)]
    pub async fn add_device(
        &self,
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
    ) -> anyhow::Result<()> {
        self.add_device_typed(
            network_code,
            device_id,
            ip,
            ip_type,
            ClientType::Vnt,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_device_with_password(
        &self,
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
        ikev2_password: Option<String>,
        device_name: Option<String>,
        ikev2_output_subnets: Option<Vec<Ipv4Net>>,
        ikev2_input_routes: Option<Vec<Ikev2InputRoute>>,
        wireguard_output_subnets: Option<Vec<Ipv4Net>>,
        wireguard_input_routes: Option<Vec<Ikev2InputRoute>>,
        wireguard_dns: Option<Vec<Ipv4Addr>>,
        wireguard_private_key: Option<String>,
    ) -> anyhow::Result<()> {
        self.upsert_device(
            network_code,
            device_id,
            ip,
            ip_type,
            ikev2_password,
            device_name,
            ikev2_output_subnets,
            ikev2_input_routes,
            wireguard_output_subnets,
            wireguard_input_routes,
            wireguard_dns,
            wireguard_private_key,
            DeviceMutation::Update,
        )
        .await
    }

    #[cfg(test)]
    pub async fn update_device(
        &self,
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        ip_type: DeviceIpType,
    ) -> anyhow::Result<()> {
        self.update_device_with_password(
            network_code,
            device_id,
            ip,
            ip_type,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }

    async fn wireguard_public_key_exists(
        &self,
        public_key: &str,
        network_code: &str,
        device_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(self.wireguard_devices().await?.into_iter().any(|device| {
            device.wireguard_public_key.as_deref() == Some(public_key)
                && !(device.network_code == network_code && device.device_id == device_id)
        }))
    }

    async fn ikev2_username_exists(&self, username: &str) -> anyhow::Result<bool> {
        if db::load_all_ikev2_devices()
            .await?
            .iter()
            .any(|device| device.device_id == username)
        {
            return Ok(true);
        }
        Ok(self.network_state_provider.iter().any(|network| {
            network
                .value()
                .get_device_entry(username)
                .is_some_and(|device| device.client_type == ClientType::Ikev2)
        }))
    }

    pub async fn ikev2_credentials(&self) -> anyhow::Result<HashMap<String, (String, String)>> {
        let mut credentials = HashMap::new();
        for device in db::load_all_ikev2_devices().await? {
            if let Some(password) = device.ikev2_password {
                credentials.insert(device.device_id, (device.network_code, password));
            }
        }
        for network in self.network_state_provider.iter() {
            let network_code = network.key().clone();
            for (username, password) in network.value().ikev2_credentials() {
                credentials.insert(username, (network_code.clone(), password));
            }
        }
        Ok(credentials)
    }

    async fn refresh_ikev2_credentials(&self) {
        let Some(manager) = self.get_ikev2_manager() else {
            return;
        };
        match self.ikev2_credentials().await {
            Ok(credentials) => {
                if let Err(error) = manager.reload_credentials(credentials).await {
                    log::error!("刷新 IKEv2 设备凭据失败: {error:#}");
                    self.set_ikev2_runtime_error(Some(error.to_string()));
                }
            }
            Err(error) => {
                log::error!("读取 IKEv2 设备凭据失败: {error:#}");
                self.set_ikev2_runtime_error(Some(error.to_string()));
            }
        }
    }

    pub async fn wireguard_devices(&self) -> anyhow::Result<Vec<db::DeviceRecord>> {
        let mut devices = db::load_all_wireguard_devices()
            .await?
            .into_iter()
            .map(|device| {
                (
                    (device.network_code.clone(), device.device_id.clone()),
                    device,
                )
            })
            .collect::<HashMap<_, _>>();
        for state in self.network_state_provider.iter() {
            for device in state.device_records_by_type(ClientType::Wireguard) {
                devices.insert(
                    (device.network_code.clone(), device.device_id.clone()),
                    device,
                );
            }
        }
        Ok(devices.into_values().collect())
    }

    async fn refresh_wireguard_peers(&self) {
        let Some(manager) = self.get_wireguard_manager() else {
            return;
        };
        match self.wireguard_devices().await {
            Ok(devices) => {
                if let Err(error) = manager.reload_devices(devices).await {
                    log::error!("刷新 WireGuard 设备失败: {error:#}");
                    self.set_wireguard_runtime_error(Some(error.to_string()));
                }
            }
            Err(error) => {
                log::error!("读取 WireGuard 设备失败: {error:#}");
                self.set_wireguard_runtime_error(Some(error.to_string()));
            }
        }
    }

    pub async fn get_device_record(
        &self,
        network_code: &str,
        device_id: &str,
    ) -> anyhow::Result<Option<db::DeviceRecord>> {
        if let Some(state) = self.network_state_provider.get(network_code)
            && let Some(entry) = state.get_device_entry(device_id)
        {
            return Ok(Some(entry.to_record(network_code)));
        }
        db::get_device(network_code, device_id).await
    }

    pub async fn restore_device_record(&self, record: db::DeviceRecord) -> anyhow::Result<()> {
        let network_code = record.network_code.clone();
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        let config = self
            .db_nets
            .read()
            .get(&network_code)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("网络编号 '{}' 不存在", network_code))?;
        let state = self.get_or_create_network_state(network_code, config).await;
        state.restore_device_record(record.clone());
        db::save_or_update_device(&record).await
    }

    pub async fn fast_register(
        &self,
        session: &mut Session,
        new_ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
        let mutation_lock = self
            .device_mutation_locks
            .entry(session.network_code.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        session.network_state.fast_register(
            &session.device_id,
            session.ip,
            new_ip,
            session.random_id,
            &session.client_instance_id,
        )?;
        session.ip = new_ip;
        // A non-Fixed FastReg can be accepted by a secondary VNTS before that
        // endpoint has received the management edit. Persist its converged
        // device-table address so a subsequent local restart does not restore
        // the stale address for this live session.
        if let Some(record) = session.network_state.get_device_entry(&session.device_id) {
            db::save_or_update_device(&record.to_record(&session.network_code)).await?;
        }
        if let Some(identity) = &session.subscription_identity
            && let Some(mut managed_session) = self.subscription_sessions.get_mut(identity)
            && managed_session.links.contains_key(&session.random_id)
        {
            managed_session.ip = new_ip;
        }
        Ok(())
    }

    pub async fn delete_device(&self, network_code: &str, device_id: &str) -> anyhow::Result<()> {
        let _ikev2_guard = self.ikev2_device_mutation_lock.lock().await;
        let _wireguard_guard = self.wireguard_device_mutation_lock.lock().await;
        let client_type = self
            .get_device_record(network_code, device_id)
            .await?
            .map(|device| device.client_type);
        if client_type == Some(ClientType::Ikev2)
            && let Some(manager) = self.get_ikev2_manager()
        {
            manager.disconnect_device(network_code, device_id).await;
        }
        if client_type == Some(ClientType::Wireguard)
            && let Some(manager) = self.get_wireguard_manager()
        {
            manager.disconnect_device(network_code, device_id).await;
        }
        let mutation_lock = self
            .device_mutation_locks
            .entry(network_code.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = mutation_lock.lock().await;
        if let Some(state) = self.network_state_provider.get(network_code) {
            if state.is_device_online(device_id) {
                bail!("设备在线，无法删除");
            }
            state.remove_device_from_memory(device_id);
        }

        db::delete_device(network_code, device_id).await?;

        // The managed-config row (credential + join id) is gone, so any further
        // register/fetch with the issued link is rejected. Drop a live control
        // connection too: it would otherwise keep receiving pushes for a device
        // that no longer exists.
        self.disconnect_subscription_session(network_code, device_id);

        if client_type == Some(ClientType::Ikev2) {
            self.refresh_ikev2_credentials().await;
        }
        if client_type == Some(ClientType::Wireguard) {
            self.refresh_wireguard_peers().await;
        }

        Ok(())
    }
}

impl ControlService {
    pub fn get_network_codes(&self) -> Vec<String> {
        self.db_nets.read().keys().cloned().collect()
    }

    pub fn get_network_state(&self, network_code: &str) -> Option<Arc<NetworkState>> {
        self.network_state_provider
            .get(network_code)
            .map(|s| s.clone())
    }

    pub fn get_network_type(&self, network_code: &str) -> Option<NetworkType> {
        self.db_nets
            .read()
            .get(network_code)
            .map(|config| config.network_type)
    }

    pub fn client_type(&self, network_code: &str, ip: Ipv4Addr) -> Option<ClientType> {
        if let Some(state) = self.get_network_state(network_code)
            && let Some(device) = state.get_device_entry_by_ip(ip)
            && device.is_connected
        {
            return Some(device.client_type);
        }
        self.get_peer_manager()
            .and_then(|manager| manager.remote_client_type(network_code, ip))
    }

    pub fn address_owned_by(&self, network_code: &str, owner: Ipv4Addr, address: Ipv4Addr) -> bool {
        if owner == address {
            return true;
        }
        if self
            .db_nets
            .read()
            .get(network_code)
            .is_some_and(|config| config.net.contains(&address))
        {
            return false;
        }
        if let Some(state) = self.get_network_state(network_code)
            && state
                .active_advertised_subnets(owner)
                .is_some_and(|subnets| subnets.iter().any(|subnet| subnet.contains(&address)))
        {
            return true;
        }
        self.get_peer_manager()
            .and_then(|manager| manager.remote_advertised_subnets(network_code, owner))
            .is_some_and(|subnets| subnets.iter().any(|subnet| subnet.contains(&address)))
    }

    pub fn ikev2_route_target(
        &self,
        network_code: &str,
        device_id: &str,
        destination: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        let config = self.db_nets.read().get(network_code).copied()?;
        if config.net.contains(&destination) {
            return Some(destination);
        }
        self.get_network_state(network_code)?
            .ikev2_input_target(device_id, destination)
    }

    pub async fn forward_ikev2_packet(
        &self,
        network_code: &str,
        device_id: &str,
        source_id: Ipv4Addr,
        payload: &[u8],
    ) -> anyhow::Result<bool> {
        use pnet_packet::ipv4::Ipv4Packet;
        let Some(ipv4) = Ipv4Packet::new(payload) else {
            return Ok(false);
        };
        let destination = ipv4.get_destination();
        let Some(target) = self.ikev2_route_target(network_code, device_id, destination) else {
            return Ok(false);
        };
        self.forward_external_packet(network_code, ClientType::Ikev2, source_id, target, payload)
            .await
    }

    pub async fn forward_wireguard_packet(
        &self,
        network_code: &str,
        device_id: &str,
        source: Ipv4Addr,
        payload: &[u8],
    ) -> anyhow::Result<bool> {
        use pnet_packet::ipv4::Ipv4Packet;
        let Some(ipv4) = Ipv4Packet::new(payload) else {
            return Ok(false);
        };
        let destination = ipv4.get_destination();
        let Some(target) = self.wireguard_route_target(network_code, device_id, destination) else {
            return Ok(false);
        };
        self.forward_external_packet(network_code, ClientType::Wireguard, source, target, payload)
            .await
    }

    pub fn wireguard_route_target(
        &self,
        network_code: &str,
        device_id: &str,
        destination: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        let state = self.get_network_state(network_code)?;
        if state.network_contains(destination) {
            Some(destination)
        } else {
            state.wireguard_input_target(device_id, destination)
        }
    }

    async fn forward_external_packet(
        &self,
        network_code: &str,
        source_type: ClientType,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        payload: &[u8],
    ) -> anyhow::Result<bool> {
        use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
        use pnet_packet::ipv4::Ipv4Packet;

        let Some(ipv4) = Ipv4Packet::new(payload) else {
            return Ok(false);
        };
        let header_length = ipv4.get_header_length() as usize * 4;
        if ipv4.get_version() != 4
            || header_length < Ipv4Packet::minimum_packet_size()
            || ipv4.get_total_length() as usize != payload.len()
            || !self.address_owned_by(network_code, source, ipv4.get_source())
            || !self.address_owned_by(network_code, destination, ipv4.get_destination())
        {
            return Ok(false);
        }
        let Some(destination_type) = self.client_type(network_code, destination) else {
            return Ok(false);
        };
        if destination_type == ClientType::Vnt {
            let local_device = self
                .get_network_state(network_code)
                .and_then(|state| state.get_device_entry_by_ip(destination));
            if local_device.is_some_and(|device| match source_type {
                ClientType::Ikev2 => !device.allow_ikev2,
                ClientType::Wireguard => !device.allow_wireguard,
                ClientType::Vnt => true,
            }) {
                return Ok(false);
            }
        }

        let mut bytes = BytesMut::zeroed(HEAD_LENGTH + payload.len());
        let mut packet = NetPacket::new(&mut bytes)?;
        let msg_type = match destination_type {
            ClientType::Ikev2 => MsgType::Ikev2Relay,
            ClientType::Wireguard => MsgType::WireGuardRelay,
            ClientType::Vnt => match source_type {
                ClientType::Ikev2 => MsgType::Ikev2Relay,
                ClientType::Wireguard => MsgType::WireGuardRelay,
                ClientType::Vnt => return Ok(false),
            },
        };
        packet.set_msg_type(msg_type);
        packet.set_gateway_flag(true);
        packet.set_ttl(5);
        packet.set_src_id(source.into());
        packet.set_dest_id(destination.into());
        packet.set_payload(payload)?;
        let data = bytes.freeze();

        if let Some(state) = self.get_network_state(network_code) {
            state.record_tx_traffic(source, payload.len());
        }

        if let Some(peer_manager) = self.get_peer_manager()
            && peer_manager
                .forward_with_best_route(network_code, destination, data.clone())
                .await
        {
            return Ok(true);
        }
        if let Some(state) = self.get_network_state(network_code)
            && let Some(sender) = state.sender_map().get(&destination)
        {
            state.record_rx_traffic(destination, payload.len());
            return Ok(sender.try_send(data).is_ok());
        }
        Ok(false)
    }

    pub fn set_peer_manager(&self, manager: Arc<crate::server::peer_server::PeerServerManager>) {
        *self.peer_manager.write() = Some(manager);
    }

    pub fn get_peer_manager(&self) -> Option<Arc<crate::server::peer_server::PeerServerManager>> {
        self.peer_manager.read().clone()
    }

    pub fn set_ikev2_manager(&self, manager: crate::server::ikev2::Ikev2Handle) {
        *self.ikev2_manager.write() = Some(manager);
    }

    pub fn get_ikev2_manager(&self) -> Option<crate::server::ikev2::Ikev2Handle> {
        self.ikev2_manager.read().clone()
    }

    pub fn replace_ikev2_manager(
        &self,
        manager: Option<crate::server::ikev2::Ikev2Handle>,
    ) -> Option<crate::server::ikev2::Ikev2Handle> {
        std::mem::replace(&mut *self.ikev2_manager.write(), manager)
    }

    pub fn set_ikev2_runtime_error(&self, error: Option<String>) {
        *self.ikev2_runtime_error.write() = error;
    }

    pub fn get_ikev2_runtime_error(&self) -> Option<String> {
        self.ikev2_runtime_error.read().clone()
    }

    pub fn set_wireguard_manager(&self, manager: crate::server::wireguard::WireGuardHandle) {
        *self.wireguard_manager.write() = Some(manager);
    }

    pub fn get_wireguard_manager(&self) -> Option<crate::server::wireguard::WireGuardHandle> {
        self.wireguard_manager.read().clone()
    }

    pub fn replace_wireguard_manager(
        &self,
        manager: Option<crate::server::wireguard::WireGuardHandle>,
    ) -> Option<crate::server::wireguard::WireGuardHandle> {
        std::mem::replace(&mut *self.wireguard_manager.write(), manager)
    }

    pub fn set_wireguard_runtime_error(&self, error: Option<String>) {
        *self.wireguard_runtime_error.write() = error;
    }

    pub fn get_wireguard_runtime_error(&self) -> Option<String> {
        self.wireguard_runtime_error.read().clone()
    }

    pub fn subnet_snapshot(
        &self,
        network_code: &str,
        exclude_ip: Ipv4Addr,
    ) -> (
        Vec<u8>,
        Vec<crate::protocol::control_message::NodeSubnetRoutes>,
    ) {
        if let Some(manager) = self.get_peer_manager() {
            return manager.subnet_snapshot(network_code, exclude_ip);
        }
        let mut by_ip = std::collections::BTreeMap::new();
        if let Some(state) = self.network_state_provider.get_network_state(network_code) {
            for (ip, subnets) in state.online_advertised_subnets() {
                if ip != exclude_ip {
                    by_ip.insert(ip, subnets);
                }
            }
        }
        crate::server::peer_server::canonical_subnet_snapshot(by_ip)
    }

    pub fn get_network_state_provider(&self) -> &NetworkStateProvider {
        &self.network_state_provider
    }

    pub async fn get_network_info(&self) -> Vec<NetworkInfoVO> {
        let networks = self
            .db_nets
            .read()
            .iter()
            .map(|(code, config)| {
                let memory_counts = self
                    .network_state_provider
                    .get(code)
                    .map(|state| state.count());
                (code.clone(), *config, memory_counts)
            })
            .collect::<Vec<_>>();

        let persisted_counts = if networks.iter().any(|(_, _, counts)| counts.is_none()) {
            match db::load_device_counts().await {
                Ok(counts) => counts,
                Err(error) => {
                    log::error!("Failed to load device counts from DB: {}", error);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        networks
            .into_iter()
            .map(|(code, config, memory_counts)| {
                let memory_counts = memory_counts.or_else(|| {
                    self.network_state_provider
                        .get(&code)
                        .map(|state| state.count())
                });
                let (all_count, online_count) =
                    network_counts(memory_counts, persisted_counts.get(&code).copied());

                NetworkInfoVO {
                    network_code: code,
                    gateway: config.gateway,
                    netmask: config.net.prefix_len(),
                    net: config.net,
                    lease_duration: config.lease_duration.as_secs(),
                    source: config.source,
                    network_type: config.network_type,
                    all_count,
                    online_count,
                }
            })
            .collect()
    }

    pub async fn get_device_info(&self, network_code: &str) -> Option<Vec<DeviceInfoVO>> {
        let mut devices = if let Some(state) = self.network_state_provider.get(network_code) {
            state.get_device_infos()
        } else {
            match db::load_all_devices(network_code).await {
                Ok(records) => records
                    .into_iter()
                    .map(|r| DeviceInfoVO {
                        device_id: r.device_id,
                        device_name: r.device_name,
                        current_device_name: None,
                        device_version: r.device_version,
                        ip: r.ip.as_ref().and_then(|s| s.parse().ok()),
                        current_ip: None,
                        ip_type: Some(r.ip_type),
                        status: "Offline".to_string(),
                        last_connect_time: format_system_time_local(i64_to_system_time(
                            r.last_connect_time,
                        )),
                        disconnect_time: None,
                        latency_ms: None,
                        server_addr: None,
                        advertised_subnets: Vec::new(),
                        ikev2_output_subnets: r.ikev2_output_subnets,
                        ikev2_input_routes: r.ikev2_input_routes,
                        wireguard_output_subnets: r.wireguard_output_subnets,
                        wireguard_input_routes: r.wireguard_input_routes,
                        wireguard_dns: r.wireguard_dns,
                        tx_bytes: r.tx_bytes as u64,
                        rx_bytes: r.rx_bytes as u64,
                        client_type: r.client_type,
                        managed: false,
                        relay_online: false,
                        subscription_online: false,
                        subscription_issued: false,
                        subscription_target_revision: None,
                        subscription_applied_revision: None,
                        subscription_status: None,
                        subscription_error: None,
                    })
                    .collect(),
                Err(e) => {
                    log::error!("Failed to load devices from DB: {}", e);
                    return None;
                }
            }
        };

        if let Some(peer_manager) = self.peer_manager.read().as_ref() {
            let remote_devices = peer_manager.get_remote_devices(network_code);

            for (ip, server_addr, latency_ms, advertised_subnets, client_type) in remote_devices {
                devices.push(DeviceInfoVO {
                    device_id: format!("remote-{}", ip),
                    device_name: format!("Remote Device ({})", ip),
                    current_device_name: None,
                    device_version: "Unknown".to_string(),
                    ip: Some(ip),
                    current_ip: None,
                    ip_type: None,
                    status: "Remote".to_string(),
                    last_connect_time: "-".to_string(),
                    disconnect_time: None,
                    latency_ms: Some(latency_ms),
                    server_addr: Some(server_addr),
                    advertised_subnets,
                    ikev2_output_subnets: Vec::new(),
                    ikev2_input_routes: Vec::new(),
                    wireguard_output_subnets: Vec::new(),
                    wireguard_input_routes: Vec::new(),
                    wireguard_dns: Vec::new(),
                    tx_bytes: 0,
                    rx_bytes: 0,
                    client_type,
                    managed: false,
                    relay_online: false,
                    subscription_online: false,
                    subscription_issued: false,
                    subscription_target_revision: None,
                    subscription_applied_revision: None,
                    subscription_status: None,
                    subscription_error: None,
                });
            }
        }

        for device in &mut devices {
            if device.client_type != ClientType::Vnt || device.device_id.starts_with("remote-") {
                continue;
            }
            if let Ok(Some(managed)) = db::get_managed_config(network_code, &device.device_id).await
            {
                device.managed = true;
                device.subscription_issued = managed.credential_key.is_some();
                device.subscription_target_revision = Some(managed.revision);
                // Sync state is an observation of the live subscription
                // session; without one the server cannot know what the
                // client runs.
                match self.subscription_live_state(network_code, &device.device_id) {
                    Some(live) => {
                        device.subscription_online = true;
                        device.subscription_applied_revision = Some(live.applied_revision as i64);
                        device.subscription_status =
                            Some(live.status(managed.revision).to_string());
                        device.subscription_error =
                            live.apply_error(managed.revision).map(str::to_string);
                    }
                    None => {
                        device.subscription_online = false;
                        device.subscription_applied_revision = None;
                        device.subscription_status = None;
                        device.subscription_error = None;
                    }
                }
            }
        }

        Some(devices)
    }
}

pub struct SubscriptionControlSession {
    pub identity: (String, String),
    pub random_id: u64,
    subscription_sessions: Arc<DashMap<(String, String), SubscriptionSessionEntry>>,
}

impl Drop for SubscriptionControlSession {
    fn drop(&mut self) {
        let remove_entry = self
            .subscription_sessions
            .get_mut(&self.identity)
            .is_some_and(|mut session| {
                session.links.remove(&self.random_id);
                session.links.is_empty()
            });
        if remove_entry {
            self.subscription_sessions
                .remove_if(&self.identity, |_, session| session.links.is_empty());
        }
    }
}

pub struct Session {
    pub network_code: String,
    pub device_id: String,
    pub ip: Ipv4Addr,
    pub random_id: u64,
    pub client_instance_id: Vec<u8>,
    pub network_state: Arc<NetworkState>,
    pub registration_status: RegistrationStatus,
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub subscription_identity: Option<(String, String)>,
    pub subscription_server_proof: Option<SubscriptionServerProof>,
    subscription_sessions: Arc<DashMap<(String, String), SubscriptionSessionEntry>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(identity) = &self.subscription_identity {
            let remove_entry =
                self.subscription_sessions
                    .get_mut(identity)
                    .is_some_and(|mut session| {
                        session.links.remove(&self.random_id);
                        session.links.is_empty()
                    });
            if remove_entry {
                self.subscription_sessions
                    .remove_if(identity, |_, session| session.links.is_empty());
            }
        }
        match self.registration_status {
            RegistrationStatus::Confirmed => {
                let record = self.network_state.offline_ip(
                    &self.device_id,
                    self.ip,
                    self.random_id,
                    &self.client_instance_id,
                );
                if let Some(record) = record {
                    tokio::spawn(async move {
                        if let Err(e) = db::save_or_update_device(&record).await {
                            log::warn!("Failed to update device record on offline: {}", e);
                        }
                    });
                }
            }
            RegistrationStatus::PendingConfirmation => {
                log::info!(
                    "Releasing pre-registered IP for network_code={}, device_id={}, ip={}",
                    self.network_code,
                    self.device_id,
                    self.ip
                );
                self.network_state.release_pre_registered_ip(
                    &self.device_id,
                    self.ip,
                    self.random_id,
                    &self.client_instance_id,
                );
            }
        }
    }
}

#[derive(Serialize)]
pub struct DeviceInfoVO {
    pub device_id: String,
    pub device_name: String,
    pub current_device_name: Option<String>,
    pub device_version: String,
    pub ip: Option<Ipv4Addr>,
    pub current_ip: Option<Ipv4Addr>,
    pub ip_type: Option<DeviceIpType>,
    pub status: String,
    pub last_connect_time: String,
    pub disconnect_time: Option<String>,
    pub latency_ms: Option<u32>,
    pub server_addr: Option<String>,
    pub advertised_subnets: Vec<Ipv4Net>,
    pub ikev2_output_subnets: Vec<Ipv4Net>,
    pub ikev2_input_routes: Vec<Ikev2InputRoute>,
    pub wireguard_output_subnets: Vec<Ipv4Net>,
    pub wireguard_input_routes: Vec<Ikev2InputRoute>,
    pub wireguard_dns: Vec<Ipv4Addr>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub client_type: ClientType,
    pub managed: bool,
    /// 中继（流量）会话在线：客户端通过本服务器（或其集群）转发数据
    pub relay_online: bool,
    /// 订阅控制连接在线：客户端通过订阅链接与本服务器保持配置同步
    #[serde(rename = "subscription_online")]
    pub subscription_online: bool,
    pub subscription_issued: bool,
    pub subscription_target_revision: Option<i64>,
    pub subscription_applied_revision: Option<i64>,
    pub subscription_status: Option<String>,
    pub subscription_error: Option<String>,
}

#[derive(Serialize)]
pub struct NetworkInfoVO {
    pub network_code: String,
    pub gateway: Ipv4Addr,
    pub netmask: u8,
    pub net: Ipv4Net,
    pub lease_duration: u64,
    pub source: NetworkSource,
    pub network_type: NetworkType,
    pub all_count: u32,
    pub online_count: u32,
}

fn network_counts(memory_counts: Option<(u32, u32)>, persisted_count: Option<u32>) -> (u32, u32) {
    memory_counts.unwrap_or((persisted_count.unwrap_or(0), 0))
}

fn has_effective_runtime_metadata(ack: &SubscriptionConfigAck) -> bool {
    !ack.effective_config_sha256.is_empty()
}

#[cfg(test)]
mod tests {
    use super::{
        ControlService, NetworkConfig, SubscriptionPushStatus, SubscriptionSessionEntry,
        SubscriptionSessionLink, ack_can_update_live_state, authenticate_managed_access,
        first_usable_ip, has_effective_runtime_metadata, network_counts, network_from_gateway,
        validate_registered_revision, validate_subscription_identity,
    };
    use crate::managed_config::client_proof;
    use crate::protocol::control_message::{
        RegRequestMsg, RegistrationMode, SubscriptionConfigAck, SubscriptionConfigApplyStatus,
        SubscriptionRegistration, SubscriptionServerProof,
    };
    use crate::server::control_server::db::{
        ClientType, DeviceIpType, Ikev2InputRoute, ManagedConfigRecord, NetworkSource, NetworkType,
    };
    use base64::Engine;
    use bytes::Bytes;
    use ipnet::Ipv4Net;
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[test]
    fn applied_ack_runtime_metadata_is_explicitly_marked_by_its_hash() {
        let mut legacy = SubscriptionConfigAck {
            revision: 1,
            status: SubscriptionConfigApplyStatus::SubscriptionConfigApplied,
            error: String::new(),
            overridden_fields: Vec::new(),
            apply_mode: String::new(),
            changed_fields: Vec::new(),
            effective_device_name: String::new(),
            effective_ip: Ipv4Addr::UNSPECIFIED,
            effective_prefix_len: 0,
            effective_output: Vec::new(),
            allow_ikev2: false,
            allow_wireguard: false,
            allow_mapping: false,
            effective_config_sha256: Vec::new(),
        };
        assert!(!has_effective_runtime_metadata(&legacy));

        legacy.effective_device_name = "node".to_string();
        legacy.effective_config_sha256 = vec![7; 32];
        assert!(has_effective_runtime_metadata(&legacy));
    }

    #[test]
    fn stale_ack_cannot_update_newer_runtime_state() {
        assert!(ack_can_update_live_state(2, 2, 1));
        assert!(ack_can_update_live_state(2, 2, 2));
        assert!(!ack_can_update_live_state(1, 2, 1));
        assert!(!ack_can_update_live_state(1, 2, 2));
        assert!(!ack_can_update_live_state(2, 2, 3));
    }

    #[test]
    fn normal_clients_are_allowed_but_only_valid_subscription_credentials_enable_sync() {
        let credential_key = vec![7_u8; 32];
        let record = ManagedConfigRecord {
            network_code: "net".into(),
            device_id: "dev".into(),
            revision: 1,
            config_toml: String::new(),
            subscription_server: String::new(),
            traffic_servers_override: None,
            credential_key: Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_key),
            ),
            subscription: None,
            join_id: "11111111-2222-3333-4444-555555555555".into(),
            updated_at: 0,
            configured_device_name: "node".into(),
            configured_ip: None,
            fixed_ip: None,
        };
        let client_nonce = vec![9_u8; 32];
        let registration = SubscriptionRegistration {
            network_code: "net".into(),
            device_id: "dev".into(),
            client_proof: client_proof(&credential_key, &client_nonce),
            client_nonce,
            instance_id: vec![3; 32],
            applied_revision: 0,
        };
        assert!(authenticate_managed_access(Some(&record), None).is_none());
        assert!(authenticate_managed_access(Some(&record), Some(&registration)).is_some());
        let mut wrong = registration.clone();
        wrong.client_proof[0] ^= 1;
        assert!(authenticate_managed_access(Some(&record), Some(&wrong)).is_none());
        let mut wrong_instance = registration.clone();
        wrong_instance.instance_id.pop();
        assert!(authenticate_managed_access(Some(&record), Some(&wrong_instance)).is_none());

        let mut draft = record;
        draft.credential_key = None;
        assert!(authenticate_managed_access(Some(&draft), None).is_none());
        assert!(authenticate_managed_access(Some(&draft), Some(&registration)).is_none());
    }

    #[test]
    fn subscription_identity_must_match_runtime_registration() {
        let request = registration("runtime-net", "runtime-dev");
        let subscription = SubscriptionRegistration {
            network_code: "managed-net".into(),
            device_id: "managed-dev".into(),
            client_nonce: vec![1; 32],
            client_proof: vec![2; 32],
            instance_id: vec![3; 32],
            applied_revision: 0,
        };
        assert!(validate_subscription_identity(&request, Some(&subscription)).is_err());

        let mut matching = subscription;
        matching.network_code = request.network_code.clone();
        matching.device_id = request.device_id.clone();
        assert_eq!(
            validate_subscription_identity(&request, Some(&matching)).unwrap(),
            Some(("runtime-net".into(), "runtime-dev".into()))
        );
    }

    #[test]
    fn managed_registration_rejects_only_revision_ahead_of_server() {
        assert!(validate_registered_revision(6, 7).is_ok());
        assert!(validate_registered_revision(7, 7).is_ok());
        assert!(validate_registered_revision(8, 7).is_err());
    }

    #[tokio::test]
    async fn managed_push_waits_only_for_registration_response_queueing() {
        let mut custom_nets = HashMap::new();
        custom_nets.insert(
            "managed-phase-net".to_string(),
            "10.73.0.0/24".parse().unwrap(),
        );
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            custom_nets,
            HashSet::from(["managed-phase-net".to_string()]),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let (sender, mut receiver) = mpsc::channel(4);
        let identity = (
            "managed-phase-net".to_string(),
            "managed-device".to_string(),
        );
        service.subscription_sessions.insert(
            identity.clone(),
            SubscriptionSessionEntry {
                instance_id: vec![3; 32],
                client_instance_id: vec![6; 32],
                runtime_network_code: identity.0.clone(),
                ip: "10.73.0.2".parse().unwrap(),
                applied_revision: 1,
                apply_error: None,
                overridden_fields: Vec::new(),
                links: HashMap::from([(
                    42,
                    SubscriptionSessionLink {
                        sender,
                        server_proof: SubscriptionServerProof {
                            server_nonce: vec![4; 32],
                            server_proof: vec![5; 32],
                            target_revision: 1,
                        },
                        registration_complete: false,
                        control_connection: false,
                    },
                )]),
            },
        );
        let record = ManagedConfigRecord {
            network_code: identity.0.clone(),
            device_id: identity.1.clone(),
            revision: 2,
            config_toml: String::new(),
            subscription_server: String::new(),
            traffic_servers_override: None,
            credential_key: None,
            subscription: None,
            join_id: "11111111-2222-3333-4444-555555555555".into(),
            updated_at: 0,
            configured_device_name: "managed-device".into(),
            configured_ip: Some("10.73.0.2".parse().unwrap()),
            fixed_ip: None,
        };

        assert_eq!(
            service.push_subscription_config(&record).await.unwrap(),
            SubscriptionPushStatus::Registering
        );
        assert!(receiver.try_recv().is_err());

        // This is exactly what the handler does after RegResponse has entered
        // the same reliable queue. No startup/application ACK is involved.
        service
            .subscription_sessions
            .get_mut(&identity)
            .unwrap()
            .links
            .get_mut(&42)
            .unwrap()
            .registration_complete = true;
        assert_eq!(
            service.push_subscription_config(&record).await.unwrap(),
            SubscriptionPushStatus::Queued
        );
        assert!(receiver.recv().await.is_some());
    }

    #[tokio::test]
    async fn direct_subscription_push_reports_queue_backpressure_and_closed_channel() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert_eq!(
            ControlService::enqueue_subscription_payload(
                &sender,
                Bytes::from_static(b"first"),
                Duration::from_millis(10),
            )
            .await,
            SubscriptionPushStatus::Queued
        );
        assert_eq!(receiver.recv().await, Some(Bytes::from_static(b"first")));

        sender.send(Bytes::from_static(b"occupied")).await.unwrap();
        assert_eq!(
            ControlService::enqueue_subscription_payload(
                &sender,
                Bytes::from_static(b"blocked"),
                Duration::from_millis(1),
            )
            .await,
            SubscriptionPushStatus::Timeout
        );
        assert_eq!(receiver.recv().await, Some(Bytes::from_static(b"occupied")));

        drop(receiver);
        assert_eq!(
            ControlService::enqueue_subscription_payload(
                &sender,
                Bytes::from_static(b"closed"),
                Duration::from_millis(10),
            )
            .await,
            SubscriptionPushStatus::Closed
        );
    }

    #[tokio::test]
    async fn subscription_push_falls_back_to_an_available_link() {
        let (closed_sender, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);

        let (blocked_sender, mut blocked_receiver) = mpsc::channel(1);
        blocked_sender
            .send(Bytes::from_static(b"occupied"))
            .await
            .unwrap();

        let (available_sender, mut available_receiver) = mpsc::channel(1);
        let status = ControlService::enqueue_subscription_payloads(
            vec![
                (closed_sender, Bytes::from_static(b"closed")),
                (blocked_sender, Bytes::from_static(b"blocked")),
                (available_sender, Bytes::from_static(b"delivered")),
            ],
            Duration::from_millis(10),
        )
        .await;

        assert_eq!(status, SubscriptionPushStatus::Queued);
        assert_eq!(
            available_receiver.recv().await,
            Some(Bytes::from_static(b"delivered"))
        );
        assert_eq!(
            blocked_receiver.recv().await,
            Some(Bytes::from_static(b"occupied"))
        );
        assert!(blocked_receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn subscription_push_uses_only_one_available_link() {
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (second_sender, mut second_receiver) = mpsc::channel(1);

        let status = ControlService::enqueue_subscription_payloads(
            vec![
                (first_sender, Bytes::from_static(b"first")),
                (second_sender, Bytes::from_static(b"second")),
            ],
            Duration::from_millis(10),
        )
        .await;

        assert_eq!(status, SubscriptionPushStatus::Queued);
        let delivered = usize::from(first_receiver.try_recv().is_ok())
            + usize::from(second_receiver.try_recv().is_ok());
        assert_eq!(delivered, 1);
    }

    fn registration(network_code: &str, device_id: &str) -> RegRequestMsg {
        RegRequestMsg {
            network_code: network_code.to_string(),
            device_id: device_id.to_string(),
            ip: None,
            name: device_id.to_string(),
            version: "test".to_string(),
            key_sign: None,
            ip_variable: true,
            server_id: 0,
            registration_mode: RegistrationMode::Normal,
            advertised_subnets: Vec::new(),
            allow_ikev2: false,
            allow_wireguard: false,
            subscription: None,
            client_instance_id: vec![1; 32],
        }
    }

    async fn multi_link_test_service(network_code: &str, net: Ipv4Net) -> ControlService {
        ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::from([(network_code.to_string(), net)]),
            HashSet::from([network_code.to_string()]),
            Duration::from_secs(3600),
        )
        .await
        .unwrap()
    }

    fn fixed_registration(
        network_code: &str,
        device_id: &str,
        ip: Ipv4Addr,
        client_instance_id: u8,
    ) -> RegRequestMsg {
        let mut request = registration(network_code, device_id);
        request.ip = Some(ip);
        request.ip_variable = false;
        request.client_instance_id = vec![client_instance_id; 32];
        request
    }

    #[tokio::test]
    async fn same_client_instance_keeps_multiple_links_until_the_last_disconnects() {
        let network_code = "multi-link-same-instance";
        let service = multi_link_test_service(network_code, "10.80.0.0/24".parse().unwrap()).await;
        let ip = "10.80.0.9".parse::<Ipv4Addr>().unwrap();
        let (sender_a, mut receiver_a) = mpsc::channel(8);
        let (sender_b, mut receiver_b) = mpsc::channel(8);
        let session_a = service
            .register(
                fixed_registration(network_code, "device-a", ip, 7),
                sender_a,
            )
            .await
            .unwrap();
        let session_b = service
            .register(
                fixed_registration(network_code, "device-a", ip, 7),
                sender_b,
            )
            .await
            .unwrap();

        assert_eq!(session_a.ip, ip);
        assert_eq!(session_b.ip, ip);
        assert_eq!(session_a.network_state.count(), (1, 1));
        let sender_pool = session_a
            .network_state
            .sender_map()
            .get(&ip)
            .unwrap()
            .clone();
        sender_pool
            .try_send(Bytes::from_static(b"one-delivery"))
            .unwrap();
        let delivered =
            usize::from(receiver_a.try_recv().is_ok()) + usize::from(receiver_b.try_recv().is_ok());
        assert_eq!(delivered, 1, "one packet must use exactly one link");

        while receiver_a.try_recv().is_ok() {}
        while receiver_b.try_recv().is_ok() {}
        drop(session_a);
        assert!(session_b.network_state.is_device_online("device-a"));
        assert!(session_b.network_state.sender_map().contains_key(&ip));
        session_b
            .network_state
            .sender_map()
            .get(&ip)
            .unwrap()
            .try_send(Bytes::from_static(b"remaining-link"))
            .unwrap();
        assert_eq!(
            receiver_b.recv().await,
            Some(Bytes::from_static(b"remaining-link"))
        );

        drop(session_b);
        assert!(
            sender_pool
                .try_send(Bytes::from_static(b"offline"))
                .is_err()
        );
        assert!(
            !service
                .get_network_state_provider()
                .get_network_state(network_code)
                .unwrap()
                .is_device_online("device-a")
        );
    }

    #[tokio::test]
    async fn new_client_instance_replaces_all_links_without_stale_drop_going_offline() {
        let network_code = "multi-link-new-instance";
        let service = multi_link_test_service(network_code, "10.81.0.0/24".parse().unwrap()).await;
        let ip = "10.81.0.9".parse::<Ipv4Addr>().unwrap();
        let (old_sender, mut old_receiver) = mpsc::channel(8);
        let (new_sender, mut new_receiver) = mpsc::channel(8);
        let old_session = service
            .register(
                fixed_registration(network_code, "device-a", ip, 8),
                old_sender,
            )
            .await
            .unwrap();
        let new_session = service
            .register(
                fixed_registration(network_code, "device-a", ip, 9),
                new_sender,
            )
            .await
            .unwrap();

        assert_eq!(
            old_session.network_state.active_link_ip(
                old_session.ip,
                &old_session.client_instance_id,
                old_session.random_id,
            ),
            None
        );
        assert_eq!(
            new_session.network_state.active_link_ip(
                new_session.ip,
                &new_session.client_instance_id,
                new_session.random_id,
            ),
            Some(ip)
        );

        new_session
            .network_state
            .sender_map()
            .get(&ip)
            .unwrap()
            .try_send(Bytes::from_static(b"new-instance"))
            .unwrap();
        assert!(old_receiver.try_recv().is_err());
        assert_eq!(
            new_receiver.recv().await,
            Some(Bytes::from_static(b"new-instance"))
        );

        drop(old_session);
        assert!(new_session.network_state.is_device_online("device-a"));
        assert!(new_session.network_state.sender_map().contains_key(&ip));
        drop(new_session);
        assert!(
            !service
                .get_network_state_provider()
                .get_network_state(network_code)
                .unwrap()
                .is_device_online("device-a")
        );
    }

    #[tokio::test]
    async fn fast_registration_is_idempotent_across_links_of_one_instance() {
        let network_code = "multi-link-fast-reg";
        let service = multi_link_test_service(network_code, "10.82.0.0/24".parse().unwrap()).await;
        let old_ip = "10.82.0.9".parse::<Ipv4Addr>().unwrap();
        let new_ip = "10.82.0.10".parse::<Ipv4Addr>().unwrap();
        let (sender_a, _receiver_a) = mpsc::channel(8);
        let (sender_b, _receiver_b) = mpsc::channel(8);
        let mut session_a = service
            .register(
                fixed_registration(network_code, "device-a", old_ip, 10),
                sender_a,
            )
            .await
            .unwrap();
        let mut session_b = service
            .register(
                fixed_registration(network_code, "device-a", old_ip, 10),
                sender_b,
            )
            .await
            .unwrap();

        service.fast_register(&mut session_a, new_ip).await.unwrap();
        assert_eq!(
            session_b.network_state.active_link_ip(
                session_b.ip,
                &session_b.client_instance_id,
                session_b.random_id,
            ),
            Some(new_ip)
        );
        service.fast_register(&mut session_b, new_ip).await.unwrap();
        assert_eq!(session_a.ip, new_ip);
        assert_eq!(session_b.ip, new_ip);
        assert!(!session_a.network_state.sender_map().contains_key(&old_ip));
        assert!(session_a.network_state.sender_map().contains_key(&new_ip));

        drop(session_a);
        assert!(session_b.network_state.is_device_online("device-a"));
        drop(session_b);
        assert!(
            !service
                .get_network_state_provider()
                .get_network_state(network_code)
                .unwrap()
                .is_device_online("device-a")
        );
    }

    #[test]
    fn network_from_gateway_preserves_non_default_gateway() {
        let gateway = Ipv4Addr::new(192, 168, 1, 100);
        let net = network_from_gateway(gateway, 24).expect("valid network");
        assert_eq!(net, "192.168.1.0/24".parse::<Ipv4Net>().unwrap());
        assert!(net.contains(&gateway));
    }

    #[test]
    fn network_from_gateway_rejects_reserved_and_too_small_networks() {
        assert!(network_from_gateway(Ipv4Addr::new(192, 168, 1, 0), 24).is_err());
        assert!(network_from_gateway(Ipv4Addr::new(192, 168, 1, 255), 24).is_err());
        assert!(network_from_gateway(Ipv4Addr::new(192, 168, 1, 1), 31).is_err());
        assert!(network_from_gateway(Ipv4Addr::UNSPECIFIED, 0).is_err());
    }

    #[test]
    fn first_usable_ip_uses_checked_host_address() {
        let net = "10.20.0.0/24".parse::<Ipv4Net>().unwrap();
        assert_eq!(first_usable_ip(net).unwrap(), Ipv4Addr::new(10, 20, 0, 1));
        assert!(first_usable_ip("255.255.255.255/32".parse().unwrap()).is_err());
    }

    #[test]
    fn network_counts_fall_back_to_persisted_devices_without_memory_state() {
        assert_eq!(network_counts(None, Some(3)), (3, 0));
        assert_eq!(network_counts(None, None), (0, 0));
        assert_eq!(network_counts(Some((2, 1)), Some(3)), (2, 1));
    }

    #[tokio::test]
    async fn custom_networks_work_without_database_persistence() {
        let mut custom_nets = HashMap::new();
        custom_nets.insert("net1".to_string(), "10.40.0.0/24".parse().unwrap());
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            custom_nets,
            HashSet::from(["net1".to_string()]),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

        let config = service.network_config("net1", None).unwrap();
        assert_eq!(config.net, "10.40.0.0/24".parse::<Ipv4Net>().unwrap());
        assert_eq!(config.gateway, Ipv4Addr::new(10, 40, 0, 1));
        assert_eq!(config.source, NetworkSource::Config);
    }

    #[test]
    fn persisted_network_overrides_configured_initial_value() {
        let persisted = NetworkConfig {
            net: "10.1.0.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(10, 1, 0, 1),
            lease_duration: Duration::from_secs(60),
            source: NetworkSource::Config,
            network_type: NetworkType::Public,
        };
        let configured = NetworkConfig {
            net: "10.2.0.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(10, 2, 0, 1),
            lease_duration: Duration::from_secs(120),
            source: NetworkSource::Config,
            network_type: NetworkType::Public,
        };
        let merged = ControlService::merge_network_configs(
            HashMap::from([("net1".to_string(), persisted)]),
            HashMap::from([("net1".to_string(), configured)]),
        );

        let actual = merged.get("net1").unwrap();
        assert_eq!(actual.net, persisted.net);
        assert_eq!(actual.gateway, persisted.gateway);
        assert_eq!(actual.lease_duration, persisted.lease_duration);
    }

    #[tokio::test]
    async fn white_list_is_exact_and_empty_list_allows_all() {
        let unrestricted = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        assert!(unrestricted.network_code_allowed("any-network"));

        let restricted = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::from(["net1".to_string()]),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        assert!(restricted.network_code_allowed("net1"));
        assert!(!restricted.network_code_allowed("NET1"));
        assert!(!restricted.network_code_allowed("net2"));
    }

    #[tokio::test]
    async fn replacing_white_list_affects_new_connections_without_disconnecting_existing_ones() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let (sender, _receiver) = mpsc::channel(8);
        let session = service
            .register(registration("net1", "device-a"), sender.clone())
            .await
            .unwrap();

        service.replace_white_list(HashSet::from(["net2".to_string()]));

        assert_eq!(service.get_white_list(), vec!["net2".to_string()]);
        assert!(session.network_state.is_device_online("device-a"));
        assert!(
            service
                .register(registration("net1", "device-b"), sender)
                .await
                .is_err()
        );
        assert!(session.network_state.is_device_online("device-a"));
    }

    #[tokio::test]
    async fn private_network_only_accepts_existing_device_ids() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "private".to_string(),
                "10.50.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Private,
            )
            .await
            .unwrap();
        service
            .add_device(
                "private",
                "known",
                "10.50.0.3".parse().unwrap(),
                DeviceIpType::Static,
            )
            .await
            .unwrap();

        let (sender, _receiver) = mpsc::channel(8);
        assert!(
            service
                .register(registration("private", "unknown"), sender.clone())
                .await
                .is_err()
        );
        let session = service
            .register(registration("private", "known"), sender)
            .await
            .unwrap();
        assert_eq!(session.ip, "10.50.0.3".parse::<Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn non_fixed_fast_registration_converges_secondary_server_state() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "public".to_string(),
                "10.60.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();
        let (sender, _receiver) = mpsc::channel(8);
        let mut session = service
            .register(registration("public", "device-a"), sender)
            .await
            .unwrap();
        let old_ip = session.ip;
        let new_ip = "10.60.0.9".parse::<Ipv4Addr>().unwrap();

        // This simulates a secondary VNTS that has not yet observed the
        // primary management endpoint's IP edit. Its Static device table still
        // contains the old address when the client sends FastReg.
        service
            .update_device("public", "device-a", old_ip, DeviceIpType::Static)
            .await
            .unwrap();
        assert_eq!(session.ip, old_ip);
        assert_eq!(
            session.network_state.configured_ip("device-a"),
            Some(old_ip)
        );
        let device_info = session
            .network_state
            .get_device_infos()
            .into_iter()
            .find(|device| device.device_id == "device-a")
            .unwrap();
        assert_eq!(device_info.ip, Some(old_ip));
        assert_eq!(device_info.current_ip, Some(old_ip));
        assert!(session.network_state.sender_map().contains_key(&old_ip));
        assert!(!session.network_state.sender_map().contains_key(&new_ip));
        assert!(
            service
                .add_device("public", "device-b", old_ip, DeviceIpType::Static)
                .await
                .is_err(),
            "the active old IP must remain reserved"
        );

        service.fast_register(&mut session, new_ip).await.unwrap();
        assert_eq!(session.ip, new_ip);
        let device_info = session
            .network_state
            .get_device_infos()
            .into_iter()
            .find(|device| device.device_id == "device-a")
            .unwrap();
        assert_eq!(device_info.current_ip, Some(new_ip));
        assert_eq!(device_info.ip, Some(new_ip));
        assert!(!session.network_state.sender_map().contains_key(&old_ip));
        assert!(session.network_state.sender_map().contains_key(&new_ip));

        // Fixed IP remains the exception: the server must not let a client
        // replace an explicitly configured fixed address.
        service
            .update_device("public", "device-a", new_ip, DeviceIpType::Fixed)
            .await
            .unwrap();
        assert!(
            service
                .fast_register(&mut session, "10.60.0.10".parse().unwrap())
                .await
                .is_err()
        );
        assert_eq!(session.ip, new_ip);
    }

    #[tokio::test]
    async fn fast_registration_makes_stale_clients_replace_their_device_list() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "fast-reg-full-sync".to_string(),
                "10.61.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();

        let (sender_a, _receiver_a) = mpsc::channel(8);
        let (sender_b, _receiver_b) = mpsc::channel(8);
        let mut session_a = service
            .register(registration("fast-reg-full-sync", "device-a"), sender_a)
            .await
            .unwrap();
        let session_b = service
            .register(registration("fast-reg-full-sync", "device-b"), sender_b)
            .await
            .unwrap();
        let old_ip = session_a.ip;

        // 模拟 B 已经同步到修改前的设备列表版本。
        let before = session_b
            .network_state
            .changed_client_simple_list(session_b.ip, u64::MAX, false, false)
            .unwrap();
        assert!(before.is_all, "客户端版本高于服务端时必须全量恢复");
        let b_version = before.data_version;

        let new_ip = "10.61.0.9".parse::<Ipv4Addr>().unwrap();
        service
            .update_device(
                "fast-reg-full-sync",
                "device-a",
                new_ip,
                DeviceIpType::Static,
            )
            .await
            .unwrap();
        service.fast_register(&mut session_a, new_ip).await.unwrap();

        let update = session_b
            .network_state
            .changed_client_simple_list(session_b.ip, b_version, false, false)
            .expect("B 的版本落后时应收到完整设备列表");
        assert!(update.data_version > b_version);
        assert!(update.is_all);
        assert!(update.list.iter().any(|device| device.ip == new_ip));
        assert!(!update.list.iter().any(|device| device.ip == old_ip));

        let migration_version = update.data_version;
        assert!(
            session_b
                .network_state
                .changed_client_simple_list(session_b.ip, migration_version, false, false)
                .is_none(),
            "已经同步到迁移版本时不应重复下发"
        );

        // 越过迁移屏障后，普通新增仍然只下发增量。
        let (sender_c, _receiver_c) = mpsc::channel(8);
        let session_c = service
            .register(registration("fast-reg-full-sync", "device-c"), sender_c)
            .await
            .unwrap();
        let incremental = session_b
            .network_state
            .changed_client_simple_list(session_b.ip, migration_version, false, false)
            .expect("新增设备后应有增量列表");
        assert!(!incremental.is_all);
        assert_eq!(incremental.list.len(), 1);
        assert_eq!(incremental.list[0].ip, session_c.ip);

        // 一直停留在迁移前版本的客户端，即使服务端后来还有普通变化，仍必须全量。
        let stale_update = session_b
            .network_state
            .changed_client_simple_list(session_b.ip, b_version, false, false)
            .expect("未越过迁移屏障的客户端仍应收到全量列表");
        assert!(stale_update.is_all);
        assert!(stale_update.list.iter().any(|device| device.ip == new_ip));
        assert!(
            stale_update
                .list
                .iter()
                .any(|device| device.ip == session_c.ip)
        );
    }

    #[tokio::test]
    async fn normal_reconnect_uses_latest_configured_ip_without_fast_registration() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "reconnect".to_string(),
                "10.70.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();
        let (sender, _receiver) = mpsc::channel(8);
        let session = service
            .register(registration("reconnect", "device-a"), sender.clone())
            .await
            .unwrap();
        let old_ip = session.ip;
        let new_ip = "10.70.0.20".parse::<Ipv4Addr>().unwrap();
        service
            .update_device("reconnect", "device-a", new_ip, DeviceIpType::Static)
            .await
            .unwrap();
        drop(session);

        let state = service.get_network_state("reconnect").unwrap();
        assert!(!state.sender_map().contains_key(&old_ip));
        let reconnected = service
            .register(registration("reconnect", "device-a"), sender)
            .await
            .unwrap();
        assert_eq!(reconnected.ip, new_ip);
        assert!(state.sender_map().contains_key(&new_ip));
    }

    #[tokio::test]
    async fn fixed_ip_uses_server_value_while_other_types_prefer_client_request() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "ip-types".to_string(),
                "10.80.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();
        service
            .add_device(
                "ip-types",
                "static-device",
                "10.80.0.3".parse().unwrap(),
                DeviceIpType::Static,
            )
            .await
            .unwrap();
        service
            .add_device(
                "ip-types",
                "fixed-device",
                "10.80.0.4".parse().unwrap(),
                DeviceIpType::Fixed,
            )
            .await
            .unwrap();
        let (sender, _receiver) = mpsc::channel(8);

        let mut static_request = registration("ip-types", "static-device");
        static_request.ip = Some("10.80.0.9".parse().unwrap());
        static_request.ip_variable = false;
        let static_session = service
            .register(static_request, sender.clone())
            .await
            .unwrap();
        assert_eq!(static_session.ip, "10.80.0.9".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            static_session
                .network_state
                .get_device_entry("static-device")
                .unwrap()
                .ip_type,
            DeviceIpType::Static
        );

        let mut fixed_request = registration("ip-types", "fixed-device");
        fixed_request.ip = Some("10.80.0.10".parse().unwrap());
        fixed_request.ip_variable = false;
        let fixed_session = service.register(fixed_request, sender).await.unwrap();
        assert_eq!(fixed_session.ip, "10.80.0.4".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            fixed_session
                .network_state
                .get_device_entry("fixed-device")
                .unwrap()
                .ip_type,
            DeviceIpType::Fixed
        );
    }

    #[tokio::test]
    async fn configured_and_active_ips_are_both_reserved_for_add_and_registration() {
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "unique-ips".to_string(),
                "10.90.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();

        let (sender, _receiver) = mpsc::channel(8);
        let first_session = service
            .register(registration("unique-ips", "device-a"), sender.clone())
            .await
            .unwrap();
        let active_ip = first_session.ip;
        let configured_ip = "10.90.0.9".parse::<Ipv4Addr>().unwrap();
        service
            .update_device(
                "unique-ips",
                "device-a",
                configured_ip,
                DeviceIpType::Static,
            )
            .await
            .unwrap();

        assert_eq!(first_session.ip, active_ip);
        assert_eq!(
            first_session.network_state.configured_ip("device-a"),
            Some(configured_ip)
        );

        for occupied_ip in [active_ip, configured_ip] {
            assert!(
                service
                    .add_device(
                        "unique-ips",
                        &format!("manual-{occupied_ip}"),
                        occupied_ip,
                        DeviceIpType::Dynamic,
                    )
                    .await
                    .is_err(),
                "manual add must reject occupied IP {occupied_ip}"
            );

            let mut strict_request = registration("unique-ips", &format!("strict-{occupied_ip}"));
            strict_request.ip = Some(occupied_ip);
            strict_request.ip_variable = false;
            assert!(
                service
                    .register(strict_request, sender.clone())
                    .await
                    .is_err(),
                "registration must reject occupied fixed request {occupied_ip}"
            );
        }

        let mut variable_request = registration("unique-ips", "variable-device");
        variable_request.ip = Some(active_ip);
        variable_request.ip_variable = true;
        let variable_session = service.register(variable_request, sender).await.unwrap();
        assert_ne!(variable_session.ip, active_ip);
        assert_ne!(variable_session.ip, configured_ip);
    }

    #[tokio::test]
    async fn re_register_with_same_ip_updates_device_version_in_memory_and_rpc_list() {
        // 回归测试：客户端升级版本后带同一 IP 重连（ip_matches 分支），
        // 必须刷新 device_version，否则 web（get_device_infos）与 RPC
        // 客户端列表（client_info_list）都会继续显示旧版本。
        let service = ControlService::new(
            "10.26.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_network(
                "ver-repro".to_string(),
                "10.71.0.1".parse().unwrap(),
                24,
                None,
                NetworkType::Public,
            )
            .await
            .unwrap();

        let (sender_a, _recv_a) = mpsc::channel(8);
        let (sender_b, _recv_b) = mpsc::channel(8);

        let mut reg_old = registration("ver-repro", "device-a");
        reg_old.version = "2.0.4".to_string();
        reg_old.ip = Some("10.71.0.2".parse().unwrap());
        service.register(reg_old, sender_a).await.unwrap();

        // 模拟客户端带新版本号重连（同一 device_id、同一 IP）
        let mut reg_new = registration("ver-repro", "device-a");
        reg_new.version = "2.0.5".to_string();
        reg_new.ip = Some("10.71.0.2".parse().unwrap());
        reg_new.advertised_subnets = vec!["192.168.10.0/24".parse().unwrap()];
        let _session_b = service.register(reg_new, sender_b).await.unwrap();

        // 另一台设备，用于从旁观察 client_info_list（列表会排除请求者自己）
        let (sender_c, _recv_c) = mpsc::channel(8);
        let session_c = service
            .register(registration("ver-repro", "device-b"), sender_c)
            .await
            .unwrap();

        let state = service.get_network_state("ver-repro").unwrap();
        let infos = state.get_device_infos();
        let dev = infos.iter().find(|d| d.device_id == "device-a").unwrap();
        assert_eq!(
            dev.device_version, "2.0.5",
            "web 通过 get_device_infos 应看到新版本"
        );
        assert_eq!(
            dev.advertised_subnets,
            vec!["192.168.10.0/24".parse::<Ipv4Net>().unwrap()]
        );

        let client_list = state.client_info_list(session_c.ip, false, false);
        let dev = client_list.iter().find(|d| d.id == "device-a").unwrap();
        assert_eq!(dev.version, "2.0.5", "RPC 客户端列表应显示新版本");
    }

    #[tokio::test]
    async fn ikev2_devices_are_precreated_unique_and_protected_from_vnt_registration() {
        let service = ControlService::new(
            "10.92.0.0/24".parse().unwrap(),
            HashMap::from([
                ("ike-a".to_string(), "10.92.0.0/24".parse().unwrap()),
                ("ike-b".to_string(), "10.93.0.0/24".parse().unwrap()),
            ]),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

        assert!(
            service
                .add_device_typed(
                    "ike-a",
                    "missing-password",
                    "10.92.0.8".parse().unwrap(),
                    DeviceIpType::Fixed,
                    ClientType::Ikev2,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .is_err()
        );
        service
            .add_device_typed(
                "ike-a",
                "alice",
                "10.92.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Ikev2,
                    Some("old-password".to_string()),
                    Some("Alice Phone".to_string()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            .await
            .unwrap();
        assert!(
            service
                .add_device_typed(
                    "ike-b",
                    "alice",
                    "10.93.0.8".parse().unwrap(),
                    DeviceIpType::Fixed,
                    ClientType::Ikev2,
                    Some("other-password".to_string()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .is_err()
        );

        let (sender, _) = mpsc::channel(8);
        assert!(
            service
                .register(registration("ike-a", "alice"), sender)
                .await
                .is_err()
        );
        let (sender, _) = mpsc::channel(8);
        assert!(
            service
                .register_ikev2("ike-a".to_string(), "unknown".to_string(), sender,)
                .await
                .is_err()
        );

        service
            .update_device_with_password(
                "ike-a",
                "alice",
                "10.92.0.9".parse().unwrap(),
                DeviceIpType::Static,
                Some("new-password".to_string()),
                Some("Alice Tablet".to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let record = service
            .get_device_record("ike-a", "alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.client_type, ClientType::Ikev2);
        assert_eq!(record.ikev2_password.as_deref(), Some("new-password"));
        assert_eq!(record.device_name, "Alice Tablet");
        assert_eq!(
            service.ikev2_credentials().await.unwrap().get("alice"),
            Some(&("ike-a".to_string(), "new-password".to_string()))
        );

        service
            .update_device_with_password(
                "ike-a",
                "alice",
                "10.92.0.9".parse().unwrap(),
                DeviceIpType::Static,
                None,
                Some("Alice Laptop".to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let record = service
            .get_device_record("ike-a", "alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.device_name, "Alice Laptop");
        assert_eq!(record.ikev2_password.as_deref(), Some("new-password"));
    }

    #[tokio::test]
    async fn ikev2_subnet_config_is_normalized_routed_and_active_only_while_online() {
        let service = ControlService::new(
            "10.96.0.0/24".parse().unwrap(),
            HashMap::from([("ike-subnets".to_string(), "10.96.0.0/24".parse().unwrap())]),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let outputs = vec![
            "192.168.20.7/24".parse().unwrap(),
            "192.168.20.0/24".parse().unwrap(),
            "172.16.0.1/16".parse().unwrap(),
        ];
        let routes = vec![
            Ikev2InputRoute {
                subnet: "10.200.0.7/16".parse().unwrap(),
                target_ip: "10.96.0.20".parse().unwrap(),
            },
            Ikev2InputRoute {
                subnet: "10.200.10.9/24".parse().unwrap(),
                target_ip: "10.96.0.21".parse().unwrap(),
            },
        ];
        service
            .add_device_typed(
                "ike-subnets",
                "router",
                "10.96.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Ikev2,
                Some("password".to_string()),
                Some("Branch router".to_string()),
                Some(outputs),
                Some(routes),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let record = service
            .get_device_record("ike-subnets", "router")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            record.ikev2_output_subnets,
            vec![
                "172.16.0.0/16".parse().unwrap(),
                "192.168.20.0/24".parse().unwrap()
            ]
        );
        assert_eq!(
            record.ikev2_input_routes[0].subnet,
            "10.200.10.0/24".parse().unwrap()
        );
        assert_eq!(
            service.ikev2_route_target("ike-subnets", "router", "10.200.10.42".parse().unwrap(),),
            Some("10.96.0.21".parse().unwrap())
        );
        assert_eq!(
            service.ikev2_route_target("ike-subnets", "router", "10.200.99.42".parse().unwrap(),),
            Some("10.96.0.20".parse().unwrap())
        );
        assert!(!service.address_owned_by(
            "ike-subnets",
            "10.96.0.8".parse().unwrap(),
            "192.168.20.10".parse().unwrap(),
        ));

        let (sender, _receiver) = mpsc::channel(8);
        let session = service
            .register_ikev2("ike-subnets".to_string(), "router".to_string(), sender)
            .await
            .unwrap();
        assert!(service.address_owned_by(
            "ike-subnets",
            session.ip,
            "192.168.20.10".parse().unwrap(),
        ));
        assert!(!service.address_owned_by(
            "ike-subnets",
            session.ip,
            "10.96.0.99".parse().unwrap(),
        ));

        let duplicate = vec![
            Ikev2InputRoute {
                subnet: "203.0.113.1/24".parse().unwrap(),
                target_ip: "10.96.0.20".parse().unwrap(),
            },
            Ikev2InputRoute {
                subnet: "203.0.113.99/24".parse().unwrap(),
                target_ip: "10.96.0.21".parse().unwrap(),
            },
        ];
        assert!(
            service
                .update_device_with_password(
                    "ike-subnets",
                    "router",
                    session.ip,
                    DeviceIpType::Fixed,
                    None,
                    None,
                    None,
                    Some(duplicate),
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .is_err()
        );
        assert!(
            service
                .add_device_typed(
                    "ike-subnets",
                    "plain-vnt",
                    "10.96.0.9".parse().unwrap(),
                    DeviceIpType::Fixed,
                    ClientType::Vnt,
                    None,
                    None,
                    Some(vec!["198.51.100.0/24".parse().unwrap()]),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn ikev2_clients_are_visible_only_to_opted_in_vnt_sessions() {
        let service = ControlService::new(
            "10.91.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let (vnt_sender, mut vnt_receiver) = mpsc::channel(8);
        let vnt = service
            .register(registration("ike-access", "vnt-a"), vnt_sender)
            .await
            .unwrap();
        service
            .add_device_typed(
                "ike-access",
                "phone",
                "10.91.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Ikev2,
                Some("password".to_string()),
                Some("Office Phone".to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let (ike_sender, mut ike_receiver) = mpsc::channel(8);
        let ike = service
            .register_ikev2("ike-access".to_string(), "phone".to_string(), ike_sender)
            .await
            .unwrap();
        assert_eq!(
            ike.network_state
                .get_device_entry("phone")
                .unwrap()
                .device_name,
            "Office Phone"
        );

        let hidden = vnt
            .network_state
            .full_client_simple_list(vnt.ip, false, false);
        assert!(!hidden.list.iter().any(|client| client.ip == ike.ip));
        let visible = vnt
            .network_state
            .full_client_simple_list(vnt.ip, true, false);
        assert!(visible.list.iter().any(|client| {
            client.ip == ike.ip
                && client.client_type == crate::protocol::control_message::ClientType::Ikev2
        }));

        service.ping_local_clients().await;
        let ping = vnt_receiver
            .try_recv()
            .expect("VNT clients should receive server pings");
        let ping = crate::protocol::ip_packet_protocol::NetPacket::new(ping)
            .expect("server ping should be a valid packet");
        assert_eq!(
            ping.msg_type().unwrap(),
            crate::protocol::ip_packet_protocol::MsgType::Ping
        );
        assert!(ping.is_gateway());
        assert!(ike_receiver.try_recv().is_err());

        let packet = test_ipv4(ike.ip, vnt.ip);
        assert!(
            !service
                .forward_ikev2_packet("ike-access", "phone", ike.ip, &packet)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn wireguard_subnet_config_updates_online_without_disconnect() {
        let service = ControlService::new(
            "10.97.0.0/24".parse().unwrap(),
            HashMap::from([("wg-subnets".to_string(), "10.97.0.0/24".parse().unwrap())]),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        service
            .add_device_typed(
                "wg-subnets",
                "router",
                "10.97.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Wireguard,
                None,
                Some("WG router".to_string()),
                None,
                None,
                Some(vec!["192.168.40.7/24".parse().unwrap()]),
                Some(vec![
                    Ikev2InputRoute {
                        subnet: "10.210.0.7/16".parse().unwrap(),
                        target_ip: "10.97.0.20".parse().unwrap(),
                    },
                    Ikev2InputRoute {
                        subnet: "10.210.10.9/24".parse().unwrap(),
                        target_ip: "10.97.0.21".parse().unwrap(),
                    },
                ]),
                Some(vec!["10.53.53.53".parse().unwrap(), "10.53.53.54".parse().unwrap()]),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .get_device_record("wg-subnets", "router")
                .await
                .unwrap()
                .unwrap()
                .wireguard_dns,
            vec![
                "10.53.53.53".parse::<Ipv4Addr>().unwrap(),
                "10.53.53.54".parse().unwrap(),
            ]
        );
        let (sender, _receiver) = mpsc::channel(8);
        let session = service
            .register_wireguard("wg-subnets".to_string(), "router".to_string(), sender)
            .await
            .unwrap();
        let before = session
            .network_state
            .get_device_entry("router")
            .unwrap()
            .data_version;

        service
            .update_device_with_password(
                "wg-subnets",
                "router",
                session.ip,
                DeviceIpType::Fixed,
                None,
                Some("WG router updated".to_string()),
                None,
                None,
                Some(vec![
                    "172.22.0.1/16".parse().unwrap(),
                    "172.22.0.0/16".parse().unwrap(),
                ]),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let entry = session.network_state.get_device_entry("router").unwrap();
        assert!(entry.is_connected);
        assert!(entry.data_version > before);
        assert_eq!(
            entry.advertised_subnets,
            vec!["172.22.0.0/16".parse().unwrap()]
        );
        assert_eq!(
            entry.wireguard_dns,
            vec![
                "10.53.53.53".parse::<Ipv4Addr>().unwrap(),
                "10.53.53.54".parse().unwrap(),
            ]
        );
        assert!(service.address_owned_by("wg-subnets", session.ip, "172.22.1.9".parse().unwrap(),));
        assert_eq!(
            service
                .wireguard_route_target("wg-subnets", "router", "10.210.10.42".parse().unwrap(),),
            Some("10.97.0.21".parse().unwrap())
        );
        assert_eq!(
            service
                .wireguard_route_target("wg-subnets", "router", "10.210.99.42".parse().unwrap(),),
            Some("10.97.0.20".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn wireguard_user_supplied_private_key_is_validated_and_deduplicated() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let service = ControlService::new(
            "10.98.0.0/24".parse().unwrap(),
            HashMap::from([("wg-keys".to_string(), "10.98.0.0/24".parse().unwrap())]),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let private_key = STANDARD.encode([7u8; 32]);
        let expected_public = STANDARD.encode(
            boringtun::x25519::PublicKey::from(&boringtun::x25519::StaticSecret::from([7u8; 32]))
                .as_bytes(),
        );

        service
            .add_device_typed(
                "wg-keys",
                "owned-key",
                "10.98.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Wireguard,
                None,
                Some("Owned key".to_string()),
                None,
                None,
                None,
                None,
                None,
                Some(private_key.clone()),
            )
            .await
            .unwrap();
        let record = service
            .get_device_record("wg-keys", "owned-key")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.wireguard_private_key.as_deref(), Some(private_key.as_str()));
        assert_eq!(
            record.wireguard_public_key.as_deref(),
            Some(expected_public.as_str())
        );

        let error = service
            .add_device_typed(
                "wg-keys",
                "clone",
                "10.98.0.9".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Wireguard,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(private_key.clone()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("已绑定其他设备"));

        // 同一设备重复提交相同私钥不算重复。
        service
            .update_device_with_password(
                "wg-keys",
                "owned-key",
                "10.98.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                None,
                Some("Owned key 2".to_string()),
                None,
                None,
                None,
                None,
                None,
                Some(private_key.clone()),
            )
            .await
            .unwrap();

        // 更换为另一个私钥成功，且旧设备不再占用新公钥。
        let private_key2 = STANDARD.encode([9u8; 32]);
        service
            .update_device_with_password(
                "wg-keys",
                "owned-key",
                "10.98.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(private_key2.clone()),
            )
            .await
            .unwrap();
        let record = service
            .get_device_record("wg-keys", "owned-key")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.wireguard_private_key.as_deref(), Some(private_key2.as_str()));

        let error = service
            .add_device_typed(
                "wg-keys",
                "bad-key",
                "10.98.0.10".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Wireguard,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some("not-a-key".to_string()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("无效的 WireGuard 私钥"));
    }

    #[tokio::test]
    async fn wireguard_devices_get_keys_and_require_vnt_opt_in() {
        let service = ControlService::new(
            "10.94.0.0/24".parse().unwrap(),
            HashMap::new(),
            HashSet::new(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let (vnt_sender, _vnt_receiver) = mpsc::channel(8);
        let vnt = service
            .register(registration("wg-access", "vnt-a"), vnt_sender)
            .await
            .unwrap();
        service
            .add_device_typed(
                "wg-access",
                "wg-phone",
                "10.94.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Wireguard,
                None,
                Some("WireGuard Phone".to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let record = service
            .get_device_record("wg-access", "wg-phone")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.client_type, ClientType::Wireguard);
        assert_eq!(record.ip_type, DeviceIpType::Static);
        assert!(
            record
                .wireguard_private_key
                .as_ref()
                .is_some_and(|key| !key.is_empty())
        );
        assert!(
            record
                .wireguard_public_key
                .as_ref()
                .is_some_and(|key| !key.is_empty())
        );

        let (wg_sender, _wg_receiver) = mpsc::channel(8);
        let wg = service
            .register_wireguard("wg-access".to_string(), "wg-phone".to_string(), wg_sender)
            .await
            .unwrap();
        let hidden = vnt
            .network_state
            .full_client_simple_list(vnt.ip, false, false);
        assert!(!hidden.list.iter().any(|client| client.ip == wg.ip));
        let visible = vnt
            .network_state
            .full_client_simple_list(vnt.ip, false, true);
        assert!(visible.list.iter().any(|client| {
            client.ip == wg.ip
                && client.client_type == crate::protocol::control_message::ClientType::Wireguard
        }));
        let packet = test_ipv4(wg.ip, vnt.ip);
        assert!(
            !service
                .forward_wireguard_packet("wg-access", "wg-phone", wg.ip, &packet)
                .await
                .unwrap()
        );
    }

    fn test_ipv4(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }
}
