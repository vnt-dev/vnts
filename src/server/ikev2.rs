use crate::protocol::ip_packet_protocol::{MsgType, NetPacket};
use crate::server::control_server::service::{ControlService, Session};
use crate::utils::config::Ikev2Config;
use anyhow::{Context, bail};
use bytes::Bytes;
use ipnet::Ipv4Net;
use pnet_packet::ipv4::Ipv4Packet;
use rand::RngCore;
use rsa::pkcs8::DecodePrivateKey;
use ryke::{
    AssignedConfig, ChildSa, CompletedSaInit, CookiePolicy, EapEvent, EapResponder, Entropy,
    ExchangeType, Identification, IkeHeader, LocalSecret, MessageBuilder, Notify, PayloadType,
    Role, SaInitResult, ServerAuth, SigningKey, TrafficSelector, TrafficSelectors, build_encrypted,
    build_informational, is_eap_request, is_ike_sa_rekey, open_encrypted, open_informational,
    payloads, responder_process_ike_rekey, responder_process_rekey, responder_respond_natt,
};
use std::collections::HashMap;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const NONCE_LEN: usize = 32;
const HALF_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_HALF_OPEN: usize = 1024;
const IKE_FRAGMENT_CONTENT: usize = 1024;
const NON_ESP_MARKER: [u8; 4] = [0; 4];
type EapCredentialMap = HashMap<Vec<u8>, (String, String)>;

// IKEV2_DIAG_TEMP: temporary diagnostics for the native-client connection failure.
// Remove this macro and every `ikev2_diag!` call once the issue is resolved.
macro_rules! ikev2_diag {
    ($($arg:tt)*) => {
        log::info!("[IKEV2-DIAG-TEMP] {}", format_args!($($arg)*))
    };
}

#[derive(Clone)]
enum SigningMaterial {
    EcdsaP256(Vec<u8>),
    Rsa(Vec<u8>),
}

impl SigningMaterial {
    fn signing_key(&self) -> anyhow::Result<SigningKey> {
        match self {
            Self::EcdsaP256(der) => SigningKey::ecdsa_p256_from_pkcs8_der(der)
                .map_err(|error| anyhow::anyhow!("invalid IKEv2 ECDSA key: {error}")),
            Self::Rsa(der) => {
                let key = rsa::RsaPrivateKey::from_pkcs8_der(der)
                    .context("invalid IKEv2 RSA PKCS#8 key")?;
                Ok(SigningKey::RsaSha256(Box::new(key)))
            }
        }
    }
}

#[derive(Clone)]
struct CertificateMaterial {
    signing: SigningMaterial,
    chain: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct HalfOpen {
    sa: CompletedSaInit,
    peer: SocketAddr,
    response: Vec<u8>,
    natt: bool,
    created: Instant,
    fragmentation_supported: bool,
}

struct EapPending {
    responder: EapResponder,
    sa: CompletedSaInit,
    peer: SocketAddr,
    natt: bool,
    child_spi: u32,
    network_code: Option<String>,
    session: Option<Session>,
    receiver: Option<mpsc::Receiver<Bytes>>,
    last_seen: Instant,
    fragmentation_supported: bool,
}

#[derive(Default)]
struct ReplayWindow {
    highest: u32,
    bitmap: u64,
}

impl ReplayWindow {
    fn permits(&self, sequence: u32) -> bool {
        if sequence == 0 {
            return false;
        }
        if sequence > self.highest {
            return true;
        }
        let distance = self.highest - sequence;
        distance < 64 && (self.bitmap & (1u64 << distance)) == 0
    }

    fn record(&mut self, sequence: u32) {
        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = sequence;
        } else {
            self.bitmap |= 1u64 << (self.highest - sequence);
        }
    }
}

struct Established {
    sa: CompletedSaInit,
    child: ChildSa,
    session: Session,
    network: Ipv4Net,
    peer: SocketAddr,
    natt: bool,
    replay: ReplayWindow,
    last_seen: Instant,
    last_ike_response: Option<(u32, Vec<u8>)>,
    fragmentation_supported: bool,
    outbound_message_id: u32,
}

struct FragmentSet {
    messages: Vec<Vec<u8>>,
    total: u16,
    updated: Instant,
}

enum Command {
    ToIke {
        session_id: u64,
        packet: Bytes,
    },
    DisconnectDevice {
        network_code: String,
        device_id: String,
        response: tokio::sync::oneshot::Sender<bool>,
    },
    ReloadConfig {
        config: Box<Ikev2Config>,
        certificate: Option<CertificateMaterial>,
        changed_network: Option<String>,
        response: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    ReloadCredentials {
        credentials: HashMap<String, (String, String)>,
        response: tokio::sync::oneshot::Sender<()>,
    },
    Shutdown {
        response: tokio::sync::oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub struct Ikev2Handle {
    command_tx: mpsc::Sender<Command>,
}

impl Ikev2Handle {
    pub async fn disconnect_device(&self, network_code: &str, device_id: &str) -> bool {
        let (response, receiver) = tokio::sync::oneshot::channel();
        if self
            .command_tx
            .send(Command::DisconnectDevice {
                network_code: network_code.to_string(),
                device_id: device_id.to_string(),
                response,
            })
            .await
            .is_err()
        {
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    pub async fn reload_network_config(
        &self,
        config: Ikev2Config,
        changed_network: Option<String>,
    ) -> anyhow::Result<()> {
        config.validate()?;
        let certificate_config = config.clone();
        let certificate =
            tokio::task::spawn_blocking(move || load_certificate(&certificate_config))
                .await
                .context("IKEv2 certificate validation task failed")??;
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(Command::ReloadConfig {
                config: Box::new(config),
                certificate,
                changed_network,
                response,
            })
            .await
            .context("IKEv2 service is not running")?;
        receiver
            .await
            .context("IKEv2 service stopped while reloading")?
            .map_err(anyhow::Error::msg)
    }

    pub async fn reload_credentials(
        &self,
        credentials: HashMap<String, (String, String)>,
    ) -> anyhow::Result<()> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(Command::ReloadCredentials {
                credentials,
                response,
            })
            .await
            .context("IKEv2 service is not running")?;
        receiver
            .await
            .context("IKEv2 service stopped while reloading credentials")
    }

    pub async fn shutdown(&self) {
        let (response, receiver) = tokio::sync::oneshot::channel();
        if self
            .command_tx
            .send(Command::Shutdown { response })
            .await
            .is_ok()
        {
            let _ = receiver.await;
        }
    }
}

struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        rand::rng().fill_bytes(out);
    }
}

struct Engine {
    config: Ikev2Config,
    control: ControlService,
    ike_socket: Arc<UdpSocket>,
    natt_socket: Arc<UdpSocket>,
    eap_credentials: EapCredentialMap,
    certificate: Option<CertificateMaterial>,
    half_open: HashMap<(u64, u64), HalfOpen>,
    eap_pending: HashMap<(u64, u64), EapPending>,
    established: HashMap<u64, Established>,
    esp_to_session: HashMap<u32, u64>,
    ike_to_session: HashMap<(u64, u64), u64>,
    fragments: HashMap<(u64, u64, u32, u8, SocketAddr), FragmentSet>,
    command_tx: mpsc::Sender<Command>,
    command_rx: mpsc::Receiver<Command>,
    entropy: SystemEntropy,
    cookie_secret: [u8; 32],
    shutdown: bool,
}

pub async fn start(config: Ikev2Config, control: ControlService) -> anyhow::Result<Ikev2Handle> {
    ikev2_diag!(
        "start requested: enabled={}, ike_bind={}, natt_bind={}, server_address={}, remote_id={}, dns_count={}, cert_configured={}, key_configured={}",
        config.enabled,
        config.ike_bind,
        config.natt_bind,
        config.server_address,
        config.remote_id,
        config.dns.len(),
        config.cert.is_some(),
        config.key.is_some()
    );
    config.validate()?;
    ikev2_diag!("configuration validation passed");
    if !config.enabled {
        bail!("IKEv2 service is disabled");
    }
    let certificate = load_certificate(&config)?;
    ikev2_diag!(
        "certificate loading passed: chain_length={}",
        certificate
            .as_ref()
            .map_or(0, |material| material.chain.len())
    );
    let ike_socket = Arc::new(
        UdpSocket::bind(config.ike_bind)
            .await
            .with_context(|| format!("failed to bind IKEv2 socket {}", config.ike_bind))?,
    );
    let natt_socket = Arc::new(
        UdpSocket::bind(config.natt_bind)
            .await
            .with_context(|| format!("failed to bind IKEv2 NAT-T socket {}", config.natt_bind))?,
    );

    ikev2_diag!(
        "UDP sockets bound successfully: ike_local={}, natt_local={}",
        ike_socket.local_addr()?,
        natt_socket.local_addr()?
    );

    let eap_credentials = credential_map(control.ikev2_credentials().await?);
    ikev2_diag!("loaded {} EAP credential(s)", eap_credentials.len());
    let (command_tx, command_rx) = mpsc::channel(2048);
    let mut cookie_secret = [0u8; 32];
    rand::rng().fill_bytes(&mut cookie_secret);
    let handle = Ikev2Handle {
        command_tx: command_tx.clone(),
    };
    let engine = Engine {
        config,
        control,
        ike_socket,
        natt_socket,
        eap_credentials,
        certificate,
        half_open: HashMap::new(),
        eap_pending: HashMap::new(),
        established: HashMap::new(),
        esp_to_session: HashMap::new(),
        ike_to_session: HashMap::new(),
        fragments: HashMap::new(),
        command_tx,
        command_rx,
        entropy: SystemEntropy,
        cookie_secret,
        shutdown: false,
    };
    log::info!(
        "IKEv2 listening on {} and NAT-T {}",
        engine.config.ike_bind,
        engine.config.natt_bind
    );
    tokio::spawn(async move {
        ikev2_diag!("engine task spawned; entering UDP receive loop");
        if let Err(error) = engine.run().await {
            log::error!("[IKEV2-DIAG-TEMP] IKEv2 engine stopped unexpectedly: {error:#}");
        }
    });
    Ok(handle)
}

pub(crate) fn validate_runtime_config(config: &Ikev2Config) -> anyhow::Result<()> {
    ikev2_diag!(
        "runtime configuration validation requested: enabled={}, ike_bind={}, natt_bind={}, remote_id={}",
        config.enabled,
        config.ike_bind,
        config.natt_bind,
        config.remote_id
    );
    config.validate()?;
    let result = load_certificate(config).map(|_| ());
    ikev2_diag!(
        "runtime configuration validation completed: success={}",
        result.is_ok()
    );
    result
}

impl Engine {
    async fn run(mut self) -> anyhow::Result<()> {
        let mut ike_buffer = vec![0u8; 65_535];
        let mut natt_buffer = vec![0u8; 65_535];
        let mut cleanup = tokio::time::interval(Duration::from_secs(10));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ikev2_diag!(
            "receive loop active: ike_local={}, natt_local={}",
            self.ike_socket.local_addr()?,
            self.natt_socket.local_addr()?
        );
        loop {
            tokio::select! {
                result = self.ike_socket.recv_from(&mut ike_buffer) => {
                    let (length, peer) = result?;
                    ikev2_diag!(
                        "UDP/500 socket received datagram: peer={}, bytes={}, prefix={}",
                        peer,
                        length,
                        wire_prefix(&ike_buffer[..length])
                    );
                    let data = ike_buffer[..length].to_vec();
                    if let Err(error) = self.handle_ike(data, peer, false).await {
                        log::warn!("[IKEV2-DIAG-TEMP] UDP/500 IKE handling failed: peer={peer}, bytes={length}, error={error:#}");
                    }
                }
                result = self.natt_socket.recv_from(&mut natt_buffer) => {
                    let (length, peer) = result?;
                    ikev2_diag!(
                        "UDP/4500 socket received datagram: peer={}, bytes={}, prefix={}",
                        peer,
                        length,
                        wire_prefix(&natt_buffer[..length])
                    );
                    if length >= NON_ESP_MARKER.len() && natt_buffer[..4] == NON_ESP_MARKER {
                        ikev2_diag!("UDP/4500 datagram classified as NAT-T IKE: peer={peer}");
                        let data = natt_buffer[4..length].to_vec();
                        if let Err(error) = self.handle_ike(data, peer, true).await {
                            log::warn!("[IKEV2-DIAG-TEMP] NAT-T IKE handling failed: peer={peer}, bytes={length}, error={error:#}");
                        }
                    } else if length == 1 && natt_buffer[0] == 0xff {
                        // RFC 3948 NAT keepalive.
                        ikev2_diag!("UDP/4500 datagram classified as NAT keepalive: peer={peer}");
                    } else {
                        ikev2_diag!("UDP/4500 datagram classified as ESP: peer={peer}");
                        let data = natt_buffer[..length].to_vec();
                        if let Err(error) = self.handle_esp(data, peer).await {
                            log::warn!("[IKEV2-DIAG-TEMP] ESP handling failed: peer={peer}, bytes={length}, error={error:#}");
                        }
                    }
                }
                Some(command) = self.command_rx.recv() => {
                    ikev2_diag!("engine received internal command: kind={}", command_kind(&command));
                    if let Err(error) = self.handle_command(command).await {
                        log::warn!("[IKEV2-DIAG-TEMP] outbound/internal command failed: {error:#}");
                    }
                    if self.shutdown {
                        ikev2_diag!("receive loop exiting after shutdown command");
                        return Ok(());
                    }
                }
                _ = cleanup.tick() => {
                    ikev2_diag!(
                        "engine heartbeat: half_open={}, eap_pending={}, established={}, fragments={}, credentials={}",
                        self.half_open.len(),
                        self.eap_pending.len(),
                        self.established.len(),
                        self.fragments.len(),
                        self.eap_credentials.len()
                    );
                    self.cleanup();
                },
            }
        }
    }

    async fn handle_ike(
        &mut self,
        mut data: Vec<u8>,
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        let mut header = IkeHeader::parse(&data).map_err(anyhow::Error::msg)?;
        ikev2_diag!(
            "IKE header parsed: peer={}, transport={}, spi_i={:016x}, spi_r={:016x}, exchange={:?}, message_id={}, next_payload={:?}, flags=0x{:02x}, version={}.{}, declared_length={}, received_length={}",
            peer,
            transport_name(natt),
            header.initiator_spi,
            header.responder_spi,
            header.exchange_type,
            header.message_id,
            header.next_payload,
            header.flags.to_u8(),
            header.major_version,
            header.minor_version,
            header.length,
            data.len()
        );
        if header.next_payload == PayloadType::EncryptedFragment {
            ikev2_diag!(
                "encrypted fragment received: peer={peer}, message_id={}",
                header.message_id
            );
            let Some(reassembled) = self.collect_fragment(&data, header, peer)? else {
                return Ok(());
            };
            data = reassembled;
            header = IkeHeader::parse(&data).map_err(anyhow::Error::msg)?;
            ikev2_diag!(
                "fragment set reassembled: peer={peer}, message_id={}, bytes={}",
                header.message_id,
                data.len()
            );
        }
        match header.exchange_type {
            ExchangeType::IkeSaInit => self.handle_sa_init(data, peer, natt).await,
            ExchangeType::IkeAuth => self.handle_ike_auth(data, header, peer, natt).await,
            ExchangeType::Informational => {
                self.handle_informational(data, header, peer, natt).await
            }
            ExchangeType::CreateChildSa => self.handle_rekey(data, header, peer, natt).await,
            ExchangeType::Other(value) => {
                ikev2_diag!(
                    "unsupported exchange ignored: peer={peer}, exchange_type={value}, message_id={}",
                    header.message_id
                );
                Ok(())
            }
        }
    }

    fn collect_fragment(
        &mut self,
        data: &[u8],
        header: IkeHeader,
        peer: SocketAddr,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if data.len() < IkeHeader::LEN + 8 {
            bail!("truncated IKE fragment");
        }
        let fragment_number =
            u16::from_be_bytes([data[IkeHeader::LEN + 4], data[IkeHeader::LEN + 5]]);
        let total = u16::from_be_bytes([data[IkeHeader::LEN + 6], data[IkeHeader::LEN + 7]]);
        ikev2_diag!(
            "fragment decoded: peer={}, spi_i={:016x}, spi_r={:016x}, message_id={}, number={}/{}, bytes={}",
            peer,
            header.initiator_spi,
            header.responder_spi,
            header.message_id,
            fragment_number,
            total,
            data.len()
        );
        if fragment_number == 0 || total == 0 || fragment_number > total || total > 64 {
            bail!("invalid IKE fragment numbering");
        }
        let sa = self
            .half_open
            .get(&(header.initiator_spi, header.responder_spi))
            .map(|entry| entry.sa.clone())
            .or_else(|| {
                self.eap_pending
                    .get(&(header.initiator_spi, header.responder_spi))
                    .map(|entry| entry.sa.clone())
            })
            .or_else(|| {
                self.ike_to_session
                    .get(&(header.initiator_spi, header.responder_spi))
                    .and_then(|id| self.established.get(id))
                    .map(|entry| entry.sa.clone())
            })
            .context("unknown fragmented IKE SA")?;
        ikev2_diag!(
            "fragment SA lookup succeeded: peer={}, spi_i={:016x}, spi_r={:016x}",
            peer,
            header.initiator_spi,
            header.responder_spi
        );
        if self.fragments.len() >= MAX_HALF_OPEN {
            bail!("too many incomplete IKE fragment sets");
        }
        let key = (
            header.initiator_spi,
            header.responder_spi,
            header.message_id,
            header.exchange_type.to_u8(),
            peer,
        );
        let set = self.fragments.entry(key).or_insert_with(|| FragmentSet {
            messages: Vec::new(),
            total,
            updated: Instant::now(),
        });
        if set.total != total {
            bail!("inconsistent IKE fragment count");
        }
        if !set.messages.iter().any(|message| {
            message.get(IkeHeader::LEN + 4..IkeHeader::LEN + 6)
                == Some(fragment_number.to_be_bytes().as_slice())
        }) {
            set.messages.push(data.to_vec());
            ikev2_diag!(
                "fragment stored: peer={peer}, message_id={}, collected={}/{}",
                header.message_id,
                set.messages.len(),
                total
            );
        } else {
            ikev2_diag!(
                "duplicate fragment ignored: peer={peer}, message_id={}, number={fragment_number}",
                header.message_id
            );
        }
        set.updated = Instant::now();
        if set.messages.len() != total as usize {
            return Ok(None);
        }
        ikev2_diag!(
            "calling ryke fragment reassembly: peer={peer}, message_id={}, fragment_count={total}",
            header.message_id
        );
        let messages = self
            .fragments
            .remove(&key)
            .context("IKE fragment set disappeared")?
            .messages;
        let (first, inner) =
            ryke::ikev2::fragment::reassemble(&sa, &messages).map_err(anyhow::Error::msg)?;
        ikev2_diag!(
            "ryke fragment reassembly returned: peer={peer}, message_id={}, first_payload={first:?}, plaintext_bytes={}",
            header.message_id,
            inner.len()
        );
        let iv = random_iv(&sa, &mut self.entropy)?;
        ikev2_diag!(
            "rebuilding reassembled encrypted request: peer={peer}, message_id={}, iv_bytes={}",
            header.message_id,
            iv.len()
        );
        build_inbound_encrypted(&sa, header, first, &inner, &iv)
            .map(Some)
            .map_err(anyhow::Error::msg)
    }

    async fn handle_sa_init(
        &mut self,
        data: Vec<u8>,
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        let header = IkeHeader::parse(&data).map_err(anyhow::Error::msg)?;
        ikev2_diag!(
            "IKE_SA_INIT entered: peer={}, transport={}, spi_i={:016x}, message_id={}, bytes={}, half_open_count={}",
            peer,
            transport_name(natt),
            header.initiator_spi,
            header.message_id,
            data.len(),
            self.half_open.len()
        );
        if let Some(existing) = self
            .half_open
            .values()
            .find(|entry| entry.sa.spi_i == header.initiator_spi && entry.peer == peer)
        {
            ikev2_diag!(
                "IKE_SA_INIT retransmission matched cached response: peer={peer}, spi_i={:016x}, response_bytes={}",
                header.initiator_spi,
                existing.response.len()
            );
            return self.send_ike(&existing.response, peer, existing.natt).await;
        }
        let local = LocalSecret::generate(&mut self.entropy, NONCE_LEN);
        let local_ip = match self.config.ike_bind.ip() {
            IpAddr::V4(ip) if !ip.is_unspecified() => IpAddr::V4(ip),
            IpAddr::V6(ip) if !ip.is_unspecified() => IpAddr::V6(ip),
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        // The data plane is deliberately UDP-encapsulated ESP only. Hashing the
        // NAT-T port here makes every standards-compliant initiator float to
        // UDP/4500, including a client that happens to have a public address.
        let our_addr = SocketAddr::new(local_ip, self.config.natt_bind.port());
        let require_cookie = self.half_open.len() >= MAX_HALF_OPEN;
        let peer_cookie = peer.to_string();
        ikev2_diag!(
            "calling ryke responder_respond_natt: peer={}, our_addr={}, require_cookie={}, request_payloads={}",
            peer,
            our_addr,
            require_cookie,
            clear_payload_types(&data)
        );
        let result = responder_respond_natt(
            &data,
            &local,
            our_addr,
            peer,
            Some(CookiePolicy {
                secret: &self.cookie_secret,
                peer: peer_cookie.as_bytes(),
                required: require_cookie,
            }),
        )
        .map_err(anyhow::Error::msg)?;
        ikev2_diag!(
            "ryke responder_respond_natt returned successfully: peer={peer}, spi_i={:016x}",
            header.initiator_spi
        );
        match result {
            SaInitResult::Established { response, mut sa } => {
                ikev2_diag!(
                    "IKE_SA_INIT established by ryke: peer={}, spi_i={:016x}, spi_r={:016x}, suite={:?}, response_bytes={}",
                    peer,
                    sa.spi_i,
                    sa.spi_r,
                    sa.suite,
                    response.len()
                );
                let fragmentation_supported = peer_supports_fragmentation(&data)?;
                ikev2_diag!(
                    "peer fragmentation capability parsed: peer={peer}, supported={fragmentation_supported}"
                );
                let response = advertise_fragmentation(&response)?;
                ikev2_diag!(
                    "fragmentation capability added to response: peer={peer}, response_bytes={}",
                    response.len()
                );
                sa.resp_message = response.clone();
                let key = (sa.spi_i, sa.spi_r);
                self.send_ike(&response, peer, natt).await?;
                self.half_open.insert(
                    key,
                    HalfOpen {
                        sa,
                        peer,
                        response,
                        natt,
                        created: Instant::now(),
                        fragmentation_supported,
                    },
                );
                ikev2_diag!(
                    "half-open SA stored: peer={peer}, spi_i={:016x}, spi_r={:016x}, half_open_count={}",
                    key.0,
                    key.1,
                    self.half_open.len()
                );
            }
            SaInitResult::InvalidKe { response, group } => {
                ikev2_diag!(
                    "IKE_SA_INIT requires different DH group: peer={peer}, requested_group={group}, response_bytes={}",
                    response.len()
                );
                self.send_ike(&response, peer, natt).await?;
            }
            SaInitResult::CookieRequired { response } => {
                ikev2_diag!(
                    "IKE_SA_INIT cookie challenge generated: peer={peer}, response_bytes={}",
                    response.len()
                );
                self.send_ike(&response, peer, natt).await?;
            }
        }
        Ok(())
    }

    async fn handle_ike_auth(
        &mut self,
        data: Vec<u8>,
        header: IkeHeader,
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        let key = (header.initiator_spi, header.responder_spi);
        ikev2_diag!(
            "IKE_AUTH entered: peer={}, transport={}, spi_i={:016x}, spi_r={:016x}, message_id={}, bytes={}, half_open_present={}, eap_pending_present={}, established_mapping_present={}",
            peer,
            transport_name(natt),
            key.0,
            key.1,
            header.message_id,
            data.len(),
            self.half_open.contains_key(&key),
            self.eap_pending.contains_key(&key),
            self.ike_to_session.contains_key(&key)
        );
        if self.eap_pending.contains_key(&key) {
            ikev2_diag!(
                "IKE_AUTH routed to existing EAP exchange: peer={peer}, message_id={}",
                header.message_id
            );
            return self.handle_eap(data, key, peer, natt).await;
        }
        if let Some(session_id) = self.ike_to_session.get(&key).copied()
            && let Some(established) = self.established.get(&session_id)
            && let Some((message_id, response)) = &established.last_ike_response
            && *message_id == header.message_id
        {
            ikev2_diag!(
                "IKE_AUTH retransmission matched established response: peer={peer}, message_id={}, response_bytes={}",
                header.message_id,
                response.len()
            );
            return self.send_ike(response, peer, natt).await;
        }
        ikev2_diag!(
            "calling ryke is_eap_request: peer={peer}, message_id={}",
            header.message_id
        );
        let eap_request = {
            let half = self.half_open.get(&key).context("unknown IKE SA")?;
            is_eap_request(&half.sa, &data).map_err(anyhow::Error::msg)?
        };
        ikev2_diag!(
            "ryke is_eap_request returned: peer={peer}, message_id={}, is_eap={eap_request}",
            header.message_id
        );
        if eap_request {
            let half = self
                .half_open
                .remove(&key)
                .expect("half-open SA was checked above");
            ikev2_diag!(
                "half-open SA removed for IKE_AUTH processing: peer={peer}, remaining_half_open={}",
                self.half_open.len()
            );
            let restore = half.clone();
            let result = self.begin_eap(data, key, half, peer, natt).await;
            if result.is_err() {
                self.half_open.insert(key, restore);
                ikev2_diag!(
                    "half-open SA restored after first EAP response failure: peer={peer}, half_open_count={}",
                    self.half_open.len()
                );
            }
            return result;
        }
        bail!("IKEv2 only supports EAP-MSCHAPv2 username/password authentication")
    }

    async fn begin_eap(
        &mut self,
        data: Vec<u8>,
        key: (u64, u64),
        half: HalfOpen,
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        ikev2_diag!(
            "begin EAP: peer={}, transport={}, spi_i={:016x}, spi_r={:016x}, request_bytes={}, credentials={}, cert_chain_length={}, fragmentation_supported={}",
            peer,
            transport_name(natt),
            key.0,
            key.1,
            data.len(),
            self.eap_credentials.len(),
            self.certificate
                .as_ref()
                .map_or(0, |material| material.chain.len()),
            half.fragmentation_supported
        );
        let certificate = self
            .certificate
            .as_ref()
            .context("EAP authentication is not configured")?;
        let users = self
            .eap_credentials
            .iter()
            .map(|(user, (_, password))| (user.clone(), password.clone()))
            .collect();
        let child_spi = random_nonzero_u32(&mut self.entropy);
        let mut responder = EapResponder::new_multi(
            half.sa.clone(),
            responder_identity(&self.config.remote_id),
            ServerAuth::Cert {
                key: certificate.signing.signing_key()?,
                chain: certificate.chain.clone(),
            },
            users,
            child_spi,
        );
        ikev2_diag!(
            "EAP responder created: peer={peer}, local_child_spi=0x{child_spi:08x}; calling ryke EapResponder::handle"
        );
        let event = responder
            .handle(&data, &mut self.entropy)
            .map_err(anyhow::Error::msg)?;
        let EapEvent::Reply(response) = event else {
            bail!("invalid first EAP exchange");
        };
        ikev2_diag!(
            "first EAP handle returned reply: peer={peer}, response_bytes={}",
            response.len()
        );
        self.send_encrypted_response(
            &response,
            &half.sa,
            peer,
            natt,
            half.fragmentation_supported,
        )
        .await?;
        self.eap_pending.insert(
            key,
            EapPending {
                responder,
                sa: half.sa,
                peer,
                natt,
                child_spi,
                network_code: None,
                session: None,
                receiver: None,
                last_seen: Instant::now(),
                fragmentation_supported: half.fragmentation_supported,
            },
        );
        ikev2_diag!(
            "EAP pending state stored: peer={peer}, spi_i={:016x}, spi_r={:016x}, pending_count={}",
            key.0,
            key.1,
            self.eap_pending.len()
        );
        Ok(())
    }

    async fn handle_eap(
        &mut self,
        data: Vec<u8>,
        key: (u64, u64),
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        let message_id = IkeHeader::parse(&data)
            .map_err(anyhow::Error::msg)?
            .message_id;
        ikev2_diag!(
            "continuing EAP: peer={}, transport={}, spi_i={:016x}, spi_r={:016x}, message_id={}, bytes={}, pending_count={}",
            peer,
            transport_name(natt),
            key.0,
            key.1,
            message_id,
            data.len(),
            self.eap_pending.len()
        );
        let mut pending = self
            .eap_pending
            .remove(&key)
            .context("unknown EAP session")?;
        pending.peer = peer;
        pending.natt = natt;
        pending.last_seen = Instant::now();
        ikev2_diag!("calling ryke EapResponder::handle: peer={peer}, message_id={message_id}");
        let event = pending
            .responder
            .handle(&data, &mut self.entropy)
            .map_err(anyhow::Error::msg)?;
        ikev2_diag!(
            "ryke EapResponder::handle returned: peer={peer}, message_id={}, event={}",
            message_id,
            eap_event_name(&event)
        );

        if pending.session.is_none() && !pending.responder.user().is_empty() {
            let user = pending.responder.user().to_vec();
            let (network_code, _) = self
                .eap_credentials
                .get(&user)
                .cloned()
                .context("unknown EAP user")?;
            let identity = String::from_utf8(user).context("EAP username must be UTF-8")?;
            ikev2_diag!(
                "EAP identity resolved to configured device: peer={peer}, network={network_code}, identity={identity}"
            );
            log::info!(
                "IKEv2 client authentication started: network={}, identity={}, peer={}",
                network_code,
                identity,
                peer
            );
            let (session, receiver) = self.register_endpoint(&network_code, &identity).await?;
            ikev2_diag!(
                "IKEv2 endpoint registration returned: peer={peer}, network={network_code}, identity={identity}, assigned_ip={}",
                session.ip
            );
            pending.responder.set_assigned(Some(AssignedConfig {
                ip: session.ip,
                dns: self.config.dns.clone(),
            }));
            pending.network_code = Some(network_code);
            pending.session = Some(session);
            pending.receiver = Some(receiver);
        }

        match event {
            EapEvent::Reply(response) => {
                ikev2_diag!(
                    "sending intermediate EAP reply: peer={peer}, message_id={message_id}, response_bytes={}",
                    response.len()
                );
                self.send_encrypted_response(
                    &response,
                    &pending.sa,
                    peer,
                    natt,
                    pending.fragmentation_supported,
                )
                .await?;
                self.eap_pending.insert(key, pending);
                ikev2_diag!(
                    "EAP pending state restored after reply: peer={peer}, message_id={message_id}, pending_count={}",
                    self.eap_pending.len()
                );
            }
            EapEvent::Established(response) => {
                ikev2_diag!(
                    "EAP authentication established: peer={peer}, message_id={message_id}, has_final_response={}",
                    response.is_some()
                );
                let response = response.context("EAP responder omitted final response")?;
                let session = pending
                    .session
                    .take()
                    .context("EAP completed without an address")?;
                let receiver = pending.receiver.take().context("EAP receiver missing")?;
                let peer_spi = pending
                    .responder
                    .peer_child_spi()
                    .context("EAP peer CHILD_SA SPI missing")?;
                let child_proposal = pending
                    .responder
                    .selected_child_proposal_num()
                    .context("EAP selected CHILD_SA proposal missing")?;
                ikev2_diag!(
                    "EAP CHILD_SA parameters ready: peer={peer}, proposal={child_proposal}, local_spi=0x{:08x}, peer_spi=0x{peer_spi:08x}, assigned_ip={}",
                    pending.child_spi,
                    session.ip
                );
                let network =
                    Ipv4Net::new(session.ip, session.network_state.net_prefix_len())?.trunc();
                let response = narrow_tsr(&response, &pending.sa, network, &mut self.entropy)?;
                ikev2_diag!(
                    "final EAP response traffic selector narrowed: peer={peer}, network={network}, response_bytes={}",
                    response.len()
                );
                let child = ChildSa::derive(
                    &pending.sa.keys.sk_d,
                    &pending.sa.ni,
                    &pending.sa.nr,
                    Role::Responder,
                    pending.child_spi,
                    peer_spi,
                );
                self.send_encrypted_response(
                    &response,
                    &pending.sa,
                    peer,
                    natt,
                    pending.fragmentation_supported,
                )
                .await?;
                self.install_established(
                    key,
                    pending.sa,
                    child,
                    session,
                    receiver,
                    network,
                    peer,
                    natt,
                    Some((
                        IkeHeader::parse(&data)
                            .map_err(anyhow::Error::msg)?
                            .message_id,
                        response,
                    )),
                    pending.fragmentation_supported,
                );
            }
            EapEvent::Failed => {
                ikev2_diag!(
                    "EAP authentication failed event: peer={peer}, message_id={message_id}, identity_known={}",
                    pending.session.is_some()
                );
                if let Some(session) = &pending.session {
                    log::info!(
                        "IKEv2 client authentication failed: network={}, identity={}, peer={}",
                        session.network_code,
                        session.device_id,
                        peer
                    );
                } else {
                    log::info!("IKEv2 client authentication failed: peer={peer}");
                }
                bail!("EAP authentication failed")
            }
        }
        Ok(())
    }

    async fn register_endpoint(
        &self,
        network_code: &str,
        identity: &str,
    ) -> anyhow::Result<(Session, mpsc::Receiver<Bytes>)> {
        ikev2_diag!(
            "registering IKEv2 endpoint: network={network_code}, identity={identity}, identity_bytes={}",
            identity.len()
        );
        if identity.is_empty() || identity.len() > 48 {
            bail!("IKEv2 identity must contain 1..=48 UTF-8 bytes");
        }
        let (sender, receiver) = mpsc::channel(1024);
        let session = self
            .control
            .register_ikev2(
                network_code.to_string(),
                identity.to_string(),
                identity.to_string(),
                sender,
            )
            .await?;
        ikev2_diag!(
            "registered IKEv2 endpoint: network={network_code}, identity={identity}, ip={}",
            session.ip
        );
        Ok((session, receiver))
    }

    #[allow(clippy::too_many_arguments)]
    fn install_established(
        &mut self,
        ike_key: (u64, u64),
        sa: CompletedSaInit,
        child: ChildSa,
        session: Session,
        mut receiver: mpsc::Receiver<Bytes>,
        network: Ipv4Net,
        peer: SocketAddr,
        natt: bool,
        last_ike_response: Option<(u32, Vec<u8>)>,
        fragmentation_supported: bool,
    ) {
        let session_id = sa.spi_r;
        let inbound_spi = child.inbound.spi();
        ikev2_diag!(
            "installing established session: network={}, identity={}, ip={}, peer={}, transport={}, session_id={:016x}, inbound_esp_spi=0x{:08x}, fragmentation_supported={}",
            session.network_code,
            session.device_id,
            session.ip,
            peer,
            transport_name(natt),
            session_id,
            inbound_spi,
            fragmentation_supported
        );
        let duplicate = self.established.iter().find_map(|(id, established)| {
            (established.session.network_code == session.network_code
                && established.session.device_id == session.device_id)
                .then_some(*id)
        });
        if let Some(old_id) = duplicate {
            ikev2_diag!(
                "removing duplicate established session before install: old_session_id={old_id:016x}"
            );
            self.remove_established(old_id);
        }
        let command_tx = self.command_tx.clone();
        tokio::spawn(async move {
            while let Some(packet) = receiver.recv().await {
                if command_tx
                    .send(Command::ToIke { session_id, packet })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        self.esp_to_session.insert(inbound_spi, session_id);
        self.ike_to_session.insert(ike_key, session_id);
        log::info!(
            "IKEv2 client connected: network={}, identity={}, ip={}, peer={}",
            session.network_code,
            session.device_id,
            session.ip,
            peer
        );
        self.established.insert(
            session_id,
            Established {
                sa,
                child,
                session,
                network,
                peer,
                natt,
                replay: ReplayWindow::default(),
                last_seen: Instant::now(),
                last_ike_response,
                fragmentation_supported,
                outbound_message_id: 0,
            },
        );
        ikev2_diag!(
            "established session installed: session_id={session_id:016x}, established_count={}, esp_mapping_count={}",
            self.established.len(),
            self.esp_to_session.len()
        );
    }

    async fn handle_esp(&mut self, data: Vec<u8>, peer: SocketAddr) -> anyhow::Result<()> {
        ikev2_diag!("ESP processing entered: peer={peer}, bytes={}", data.len());
        if data.len() < 8 {
            bail!("ESP packet is too short");
        }
        let spi = u32::from_be_bytes(data[..4].try_into()?);
        let sequence = u32::from_be_bytes(data[4..8].try_into()?);
        ikev2_diag!("ESP header decoded: peer={peer}, spi=0x{spi:08x}, sequence={sequence}");
        let session_id = *self.esp_to_session.get(&spi).context("unknown ESP SPI")?;
        ikev2_diag!(
            "ESP SPI mapped to session: peer={peer}, spi=0x{spi:08x}, session_id={session_id:016x}"
        );
        let (network_code, source, destination, inner) = {
            let established = self
                .established
                .get_mut(&session_id)
                .context("unknown IKEv2 session")?;
            if !established.replay.permits(sequence) {
                bail!("ESP replay rejected");
            }
            ikev2_diag!(
                "calling ryke ESP inbound open: peer={peer}, spi=0x{spi:08x}, sequence={sequence}"
            );
            let (mut inner, next_header) = established
                .child
                .inbound
                .open(&data)
                .map_err(anyhow::Error::msg)?;
            ikev2_diag!(
                "ryke ESP inbound open returned: peer={peer}, spi=0x{spi:08x}, sequence={sequence}, next_header={next_header}, plaintext_bytes={}",
                inner.len()
            );
            if next_header != ryke::esp::next_header::IPV4 {
                bail!("only inner IPv4 is supported");
            }
            let (source, destination, total_length) =
                checked_ipv4(&inner).context("invalid inner IPv4 packet")?;
            ikev2_diag!(
                "inner IPv4 decoded: peer={peer}, source={source}, destination={destination}, total_length={total_length}"
            );
            if source != established.session.ip
                || !established.network.contains(&destination)
                || destination == established.network.network()
                || destination == established.network.broadcast()
            {
                bail!("inner IPv4 source or destination is outside the assigned network");
            }
            established.replay.record(sequence);
            established.peer = peer;
            established.natt = true;
            established.last_seen = Instant::now();
            inner.truncate(total_length);
            (
                established.session.network_code.clone(),
                source,
                destination,
                inner,
            )
        };
        let _ = self
            .control
            .forward_ikev2_packet(&network_code, source, destination, &inner)
            .await?;
        ikev2_diag!(
            "inner IPv4 forwarded: network={network_code}, source={source}, destination={destination}, bytes={}",
            inner.len()
        );
        Ok(())
    }

    async fn handle_command(&mut self, command: Command) -> anyhow::Result<()> {
        let (session_id, packet) = match command {
            Command::ToIke { session_id, packet } => (session_id, packet),
            Command::DisconnectDevice {
                network_code,
                device_id,
                response,
            } => {
                ikev2_diag!("disconnect command: network={network_code}, identity={device_id}");
                let session_id = self.established.iter().find_map(|(id, established)| {
                    (established.session.network_code == network_code
                        && established.session.device_id == device_id)
                        .then_some(*id)
                });
                let disconnected = if let Some(session_id) = session_id {
                    self.disconnect_established(session_id).await
                } else {
                    false
                };
                let _ = response.send(disconnected);
                ikev2_diag!(
                    "disconnect command completed: network={network_code}, identity={device_id}, disconnected={disconnected}"
                );
                return Ok(());
            }
            Command::ReloadConfig {
                config,
                certificate,
                changed_network,
                response,
            } => {
                ikev2_diag!(
                    "reload config command: changed_network={changed_network:?}, established_before={}",
                    self.established.len()
                );
                let session_ids = self
                    .established
                    .iter()
                    .filter_map(|(id, established)| {
                        changed_network
                            .as_ref()
                            .is_none_or(|network| established.session.network_code == *network)
                            .then_some(*id)
                    })
                    .collect::<Vec<_>>();
                for session_id in session_ids {
                    self.disconnect_established(session_id).await;
                }
                self.half_open.clear();
                self.eap_pending.clear();
                self.fragments.clear();
                self.config = *config;
                self.certificate = certificate;
                let _ = response.send(Ok(()));
                ikev2_diag!(
                    "reload config command completed: half_open=0, eap_pending=0, fragments=0"
                );
                return Ok(());
            }
            Command::ReloadCredentials {
                credentials,
                response,
            } => {
                ikev2_diag!(
                    "reload credentials command: credential_count={}",
                    credentials.len()
                );
                self.eap_credentials = credential_map(credentials);
                self.half_open.clear();
                self.eap_pending.clear();
                self.fragments.clear();
                let _ = response.send(());
                ikev2_diag!("reload credentials command completed");
                return Ok(());
            }
            Command::Shutdown { response } => {
                ikev2_diag!(
                    "shutdown command: established_before={}",
                    self.established.len()
                );
                let session_ids = self.established.keys().copied().collect::<Vec<_>>();
                for session_id in session_ids {
                    self.disconnect_established(session_id).await;
                }
                self.shutdown = true;
                let _ = response.send(());
                return Ok(());
            }
        };
        let packet = NetPacket::new(packet)?;
        if packet.msg_type()? != MsgType::Ikev2Relay {
            ikev2_diag!(
                "internal packet ignored because message type is not Ikev2Relay: session_id={session_id:016x}"
            );
            return Ok(());
        }
        ikev2_diag!(
            "processing outbound relay packet: session_id={session_id:016x}, payload_bytes={}",
            packet.payload().len()
        );
        let (peer, natt, esp) = {
            let established = self
                .established
                .get_mut(&session_id)
                .context("IKEv2 session is no longer active")?;
            let source = Ipv4Addr::from(packet.src_id());
            let destination = Ipv4Addr::from(packet.dest_id());
            let (inner_source, inner_destination, total_length) =
                checked_ipv4(packet.payload()).context("invalid relay IPv4 packet")?;
            if destination != established.session.ip
                || inner_source != source
                || inner_destination != destination
            {
                bail!("relay packet address mismatch");
            }
            let esp = established
                .child
                .outbound
                .seal(
                    &packet.payload()[..total_length],
                    ryke::esp::next_header::IPV4,
                )
                .map_err(anyhow::Error::msg)?;
            ikev2_diag!(
                "outbound ESP sealed: session_id={session_id:016x}, source={source}, destination={destination}, esp_bytes={}",
                esp.len()
            );
            (established.peer, established.natt, esp)
        };
        if !natt {
            bail!("raw IP ESP is not supported; client must use NAT-T");
        }
        self.natt_socket.send_to(&esp, peer).await?;
        ikev2_diag!(
            "outbound ESP sent: session_id={session_id:016x}, peer={peer}, bytes={}",
            esp.len()
        );
        Ok(())
    }

    async fn disconnect_established(&mut self, session_id: u64) -> bool {
        ikev2_diag!("disconnecting established session: session_id={session_id:016x}");
        let deletion = self
            .established
            .get_mut(&session_id)
            .and_then(|established| {
                let iv = random_iv(&established.sa, &mut self.entropy).ok()?;
                let payload = ryke::ikev2::payload::Delete::ike_sa().to_bytes();
                let packet = build_informational(
                    &established.sa,
                    established.outbound_message_id,
                    false,
                    &[(PayloadType::Delete, payload)],
                    &iv,
                )
                .ok()?;
                established.outbound_message_id = established.outbound_message_id.wrapping_add(1);
                Some((packet, established.peer, established.natt))
            });
        if let Some((packet, peer, natt)) = deletion {
            ikev2_diag!(
                "sending IKE delete notification: session_id={session_id:016x}, peer={peer}, bytes={}",
                packet.len()
            );
            let _ = self.send_ike(&packet, peer, natt).await;
        } else {
            ikev2_diag!(
                "IKE delete notification could not be built or session was absent: session_id={session_id:016x}"
            );
        }
        let existed = self.established.contains_key(&session_id);
        self.remove_established(session_id);
        ikev2_diag!(
            "disconnect established completed: session_id={session_id:016x}, existed={existed}"
        );
        existed
    }

    async fn handle_informational(
        &mut self,
        data: Vec<u8>,
        header: IkeHeader,
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        let key = (header.initiator_spi, header.responder_spi);
        ikev2_diag!(
            "INFORMATIONAL entered: peer={}, transport={}, spi_i={:016x}, spi_r={:016x}, message_id={}, bytes={}",
            peer,
            transport_name(natt),
            key.0,
            key.1,
            header.message_id,
            data.len()
        );
        let session_id = *self.ike_to_session.get(&key).context("unknown IKE SA")?;
        ikev2_diag!(
            "INFORMATIONAL mapped to session: peer={peer}, session_id={session_id:016x}; calling ryke open_informational"
        );
        let (response, delete) = {
            let established = self
                .established
                .get_mut(&session_id)
                .context("unknown session")?;
            let payloads =
                open_informational(&established.sa, &data).map_err(anyhow::Error::msg)?;
            ikev2_diag!(
                "ryke open_informational returned: peer={peer}, session_id={session_id:016x}, payload_count={}",
                payloads.len()
            );
            let delete = payloads
                .iter()
                .any(|(kind, _)| *kind == PayloadType::Delete);
            established.peer = peer;
            established.natt = natt;
            established.last_seen = Instant::now();
            let iv = random_iv(&established.sa, &mut self.entropy)?;
            let response = build_informational(&established.sa, header.message_id, true, &[], &iv)
                .map_err(anyhow::Error::msg)?;
            (response, delete)
        };
        self.send_ike(&response, peer, natt).await?;
        ikev2_diag!(
            "INFORMATIONAL response sent: peer={peer}, session_id={session_id:016x}, delete={delete}, bytes={}",
            response.len()
        );
        if delete {
            ikev2_diag!("peer requested SA deletion: peer={peer}, session_id={session_id:016x}");
            self.remove_established(session_id);
        }
        Ok(())
    }

    async fn handle_rekey(
        &mut self,
        data: Vec<u8>,
        header: IkeHeader,
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        let key = (header.initiator_spi, header.responder_spi);
        ikev2_diag!(
            "CREATE_CHILD_SA entered: peer={}, transport={}, spi_i={:016x}, spi_r={:016x}, message_id={}, bytes={}",
            peer,
            transport_name(natt),
            key.0,
            key.1,
            header.message_id,
            data.len()
        );
        let session_id = *self.ike_to_session.get(&key).context("unknown IKE SA")?;
        let old_sa = self
            .established
            .get(&session_id)
            .context("unknown session")?
            .sa
            .clone();
        ikev2_diag!(
            "calling ryke open_encrypted for CREATE_CHILD_SA: peer={peer}, session_id={session_id:016x}"
        );
        let (first, inner) = open_encrypted(&old_sa, &data).map_err(anyhow::Error::msg)?;
        ikev2_diag!(
            "ryke open_encrypted returned: peer={peer}, session_id={session_id:016x}, first_payload={first:?}, plaintext_bytes={}",
            inner.len()
        );
        let inner_payloads = payloads(first, &inner)
            .map(|payload| {
                let payload = payload.map_err(anyhow::Error::msg)?;
                Ok((payload.payload_type, payload.data.to_vec()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        ikev2_diag!(
            "CREATE_CHILD_SA inner payloads decoded: peer={peer}, session_id={session_id:016x}, payload_types={}",
            payload_type_list(&inner_payloads)
        );
        if is_ike_sa_rekey(&inner_payloads) {
            ikev2_diag!(
                "CREATE_CHILD_SA classified as IKE SA rekey: peer={peer}, session_id={session_id:016x}"
            );
            let new_spi_r = self.entropy.next_u64().max(1);
            let mut private = [0u8; 32];
            self.entropy.fill(&mut private);
            let mut nonce = vec![0u8; NONCE_LEN];
            self.entropy.fill(&mut nonce);
            let iv = random_iv(&old_sa, &mut self.entropy)?;
            let (response, new_sa) =
                responder_process_ike_rekey(&old_sa, &data, new_spi_r, &private, &nonce, &iv)
                    .map_err(anyhow::Error::msg)?;
            ikev2_diag!(
                "ryke IKE SA rekey returned: peer={peer}, session_id={session_id:016x}, new_spi_i={:016x}, new_spi_r={:016x}, response_bytes={}",
                new_sa.spi_i,
                new_sa.spi_r,
                response.len()
            );
            let fragmentation_supported = self
                .established
                .get(&session_id)
                .is_some_and(|session| session.fragmentation_supported);
            self.send_encrypted_response(&response, &old_sa, peer, natt, fragmentation_supported)
                .await?;
            self.ike_to_session.remove(&key);
            self.ike_to_session
                .insert((new_sa.spi_i, new_sa.spi_r), session_id);
            if let Some(established) = self.established.get_mut(&session_id) {
                established.sa = new_sa;
                established.peer = peer;
                established.natt = natt;
                established.last_seen = Instant::now();
            }
            ikev2_diag!("IKE SA rekey installed: peer={peer}, session_id={session_id:016x}");
            return Ok(());
        }
        ikev2_diag!(
            "CREATE_CHILD_SA classified as CHILD SA rekey: peer={peer}, session_id={session_id:016x}"
        );
        let (response, old_spi, new_spi) = {
            let established = self
                .established
                .get_mut(&session_id)
                .context("unknown session")?;
            let new_spi = random_nonzero_u32(&mut self.entropy);
            let mut nonce = vec![0u8; NONCE_LEN];
            self.entropy.fill(&mut nonce);
            let iv = random_iv(&established.sa, &mut self.entropy)?;
            let (response, child) = responder_process_rekey(
                &established.sa,
                &data,
                new_spi,
                &nonce,
                &iv,
                Some(established.session.ip),
            )
            .map_err(anyhow::Error::msg)?;
            ikev2_diag!(
                "ryke CHILD SA rekey returned: peer={peer}, session_id={session_id:016x}, old_spi=0x{:08x}, new_spi=0x{new_spi:08x}, response_bytes={}",
                established.child.inbound.spi(),
                response.len()
            );
            let response = narrow_tsr(
                &response,
                &established.sa,
                established.network,
                &mut self.entropy,
            )?;
            let old_spi = established.child.inbound.spi();
            established.child = child;
            established.replay = ReplayWindow::default();
            established.peer = peer;
            established.natt = natt;
            established.last_seen = Instant::now();
            (response, old_spi, new_spi)
        };
        self.esp_to_session.remove(&old_spi);
        self.esp_to_session.insert(new_spi, session_id);
        let established = self
            .established
            .get(&session_id)
            .context("unknown session")?;
        self.send_encrypted_response(
            &response,
            &established.sa,
            peer,
            natt,
            established.fragmentation_supported,
        )
        .await?;
        ikev2_diag!(
            "CHILD SA rekey response sent and mapping installed: peer={peer}, session_id={session_id:016x}, old_spi=0x{old_spi:08x}, new_spi=0x{new_spi:08x}"
        );
        Ok(())
    }

    async fn send_encrypted_response(
        &self,
        response: &[u8],
        sa: &CompletedSaInit,
        peer: SocketAddr,
        natt: bool,
        fragmentation_supported: bool,
    ) -> anyhow::Result<()> {
        ikev2_diag!(
            "preparing encrypted IKE response: peer={}, transport={}, bytes={}, fragmentation_supported={}",
            peer,
            transport_name(natt),
            response.len(),
            fragmentation_supported
        );
        if !fragmentation_supported || response.len() <= IKE_FRAGMENT_CONTENT + 128 {
            ikev2_diag!(
                "encrypted IKE response does not require fragmentation: peer={peer}, bytes={}",
                response.len()
            );
            return self.send_ike(response, peer, natt).await;
        }
        let header = IkeHeader::parse(response).map_err(anyhow::Error::msg)?;
        let (first, inner) = open_outbound_encrypted(sa, response)?;
        let mut entropy = SystemEntropy;
        let fragments = ryke::ikev2::fragment::build_fragments(
            sa,
            &header,
            first,
            &inner,
            &mut entropy,
            IKE_FRAGMENT_CONTENT,
        )
        .map_err(anyhow::Error::msg)?;
        ikev2_diag!(
            "ryke built outbound IKE fragments: peer={peer}, original_bytes={}, fragment_count={}",
            response.len(),
            fragments.len()
        );
        for (index, fragment) in fragments.into_iter().enumerate() {
            ikev2_diag!(
                "sending outbound IKE fragment: peer={peer}, index={}, bytes={}",
                index + 1,
                fragment.len()
            );
            self.send_ike(&fragment, peer, natt).await?;
        }
        Ok(())
    }

    async fn send_ike(&self, data: &[u8], peer: SocketAddr, natt: bool) -> anyhow::Result<()> {
        let summary = ike_header_summary(data);
        ikev2_diag!(
            "sending IKE datagram: peer={}, transport={}, ike_bytes={}, header={summary}",
            peer,
            transport_name(natt),
            data.len()
        );
        if natt {
            let mut framed = Vec::with_capacity(4 + data.len());
            framed.extend_from_slice(&NON_ESP_MARKER);
            framed.extend_from_slice(data);
            let sent = self.natt_socket.send_to(&framed, peer).await?;
            ikev2_diag!(
                "IKE datagram send completed: peer={peer}, transport=NAT-T/UDP4500, wire_bytes={sent}"
            );
        } else {
            let sent = self.ike_socket.send_to(data, peer).await?;
            ikev2_diag!(
                "IKE datagram send completed: peer={peer}, transport=IKE/UDP500, wire_bytes={sent}"
            );
        }
        Ok(())
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let half_open_before = self.half_open.len();
        let eap_pending_before = self.eap_pending.len();
        let fragments_before = self.fragments.len();
        self.half_open
            .retain(|_, value| now.duration_since(value.created) < HALF_OPEN_TIMEOUT);
        self.eap_pending
            .retain(|_, value| now.duration_since(value.last_seen) < HALF_OPEN_TIMEOUT);
        self.fragments
            .retain(|_, value| now.duration_since(value.updated) < HALF_OPEN_TIMEOUT);
        let expired = self
            .established
            .iter()
            .filter_map(|(id, value)| {
                (now.duration_since(value.last_seen) >= SESSION_IDLE_TIMEOUT).then_some(*id)
            })
            .collect::<Vec<_>>();
        ikev2_diag!(
            "cleanup scan completed: expired_half_open={}, expired_eap_pending={}, expired_fragment_sets={}, expired_established={}",
            half_open_before.saturating_sub(self.half_open.len()),
            eap_pending_before.saturating_sub(self.eap_pending.len()),
            fragments_before.saturating_sub(self.fragments.len()),
            expired.len()
        );
        for id in expired {
            ikev2_diag!("removing idle established session: session_id={id:016x}");
            self.remove_established(id);
        }
    }

    fn remove_established(&mut self, session_id: u64) {
        ikev2_diag!("removing established session state: session_id={session_id:016x}");
        if let Some(established) = self.established.remove(&session_id) {
            self.esp_to_session.remove(&established.child.inbound.spi());
            self.ike_to_session.retain(|_, id| *id != session_id);
            log::info!(
                "IKEv2 client disconnected: network={}, identity={}, ip={}, peer={}",
                established.session.network_code,
                established.session.device_id,
                established.session.ip,
                established.peer
            );
            ikev2_diag!(
                "established session state removed: session_id={session_id:016x}, remaining_established={}",
                self.established.len()
            );
        } else {
            ikev2_diag!(
                "established session state was already absent: session_id={session_id:016x}"
            );
        }
    }
}

// IKEV2_DIAG_TEMP helpers. Remove together with the temporary diagnostics above.
fn transport_name(natt: bool) -> &'static str {
    if natt { "NAT-T/UDP4500" } else { "IKE/UDP500" }
}

fn command_kind(command: &Command) -> &'static str {
    match command {
        Command::ToIke { .. } => "ToIke",
        Command::DisconnectDevice { .. } => "DisconnectDevice",
        Command::ReloadConfig { .. } => "ReloadConfig",
        Command::ReloadCredentials { .. } => "ReloadCredentials",
        Command::Shutdown { .. } => "Shutdown",
    }
}

fn eap_event_name(event: &EapEvent) -> &'static str {
    match event {
        EapEvent::Reply(_) => "Reply",
        EapEvent::Established(_) => "Established",
        EapEvent::Failed => "Failed",
    }
}

fn wire_prefix(data: &[u8]) -> String {
    data.iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn ike_header_summary(data: &[u8]) -> String {
    match IkeHeader::parse(data) {
        Ok(header) => format!(
            "spi_i={:016x},spi_r={:016x},exchange={:?},message_id={},next_payload={:?},flags=0x{:02x},length={}",
            header.initiator_spi,
            header.responder_spi,
            header.exchange_type,
            header.message_id,
            header.next_payload,
            header.flags.to_u8(),
            header.length
        ),
        Err(error) => format!("unparseable:{error}"),
    }
}

fn clear_payload_types(message: &[u8]) -> String {
    let Ok(header) = IkeHeader::parse(message) else {
        return "unparseable-header".to_string();
    };
    payloads(header.next_payload, &message[IkeHeader::LEN..])
        .map(|payload| match payload {
            Ok(payload) => format!("{:?}", payload.payload_type),
            Err(error) => format!("error:{error}"),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn payload_type_list(payloads: &[(PayloadType, Vec<u8>)]) -> String {
    payloads
        .iter()
        .map(|(payload_type, _)| format!("{payload_type:?}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn responder_identity(remote_id: &str) -> Identification {
    match remote_id.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => Identification {
            id_type: ryke::ikev2::payload::id_type::IPV4_ADDR,
            data: address.octets().to_vec(),
        },
        Ok(IpAddr::V6(address)) => Identification {
            id_type: ryke::ikev2::payload::id_type::IPV6_ADDR,
            data: address.octets().to_vec(),
        },
        Err(_) => Identification::fqdn(remote_id),
    }
}

fn checked_ipv4(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, usize)> {
    let ipv4 = Ipv4Packet::new(packet)?;
    let header_length = usize::from(ipv4.get_header_length()) * 4;
    let total_length = usize::from(ipv4.get_total_length());
    if ipv4.get_version() != 4
        || header_length < Ipv4Packet::minimum_packet_size()
        || total_length < header_length
        || total_length > packet.len()
    {
        return None;
    }
    Some((ipv4.get_source(), ipv4.get_destination(), total_length))
}

fn credential_map(credentials: HashMap<String, (String, String)>) -> EapCredentialMap {
    let mut eap_credentials = HashMap::new();
    for (username, credential) in credentials {
        eap_credentials.insert(username.into_bytes(), credential);
    }
    eap_credentials
}

fn random_nonzero_u32(entropy: &mut impl Entropy) -> u32 {
    loop {
        let value = entropy.next_u64() as u32;
        if value != 0 {
            return value;
        }
    }
}

fn random_iv(sa: &CompletedSaInit, entropy: &mut impl Entropy) -> anyhow::Result<Vec<u8>> {
    let mut iv = vec![0u8; sa.suite.sk_iv_len().map_err(anyhow::Error::msg)?];
    entropy.fill(&mut iv);
    Ok(iv)
}

fn opposite_role_view(sa: &CompletedSaInit) -> CompletedSaInit {
    let mut opposite = sa.clone();
    opposite.role = match sa.role {
        Role::Initiator => Role::Responder,
        Role::Responder => Role::Initiator,
    };
    opposite
}

fn open_outbound_encrypted(
    sa: &CompletedSaInit,
    message: &[u8],
) -> anyhow::Result<(PayloadType, Vec<u8>)> {
    open_encrypted(&opposite_role_view(sa), message).map_err(anyhow::Error::msg)
}

fn build_inbound_encrypted(
    sa: &CompletedSaInit,
    header: IkeHeader,
    first_inner: PayloadType,
    inner: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, ryke::IkeError> {
    build_encrypted(&opposite_role_view(sa), header, first_inner, inner, iv)
}

fn encode_payload_chain(payloads: &[(PayloadType, Vec<u8>)]) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for (index, (_, body)) in payloads.iter().enumerate() {
        let length = 4usize
            .checked_add(body.len())
            .context("IKE payload too large")?;
        let length = u16::try_from(length).context("IKE payload too large")?;
        let next = payloads
            .get(index + 1)
            .map(|(kind, _)| *kind)
            .unwrap_or(PayloadType::NoNext);
        bytes.push(next.to_u8());
        bytes.push(0);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(body);
    }
    Ok(bytes)
}

fn peer_supports_fragmentation(message: &[u8]) -> anyhow::Result<bool> {
    let header = IkeHeader::parse(message).map_err(anyhow::Error::msg)?;
    for payload in payloads(header.next_payload, &message[IkeHeader::LEN..]) {
        let payload = payload.map_err(anyhow::Error::msg)?;
        if payload.payload_type == PayloadType::Notify
            && Notify::parse(payload.data)
                .map(|notify| {
                    notify.notify_type
                        == ryke::ikev2::payload::notify_type::IKEV2_FRAGMENTATION_SUPPORTED
                })
                .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn advertise_fragmentation(message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let header = IkeHeader::parse(message).map_err(anyhow::Error::msg)?;
    let mut builder = MessageBuilder::new(header);
    for payload in payloads(header.next_payload, &message[IkeHeader::LEN..]) {
        let payload = payload.map_err(anyhow::Error::msg)?;
        builder = builder.push(payload.payload_type, payload.data.to_vec());
    }
    let notify = Notify::status(
        ryke::ikev2::payload::notify_type::IKEV2_FRAGMENTATION_SUPPORTED,
        Vec::new(),
    );
    Ok(builder.push(PayloadType::Notify, notify.to_bytes()).build())
}

fn narrow_tsr(
    response: &[u8],
    sa: &CompletedSaInit,
    network: Ipv4Net,
    entropy: &mut impl Entropy,
) -> anyhow::Result<Vec<u8>> {
    let header = IkeHeader::parse(response).map_err(anyhow::Error::msg)?;
    let (first, inner) = open_outbound_encrypted(sa, response)?;
    let selector = TrafficSelectors {
        selectors: vec![TrafficSelector {
            ts_type: 7,
            ip_protocol: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_addr: network.network().octets().to_vec(),
            end_addr: network.broadcast().octets().to_vec(),
        }],
    }
    .to_bytes();
    let mut decoded = Vec::new();
    for payload in payloads(first, &inner) {
        let payload = payload.map_err(anyhow::Error::msg)?;
        decoded.push((
            payload.payload_type,
            if payload.payload_type == PayloadType::TrafficSelectorResponder {
                selector.clone()
            } else {
                payload.data.to_vec()
            },
        ));
    }
    let first = decoded
        .first()
        .map(|(kind, _)| *kind)
        .unwrap_or(PayloadType::NoNext);
    let inner = encode_payload_chain(&decoded)?;
    let iv = random_iv(sa, entropy)?;
    build_encrypted(sa, header, first, &inner, &iv).map_err(anyhow::Error::msg)
}

fn load_certificate(config: &Ikev2Config) -> anyhow::Result<Option<CertificateMaterial>> {
    let Some(cert_path) = config.cert.as_ref() else {
        ikev2_diag!("certificate loading skipped because cert path is not configured");
        return Ok(None);
    };
    ikev2_diag!(
        "loading certificate material: cert_path={}, remote_id={}",
        cert_path.display(),
        config.remote_id
    );
    let key_path = config
        .key
        .as_ref()
        .context("ikev2.key is required for EAP")?;
    let cert_bytes = std::fs::read(cert_path)
        .with_context(|| format!("failed to read IKEv2 certificate {}", cert_path.display()))?;
    ikev2_diag!(
        "certificate file read: cert_path={}, bytes={}",
        cert_path.display(),
        cert_bytes.len()
    );
    let chain = rustls_pemfile::certs(&mut Cursor::new(cert_bytes))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect::<Vec<_>>();
    ikev2_diag!(
        "certificate PEM decoded: cert_path={}, chain_length={}",
        cert_path.display(),
        chain.len()
    );
    let leaf = chain.first().context("IKEv2 certificate chain is empty")?;
    if !crate::utils::ikev2_cert::certificate_matches_remote_id(leaf, &config.remote_id)? {
        bail!("IKEv2 certificate SAN does not match remote_id");
    }
    ikev2_diag!(
        "certificate SAN matches remote_id: remote_id={}",
        config.remote_id
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (not_before, not_after) =
        ryke::ikev2::sign::cert_validity(leaf).map_err(anyhow::Error::msg)?;
    if now < not_before || now > not_after {
        bail!("IKEv2 certificate is not currently valid");
    }
    ikev2_diag!(
        "certificate validity check passed: not_before={not_before}, not_after={not_after}, now={now}"
    );

    ikev2_diag!(
        "loading private key metadata: key_path={}",
        key_path.display()
    );
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("failed to read IKEv2 private key {}", key_path.display()))?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key_bytes))?
        .context("IKEv2 private key PEM contains no supported key")?;
    let der = key.secret_der().to_vec();
    let signing = if SigningKey::ecdsa_p256_from_pkcs8_der(&der).is_ok() {
        ikev2_diag!("private key decoded as ECDSA P-256 PKCS#8");
        SigningMaterial::EcdsaP256(der)
    } else if rsa::RsaPrivateKey::from_pkcs8_der(&der).is_ok() {
        ikev2_diag!("private key decoded as RSA PKCS#8");
        SigningMaterial::Rsa(der)
    } else {
        bail!("IKEv2 private key must be RSA or ECDSA P-256 PKCS#8 PEM");
    };
    let signing_key = signing.signing_key()?;
    let probe = b"vnts-ikev2-certificate-key-check";
    let signature = signing_key
        .sign_auth_data(probe)
        .map_err(anyhow::Error::msg)?;
    ryke::VerifyingKey::from_cert_der(leaf)
        .and_then(|key| key.verify_auth_data(&signature, probe))
        .map_err(|_| anyhow::anyhow!("IKEv2 private key does not match the leaf certificate"))?;
    ikev2_diag!("certificate/private-key match check passed");
    Ok(Some(CertificateMaterial { signing, chain }))
}

#[cfg(test)]
mod tests {
    use super::{ReplayWindow, SystemEntropy, encode_payload_chain, start};
    use crate::server::control_server::db::{ClientType, DeviceIpType};
    use crate::server::control_server::service::ControlService;
    use crate::utils::config::Ikev2Config;
    use ipnet::Ipv4Net;
    use ryke::{
        Configuration, ExchangeType, Flags, Identification, IkeHeader, LocalSecret, PayloadType,
        Proposal, SecurityAssociation, TrafficSelector, TrafficSelectors, Transform,
        build_encrypted, initiator_complete, initiator_request, open_encrypted, payloads,
    };
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn replay_window_accepts_new_and_out_of_order_once() {
        let mut window = ReplayWindow::default();
        assert!(window.permits(10));
        window.record(10);
        assert!(!window.permits(10));
        assert!(window.permits(8));
        window.record(8);
        assert!(!window.permits(8));
        assert!(!window.permits(0));
    }

    fn unused_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn cbc_offer() -> SecurityAssociation {
        use ryke::ikev2::payload::{protocol_id, transform_id, transform_type};

        SecurityAssociation {
            proposals: vec![Proposal {
                num: 1,
                protocol_id: protocol_id::IKE,
                spi: Vec::new(),
                transforms: vec![
                    Transform {
                        transform_type: transform_type::ENCR,
                        transform_id: transform_id::AES_CBC,
                        key_length: Some(256),
                    },
                    Transform {
                        transform_type: transform_type::INTEG,
                        transform_id: transform_id::AUTH_HMAC_SHA2_256_128,
                        key_length: None,
                    },
                    Transform {
                        transform_type: transform_type::PRF,
                        transform_id: transform_id::PRF_HMAC_SHA2_256,
                        key_length: None,
                    },
                    Transform {
                        transform_type: transform_type::DH,
                        transform_id: transform_id::X25519,
                        key_length: None,
                    },
                ],
            }],
        }
    }

    #[tokio::test]
    async fn eap_mschapv2_handshake_over_cbc_uses_the_configured_certificate_and_user() {
        let ike_port = unused_udp_port();
        let mut natt_port = unused_udp_port();
        while natt_port == ike_port {
            natt_port = unused_udp_port();
        }
        let generated =
            rcgen::generate_simple_self_signed(vec!["vpn.example.com".to_string()]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("ike.pem");
        let key_path = directory.path().join("ike.key");
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
        let cert_der = generated.cert.der().as_ref().to_vec();
        let config = Ikev2Config {
            enabled: true,
            ike_bind: SocketAddr::from(([127, 0, 0, 1], ike_port)),
            natt_bind: SocketAddr::from(([127, 0, 0, 1], natt_port)),
            server_address: "127.0.0.1".to_string(),
            remote_id: "vpn.example.com".to_string(),
            cert: Some(cert_path),
            key: Some(key_path),
            dns: Vec::new(),
        };
        let control = ControlService::new(
            "10.78.0.0/24".parse::<Ipv4Net>().unwrap(),
            HashMap::from([("eap-test".to_string(), "10.78.0.0/24".parse().unwrap())]),
            Default::default(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        control
            .add_device_typed(
                "eap-test",
                "alice",
                "10.78.0.8".parse().unwrap(),
                DeviceIpType::Fixed,
                ClientType::Ikev2,
                Some("password".to_string()),
            )
            .await
            .unwrap();
        let _handle = start(config, control.clone()).await.unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut entropy = SystemEntropy;
        let local = LocalSecret::generate(&mut entropy, 32);
        let request = initiator_request(&local, &cbc_offer());
        socket
            .send_to(&request, SocketAddr::from(([127, 0, 0, 1], ike_port)))
            .await
            .unwrap();
        let mut buffer = vec![0u8; 8192];
        let (length, _) = socket.recv_from(&mut buffer).await.unwrap();
        let sa = initiator_complete(&local, &request, &buffer[..length]).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let protection_sa = sa.clone();
        let mut client = ryke::EapInitiator::new(
            sa,
            Identification::fqdn("alice"),
            b"alice".to_vec(),
            "password".to_string(),
            0x3344_5566,
            ryke::ServerVerify::TrustedCas {
                cas: vec![cert_der],
                expected_dns: "vpn.example.com".to_string(),
                now_unix: now,
            },
        );
        // Android's platform VPN uses an empty outer EAP identity by default;
        // the configured account name appears later in the MSCHAPv2 Response.
        client.set_eap_identity(Vec::new());
        // Android sends conventional encryption as proposal 1 and AEAD as
        // proposal 2. The responder must return GCM with proposal number 2.
        let child_offer = SecurityAssociation {
            proposals: vec![
                Proposal {
                    num: 1,
                    protocol_id: ryke::ikev2::payload::protocol_id::ESP,
                    spi: 0x3344_5566u32.to_be_bytes().to_vec(),
                    transforms: vec![
                        Transform {
                            transform_type: ryke::ikev2::payload::transform_type::ENCR,
                            transform_id: ryke::ikev2::payload::transform_id::AES_CBC,
                            key_length: Some(256),
                        },
                        Transform {
                            transform_type: ryke::ikev2::payload::transform_type::INTEG,
                            transform_id:
                                ryke::ikev2::payload::transform_id::AUTH_HMAC_SHA2_256_128,
                            key_length: None,
                        },
                    ],
                },
                Proposal {
                    num: 2,
                    protocol_id: ryke::ikev2::payload::protocol_id::ESP,
                    spi: 0x3344_5566u32.to_be_bytes().to_vec(),
                    transforms: vec![Transform {
                        transform_type: ryke::ikev2::payload::transform_type::ENCR,
                        transform_id: ryke::ikev2::payload::transform_id::AES_GCM_16,
                        key_length: Some(256),
                    }],
                },
            ],
        };
        let any = TrafficSelectors {
            selectors: vec![TrafficSelector::ipv4_any()],
        }
        .to_bytes();
        let initial_payloads = vec![
            (
                PayloadType::IdInitiator,
                Identification::fqdn("alice").to_bytes(),
            ),
            (
                PayloadType::Configuration,
                Configuration::request_ipv4().to_bytes(),
            ),
            (PayloadType::SecurityAssociation, child_offer.to_bytes()),
            (PayloadType::TrafficSelectorInitiator, any.clone()),
            (PayloadType::TrafficSelectorResponder, any),
        ];
        let outbound_inner = encode_payload_chain(&initial_payloads).unwrap();
        let mut outbound = build_encrypted(
            &protection_sa,
            IkeHeader {
                initiator_spi: protection_sa.spi_i,
                responder_spi: protection_sa.spi_r,
                next_payload: PayloadType::NoNext,
                major_version: 2,
                minor_version: 0,
                exchange_type: ExchangeType::IkeAuth,
                flags: Flags {
                    initiator: true,
                    version: false,
                    response: false,
                },
                message_id: 1,
                length: 0,
            },
            PayloadType::IdInitiator,
            &outbound_inner,
            &[0xA5; 16],
        )
        .unwrap();
        let natt_addr = SocketAddr::from(([127, 0, 0, 1], natt_port));
        let mut established = false;
        for _ in 0..8 {
            let mut framed = vec![0u8; 4];
            framed.extend_from_slice(&outbound);
            socket.send_to(&framed, natt_addr).await.unwrap();
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            match client.handle(&buffer[4..length], &mut entropy).unwrap() {
                ryke::EapEvent::Reply(next) => outbound = next,
                ryke::EapEvent::Established(_) => {
                    let (first, inner) =
                        open_encrypted(&protection_sa, &buffer[4..length]).unwrap();
                    let selected = payloads(first, &inner)
                        .find_map(|payload| {
                            let payload = payload.ok()?;
                            (payload.payload_type == PayloadType::SecurityAssociation)
                                .then(|| SecurityAssociation::parse(payload.data).unwrap())
                        })
                        .unwrap();
                    assert_eq!(selected.proposals[0].num, 2);
                    established = true;
                    break;
                }
                ryke::EapEvent::Failed => break,
            }
        }
        assert!(established);
        assert!(
            control
                .get_network_state("eap-test")
                .unwrap()
                .is_device_online("alice")
        );
    }
}
