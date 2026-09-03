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
    AssignedConfig, AuthConfig, ChildSa, CompletedSaInit, CookiePolicy, EapEvent, EapResponder,
    Entropy, ExchangeType, Identification, IkeHeader, LocalAuth, LocalSecret, MessageBuilder,
    Notify, PayloadType, PeerAuth, Role, SaInitResult, ServerAuth, SigningKey, TrafficSelector,
    TrafficSelectors, build_encrypted_gcm, build_informational, is_eap_request, is_ike_sa_rekey,
    open_encrypted_gcm, open_informational, payloads, responder_process_auth,
    responder_process_ike_rekey, responder_process_rekey, responder_respond_natt,
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

#[derive(Clone)]
struct NetworkAuth {
    network_code: String,
    psk: Option<Vec<u8>>,
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
        changed_network: String,
        response: tokio::sync::oneshot::Sender<Result<(), String>>,
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
        changed_network: String,
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
    networks: Vec<NetworkAuth>,
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
}

pub async fn start(config: Ikev2Config, control: ControlService) -> anyhow::Result<Ikev2Handle> {
    config.validate()?;
    let certificate = load_certificate(&config)?;
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

    let (networks, eap_credentials) = runtime_credentials(&config);
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
        networks,
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
    };
    log::info!(
        "IKEv2 listening on {} and NAT-T {}",
        engine.config.ike_bind,
        engine.config.natt_bind
    );
    tokio::spawn(async move {
        if let Err(error) = engine.run().await {
            log::error!("IKEv2 server stopped: {error:#}");
        }
    });
    Ok(handle)
}

pub(crate) fn validate_runtime_config(config: &Ikev2Config) -> anyhow::Result<()> {
    config.validate()?;
    load_certificate(config).map(|_| ())
}

impl Engine {
    async fn run(mut self) -> anyhow::Result<()> {
        let mut ike_buffer = vec![0u8; 65_535];
        let mut natt_buffer = vec![0u8; 65_535];
        let mut cleanup = tokio::time::interval(Duration::from_secs(10));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                result = self.ike_socket.recv_from(&mut ike_buffer) => {
                    let (length, peer) = result?;
                    let data = ike_buffer[..length].to_vec();
                    if let Err(error) = self.handle_ike(data, peer, false).await {
                        log::debug!("invalid IKEv2 packet from {peer}: {error:#}");
                    }
                }
                result = self.natt_socket.recv_from(&mut natt_buffer) => {
                    let (length, peer) = result?;
                    if length >= NON_ESP_MARKER.len() && natt_buffer[..4] == NON_ESP_MARKER {
                        let data = natt_buffer[4..length].to_vec();
                        if let Err(error) = self.handle_ike(data, peer, true).await {
                            log::debug!("invalid IKEv2 NAT-T packet from {peer}: {error:#}");
                        }
                    } else if length == 1 && natt_buffer[0] == 0xff {
                        // RFC 3948 NAT keepalive.
                    } else {
                        let data = natt_buffer[..length].to_vec();
                        if let Err(error) = self.handle_esp(data, peer).await {
                            log::debug!("invalid ESP packet from {peer}: {error:#}");
                        }
                    }
                }
                Some(command) = self.command_rx.recv() => {
                    if let Err(error) = self.handle_command(command).await {
                        log::debug!("IKEv2 outbound packet dropped: {error:#}");
                    }
                }
                _ = cleanup.tick() => self.cleanup(),
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
        if header.next_payload == PayloadType::EncryptedFragment {
            let Some(reassembled) = self.collect_fragment(&data, header, peer)? else {
                return Ok(());
            };
            data = reassembled;
            header = IkeHeader::parse(&data).map_err(anyhow::Error::msg)?;
        }
        match header.exchange_type {
            ExchangeType::IkeSaInit => self.handle_sa_init(data, peer, natt).await,
            ExchangeType::IkeAuth => self.handle_ike_auth(data, header, peer, natt).await,
            ExchangeType::Informational => {
                self.handle_informational(data, header, peer, natt).await
            }
            ExchangeType::CreateChildSa => self.handle_rekey(data, header, peer, natt).await,
            ExchangeType::Other(_) => Ok(()),
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
        }
        set.updated = Instant::now();
        if set.messages.len() != total as usize {
            return Ok(None);
        }
        let messages = self
            .fragments
            .remove(&key)
            .context("IKE fragment set disappeared")?
            .messages;
        let (first, inner) = ryke::ikev2::fragment::reassemble(&messages, &sa.keys.sk_ei)
            .map_err(anyhow::Error::msg)?;
        let iv = random_iv(&mut self.entropy);
        build_encrypted_gcm(header, first, &inner, &sa.keys.sk_ei, &iv)
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
        if let Some(existing) = self
            .half_open
            .values()
            .find(|entry| entry.sa.spi_i == header.initiator_spi && entry.peer == peer)
        {
            return self.send_ike(&existing.response, peer, existing.natt).await;
        }
        let local = LocalSecret::generate(&mut self.entropy, NONCE_LEN);
        let public_ip = self
            .config
            .public_ip
            .unwrap_or_else(|| match self.config.ike_bind.ip() {
                IpAddr::V4(ip) if !ip.is_unspecified() => IpAddr::V4(ip),
                IpAddr::V6(ip) if !ip.is_unspecified() => IpAddr::V6(ip),
                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            });
        // The data plane is deliberately UDP-encapsulated ESP only. Hashing the
        // NAT-T port here makes every standards-compliant initiator float to
        // UDP/4500, including a client that happens to have a public address.
        let our_addr = SocketAddr::new(public_ip, self.config.natt_bind.port());
        let require_cookie = self.half_open.len() >= MAX_HALF_OPEN;
        let peer_cookie = peer.to_string();
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
        match result {
            SaInitResult::Established { response, mut sa } => {
                let fragmentation_supported = peer_supports_fragmentation(&data)?;
                let response = advertise_fragmentation(&response)?;
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
            }
            SaInitResult::InvalidKe { response, .. }
            | SaInitResult::CookieRequired { response } => {
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
        if self.eap_pending.contains_key(&key) {
            return self.handle_eap(data, key, peer, natt).await;
        }
        if let Some(session_id) = self.ike_to_session.get(&key).copied()
            && let Some(established) = self.established.get(&session_id)
            && let Some((message_id, response)) = &established.last_ike_response
            && *message_id == header.message_id
        {
            return self.send_ike(response, peer, natt).await;
        }
        let half = self.half_open.remove(&key).context("unknown IKE SA")?;
        if is_eap_request(&half.sa, &data) {
            return self.begin_eap(data, key, half, peer, natt).await;
        }
        self.finish_psk(data, key, half, peer, natt).await
    }

    async fn finish_psk(
        &mut self,
        data: Vec<u8>,
        key: (u64, u64),
        half: HalfOpen,
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        let child_spi = random_nonzero_u32(&mut self.entropy);
        let identity = ryke::peer_id_from_auth(&half.sa, &data).map_err(anyhow::Error::msg)?;
        let identity = identity_string(&identity)?;
        let mut matched: Option<(NetworkAuth, u32)> = None;
        for network in &self.networks {
            let Some(psk) = &network.psk else { continue };
            let config = AuthConfig {
                id: Identification::fqdn(&self.config.remote_id),
                local: LocalAuth::Psk(psk.clone()),
                peer: PeerAuth::Psk(psk.clone()),
            };
            let iv = random_iv(&mut self.entropy);
            if let Ok((_, _, peer_spi)) =
                responder_process_auth(&half.sa, &data, &config, child_spi, &iv, None)
            {
                matched = Some((network.clone(), peer_spi));
            }
        }
        let (network, peer_spi) = matched.context("IKEv2 PSK authentication failed")?;
        let (session, receiver) = self
            .register_endpoint(&network.network_code, "psk", &identity)
            .await?;
        let assigned = AssignedConfig {
            ip: session.ip,
            dns: self.config.dns.clone(),
        };
        let psk = network.psk.context("missing PSK")?;
        let auth = AuthConfig {
            id: Identification::fqdn(&self.config.remote_id),
            local: LocalAuth::Psk(psk.clone()),
            peer: PeerAuth::Psk(psk),
        };
        let iv = random_iv(&mut self.entropy);
        let (response, _, verified_peer_spi) =
            responder_process_auth(&half.sa, &data, &auth, child_spi, &iv, Some(&assigned))
                .map_err(anyhow::Error::msg)?;
        if verified_peer_spi != peer_spi {
            bail!("IKEv2 peer CHILD_SA SPI changed during authentication");
        }
        let network_net = Ipv4Net::new(session.ip, session.network_state.net_prefix_len())?.trunc();
        let response = narrow_tsr(&response, &half.sa, network_net, &mut self.entropy)?;
        let child = ChildSa::derive(
            &half.sa.keys.sk_d,
            &half.sa.ni,
            &half.sa.nr,
            Role::Responder,
            child_spi,
            peer_spi,
        );
        let message_id = IkeHeader::parse(&data)
            .map_err(anyhow::Error::msg)?
            .message_id;
        self.send_encrypted_response(
            &response,
            &half.sa,
            peer,
            natt,
            half.fragmentation_supported,
        )
        .await?;
        self.install_established(
            key,
            half.sa,
            child,
            session,
            receiver,
            network_net,
            peer,
            natt,
            Some((message_id, response)),
            half.fragmentation_supported,
        );
        Ok(())
    }

    async fn begin_eap(
        &mut self,
        data: Vec<u8>,
        key: (u64, u64),
        half: HalfOpen,
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
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
            Identification::fqdn(&self.config.remote_id),
            ServerAuth::Cert {
                key: certificate.signing.signing_key()?,
                chain: certificate.chain.clone(),
            },
            users,
            child_spi,
        );
        let event = responder
            .handle(&data, &mut self.entropy)
            .map_err(anyhow::Error::msg)?;
        let EapEvent::Reply(response) = event else {
            bail!("invalid first EAP exchange");
        };
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
        Ok(())
    }

    async fn handle_eap(
        &mut self,
        data: Vec<u8>,
        key: (u64, u64),
        peer: SocketAddr,
        natt: bool,
    ) -> anyhow::Result<()> {
        let mut pending = self
            .eap_pending
            .remove(&key)
            .context("unknown EAP session")?;
        pending.peer = peer;
        pending.natt = natt;
        pending.last_seen = Instant::now();
        let event = pending
            .responder
            .handle(&data, &mut self.entropy)
            .map_err(anyhow::Error::msg)?;

        if pending.session.is_none() && !pending.responder.user().is_empty() {
            let user = pending.responder.user().to_vec();
            let (network_code, _) = self
                .eap_credentials
                .get(&user)
                .cloned()
                .context("unknown EAP user")?;
            let identity = String::from_utf8(user).context("EAP username must be UTF-8")?;
            let (session, receiver) = self
                .register_endpoint(&network_code, "eap", &identity)
                .await?;
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
                self.send_encrypted_response(
                    &response,
                    &pending.sa,
                    peer,
                    natt,
                    pending.fragmentation_supported,
                )
                .await?;
                self.eap_pending.insert(key, pending);
            }
            EapEvent::Established(response) => {
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
                let network =
                    Ipv4Net::new(session.ip, session.network_state.net_prefix_len())?.trunc();
                let response = narrow_tsr(&response, &pending.sa, network, &mut self.entropy)?;
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
            EapEvent::Failed => bail!("EAP authentication failed"),
        }
        Ok(())
    }

    async fn register_endpoint(
        &self,
        network_code: &str,
        auth_kind: &str,
        identity: &str,
    ) -> anyhow::Result<(Session, mpsc::Receiver<Bytes>)> {
        if identity.is_empty() || identity.len() > 48 {
            bail!("IKEv2 identity must contain 1..=48 UTF-8 bytes");
        }
        let device_id = format!("ikev2:{auth_kind}:{identity}");
        let (sender, receiver) = mpsc::channel(1024);
        let session = self
            .control
            .register_ikev2(
                network_code.to_string(),
                device_id,
                identity.to_string(),
                sender,
            )
            .await?;
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
        let duplicate = self.established.iter().find_map(|(id, established)| {
            (established.session.network_code == session.network_code
                && established.session.device_id == session.device_id)
                .then_some(*id)
        });
        if let Some(old_id) = duplicate {
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
    }

    async fn handle_esp(&mut self, data: Vec<u8>, peer: SocketAddr) -> anyhow::Result<()> {
        if data.len() < 8 {
            bail!("ESP packet is too short");
        }
        let spi = u32::from_be_bytes(data[..4].try_into()?);
        let sequence = u32::from_be_bytes(data[4..8].try_into()?);
        let session_id = *self.esp_to_session.get(&spi).context("unknown ESP SPI")?;
        let (network_code, source, destination, inner) = {
            let established = self
                .established
                .get_mut(&session_id)
                .context("unknown IKEv2 session")?;
            if !established.replay.permits(sequence) {
                bail!("ESP replay rejected");
            }
            let (mut inner, next_header) = established
                .child
                .inbound
                .open(&data)
                .map_err(anyhow::Error::msg)?;
            if next_header != ryke::esp::next_header::IPV4 {
                bail!("only inner IPv4 is supported");
            }
            let (source, destination, total_length) =
                checked_ipv4(&inner).context("invalid inner IPv4 packet")?;
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
                return Ok(());
            }
            Command::ReloadConfig {
                config,
                certificate,
                changed_network,
                response,
            } => {
                let session_ids = self
                    .established
                    .iter()
                    .filter_map(|(id, established)| {
                        (established.session.network_code == changed_network).then_some(*id)
                    })
                    .collect::<Vec<_>>();
                for session_id in session_ids {
                    self.disconnect_established(session_id).await;
                }
                self.half_open.clear();
                self.eap_pending.clear();
                self.fragments.clear();
                let (networks, eap_credentials) = runtime_credentials(&config);
                self.config = *config;
                self.networks = networks;
                self.eap_credentials = eap_credentials;
                self.certificate = certificate;
                let _ = response.send(Ok(()));
                return Ok(());
            }
        };
        let packet = NetPacket::new(packet)?;
        if packet.msg_type()? != MsgType::Ikev2Relay {
            return Ok(());
        }
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
            (established.peer, established.natt, esp)
        };
        if !natt {
            bail!("raw IP ESP is not supported; client must use NAT-T");
        }
        self.natt_socket.send_to(&esp, peer).await?;
        Ok(())
    }

    async fn disconnect_established(&mut self, session_id: u64) -> bool {
        let deletion = self
            .established
            .get_mut(&session_id)
            .and_then(|established| {
                let iv = random_iv(&mut self.entropy);
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
            let _ = self.send_ike(&packet, peer, natt).await;
        }
        let existed = self.established.contains_key(&session_id);
        self.remove_established(session_id);
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
        let session_id = *self.ike_to_session.get(&key).context("unknown IKE SA")?;
        let (response, delete) = {
            let established = self
                .established
                .get_mut(&session_id)
                .context("unknown session")?;
            let payloads =
                open_informational(&established.sa, &data).map_err(anyhow::Error::msg)?;
            let delete = payloads
                .iter()
                .any(|(kind, _)| *kind == PayloadType::Delete);
            established.peer = peer;
            established.natt = natt;
            established.last_seen = Instant::now();
            let iv = random_iv(&mut self.entropy);
            let response = build_informational(&established.sa, header.message_id, true, &[], &iv)
                .map_err(anyhow::Error::msg)?;
            (response, delete)
        };
        self.send_ike(&response, peer, natt).await?;
        if delete {
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
        let session_id = *self.ike_to_session.get(&key).context("unknown IKE SA")?;
        let old_sa = self
            .established
            .get(&session_id)
            .context("unknown session")?
            .sa
            .clone();
        let (first, inner) =
            open_encrypted_gcm(&data, &old_sa.keys.sk_ei).map_err(anyhow::Error::msg)?;
        let inner_payloads = payloads(first, &inner)
            .map(|payload| {
                let payload = payload.map_err(anyhow::Error::msg)?;
                Ok((payload.payload_type, payload.data.to_vec()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if is_ike_sa_rekey(&inner_payloads) {
            let new_spi_r = self.entropy.next_u64().max(1);
            let mut private = [0u8; 32];
            self.entropy.fill(&mut private);
            let mut nonce = vec![0u8; NONCE_LEN];
            self.entropy.fill(&mut nonce);
            let iv = random_iv(&mut self.entropy);
            let (response, new_sa) =
                responder_process_ike_rekey(&old_sa, &data, new_spi_r, &private, &nonce, &iv)
                    .map_err(anyhow::Error::msg)?;
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
            return Ok(());
        }
        let (response, old_spi, new_spi) = {
            let established = self
                .established
                .get_mut(&session_id)
                .context("unknown session")?;
            let new_spi = random_nonzero_u32(&mut self.entropy);
            let mut nonce = vec![0u8; NONCE_LEN];
            self.entropy.fill(&mut nonce);
            let iv = random_iv(&mut self.entropy);
            let (response, child) = responder_process_rekey(
                &established.sa,
                &data,
                new_spi,
                &nonce,
                &iv,
                Some(established.session.ip),
            )
            .map_err(anyhow::Error::msg)?;
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
        if !fragmentation_supported || response.len() <= IKE_FRAGMENT_CONTENT + 128 {
            return self.send_ike(response, peer, natt).await;
        }
        let header = IkeHeader::parse(response).map_err(anyhow::Error::msg)?;
        let (first, inner) =
            open_encrypted_gcm(response, &sa.keys.sk_er).map_err(anyhow::Error::msg)?;
        let fragments = ryke::ikev2::fragment::build_fragments(
            &header,
            first,
            &inner,
            &sa.keys.sk_er,
            rand::random(),
            IKE_FRAGMENT_CONTENT,
        )
        .map_err(anyhow::Error::msg)?;
        for fragment in fragments {
            self.send_ike(&fragment, peer, natt).await?;
        }
        Ok(())
    }

    async fn send_ike(&self, data: &[u8], peer: SocketAddr, natt: bool) -> anyhow::Result<()> {
        if natt {
            let mut framed = Vec::with_capacity(4 + data.len());
            framed.extend_from_slice(&NON_ESP_MARKER);
            framed.extend_from_slice(data);
            self.natt_socket.send_to(&framed, peer).await?;
        } else {
            self.ike_socket.send_to(data, peer).await?;
        }
        Ok(())
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
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
        for id in expired {
            self.remove_established(id);
        }
    }

    fn remove_established(&mut self, session_id: u64) {
        if let Some(established) = self.established.remove(&session_id) {
            self.esp_to_session.remove(&established.child.inbound.spi());
            self.ike_to_session.retain(|_, id| *id != session_id);
            log::info!(
                "IKEv2 client disconnected: network={}, ip={}, peer={}",
                established.session.network_code,
                established.session.ip,
                established.peer
            );
        }
    }
}

fn identity_string(identity: &Identification) -> anyhow::Result<String> {
    if identity.data.is_empty() {
        bail!("IKEv2 Local ID cannot be empty");
    }
    String::from_utf8(identity.data.clone()).context("IKEv2 Local ID must be UTF-8")
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

fn runtime_credentials(config: &Ikev2Config) -> (Vec<NetworkAuth>, EapCredentialMap) {
    let networks = config
        .networks
        .iter()
        .map(|network| NetworkAuth {
            network_code: network.network_code.clone(),
            psk: network.psk.as_ref().map(|value| value.as_bytes().to_vec()),
        })
        .collect();
    let mut eap_credentials = HashMap::new();
    for network in &config.networks {
        for (user, password) in &network.eap_users {
            eap_credentials.insert(
                user.as_bytes().to_vec(),
                (network.network_code.clone(), password.clone()),
            );
        }
    }
    (networks, eap_credentials)
}

fn random_nonzero_u32(entropy: &mut impl Entropy) -> u32 {
    loop {
        let value = entropy.next_u64() as u32;
        if value != 0 {
            return value;
        }
    }
}

fn random_iv(entropy: &mut impl Entropy) -> [u8; 8] {
    let mut iv = [0u8; 8];
    entropy.fill(&mut iv);
    iv
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
    let (first, inner) =
        open_encrypted_gcm(response, &sa.keys.sk_er).map_err(anyhow::Error::msg)?;
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
    let iv = random_iv(entropy);
    build_encrypted_gcm(header, first, &inner, &sa.keys.sk_er, &iv).map_err(anyhow::Error::msg)
}

fn load_certificate(config: &Ikev2Config) -> anyhow::Result<Option<CertificateMaterial>> {
    let has_eap = config
        .networks
        .iter()
        .any(|network| !network.eap_users.is_empty());
    if !has_eap {
        return Ok(None);
    }
    let cert_path = config
        .cert
        .as_ref()
        .context("ikev2.cert is required for EAP")?;
    let key_path = config
        .key
        .as_ref()
        .context("ikev2.key is required for EAP")?;
    let cert_bytes = std::fs::read(cert_path)
        .with_context(|| format!("failed to read IKEv2 certificate {}", cert_path.display()))?;
    let chain = rustls_pemfile::certs(&mut Cursor::new(cert_bytes))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect::<Vec<_>>();
    let leaf = chain.first().context("IKEv2 certificate chain is empty")?;
    if !ryke::ikev2::sign::cert_has_dns_name(leaf, &config.remote_id).map_err(anyhow::Error::msg)? {
        bail!("IKEv2 certificate SAN does not match remote_id");
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (not_before, not_after) =
        ryke::ikev2::sign::cert_validity(leaf).map_err(anyhow::Error::msg)?;
    if now < not_before || now > not_after {
        bail!("IKEv2 certificate is not currently valid");
    }

    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("failed to read IKEv2 private key {}", key_path.display()))?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key_bytes))?
        .context("IKEv2 private key PEM contains no supported key")?;
    let der = key.secret_der().to_vec();
    let signing = if SigningKey::ecdsa_p256_from_pkcs8_der(&der).is_ok() {
        SigningMaterial::EcdsaP256(der)
    } else if rsa::RsaPrivateKey::from_pkcs8_der(&der).is_ok() {
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
    Ok(Some(CertificateMaterial { signing, chain }))
}

#[cfg(test)]
mod tests {
    use super::{ReplayWindow, SystemEntropy, start};
    use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
    use crate::protocol::ip_packet_protocol::{MsgType, NetPacket};
    use crate::server::control_server::service::ControlService;
    use crate::utils::config::{Ikev2Config, Ikev2NetworkConfig};
    use ipnet::Ipv4Net;
    use ryke::{
        AuthConfig, Entropy, Identification, LocalSecret, default_offer, initiator_auth_request,
        initiator_complete, initiator_request, initiator_verify_auth,
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

    #[tokio::test]
    async fn psk_handshake_assigns_an_address_from_the_vnt_network() {
        let ike_port = unused_udp_port();
        let mut natt_port = unused_udp_port();
        while natt_port == ike_port {
            natt_port = unused_udp_port();
        }
        let config = Ikev2Config {
            ike_bind: SocketAddr::from(([127, 0, 0, 1], ike_port)),
            natt_bind: SocketAddr::from(([127, 0, 0, 1], natt_port)),
            remote_id: "vpn.example.com".to_string(),
            cert: None,
            key: None,
            dns: Vec::new(),
            public_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            networks: vec![Ikev2NetworkConfig {
                network_code: "ike-test".to_string(),
                psk: Some("test-secret".to_string()),
                eap_users: HashMap::new(),
            }],
        };
        let mut reloaded_config = config.clone();
        let control = ControlService::new(
            "10.77.0.0/24".parse::<Ipv4Net>().unwrap(),
            HashMap::new(),
            Default::default(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let vnt_ip = Ipv4Addr::new(10, 77, 0, 50);
        let (vnt_sender, mut vnt_receiver) = tokio::sync::mpsc::channel(8);
        let _vnt_session = control
            .register(
                RegRequestMsg {
                    network_code: "ike-test".to_string(),
                    device_id: "vnt-target".to_string(),
                    ip: Some(vnt_ip),
                    name: "target".to_string(),
                    version: "test".to_string(),
                    key_sign: None,
                    ip_variable: false,
                    server_id: 0,
                    registration_mode: RegistrationMode::Normal,
                    advertised_subnets: Vec::new(),
                    allow_ikev2: true,
                },
                vnt_sender,
            )
            .await
            .unwrap();
        let handle = start(config, control.clone()).await.unwrap();

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut entropy = SystemEntropy;
        let local = LocalSecret::generate(&mut entropy, 32);
        let request = initiator_request(&local, &default_offer());
        socket
            .send_to(&request, SocketAddr::from(([127, 0, 0, 1], ike_port)))
            .await
            .unwrap();
        let mut buffer = vec![0u8; 8192];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let sa = initiator_complete(&local, &request, &buffer[..length]).unwrap();

        let auth = AuthConfig::psk(Identification::fqdn("phone-a"), b"test-secret".to_vec());
        let mut iv = [0u8; 8];
        entropy.fill(&mut iv);
        let auth_request = initiator_auth_request(&sa, &auth, 0x1234_5678, &iv).unwrap();
        let mut framed = vec![0u8; 4];
        framed.extend_from_slice(&auth_request);
        socket
            .send_to(&framed, SocketAddr::from(([127, 0, 0, 1], natt_port)))
            .await
            .unwrap();
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..4], &[0, 0, 0, 0]);
        let (first, inner) = ryke::open_encrypted_gcm(&buffer[4..length], &sa.keys.sk_er).unwrap();
        let tsr = ryke::payloads(first, &inner)
            .map(Result::unwrap)
            .find(|payload| payload.payload_type == ryke::PayloadType::TrafficSelectorResponder)
            .unwrap();
        let selectors = ryke::TrafficSelectors::parse(tsr.data).unwrap();
        assert_eq!(selectors.selectors[0].start_addr, vec![10, 77, 0, 0]);
        assert_eq!(selectors.selectors[0].end_addr, vec![10, 77, 0, 255]);
        let (server_id, peer_spi, assigned) =
            initiator_verify_auth(&sa, &buffer[4..length], &auth).unwrap();
        assert_eq!(server_id, Identification::fqdn("vpn.example.com"));
        let assigned = assigned.unwrap();
        assert!(
            "10.77.0.0/24"
                .parse::<Ipv4Net>()
                .unwrap()
                .contains(&assigned)
        );

        let mut dpd_iv = [0u8; 8];
        entropy.fill(&mut dpd_iv);
        let dpd = ryke::dpd_request(&sa, 2, &dpd_iv).unwrap();
        let mut framed_dpd = vec![0u8; 4];
        framed_dpd.extend_from_slice(&dpd);
        socket
            .send_to(&framed_dpd, SocketAddr::from(([127, 0, 0, 1], natt_port)))
            .await
            .unwrap();
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert!(
            ryke::open_informational(&sa, &buffer[4..length])
                .unwrap()
                .is_empty()
        );

        let mut rekey_nonce = [0u8; 32];
        entropy.fill(&mut rekey_nonce);
        let mut rekey_iv = [0u8; 8];
        entropy.fill(&mut rekey_iv);
        let new_client_spi = 0x2233_4455;
        let rekey = ryke::ikev2::rekey::build_rekey_request(
            &sa,
            3,
            peer_spi,
            new_client_spi,
            &rekey_nonce,
            &rekey_iv,
        )
        .unwrap();
        let mut framed_rekey = vec![0u8; 4];
        framed_rekey.extend_from_slice(&rekey);
        socket
            .send_to(&framed_rekey, SocketAddr::from(([127, 0, 0, 1], natt_port)))
            .await
            .unwrap();
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let mut child = ryke::ikev2::rekey::initiator_complete_rekey(
            &sa,
            &rekey_nonce,
            new_client_spi,
            &buffer[4..length],
        )
        .unwrap();
        let request_ip = ipv4_packet(assigned, vnt_ip);
        let esp = child
            .outbound
            .seal(&request_ip, ryke::esp::next_header::IPV4)
            .unwrap();
        socket
            .send_to(&esp, SocketAddr::from(([127, 0, 0, 1], natt_port)))
            .await
            .unwrap();
        let relayed = tokio::time::timeout(Duration::from_secs(2), vnt_receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let relayed = NetPacket::new(relayed).unwrap();
        assert_eq!(relayed.msg_type().unwrap(), MsgType::Ikev2Relay);
        assert!(relayed.is_gateway());
        assert_eq!(relayed.payload(), request_ip);
        socket
            .send_to(&esp, SocketAddr::from(([127, 0, 0, 1], natt_port)))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), vnt_receiver.recv())
                .await
                .is_err()
        );

        let reply_ip = ipv4_packet(vnt_ip, assigned);
        assert!(
            control
                .forward_ikev2_packet("ike-test", vnt_ip, assigned, &reply_ip)
                .await
                .unwrap()
        );
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let (opened, next_header) = child.inbound.open(&buffer[..length]).unwrap();
        assert_eq!(next_header, ryke::esp::next_header::IPV4);
        assert_eq!(opened, reply_ip);
        reloaded_config.networks[0].psk = Some("rotated-secret".to_string());
        handle
            .reload_network_config(reloaded_config, "ike-test".to_string())
            .await
            .unwrap();
        assert!(
            !control
                .get_network_state("ike-test")
                .unwrap()
                .is_device_online("ikev2:psk:phone-a")
        );
    }

    #[tokio::test]
    async fn eap_mschapv2_handshake_uses_the_configured_certificate_and_user() {
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
            ike_bind: SocketAddr::from(([127, 0, 0, 1], ike_port)),
            natt_bind: SocketAddr::from(([127, 0, 0, 1], natt_port)),
            remote_id: "vpn.example.com".to_string(),
            cert: Some(cert_path),
            key: Some(key_path),
            dns: Vec::new(),
            public_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            networks: vec![Ikev2NetworkConfig {
                network_code: "eap-test".to_string(),
                psk: None,
                eap_users: HashMap::from([("alice".to_string(), "password".to_string())]),
            }],
        };
        let control = ControlService::new(
            "10.78.0.0/24".parse::<Ipv4Net>().unwrap(),
            HashMap::new(),
            Default::default(),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let _handle = start(config, control).await.unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut entropy = SystemEntropy;
        let local = LocalSecret::generate(&mut entropy, 32);
        let request = initiator_request(&local, &default_offer());
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
        let mut outbound = client.start(&mut entropy).unwrap();
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
                    established = true;
                    break;
                }
                ryke::EapEvent::Failed => break,
            }
        }
        assert!(established);
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }
}
