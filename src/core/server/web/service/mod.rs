use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use base64::engine::general_purpose;
use base64::Engine;
use crossbeam_utils::atomic::AtomicCell;
use ipnetwork::Ipv4Network;
use rsa::rand_core::RngCore;

use crate::core::entity::WireGuardConfig;

use crate::core::server::web::vo::req::{CreateWGData, CreateWgConfig, LoginData, RemoveClientReq};
use crate::core::server::web::vo::res::{
    ClientInfo, ClientStatusInfo, GroupList, NetworkInfo, WGData, WgConfig,
};
use crate::core::service::server::{generate_ip, RegisterClientRequest};
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;

#[derive(Clone)]
pub struct VntsWebService {
    cache: AppCache,
    config: ConfigInfo,
    login_time: Arc<AtomicCell<(Instant, usize)>>,
}

impl VntsWebService {
    pub fn new(cache: AppCache, config: ConfigInfo) -> Self {
        Self {
            cache,
            config,
            login_time: Arc::new(AtomicCell::new((Instant::now(), 0))),
        }
    }
}

impl VntsWebService {
    pub async fn login(&self, login_data: LoginData) -> Result<String, String> {
        let (time, count) = self.login_time.load();
        if count >= 3 && time.elapsed() < Duration::from_secs(60) {
            return Err("一分钟后再试".into());
        }
        if login_data.username == self.config.username
            && login_data.password == self.config.password
        {
            self.login_time.store((time, 0));
            let auth = uuid::Uuid::new_v4().to_string().replace("-", "");
            self.cache
                .auth_map
                .insert(auth.clone(), (), Duration::from_secs(3600 * 24))
                .await;
            Ok(auth)
        } else {
            self.login_time.store((Instant::now(), count + 1));
            Err("账号或密码错误".into())
        }
    }
    pub fn check_auth(&self, auth: &String) -> bool {
        self.cache.auth_map.get(auth).is_some()
    }
    pub fn group_list(&self) -> GroupList {
        let group_list: Vec<String> = self
            .cache
            .virtual_network
            .key_values()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        GroupList { group_list }
    }
    pub fn remove_client(&self, req: RemoveClientReq) {
        if let Some(ip) = req.virtual_ip {
            if let Some(network_info) = self.cache.virtual_network.get(&req.group_id) {
                if let Some(client_info) = network_info.write().clients.remove(&ip.into()) {
                    if let Some(key) = client_info.wireguard {
                        self.cache.wg_group_map.remove(&key);
                    }
                }
            }
        } else {
            if let Some(network_info) = self.cache.virtual_network.remove(&req.group_id) {
                for (_, client_info) in network_info.write().clients.drain() {
                    if let Some(key) = client_info.wireguard {
                        self.cache.wg_group_map.remove(&key);
                    }
                }
            }
        }
    }
    pub fn gen_wg_private_key(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        return general_purpose::STANDARD.encode(bytes);
    }
    pub async fn create_wg_config(&self, wg_data: CreateWGData) -> anyhow::Result<WGData> {
        let device_id = wg_data.device_id.trim().to_string();
        let group_id = wg_data.group_id.trim().to_string();
        if group_id.is_empty() {
            Err(anyhow!("组网id不能为空"))?;
        }
        if device_id.is_empty() {
            Err(anyhow!("设备id不能为空"))?;
        }
        let cache = &self.cache;
        let (secret_key, public_key) = Self::check_wg_config(&wg_data.config)?;
        let gateway = self.config.gateway;
        let netmask = self.config.netmask;
        let network = Ipv4Network::with_netmask(gateway, netmask)?;
        let network = Ipv4Network::with_netmask(network.network(), netmask)?;
        let virtual_ip = if wg_data.virtual_ip.trim().is_empty() {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::from_str(&wg_data.virtual_ip).context("虚拟IP错误")?
        };
        let register_client_request = RegisterClientRequest {
            group_id: group_id.clone(),
            virtual_ip,
            gateway,
            netmask,
            allow_ip_change: false,
            device_id: device_id.clone(),
            version: String::from("wg"),
            name: wg_data.name.clone(),
            client_secret: true,
            client_secret_hash: vec![],
            server_secret: true,
            address: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
            tcp_sender: None,
            online: false,
            wireguard: Some(public_key),
        };
        let response = generate_ip(cache, register_client_request).await?;
        let wireguard_config = WireGuardConfig {
            vnts_endpoint: wg_data.config.vnts_endpoint.clone(),
            vnts_allowed_ips: network.to_string(),
            group_id: group_id.clone(),
            device_id: device_id.clone(),
            ip: response.virtual_ip,
            prefix: network.prefix(),
            persistent_keepalive: wg_data.config.persistent_keepalive,
            secret_key,
            public_key,
        };
        cache.wg_group_map.insert(public_key, wireguard_config);
        let config = WgConfig {
            vnts_endpoint: wg_data.config.vnts_endpoint,
            vnts_public_key: general_purpose::STANDARD.encode(&self.config.wg_public_key),
            vnts_allowed_ips: network.to_string(),
            public_key: general_purpose::STANDARD.encode(public_key),
            private_key: general_purpose::STANDARD.encode(secret_key),
            ip: response.virtual_ip,
            prefix: network.prefix(),
            persistent_keepalive: wg_data.config.persistent_keepalive,
        };
        let wg_data = WGData {
            group_id,
            virtual_ip: response.virtual_ip,
            device_id,
            name: wg_data.name,
            config,
        };
        Ok(wg_data)
    }
    fn check_wg_config(config: &CreateWgConfig) -> anyhow::Result<([u8; 32], [u8; 32])> {
        match config.vnts_endpoint.to_socket_addrs() {
            Ok(mut addr) => {
                if let Some(addr) = addr.next() {
                    if addr.ip().is_unspecified() || addr.port() == 0 {
                        Err(anyhow!("服务端地址错误"))?
                    }
                }
            }
            Err(e) => Err(anyhow!("服务端地址解析失败:{}", e))?,
        }

        let private_key = general_purpose::STANDARD
            .decode(&config.private_key)
            .context("私钥错误")?;
        let private_key: [u8; 32] = private_key.try_into().map_err(|_| anyhow!("私钥错误"))?;
        let secret_key = boringtun::x25519::StaticSecret::from(private_key);
        let public_key = *boringtun::x25519::PublicKey::from(&secret_key).as_bytes();

        Ok((private_key, public_key))
    }
    pub fn group_info(&self, group: String) -> Option<NetworkInfo> {
        if let Some(info) = self.cache.virtual_network.get(&group) {
            let guard = info.read();
            let mut network = NetworkInfo::new(
                guard.network_ip.into(),
                guard.mask_ip.into(),
                guard.gateway_ip.into(),
                general_purpose::STANDARD.encode(&self.config.wg_public_key),
            );
            for info in guard.clients.values() {
                let address = match info.address {
                    SocketAddr::V4(_) => info.address,
                    SocketAddr::V6(ipv6) => {
                        if let Some(ipv4) = ipv6.ip().to_ipv4_mapped() {
                            SocketAddr::V4(SocketAddrV4::new(ipv4, ipv6.port()))
                        } else {
                            info.address
                        }
                    }
                };
                let status_info = if let Some(client_status) = &info.client_status {
                    Some(ClientStatusInfo {
                        p2p_list: client_status.p2p_list.clone(),
                        up_stream: client_status.up_stream,
                        down_stream: client_status.down_stream,
                        is_cone: client_status.is_cone,
                        update_time: format!(
                            "{}",
                            client_status.update_time.format("%Y-%m-%d %H:%M:%S")
                        ),
                    })
                } else {
                    None
                };
                let mut wg_config = None;
                if let Some(key) = &info.wireguard {
                    if let Some(v) = self.cache.wg_group_map.get(key) {
                        wg_config.replace(v.clone());
                    }
                }
                let client_info = ClientInfo {
                    device_id: info.device_id.clone(),
                    version: info.version.clone(),
                    name: info.name.clone(),
                    client_secret: info.client_secret,
                    server_secret: info.server_secret,
                    address,
                    online: info.online,
                    virtual_ip: info.virtual_ip.into(),
                    status_info,
                    last_join_time: info.last_join_time.format("%Y-%m-%d %H:%M:%S").to_string(),
                    wg_config: wg_config.map(|v| v.into()),
                };
                network.clients.push(client_info);
            }
            network
                .clients
                .sort_by(|v1, v2| v1.virtual_ip.cmp(&v2.virtual_ip));
            Some(network)
        } else {
            None
        }
    }
}
