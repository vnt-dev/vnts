use crate::cipher::RsaCipher;
use crate::core::server::web::vo::{ClientInfo, GroupList, GroupsInfo, LoginData, NetworkInfo};
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;
use uuid::uuid;

#[derive(Clone)]
pub struct VntsWebService {
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
}

impl VntsWebService {
    pub fn new(cache: AppCache, config: ConfigInfo, rsa_cipher: Option<RsaCipher>) -> Self {
        Self {
            cache,
            config,
            rsa_cipher,
        }
    }
}

impl VntsWebService {
    pub async fn login(&self, login_data: LoginData) -> Option<String> {
        if login_data.username == self.config.username
            && login_data.password == self.config.password
        {
            let auth = uuid::Uuid::new_v4().to_string();
            self.cache
                .auth_map
                .insert(auth.clone(), (), Duration::from_secs(3600 * 24))
                .await;
            Some(auth)
        } else {
            None
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
    pub fn group_info(&self, group: String) -> Option<NetworkInfo> {
        if let Some(info) = self.cache.virtual_network.get(&group) {
            let guard = info.read();
            let mut network = NetworkInfo::new(
                guard.network_ip.into(),
                guard.mask_ip.into(),
                guard.gateway_ip.into(),
            );
            for into in guard.clients.values() {
                let address = match into.address {
                    SocketAddr::V4(_) => into.address,
                    SocketAddr::V6(ipv6) => {
                        if let Some(ipv4) = ipv6.ip().to_ipv4_mapped() {
                            SocketAddr::V4(SocketAddrV4::new(ipv4, ipv6.port()))
                        } else {
                            into.address
                        }
                    }
                };
                let client_info = ClientInfo {
                    device_id: into.device_id.clone(),
                    name: into.name.clone(),
                    client_secret: into.client_secret,
                    server_secret: into.server_secret.is_some(),
                    address,
                    online: into.online,
                    virtual_ip: into.virtual_ip.into(),
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
    pub fn groups_info(&self) -> GroupsInfo {
        let mut data = GroupsInfo::new();
        for (group, info) in self.cache.virtual_network.key_values() {
            let guard = info.read();
            let mut network = NetworkInfo::new(
                guard.network_ip.into(),
                guard.mask_ip.into(),
                guard.gateway_ip.into(),
            );
            for (_ip, into) in guard.clients.iter() {
                let client_info = ClientInfo {
                    device_id: into.device_id.clone(),
                    name: into.name.clone(),
                    client_secret: into.client_secret,
                    server_secret: into.server_secret.is_some(),
                    address: into.address,
                    online: into.online,
                    virtual_ip: into.virtual_ip.into(),
                };
                network.clients.push(client_info);
            }
            network
                .clients
                .sort_by(|v1, v2| v1.virtual_ip.cmp(&v2.virtual_ip));
            data.data.insert(group.to_string(), network);
        }
        data
    }
}
