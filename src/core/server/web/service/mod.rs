use crossbeam_utils::atomic::AtomicCell;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cipher::RsaCipher;
use crate::core::server::web::vo::{
    ClientInfo, ClientStatusInfo, GroupList, LoginData, NetworkInfo,
};
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;

#[derive(Clone)]
pub struct VntsWebService {
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
    login_time: Arc<AtomicCell<(Instant, usize)>>,
}

impl VntsWebService {
    pub fn new(cache: AppCache, config: ConfigInfo, rsa_cipher: Option<RsaCipher>) -> Self {
        Self {
            cache,
            config,
            rsa_cipher,
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
                let status_info = if let Some(client_status) = &into.client_status {
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

                let client_info = ClientInfo {
                    device_id: into.device_id.clone(),
                    name: into.name.clone(),
                    client_secret: into.client_secret,
                    server_secret: into.server_secret.is_some(),
                    address,
                    online: into.online,
                    virtual_ip: into.virtual_ip.into(),
                    status_info,
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
    // pub fn groups_info(&self) -> GroupsInfo {
    //     let mut data = GroupsInfo::new();
    //     for (group, info) in self.cache.virtual_network.key_values() {
    //         let guard = info.read();
    //         let mut network = NetworkInfo::new(
    //             guard.network_ip.into(),
    //             guard.mask_ip.into(),
    //             guard.gateway_ip.into(),
    //         );
    //         for (_ip, into) in guard.clients.iter() {
    //             let client_info = ClientInfo {
    //                 device_id: into.device_id.clone(),
    //                 name: into.name.clone(),
    //                 client_secret: into.client_secret,
    //                 server_secret: into.server_secret.is_some(),
    //                 address: into.address,
    //                 online: into.online,
    //                 virtual_ip: into.virtual_ip.into(),
    //             };
    //             network.clients.push(client_info);
    //         }
    //         network
    //             .clients
    //             .sort_by(|v1, v2| v1.virtual_ip.cmp(&v2.virtual_ip));
    //         data.data.insert(group.to_string(), network);
    //     }
    //     data
    // }
}
