use crate::cipher::RsaCipher;
use crate::core::server::web::vo::{ClientInfo, GroupsInfo, NetworkInfo};
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;

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
    pub fn groups_info(&self) -> GroupsInfo {
        let mut data = GroupsInfo::new();
        for (group, info) in self.cache.virtual_network.iter() {
            let guard = info.read();
            let mut network = NetworkInfo::new(
                guard.network_ip.into(),
                guard.mask_ip.into(),
                guard.gateway_ip.into(),
            );
            for (ip, into) in guard.clients.iter() {
                let client_info = ClientInfo {
                    device_id: into.device_id.clone(),
                    name: into.name.clone(),
                    client_secret: into.client_secret,
                    server_secret: into.server_secret.is_some(),
                    address: into.address,
                    online: into.online,
                    virtual_ip: into.virtual_ip.into(),
                };
                network.clients.insert((*ip).into(), client_info);
            }
            data.data.insert(group.to_string(), network);
        }
        data
    }
}
