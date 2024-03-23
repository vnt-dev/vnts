use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use parking_lot::RwLock;

use crate::cipher::Aes256GcmCipher;
use crate::core::entity::NetworkInfo;
use crate::core::store::expire_map::ExpireMap;

#[derive(Clone)]
pub struct AppCache {
    // group -> NetworkInfo
    pub virtual_network: ExpireMap<String, Arc<RwLock<NetworkInfo>>>,
    // (group,ip) -> addr
    pub ip_session: ExpireMap<(String, u32), SocketAddr>,
    // addr -> (group，ip)
    pub addr_session: ExpireMap<SocketAddr, (String, u32)>,
    pub cipher_session: ExpireMap<SocketAddr, Arc<Aes256GcmCipher>>,
    pub auth_map: ExpireMap<String, ()>,
}

pub struct Context {
    pub network_info: Arc<RwLock<NetworkInfo>>,
    pub group: String,
    pub virtual_ip: u32,
}

impl AppCache {
    pub fn new() -> Self {
        // 网段7天未使用则回收
        let virtual_network: ExpireMap<String, Arc<RwLock<NetworkInfo>>> =
            ExpireMap::new(|k, v| {});
        let virtual_network_ = virtual_network.clone();
        // ip一天未使用则回收
        let ip_session: ExpireMap<(String, u32), SocketAddr> =
            ExpireMap::new(move |k: (String, u32), addr: SocketAddr| {
                log::info!("ip_session eviction {:?}", k);
                if let Some(v) = virtual_network_.get(&k.0) {
                    let mut lock = v.write();
                    if let Some(dev) = lock.clients.get(&k.1) {
                        if dev.address == addr {
                            lock.clients.remove(&k.1);
                            lock.epoch += 1;
                        }
                    }
                }
            });
        let virtual_network_ = virtual_network.clone();
        // 20秒钟没有收到消息则判定为掉线
        let addr_session = ExpireMap::new(move |addr: SocketAddr, (group, virtual_ip)| {
            log::info!(
                "addr_session eviction group={},virtual_ip={},addr={}",
                group,
                Ipv4Addr::from(virtual_ip),
                addr
            );

            if let Some(v) = virtual_network_.get(&group) {
                let mut lock = v.write();
                if let Some(item) = lock.clients.get_mut(&virtual_ip) {
                    if item.address != addr {
                        return;
                    }
                    item.online = false;
                    lock.epoch += 1;
                }
            }
        });
        let cipher_session = ExpireMap::new(|k, v| {});
        let auth_map = ExpireMap::new(|k, v| {});
        Self {
            virtual_network,
            ip_session,
            addr_session,
            cipher_session,
            auth_map,
        }
    }
}

impl AppCache {
    pub fn get_context(&self, addr: &SocketAddr) -> Option<Context> {
        if let Some((group, virtual_ip)) = self.addr_session.get(&addr) {
            if let Some(network_info) = self.virtual_network.get(&group) {
                Some(Context {
                    network_info,
                    group,
                    virtual_ip,
                })
            } else {
                None
            }
        } else {
            None
        }
    }
    pub async fn insert_cipher_session(&self, key: SocketAddr, value: Aes256GcmCipher) {
        self.cipher_session
            .insert(key, Arc::new(value), Duration::from_secs(120))
            .await
    }
    pub async fn insert_ip_session(&self, key: (String, u32), value: SocketAddr) {
        self.ip_session
            .insert(key, value, Duration::from_secs(24 * 3600))
            .await
    }
    pub async fn insert_addr_session(&self, key: SocketAddr, value: (String, u32)) {
        self.addr_session
            .insert(key, value, Duration::from_secs(20))
            .await
    }
}
