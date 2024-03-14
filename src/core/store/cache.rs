use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use parking_lot::RwLock;

use crate::cipher::Aes256GcmCipher;
use crate::core::entity::NetworkInfo;

#[derive(Clone)]
pub struct AppCache {
    // group -> NetworkInfo
    pub virtual_network: Cache<String, Arc<RwLock<NetworkInfo>>>,
    // (group,ip) -> addr
    pub ip_session: Cache<(String, u32), SocketAddr>,
    // addr -> (group，ip)
    pub addr_session: Cache<SocketAddr, (String, u32)>,
    pub cipher_session: Cache<SocketAddr, Arc<Aes256GcmCipher>>,
}

pub struct Context {
    pub network_info: Arc<RwLock<NetworkInfo>>,
    pub group: String,
    pub virtual_ip: u32,
}

impl AppCache {
    pub fn new() -> Self {
        // 网段7天未使用则回收
        let virtual_network: Cache<String, Arc<RwLock<NetworkInfo>>> = Cache::builder()
            .time_to_idle(Duration::from_secs(60 * 60 * 24 * 7))
            .build();
        let virtual_network_ = virtual_network.clone();
        // ip一天未使用则回收
        let ip_session: Cache<(String, u32), SocketAddr> = Cache::builder()
            .time_to_idle(Duration::from_secs(60 * 60 * 24 * 1))
            .eviction_listener(move |k: Arc<(String, u32)>, addr: SocketAddr, cause| {
                if cause != moka::notification::RemovalCause::Expired {
                    return;
                }
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
            })
            .build();
        let virtual_network_ = virtual_network.clone();
        // 20秒钟没有收到消息则判定为掉线
        let addr_session = Cache::builder()
            .time_to_idle(Duration::from_secs(20))
            .eviction_listener(move |addr: Arc<SocketAddr>, (group, virtual_ip), cause| {
                if cause != moka::notification::RemovalCause::Expired {
                    return;
                }
                log::info!(
                    "addr_session eviction group={},virtual_ip={}",
                    group,
                    virtual_ip
                );
                if let Some(v) = virtual_network_.get(&group) {
                    let mut lock = v.write();
                    if let Some(item) = lock.clients.get_mut(&virtual_ip) {
                        if item.address != *addr {
                            return;
                        }
                        item.online = false;
                        lock.epoch += 1;
                    }
                }
            })
            .build();
        let cipher_session = Cache::builder()
            .time_to_idle(Duration::from_secs(60 * 2))
            .build();
        Self {
            virtual_network,
            ip_session,
            addr_session,
            cipher_session,
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
}
