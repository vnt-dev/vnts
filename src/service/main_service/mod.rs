use std::collections::HashMap;
use std::net::SocketAddr;
use moka::sync::Cache;
use std::time::Duration;
use std::sync::Arc;
use crossbeam_skiplist::SkipMap;
use parking_lot::RwLock;
use tokio::sync::mpsc::Sender;

mod udp_service;
mod tcp_service;
mod common;
pub use udp_service::start_udp;
pub use tcp_service::start_tcp;



lazy_static::lazy_static! {
    //七天不连接则回收ip
     static ref DEVICE_ID_SESSION:Cache<(String,String),()> = Cache::builder()
        .time_to_idle(Duration::from_secs(60*60*24*7)).eviction_listener(|k:Arc<(String,String)>,_,cause|{
			if cause!=moka::notification::RemovalCause::Expired{
				return;
			}
            log::info!("DEVICE_ID_SESSION eviction {:?}", k);
            if let Some(v) = VIRTUAL_NETWORK.get(&k.0){
                let mut lock = v.write();
                lock.virtual_ip_map.remove(&k.1);
                lock.epoch+=1;
            }
         }).build();
    //七天没有用户则回收网段缓存
    static ref VIRTUAL_NETWORK:Cache<String, Arc<RwLock<VirtualNetwork>>> = Cache::builder()
        .time_to_idle(Duration::from_secs(60*60*24*7)).build();
    static ref DEVICE_ADDRESS:SkipMap<(String,u32), PeerLink> = SkipMap::new();
    //udp专用 10秒钟没有收到消息则判定为掉线
    // 地址 -> 注册信息
    static ref UDP_SESSION:Cache<SocketAddr,Context> = Cache::builder()
        .time_to_idle(Duration::from_secs(10)).eviction_listener(|_,context:Context,cause|{
			if cause!=moka::notification::RemovalCause::Expired{
				return;
			}
            log::info!("UDP_SESSION eviction {:?}", context);
            if let Some(v) = VIRTUAL_NETWORK.get(&context.token){
                let mut lock = v.write();
                if let Some(mut item) = lock.virtual_ip_map.get_mut(&context.device_id){
                    if item.id!=context.id{
                        return;
                    }
                    item.status = PeerDeviceStatus::Offline;
                    DEVICE_ADDRESS.remove(&(context.token,context.virtual_ip));
                }
                lock.epoch+=1;
            }
         }).build();
}

#[derive(Clone)]
pub enum PeerLink {
    Tcp(Sender<Vec<u8>>),
    Udp(SocketAddr),
}


#[derive(Clone, Debug)]
pub struct Context {
    token: String,
    virtual_ip: u32,
    id: i64,
    device_id: String,
}

#[derive(Clone, Debug)]
pub struct VirtualNetwork {
    epoch: u32,
    // device_id -> DeviceInfo
    virtual_ip_map: HashMap<String, DeviceInfo>,
}

#[derive(Clone, Debug)]
pub struct DeviceInfo {
    id: i64,
    ip: u32,
    name: String,
    status: PeerDeviceStatus,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeerDeviceStatus {
    Online,
    Offline,
}

impl Into<u8> for PeerDeviceStatus {
    fn into(self) -> u8 {
        match self {
            PeerDeviceStatus::Online => 0,
            PeerDeviceStatus::Offline => 1,
        }
    }
}

impl From<u8> for PeerDeviceStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PeerDeviceStatus::Online,
            _ => PeerDeviceStatus::Offline
        }
    }
}