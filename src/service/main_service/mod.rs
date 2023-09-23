use dashmap::DashMap;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use parking_lot::RwLock;
use tokio::sync::mpsc::Sender;

pub use tcp_service::start_tcp;
pub use udp_service::start_udp;

use crate::cipher::Aes256GcmCipher;

mod common;
mod tcp_service;
mod udp_service;

lazy_static::lazy_static! {
    //七天不连接则回收ip
     static ref DEVICE_ID_SESSION:Cache<(String,String),i64> = Cache::builder()
        .time_to_idle(Duration::from_secs(60*60*24*7)).eviction_listener(|k:Arc<(String,String)>,id:i64,cause|{
            if cause!=moka::notification::RemovalCause::Expired{
                return;
            }
            log::info!("DEVICE_ID_SESSION eviction {:?}", k);
            if let Some(v) = VIRTUAL_NETWORK.get(&k.0){
                let mut lock = v.write();
                if let Some(dev) = lock.virtual_ip_map.get(&k.1){
                    if dev.id==id{
                        lock.virtual_ip_map.remove(&k.1);
                        lock.epoch+=1;
                    }
                }
            }
         }).build();
    //七天没有用户则回收网段缓存
    static ref VIRTUAL_NETWORK:Cache<String, Arc<RwLock<VirtualNetwork>>> = Cache::builder()
        .time_to_idle(Duration::from_secs(60*60*24*7)).build();
    static ref DEVICE_ADDRESS:DashMap<(String,u32), (PeerLink,Context)> = DashMap::new();
    static ref TCP_AES:DashMap<SocketAddr,Aes256GcmCipher> = DashMap::new();
    static ref UDP_AES:Cache<SocketAddr,Aes256GcmCipher> = Cache::builder()
        .time_to_idle(Duration::from_secs(30)).build();
    //udp专用 20秒钟没有收到消息则判定为掉线
    // 地址 -> 注册信息
    static ref UDP_SESSION:Cache<SocketAddr,Context> = Cache::builder()
        .time_to_idle(Duration::from_secs(20)).eviction_listener(|_,context:Context,cause|{
            if cause!=moka::notification::RemovalCause::Expired{
                return;
            }
            log::info!("UDP_SESSION eviction token={},virtual_ip={},device_id={},id={}", context.token,context.virtual_ip,context.device_id,context.id);
            if let Some(v) = VIRTUAL_NETWORK.get(&context.token){
                let mut lock = v.write();
                if let Some(item) = lock.virtual_ip_map.get_mut(&context.device_id){
                    if item.id!=context.id{
                        return;
                    }
                    item.status = PeerDeviceStatus::Offline;
                    DEVICE_ADDRESS.remove(&(context.token,context.virtual_ip));
                    lock.epoch+=1;
                }
            }
         }).build();
}

#[derive(Clone)]
pub enum PeerLink {
    Tcp(Sender<Vec<u8>>),
    Udp(SocketAddr),
}

#[derive(Clone)]
pub struct Context {
    token: String,
    virtual_ip: u32,
    id: i64,
    device_id: String,
    client_secret: bool,
    address: SocketAddr,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            token: "".to_string(),
            virtual_ip: 0,
            id: 0,
            device_id: "".to_string(),
            client_secret: false,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }
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
    client_secret: bool,
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
            _ => PeerDeviceStatus::Offline,
        }
    }
}
