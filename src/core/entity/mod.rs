use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use chrono::{DateTime, Local};
use tokio::sync::mpsc::Sender;

#[derive(Clone, Debug)]
pub struct WireGuardConfig {
    pub vnts_endpoint: String,
    pub vnts_allowed_ips: String,
    pub group_id: String,
    pub device_id: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub persistent_keepalive: u16,
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
}
/// 网段信息
#[derive(Default, Debug)]
pub struct NetworkInfo {
    // 组网编号
    // pub group: String,
    // 网段
    pub network_ip: u32,
    // 掩码
    pub mask_ip: u32,
    // 网关
    pub gateway_ip: u32,
    // 纪元号
    pub epoch: u64,
    // 网段下的客户端列表 ip->ClientInfo
    pub clients: HashMap<u32, ClientInfo>,
}

impl NetworkInfo {
    pub fn new(network_ip: u32, mask_ip: u32, gateway_ip: u32) -> Self {
        Self {
            network_ip,
            mask_ip,
            gateway_ip,
            epoch: 0,
            clients: Default::default(),
        }
    }
}

/// 客户端信息
#[derive(Debug)]
pub struct ClientInfo {
    // 设备ID
    pub device_id: String,
    // 版本
    pub version: String,
    // 名称
    pub name: String,
    // 客户端间是否加密
    pub client_secret: bool,
    // 加密hash
    pub client_secret_hash: Vec<u8>,
    // 和服务端是否加密
    pub server_secret: bool,
    // 链接服务器的来源地址
    pub address: SocketAddr,
    // 是否在线
    pub online: bool,
    // 分配的ip
    pub virtual_ip: u32,
    // 建立的tcp连接发送端
    pub tcp_sender: Option<Sender<Vec<u8>>>,
    // wireguard客户端公钥
    pub wireguard: Option<[u8; 32]>,
    pub wg_sender: Option<Sender<(Vec<u8>, Ipv4Addr)>>,
    pub client_status: Option<ClientStatusInfo>,
    pub last_join_time: DateTime<Local>,
    pub timestamp: i64,
}
/// 客户端简要信息
#[derive(Debug)]
pub struct SimpleClientInfo {
    // 分配的ip
    pub virtual_ip: u32,
    // 版本
    pub version: String,
    // 名称
    pub name: String,
    // 客户端间是否加密
    pub client_secret: bool,
    // 加密hash
    pub client_secret_hash: Vec<u8>,
    // 和服务端是否加密
    pub server_secret: bool,
    // 是否在线
    pub online: bool,
    // 是wg客户端
    pub wireguard: bool,
}
impl From<&ClientInfo> for SimpleClientInfo {
    fn from(value: &ClientInfo) -> Self {
        Self {
            virtual_ip: value.virtual_ip,
            version: value.version.clone(),
            name: value.name.clone(),
            client_secret: value.client_secret,
            client_secret_hash: if value.online {
                value.client_secret_hash.clone()
            } else {
                vec![]
            },
            server_secret: value.server_secret,
            online: value.online,
            wireguard: value.wireguard.is_some(),
        }
    }
}
impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            device_id: "".to_string(),
            version: "".to_string(),
            name: "".to_string(),
            client_secret: false,
            client_secret_hash: vec![],
            server_secret: false,
            address: "0.0.0.0:0".parse().unwrap(),
            online: false,
            virtual_ip: 0,
            tcp_sender: None,
            wireguard: None,
            wg_sender: None,
            client_status: None,
            last_join_time: Local::now(),
            timestamp: 0,
        }
    }
}
#[derive(Debug)]
pub struct ClientStatusInfo {
    pub p2p_list: Vec<Ipv4Addr>,
    pub up_stream: u64,
    pub down_stream: u64,
    pub is_cone: bool,
    pub update_time: DateTime<Local>,
}

impl Default for ClientStatusInfo {
    fn default() -> Self {
        ClientStatusInfo {
            p2p_list: vec![],
            up_stream: 0,
            down_stream: 0,
            is_cone: false,
            update_time: Local::now(),
        }
    }
}
