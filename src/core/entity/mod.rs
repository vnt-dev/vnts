use crate::cipher::Aes256GcmCipher;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::Sender;

/// 网段信息
#[derive(Default)]
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
    pub epoch: u16,
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
pub struct ClientInfo {
    // 设备ID
    pub device_id: String,
    // 名称
    pub name: String,
    // 客户端间是否加密
    pub client_secret: bool,
    // 和服务端的加密方式
    pub server_secret: Option<Aes256GcmCipher>,
    // 链接服务器的来源地址
    pub address: SocketAddr,
    // 是否在线
    pub online: bool,
    // 分配的ip
    pub virtual_ip: u32,
    // 建立的tcp连接发送端
    pub tcp_sender: Option<Sender<Vec<u8>>>,
}

impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            device_id: "".to_string(),
            name: "".to_string(),
            client_secret: false,
            server_secret: None,
            address: "0.0.0.0:0".parse().unwrap(),
            online: false,
            virtual_ip: 0,
            tcp_sender: None,
        }
    }
}
