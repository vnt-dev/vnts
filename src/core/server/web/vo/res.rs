use crate::core::entity::WireGuardConfig;
use base64::engine::general_purpose;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Serialize, Deserialize)]
pub struct WGData {
    pub group_id: String,
    pub virtual_ip: Ipv4Addr,
    pub device_id: String,
    pub name: String,
    pub config: WgConfig,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct WgConfig {
    pub vnts_endpoint: String,
    pub vnts_public_key: String,
    pub vnts_allowed_ips: String,

    pub public_key: String,
    pub private_key: String,
    // 合一起是 Address = ip/prefix
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub persistent_keepalive: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    // 设备ID
    pub device_id: String,
    // 客户端版本
    pub version: String,
    // 名称
    pub name: String,
    // 客户端间是否加密
    pub client_secret: bool,
    // 客户端和服务端是否加密
    pub server_secret: bool,
    // 链接服务器的来源地址
    pub address: SocketAddr,
    // 是否在线
    pub online: bool,
    // 分配的ip
    pub virtual_ip: Ipv4Addr,
    pub status_info: Option<ClientStatusInfo>,
    pub last_join_time: String,
    // wg配置
    pub wg_config: Option<WireGuardConfigRes>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireGuardConfigRes {
    pub vnts_endpoint: String,
    pub vnts_allowed_ips: String,
    pub group_id: String,
    pub device_id: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub persistent_keepalive: u16,
    pub secret_key: String,
    pub public_key: String,
}
impl From<WireGuardConfig> for WireGuardConfigRes {
    fn from(value: WireGuardConfig) -> Self {
        Self {
            vnts_endpoint: value.vnts_endpoint,
            vnts_allowed_ips: value.vnts_allowed_ips,
            group_id: value.group_id,
            device_id: value.device_id,
            ip: value.ip,
            prefix: value.prefix,
            persistent_keepalive: value.persistent_keepalive,
            secret_key: general_purpose::STANDARD.encode(&value.secret_key),
            public_key: general_purpose::STANDARD.encode(&value.public_key),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientStatusInfo {
    pub p2p_list: Vec<Ipv4Addr>,
    pub up_stream: u64,
    pub down_stream: u64,
    pub is_cone: bool,
    pub update_time: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    // 网段
    pub network_ip: Ipv4Addr,
    // 掩码
    pub mask_ip: Ipv4Addr,
    // 网关
    pub gateway_ip: Ipv4Addr,
    // vnts的公钥
    pub vnts_public_key: String,
    // 网段下的客户端列表
    pub clients: Vec<ClientInfo>,
}

impl NetworkInfo {
    pub fn new(
        network_ip: Ipv4Addr,
        mask_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        vnts_public_key: String,
    ) -> Self {
        Self {
            network_ip,
            mask_ip,
            gateway_ip,
            vnts_public_key,
            clients: Default::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupList {
    pub group_list: Vec<String>,
}
