use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use chrono::Local;
use moka::sync::Cache;
use packet::icmp::{icmp, Kind};
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use parking_lot::Mutex;
use protobuf::Message;

use crate::error::*;
use crate::proto::message;
use crate::proto::message::{DeviceList, RegistrationRequest, RegistrationResponse};
use crate::protocol::{control_packet, error_packet, MAX_TTL, NetPacket, Protocol, service_packet, Version};

lazy_static::lazy_static! {
     static ref DEVICE_ID_SESSION:Cache<(String,String),()> = Cache::builder()
        .time_to_idle(Duration::from_secs(60*60*24*7)).eviction_listener(|k:Arc<(String,String)>,_,cause|{
			if cause!=moka::notification::RemovalCause::Expired{
				return;
			}
            log::info!("eviction {:?}", k);
            if let Some(v) = VIRTUAL_NETWORK.get(&k.0){
                let mut lock = v.lock();
                lock.virtual_ip_map.remove(&k.1);
                lock.epoch+=1;
            }
         }).build();
    //10秒钟没有收到消息则判定为掉线
    // 地址 -> 注册信息
    static ref SESSION:Cache<SocketAddr,Context> = Cache::builder()
        .time_to_idle(Duration::from_secs(10)).eviction_listener(|_,context:Context,cause|{
			if cause!=moka::notification::RemovalCause::Expired{
				return;
			}
            log::info!("eviction {:?}", context);
            if let Some(v) = VIRTUAL_NETWORK.get(&context.token){
                let mut lock = v.lock();
                if let Some(mut item) = lock.virtual_ip_map.get_mut(&context.device_id){
                    if item.id!=context.id{
                        return;
                    }
                    item.status = PeerDeviceStatus::Offline;
                }
                DEVICE_ADDRESS.invalidate(&(context.token,context.virtual_ip));
                lock.epoch+=1;
            }
         }).build();
    // (token,ip) ->地址
    static ref DEVICE_ADDRESS:Cache<(String,u32), SocketAddr> = Cache::builder()
        .time_to_idle(Duration::from_secs(2 * 61)).build();
    static ref VIRTUAL_NETWORK:Cache<String, Arc<Mutex<VirtualNetwork>>> = Cache::builder()
        .time_to_idle(Duration::from_secs(60*60*24*7)).build();
}
#[derive(Clone, Debug)]
struct Context {
    token: String,
    virtual_ip: u32,
    id: i64,
    device_id: String,
}

#[derive(Clone, Debug)]
struct VirtualNetwork {
    epoch: u32,
    // device_id -> DeviceInfo
    virtual_ip_map: HashMap<String, DeviceInfo>,
}

#[derive(Clone, Debug)]
struct DeviceInfo {
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

pub fn handle_loop(udp: UdpSocket) {
    let mut buf = [0u8; 65536];
    loop {
        match udp.recv_from(&mut buf) {
            Ok((len, addr)) => {
                match handle(&udp, &mut buf[..len], addr) {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("{:?}", e)
                    }
                }
            }
            Err(e) => {
                log::error!("{:?}", e)
            }
        }
    }
}

fn handle(udp: &UdpSocket, buf: &mut [u8], addr: SocketAddr) -> Result<()> {
    let net_packet = NetPacket::new(buf)?;
    if net_packet.protocol() == Protocol::Service
        && net_packet.transport_protocol()
        == <service_packet::Protocol as Into<u8>>::into(
        service_packet::Protocol::RegistrationRequest,
    )
    {
        let request = RegistrationRequest::parse_from_bytes(net_packet.payload())?;
        log::info!("register:{:?}",request);
        let mut response = RegistrationResponse::new();
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                response.public_ip = ipv4.into();
                response.public_port = addr.port() as u32;
            }
            IpAddr::V6(_) => {
                log::error!("不支持ipv6{:?}", request);
                return Ok(());
            }
        }
        //todo 暂时写死地址 考虑验证token,比如从数据库根据token读出网关
        response.virtual_netmask = u32::from_be_bytes(NETMASK.octets());
        response.virtual_gateway = u32::from_be_bytes(GATE_WAY.octets());
        if let Some(v) = VIRTUAL_NETWORK.optionally_get_with(request.token.clone(), || {
            Some(Arc::new(parking_lot::const_mutex(VirtualNetwork {
                epoch: 0,
                virtual_ip_map: HashMap::new(),
            })))
        }) {
            let mut lock = v.lock();
            lock.epoch += 1;
            response.epoch = lock.epoch;
            let (id, mut virtual_ip) =
                if let Some(mut device_info) = lock.virtual_ip_map.get_mut(&request.device_id) {
                    device_info.status = PeerDeviceStatus::Online;
                    (device_info.id, device_info.ip)
                } else {
                    (Local::now().timestamp_millis(), 0)
                };
            if virtual_ip == 0 {
                //获取一个未使用的ip
                let set: HashSet<u32> = lock
                    .virtual_ip_map
                    .iter()
                    .map(|(_, device_info)| device_info.ip)
                    .collect();
                for ip in response.virtual_gateway + 1..response.virtual_gateway + 128 {
                    if !set.contains(&ip) {
                        virtual_ip = ip;
                        break;
                    }
                }
                if virtual_ip == 0 {
                    log::error!("地址使用完:{:?}", request);
                    let mut net_packet = NetPacket::new([0u8; 12])?;
                    net_packet.set_version(Version::V1);
                    net_packet.set_protocol(Protocol::Error);
                    net_packet
                        .set_transport_protocol(error_packet::Protocol::AddressExhausted.into());
                    net_packet.first_set_ttl(MAX_TTL);
                    net_packet.set_source(GATE_WAY);
                    udp.send_to(net_packet.buffer(), addr)?;
                    return Ok(());
                }
                lock.virtual_ip_map.insert(
                    request.device_id.clone(),
                    DeviceInfo {
                        id,
                        name: request.name.clone(),
                        ip: virtual_ip,
                        status: PeerDeviceStatus::Online,
                    },
                );
            }
            for (_device_id, device_info) in &lock.virtual_ip_map {
                if device_info.ip != virtual_ip {
                    let mut dev = message::DeviceInfo::new();
                    dev.virtual_ip = device_info.ip;
                    dev.name = device_info.name.clone();
                    let status: u8 = device_info.status.into();
                    dev.device_status = status as u32;
                    response.device_info_list.push(dev);
                }
            }
            DEVICE_ID_SESSION.insert((request.token.clone(), request.device_id.clone()), ());
            DEVICE_ADDRESS.insert((request.token.clone(), virtual_ip), addr);
            drop(lock);
            response.virtual_ip = virtual_ip;
            SESSION.insert(
                addr,
                Context {
                    token: request.token.clone(),
                    virtual_ip,
                    id,
                    device_id: request.device_id.clone(),
                },
            );
        }
        let bytes = response.write_to_bytes()?;

        let mut net_packet = NetPacket::new(vec![0u8; 12 + bytes.len()])?;
        net_packet.set_version(Version::V1);
        net_packet.set_protocol(Protocol::Service);
        net_packet.set_source(GATE_WAY);
        net_packet.set_destination(Ipv4Addr::from(response.virtual_ip));
        net_packet.set_transport_protocol(service_packet::Protocol::RegistrationResponse.into());
        net_packet.first_set_ttl(MAX_TTL);
        net_packet.set_payload(&bytes);
        udp.send_to(net_packet.buffer(), addr)?;
        return Ok(());
    } else if let Some(context) = SESSION.get(&addr) {
        if DEVICE_ADDRESS
            .get(&(context.token.clone(), context.virtual_ip))
            .is_some()
        {
            if DEVICE_ID_SESSION
                .get(&(context.token.clone(), context.device_id.clone()))
                .is_some()
            {
                handle_(udp, addr, net_packet, context)?;
                return Ok(());
            }
        }
    }
    let source = net_packet.source();
    let mut net_packet = NetPacket::new([0u8; 12])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Error);
    net_packet.set_transport_protocol(error_packet::Protocol::Disconnect.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_source(GATE_WAY);
    net_packet.set_destination(source);
    udp.send_to(net_packet.buffer(), addr)?;
    Ok(())
}

const GATE_WAY: Ipv4Addr = Ipv4Addr::new(10, 26, 0, 1);
const BROADCAST: Ipv4Addr = Ipv4Addr::new(10, 26, 0, 255);
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

fn handle_(
    udp: &UdpSocket,
    addr: SocketAddr,
    mut net_packet: NetPacket<&mut [u8]>,
    context: Context,
) -> Result<()> {
    let source = net_packet.source();
    let destination = net_packet.destination();
    if destination != GATE_WAY {
        // 转发
        if net_packet.ttl() > 1 {
            net_packet.set_ttl(net_packet.ttl() - 1);
            if destination.is_broadcast() || (destination.octets()[3] == 255 && BROADCAST == destination) {
                //本地广播和直接广播
                if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                    if let Some(lock) = v.try_lock() {
                        let ips: Vec<u32> = lock
                            .virtual_ip_map
                            .iter()
                            .map(|(_, device_info)| device_info.ip)
                            .filter(|ip| ip != &context.virtual_ip)
                            .collect();
                        drop(lock);
                        for ip in ips {
                            if let Some(peer) = DEVICE_ADDRESS.get(&(context.token.clone(), ip)) {
                                udp.send_to(net_packet.buffer(), peer)?;
                            }
                        }
                    }
                }
            } else if let Some(peer) =
                DEVICE_ADDRESS.get(&(context.token, destination.into()))
            {
                udp.send_to(net_packet.buffer(), peer)?;
            }
        }
        return Ok(());
    }
    match net_packet.protocol() {
        Protocol::Service => {
            match service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::RegistrationRequest => {}
                service_packet::Protocol::RegistrationResponse => {}
                service_packet::Protocol::UnKnow(_) => {}
                service_packet::Protocol::PollDeviceList => {
                    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                        //优先级较低，获取不到锁也问题不大
                        if let Some(lock) = v.try_lock() {
                            let ips: Vec<message::DeviceInfo> = lock
                                .virtual_ip_map
                                .iter()
                                .filter(|&(_, dev)| {
                                    dev.ip != context.virtual_ip
                                })
                                .map(|(_, device_info)| {
                                    let mut dev = message::DeviceInfo::new();
                                    dev.virtual_ip = device_info.ip;
                                    dev.name = device_info.name.clone();
                                    let status: u8 = device_info.status.into();
                                    dev.device_status = status as u32;
                                    dev
                                })
                                .collect();
                            let epoch = lock.epoch;
                            drop(lock);
                            let mut device_list = DeviceList::new();
                            device_list.epoch = epoch;
                            device_list.device_info_list = ips;
                            let bytes = device_list.write_to_bytes()?;
                            let mut device_list_packet =
                                NetPacket::new(vec![0u8; 12 + bytes.len()])?;
                            device_list_packet.set_version(Version::V1);
                            device_list_packet.set_protocol(Protocol::Service);
                            device_list_packet.set_transport_protocol(
                                service_packet::Protocol::PushDeviceList.into(),
                            );
                            device_list_packet.first_set_ttl(MAX_TTL);
                            device_list_packet.set_source(destination);
                            device_list_packet.set_destination(source);
                            device_list_packet.set_payload(&bytes);
                            udp.send_to(device_list_packet.buffer(), addr)?;
                            log::info!("device_list_packet {:?}",device_list_packet);
                        }
                    }
                }
                service_packet::Protocol::PushDeviceList => {}
            }
        }
        Protocol::Control => {
            match control_packet::Protocol::from(net_packet.transport_protocol()) {
                control_packet::Protocol::Ping => {
                    net_packet.first_set_ttl(MAX_TTL);
                    net_packet.set_transport_protocol(control_packet::Protocol::Pong.into());
                    net_packet.set_source(destination);
                    net_packet.set_destination(source);
                    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                        //优先级较低，获取不到锁也问题不大
                        if let Some(lock) = v.try_lock() {
                            let mut pong_packet = control_packet::PongPacket::new(net_packet.payload_mut())?;
                            pong_packet.set_epoch(lock.epoch as u16);
                        }
                    }
                    udp.send_to(net_packet.buffer(), addr)?;
                }
                _ => {}
            }
        }
        Protocol::Error => {}
        Protocol::OtherTurn => {}
        Protocol::Ipv4Turn => {
            let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
            if ipv4.protocol() == ipv4::protocol::Protocol::Icmp {
                let mut icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
                if icmp_packet.kind() == Kind::EchoRequest {
                    //开启ping
                    icmp_packet.set_kind(Kind::EchoReply);
                    icmp_packet.update_checksum();
                    ipv4.set_source_ip(destination);
                    ipv4.set_destination_ip(source);
                    ipv4.update_checksum();
                    net_packet.set_source(destination);
                    net_packet.set_destination(source);
                    udp.send_to(net_packet.buffer(), addr)?;
                    return Ok(());
                }
            }
        }
        Protocol::UnKnow(_) => {}
    }
    Ok(())
}
