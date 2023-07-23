use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use chrono::Local;
use packet::icmp::{icmp, Kind};
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use parking_lot::RwLock;
use protobuf::Message;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use crate::ConfigInfo;
use crate::error::Error;
use crate::proto::message;
use crate::proto::message::{DeviceList, RegistrationRequest, RegistrationResponse};
use crate::protocol::ip_turn_packet::BroadcastPacketEnd;
use crate::protocol::{control_packet, error_packet, ip_turn_packet, MAX_TTL, NetPacket, Protocol, service_packet, Version};
use crate::service::igmp_server::Multicast;
use crate::service::main_service::{Context, DEVICE_ADDRESS, DEVICE_ID_SESSION, DeviceInfo, PeerDeviceStatus, PeerLink, UDP_SESSION, VIRTUAL_NETWORK, VirtualNetwork};

pub fn register(data: &[u8], config: &ConfigInfo, addr: SocketAddr, link: PeerLink) -> crate::error::Result<(Context, RegistrationResponse)> {
    let request = RegistrationRequest::parse_from_bytes(data)?;
    log::info!("register:{:?}",request);
    if let Some(white_token) = &config.white_token {
        if !white_token.contains(&request.token) {
            log::info!("token不在白名单，white_token={:?}，token={:?}",white_token,request.token);
            return Err(Error::TokenError);
        }
    }
    let mut response = RegistrationResponse::new();
    response.public_port = addr.port() as u32;
    match addr.ip() {
        IpAddr::V4(ipv4) => {
            response.public_ip = ipv4.into();
        }
        IpAddr::V6(ipv6) => {
            response.public_ipv6 = ipv6.octets().to_vec();
        }
    }
    response.virtual_netmask = config.netmask.into();
    response.virtual_gateway = config.gateway.into();
    let v = VIRTUAL_NETWORK.optionally_get_with(request.token.clone(), || {
        Some(Arc::new(parking_lot::const_rwlock(VirtualNetwork {
            epoch: 0,
            virtual_ip_map: HashMap::new(),
        })))
    }).unwrap();

    let mut lock = v.write();
    lock.epoch += 1;
    response.epoch = lock.epoch;
    let (id, mut virtual_ip) = if let Some(mut device_info) = lock.virtual_ip_map.get_mut(&request.device_id) {
        device_info.status = PeerDeviceStatus::Online;
        device_info.name = request.name.clone();
        if request.virtual_ip != 0 && device_info.ip != request.virtual_ip {
            (Local::now().timestamp_millis(), 0)
        } else {
            (Local::now().timestamp_millis(), device_info.ip)
        }
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
        let ip_range = (response.virtual_gateway & response.virtual_netmask) + 1..response.virtual_gateway | (!response.virtual_netmask);
        if request.virtual_ip != 0 {
            let ip = request.virtual_ip;
            if u32::from(config.gateway) == ip || u32::from(config.broadcast) == ip || !ip_range.contains(&ip) {
                log::warn!("手动指定的ip无效:{:?}", request);
                return Err(Error::InvalidIp);
            }
            //手动指定ip
            if set.contains(&ip) {
                log::warn!("手动指定的ip已经存在:{:?}", request);
                if !request.allow_ip_change {
                    return Err(Error::IpAlreadyExists);
                }
            } else {
                virtual_ip = ip;
            }
        }
        if virtual_ip == 0 {
            for ip in ip_range {
                if ip == response.virtual_gateway {
                    continue;
                }
                if !set.contains(&ip) {
                    virtual_ip = ip;
                    break;
                }
            }
        }
        if virtual_ip == 0 {
            log::error!("地址使用完:{:?}", request);
            return Err(Error::AddressExhausted);
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
            let mut dev = crate::proto::message::DeviceInfo::new();
            dev.virtual_ip = device_info.ip;
            dev.name = device_info.name.clone();
            let status: u8 = device_info.status.into();
            dev.device_status = status as u32;
            response.device_info_list.push(dev);
        }
    }
    DEVICE_ADDRESS.insert((request.token.clone(), virtual_ip), link.clone());
    drop(lock);
    DEVICE_ID_SESSION.insert((request.token.clone(), request.device_id.clone()), ());
    response.virtual_ip = virtual_ip;
    let context = Context {
        token: request.token.clone(),
        virtual_ip,
        id,
        device_id: request.device_id.clone(),
    };
    match link {
        PeerLink::Tcp(_) => {}
        PeerLink::Udp(_) => {
            UDP_SESSION.insert(
                addr,
                context.clone(),
            );
        }
    }
    Ok((context, response))
}

pub async fn broadcast(source_addr: SocketAddr, main_udp: &UdpSocket, context: &Context, buf: &[u8], multicast_info: Option<&RwLock<Multicast>>, exclude: &[Ipv4Addr]) -> crate::error::Result<()> {
    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
        let ips: Vec<u32> = v.read()
            .virtual_ip_map
            .iter()
            .map(|(_, device_info)| device_info.ip)
            .filter(|ip| ip != &context.virtual_ip)
            .collect();
        let multicast = multicast_info.map(|v| v.read().clone());
        for ip in ips {
            let ipv4 = Ipv4Addr::from(ip);
            if let Some(multicast) = &multicast {
                if !multicast.is_send(&ipv4) {
                    continue;
                }
            }
            if !exclude.contains(&ipv4) {
                if let Some(peer) = DEVICE_ADDRESS.get(&(context.token.clone(), ip)) {
                    match peer {
                        PeerLink::Tcp(sender) => {
                            let _ = sender.send(buf.to_vec()).await;
                        }
                        PeerLink::Udp(addr) => {
                            if addr != source_addr {
                                let _ = main_udp.send_to(&buf[4..], addr).await;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// 选择性转发广播/组播，并且去除尾部
pub async fn change_broadcast(source_addr: SocketAddr, udp: &UdpSocket, context: &Context, broadcast_addr: Ipv4Addr, destination: Ipv4Addr, buf: &[u8]) -> crate::error::Result<()> {
    let end_len = buf[buf.len() - 1] as usize * 4 + 1;
    if buf.len() <= end_len {
        return Err(Error::InvalidPacket);
    }
    let packet_end = BroadcastPacketEnd::new(&buf[buf.len() - end_len..])?;
    let end_len = packet_end.len();
    let exclude = packet_end.addresses();
    let buf = &buf[..buf.len() - end_len];
    if destination.is_broadcast() || broadcast_addr == destination {
        broadcast(source_addr, udp, context, buf, None, &exclude).await?;
    } else if destination.is_multicast() {
        if let Some(multicast_info) = crate::service::igmp_server
        ::load(&context.token, destination) {
            broadcast(source_addr, udp, context, buf, Some(&multicast_info), &exclude).await?;
        }
    }
    Ok(())
}

pub async fn handle(context: &mut Context, main_udp: &UdpSocket, buf: &mut [u8], addr: SocketAddr, config: &ConfigInfo, sender: Option<&Sender<Vec<u8>>>) -> crate::error::Result<()> {
    let reg: u8 = service_packet::Protocol::RegistrationRequest.into();
    match NetPacket::new(&mut buf[4..]) {
        Ok(mut net_packet) => {
            if net_packet.protocol() == Protocol::Service
                && net_packet.transport_protocol() == reg {
                let link = sender.map(|v| PeerLink::Tcp(v.clone())).unwrap_or(PeerLink::Udp(addr));
                //注册请求
                match register(net_packet.payload(), config, addr, link.clone()) {
                    Ok((c, response)) => {
                        *context = c;
                        let bytes = response.write_to_bytes()?;
                        let mut rs = vec![0u8; 4 + 12 + bytes.len()];
                        let mut net_packet = NetPacket::new(&mut rs[4..])?;
                        net_packet.set_version(Version::V1);
                        net_packet.set_protocol(Protocol::Service);
                        net_packet.set_source(config.gateway);
                        net_packet.set_destination(Ipv4Addr::UNSPECIFIED);
                        net_packet.set_transport_protocol(service_packet::Protocol::RegistrationResponse.into());
                        net_packet.first_set_ttl(MAX_TTL);
                        net_packet.set_payload(&bytes);
                        match link {
                            PeerLink::Tcp(sender) => {
                                let _ = sender.send(rs).await;
                            }
                            PeerLink::Udp(addr) => {
                                main_udp.send_to(net_packet.buffer(), addr).await?;
                            }
                        }
                    }
                    Err(e) => {
                        //带上tcp头
                        let mut rs = vec![0u8; 4 + 12];
                        let mut net_packet = NetPacket::new(&mut rs[4..]).unwrap();
                        net_packet.set_version(Version::V1);
                        net_packet.set_protocol(Protocol::Error);
                        net_packet.first_set_ttl(MAX_TTL);
                        net_packet.set_source(config.gateway);
                        match e {
                            Error::AddressExhausted => {
                                net_packet
                                    .set_transport_protocol(error_packet::Protocol::AddressExhausted.into());
                            }
                            Error::TokenError => {
                                net_packet
                                    .set_transport_protocol(error_packet::Protocol::TokenError.into());
                            }
                            Error::IpAlreadyExists => {
                                net_packet
                                    .set_transport_protocol(error_packet::Protocol::IpAlreadyExists.into());
                            }
                            Error::InvalidIp => {
                                net_packet
                                    .set_transport_protocol(error_packet::Protocol::InvalidIp.into());
                            }
                            e => {
                                log::info!("注册失败:{:?}",e);
                                return Ok(());
                            }
                        }
                        match link {
                            PeerLink::Tcp(sender) => {
                                let _ = sender.send(rs).await;
                            }
                            PeerLink::Udp(_) => {
                                main_udp.send_to(net_packet.buffer(), addr).await?;
                            }
                        }
                    }
                }
            } else {
                if context.virtual_ip != 0 {
                    let source = net_packet.source();
                    let destination = net_packet.destination();
                    if destination == config.gateway {
                        //给网关的消息
                        match net_packet.protocol() {
                            Protocol::Service => {
                                if service_packet::Protocol::PollDeviceList == service_packet::Protocol::from(net_packet.transport_protocol()) {
                                    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                                        let (ips, epoch) = {
                                            let lock = v.read();
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
                                            (ips, epoch)
                                        };
                                        let mut device_list = DeviceList::new();
                                        device_list.epoch = epoch;
                                        device_list.device_info_list = ips;
                                        log::info!("context:{:?},device_list:{:?}",context,device_list);
                                        let bytes = device_list.write_to_bytes()?;
                                        let mut vec = vec![0u8; 4 + 12 + bytes.len()];
                                        let mut device_list_packet =
                                            NetPacket::new(&mut vec[4..])?;
                                        device_list_packet.set_version(Version::V1);
                                        device_list_packet.set_protocol(Protocol::Service);
                                        device_list_packet.set_transport_protocol(
                                            service_packet::Protocol::PushDeviceList.into(),
                                        );
                                        device_list_packet.first_set_ttl(MAX_TTL);
                                        device_list_packet.set_source(destination);
                                        device_list_packet.set_destination(source);
                                        device_list_packet.set_payload(&bytes);
                                        match sender {
                                            None => {
                                                main_udp.send_to(device_list_packet.buffer(), addr).await?;
                                            }
                                            Some(sender) => {
                                                let _ = sender.send(vec).await;
                                            }
                                        }
                                    }
                                }
                            }
                            Protocol::Control => {
                                if control_packet::Protocol::Ping == control_packet::Protocol::from(net_packet.transport_protocol()) {
                                    let _ = DEVICE_ADDRESS.get(&(context.token.clone(), context.virtual_ip));
                                    let _ = DEVICE_ID_SESSION.get(&(context.token.clone(), context.device_id.clone()));
                                    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                                        let epoch = v.read().epoch;
                                        net_packet.first_set_ttl(MAX_TTL);
                                        net_packet.set_transport_protocol(control_packet::Protocol::Pong.into());
                                        net_packet.set_source(destination);
                                        net_packet.set_destination(source);
                                        let mut pong_packet = control_packet::PongPacket::new(net_packet.payload_mut())?;
                                        pong_packet.set_epoch(epoch as u16);
                                        match sender {
                                            None => {
                                                main_udp.send_to(net_packet.buffer(), addr).await?;
                                            }
                                            Some(sender) => {
                                                let _ = sender.send(buf.to_vec()).await;
                                            }
                                        }
                                    }
                                }
                            }
                            Protocol::IpTurn => {
                                let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
                                match ipv4.protocol() {
                                    ipv4::protocol::Protocol::Icmp => {
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
                                            match sender {
                                                None => {
                                                    main_udp.send_to(net_packet.buffer(), addr).await?;
                                                }
                                                Some(sender) => {
                                                    let _ = sender.send(buf.to_vec()).await;
                                                }
                                            }
                                        }
                                    }
                                    ipv4::protocol::Protocol::Igmp => {
                                        crate::service::igmp_server::handle(ipv4.payload(), &context.token, source)?;
                                        //Igmp数据也会广播出去，让大家都知道谁加入什么组播
                                        net_packet.set_destination(Ipv4Addr::new(224, 0, 0, 1));
                                        broadcast(addr, main_udp, &context, net_packet.buffer(), None, &[]).await?;
                                    }
                                    _ => {}
                                }
                            }
                            _ => {
                                log::info!("无效数据类型:{:?},Protocol={:?}",addr,net_packet.protocol())
                            }
                        }
                    } else {
                        //需要转发的数据
                        if net_packet.ttl() > 1 {
                            net_packet.set_ttl(net_packet.ttl() - 1);
                            if Protocol::IpTurn == net_packet.protocol() {
                                //处理广播
                                match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                                    ip_turn_packet::Protocol::Icmp => {}
                                    ip_turn_packet::Protocol::Igmp => {
                                        let ipv4 = IpV4Packet::new(net_packet.payload())?;
                                        if ipv4.protocol() == ipv4::protocol::Protocol::Igmp {
                                            crate::service::igmp_server::handle(ipv4.payload(), &context.token, source)?;
                                            //Igmp数据也会广播出去，让大家都知道谁加入什么组播
                                            broadcast(addr, main_udp, &context, buf, None, &[]).await?;
                                        }
                                        return Ok(());
                                    }
                                    ip_turn_packet::Protocol::Ipv4 => {
                                        //处理广播
                                        if destination.is_broadcast() || config.broadcast == destination {
                                            broadcast(addr, main_udp, &context, buf, None, &[]).await?;
                                            return Ok(());
                                        } else if destination.is_multicast() {
                                            if let Some(multicast_info) = crate::service::igmp_server
                                            ::load(&context.token, destination) {
                                                broadcast(addr, main_udp, &context, buf, Some(&multicast_info), &[]).await?;
                                            }
                                            return Ok(());
                                        }
                                    }
                                    ip_turn_packet::Protocol::Ipv4Broadcast => {
                                        net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
                                        return change_broadcast(addr, main_udp, &context, config.broadcast, destination, buf).await;
                                    }
                                    ip_turn_packet::Protocol::Unknown(_) => {}
                                }
                            }
                            //其他的直接转发
                            if let Some(peer) =
                                DEVICE_ADDRESS.get(&(context.token.clone(), destination.into()))
                            {
                                match peer {
                                    PeerLink::Tcp(sender) => {
                                        let _ = sender.send(buf.to_vec()).await;
                                    }
                                    PeerLink::Udp(addr) => {
                                        main_udp.send_to(net_packet.buffer(), addr).await?;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    let source = net_packet.source();
                    let mut rs = vec![0u8; 4 + 12];
                    let mut net_packet = NetPacket::new(&mut rs[4..])?;
                    net_packet.set_version(Version::V1);
                    net_packet.set_protocol(Protocol::Error);
                    net_packet.set_transport_protocol(error_packet::Protocol::Disconnect.into());
                    net_packet.first_set_ttl(MAX_TTL);
                    net_packet.set_source(config.gateway);
                    net_packet.set_destination(source);
                    if let Some(sender) = sender {
                        let _ = sender.send(rs).await;
                    } else {
                        main_udp.send_to(net_packet.buffer(), addr).await?;
                    }
                }
            }
        }
        Err(e) => {
            log::warn!("数据错误:{},{:?}",addr,e);
        }
    }
    return Ok(());
}



