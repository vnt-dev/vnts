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

use crate::cipher::Aes256GcmCipher;
use crate::cipher::{Finger, RsaCipher};
use crate::error::Error;
use crate::proto::message;
use crate::proto::message::{DeviceList, RegistrationRequest, RegistrationResponse};
use crate::protocol::ip_turn_packet::BroadcastPacket;
use crate::protocol::{
    body::ENCRYPTION_RESERVED, control_packet, error_packet, ip_turn_packet, service_packet,
    NetPacket, Protocol, Version, MAX_TTL,
};
use crate::service::igmp_server::Multicast;
use crate::service::main_service::{
    Context, DeviceInfo, PeerDeviceStatus, PeerLink, VirtualNetwork, DEVICE_ADDRESS,
    DEVICE_ID_SESSION, TCP_AES, UDP_AES, UDP_SESSION, VIRTUAL_NETWORK,
};
use crate::ConfigInfo;

fn check_reg(request: &RegistrationRequest) -> crate::error::Result<()> {
    if request.token.len() == 0 || request.token.len() > 64 {
        return Err(Error::InvalidPacket);
    }
    if request.device_id.len() == 0 || request.device_id.len() > 64 {
        return Err(Error::InvalidPacket);
    }
    if request.name.len() == 0 || request.name.len() > 64 {
        return Err(Error::InvalidPacket);
    }
    Ok(())
}

fn register0(
    context: &mut Option<Context>,
    data: &[u8],
    config: &ConfigInfo,
    addr: SocketAddr,
    link: PeerLink,
) -> crate::error::Result<RegistrationResponse> {
    let request = RegistrationRequest::parse_from_bytes(data)?;
    check_reg(&request)?;
    log::info!(
        "register,id={:?},name={:?},version={:?},virtual_ip={},client_secret={},allow_ip_change={},is_fast={}",
        request.device_id,
        request.name,
        request.version,
        request.virtual_ip,
        request.client_secret,
        request.allow_ip_change,
        request.is_fast
    );
    if let Some(white_token) = &config.white_token {
        if !white_token.contains(&request.token) {
            log::info!(
                "token不在白名单，white_token={:?}，token={:?}",
                white_token,
                request.token
            );
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
    let v = VIRTUAL_NETWORK
        .optionally_get_with(request.token.clone(), || {
            Some(Arc::new(parking_lot::const_rwlock(VirtualNetwork {
                epoch: 0,
                virtual_ip_map: HashMap::new(),
            })))
        })
        .unwrap();

    let mut lock = v.write();
    lock.epoch += 1;
    response.epoch = lock.epoch;
    let (id, mut virtual_ip) =
        if let Some(device_info) = lock.virtual_ip_map.get_mut(&request.device_id) {
            device_info.status = PeerDeviceStatus::Online;
            device_info.name = request.name.clone();
            device_info.client_secret = request.client_secret;
            device_info.id = Local::now().timestamp_millis();
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
            .filter(|(key, _)| *key != &request.device_id)
            .map(|(_, device_info)| device_info.ip)
            .collect();
        let ip_range = (response.virtual_gateway & response.virtual_netmask) + 1
            ..response.virtual_gateway | (!response.virtual_netmask);
        if request.virtual_ip != 0 {
            let ip = request.virtual_ip;
            if u32::from(config.gateway) == ip
                || u32::from(config.broadcast) == ip
                || !ip_range.contains(&ip)
            {
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
                client_secret: request.client_secret,
            },
        );
    } else {
        lock.virtual_ip_map.get_mut(&request.device_id).unwrap().id = id;
    }
    for (_device_id, device_info) in &lock.virtual_ip_map {
        if device_info.ip != virtual_ip {
            let mut dev = message::DeviceInfo::new();
            dev.virtual_ip = device_info.ip;
            dev.name = device_info.name.clone();
            let status: u8 = device_info.status.into();
            dev.device_status = status as u32;
            dev.client_secret = device_info.client_secret;
            response.device_info_list.push(dev);
        }
    }
    response.virtual_ip = virtual_ip;
    let c = context.get_or_insert_with(|| Context::default());
    c.id = id;
    c.virtual_ip = virtual_ip;
    c.token = request.token.clone();
    c.device_id = request.device_id.clone();
    c.client_secret = request.client_secret;
    c.address = addr;
    DEVICE_ADDRESS.insert(
        (request.token.clone(), virtual_ip),
        (link.clone(), c.clone()),
    );
    drop(lock);
    DEVICE_ID_SESSION.insert((request.token.clone(), request.device_id.clone()), id);
    match link {
        PeerLink::Tcp(_) => {}
        PeerLink::Udp(_) => {
            UDP_SESSION.insert(addr, c.clone());
        }
    }
    Ok(response)
}

async fn register(
    context: &mut Option<Context>,
    aes_gcm_cipher: &Option<Aes256GcmCipher>,
    main_udp: &UdpSocket,
    net_packet: NetPacket<&mut [u8]>,
    config: &ConfigInfo,
    addr: SocketAddr,
    sender: Option<&Sender<Vec<u8>>>,
) -> crate::error::Result<RegistrationResponse> {
    let link = sender
        .map(|v| PeerLink::Tcp(v.clone()))
        .unwrap_or(PeerLink::Udp(addr));
    match register0(context, net_packet.payload(), config, addr, link.clone()) {
        Ok(response) => {
            let bytes = response.write_to_bytes()?;
            let mut rs = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
            let mut packet = NetPacket::new_encrypt(&mut rs)?;
            packet.set_version(Version::V1);
            packet.set_protocol(Protocol::Service);
            packet.set_source(config.gateway);
            packet.set_destination(Ipv4Addr::UNSPECIFIED);
            packet.set_transport_protocol(service_packet::Protocol::RegistrationResponse.into());
            packet.first_set_ttl(MAX_TTL);
            packet.set_payload(&bytes)?;
            packet.set_gateway_flag(true);
            reply_vec(aes_gcm_cipher, &sender, main_udp, addr, rs).await?;
            Ok(response)
        }
        Err(e) => {
            let mut rs = vec![0u8; 12 + ENCRYPTION_RESERVED];
            let mut packet = NetPacket::new_encrypt(&mut rs).unwrap();
            packet.set_version(Version::V1);
            packet.set_protocol(Protocol::Error);
            packet.first_set_ttl(MAX_TTL);
            packet.set_source(config.gateway);
            packet.set_gateway_flag(true);
            match e {
                Error::AddressExhausted => {
                    packet.set_transport_protocol(error_packet::Protocol::AddressExhausted.into());
                }
                Error::TokenError => {
                    packet.set_transport_protocol(error_packet::Protocol::TokenError.into());
                }
                Error::IpAlreadyExists => {
                    packet.set_transport_protocol(error_packet::Protocol::IpAlreadyExists.into());
                }
                Error::InvalidIp => {
                    packet.set_transport_protocol(error_packet::Protocol::InvalidIp.into());
                }
                e => {
                    log::info!("注册失败:{:?}", e);
                    return Err(e);
                }
            }
            reply_vec(aes_gcm_cipher, &sender, main_udp, addr, rs).await?;
            return Err(e);
        }
    }
}

async fn broadcast(
    main_udp: &UdpSocket,
    context: &Context,
    buf: &[u8],
    multicast_info: Option<&RwLock<Multicast>>,
    exclude: &[Ipv4Addr],
) -> crate::error::Result<()> {
    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
        let ips: Vec<u32> = v
            .read()
            .virtual_ip_map
            .iter()
            .map(|(_, device_info)| device_info.ip)
            .filter(|ip| ip != &context.virtual_ip)
            .collect();
        let multicast = multicast_info.map(|v| v.read().clone());
        let client_secret = NetPacket::new(buf)?.is_encrypt();
        for ip in ips {
            let ipv4 = Ipv4Addr::from(ip);
            if let Some(multicast) = &multicast {
                if !multicast.is_send(&ipv4) {
                    continue;
                }
            }
            if !exclude.contains(&ipv4) {
                if let Some(peer) = DEVICE_ADDRESS.get(&(context.token.clone(), ip)) {
                    let (peer_link, peer_context) = peer.value().clone();
                    drop(peer);
                    if peer_context.client_secret == client_secret {
                        match peer_link {
                            PeerLink::Tcp(sender) => {
                                let _ = sender.send(buf.to_vec()).await;
                            }
                            PeerLink::Udp(addr) => {
                                let _ = main_udp.send_to(buf, addr).await;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn broadcast_igmp(
    main_udp: &UdpSocket,
    context: &Context,
    net_packet: NetPacket<&mut [u8]>,
) -> crate::error::Result<()> {
    let buf = if net_packet.reserve() != ENCRYPTION_RESERVED {
        let mut buf_packet = vec![0; net_packet.data_len() + ENCRYPTION_RESERVED];
        buf_packet.copy_from_slice(net_packet.buffer());
        buf_packet
    } else {
        net_packet.buffer().to_vec()
    };
    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
        let ips: Vec<u32> = v
            .read()
            .virtual_ip_map
            .iter()
            .map(|(_, device_info)| device_info.ip)
            .filter(|ip| ip != &context.virtual_ip)
            .collect();
        for ip in ips {
            if let Some(peer) = DEVICE_ADDRESS.get(&(context.token.clone(), ip)) {
                let (peer_link, peer_context) = peer.value().clone();
                drop(peer);
                match peer_link {
                    PeerLink::Tcp(sender) => {
                        if let Some(aes) = TCP_AES.get(&peer_context.address) {
                            let mut packet = NetPacket::new_encrypt(buf.clone())?;
                            aes.value().encrypt_ipv4(&mut packet)?;
                            drop(aes);
                            let _ = sender.send(packet.buffer().to_vec()).await;
                        } else {
                            let mut packet = NetPacket::new_encrypt(&buf)?;
                            let _ = sender.send(packet.buffer().to_vec()).await;
                        }
                    }
                    PeerLink::Udp(addr) => {
                        if let Some(aes) = UDP_AES.get(&peer_context.address) {
                            let mut packet = NetPacket::new_encrypt(buf.clone())?;
                            aes.encrypt_ipv4(&mut packet)?;
                            let _ = main_udp.send_to(packet.buffer(), addr).await;
                        } else {
                            let mut packet = NetPacket::new_encrypt(&buf)?;
                            let _ = main_udp.send_to(packet.buffer(), addr).await;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// 选择性转发广播/组播，并且去除尾部
async fn change_broadcast(
    udp: &UdpSocket,
    context: &Context,
    broadcast_addr: Ipv4Addr,
    destination: Ipv4Addr,
    broadcast_packet: BroadcastPacket<&[u8]>,
) -> crate::error::Result<()> {
    let exclude = broadcast_packet.addresses();
    let buf = broadcast_packet.data()?;
    if destination.is_broadcast() || broadcast_addr == destination {
        broadcast(udp, context, buf, None, &exclude).await?;
    } else if destination.is_multicast() {
        if let Some(multicast_info) = crate::service::igmp_server::load(&context.token, destination)
        {
            broadcast(udp, context, buf, Some(&multicast_info), &exclude).await?;
        }
    }
    Ok(())
}

async fn request_addr(
    aes_gcm_cipher: &Option<Aes256GcmCipher>,
    main_udp: &UdpSocket,
    addr: SocketAddr,
    net_packet: NetPacket<&mut [u8]>,
    sender: Option<&Sender<Vec<u8>>>,
) -> crate::error::Result<()> {
    match addr.ip() {
        IpAddr::V4(ipv4) => {
            let mut vec = vec![0u8; 12 + 6 + ENCRYPTION_RESERVED];
            let mut packet = NetPacket::new_encrypt(&mut vec)?;
            packet.set_version(Version::V1);
            packet.set_protocol(Protocol::Control);
            packet.set_transport_protocol(control_packet::Protocol::AddrResponse.into());
            packet.first_set_ttl(MAX_TTL);
            packet.set_source(net_packet.destination());
            packet.set_destination(net_packet.source());
            packet.set_gateway_flag(true);
            let mut addr_packet = control_packet::AddrPacket::new(packet.payload_mut())?;
            addr_packet.set_ipv4(ipv4);
            addr_packet.set_port(addr.port());
            reply_vec(aes_gcm_cipher, &sender, main_udp, addr, vec).await?;
        }
        IpAddr::V6(_) => {}
    }
    Ok(())
}
async fn server_packet_pre_handle(
    context: &mut Option<Context>,
    rsa_cipher: &Option<RsaCipher>,
    aes_gcm_cipher: &mut Option<Aes256GcmCipher>,
    main_udp: &UdpSocket,
    net_packet: NetPacket<&mut [u8]>,
    config: &ConfigInfo,
    addr: SocketAddr,
    sender: Option<&Sender<Vec<u8>>>,
) -> crate::error::Result<()> {
    let source = net_packet.source();
    let destination = net_packet.destination();
    match net_packet.protocol() {
        Protocol::Service => {
            match service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::RegistrationRequest => {
                    register(
                        context,
                        aes_gcm_cipher,
                        main_udp,
                        net_packet,
                        config,
                        addr,
                        sender,
                    )
                    .await?;
                }
                service_packet::Protocol::HandshakeRequest => {
                    // 握手请求,有加密的话回应公钥
                    let mut res = message::HandshakeResponse::new();
                    res.version = "1.1.3".to_string();
                    if let Some(rsp_cipher) = rsa_cipher {
                        res.public_key.extend_from_slice(rsp_cipher.public_key());
                        res.secret = true;
                        res.key_finger = rsp_cipher.finger()?;
                    }
                    let bytes = res.write_to_bytes()?;
                    let mut vec = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
                    let mut packet = NetPacket::new_encrypt(&mut vec)?;
                    packet.set_version(Version::V1);
                    packet.set_protocol(Protocol::Service);
                    packet
                        .set_transport_protocol(service_packet::Protocol::HandshakeResponse.into());
                    packet.first_set_ttl(MAX_TTL);
                    packet.set_source(destination);
                    packet.set_destination(source);
                    packet.set_payload(&bytes)?;
                    packet.set_gateway_flag(true);
                    reply_vec(&None, &sender, main_udp, addr, vec).await?;
                }
                service_packet::Protocol::SecretHandshakeRequest => {
                    // 同步密钥,这个是用公钥加密的,使用私钥解密
                    if aes_gcm_cipher.is_none() {
                        if let Some(rsp_cipher) = rsa_cipher {
                            let rsa_secret_body = rsp_cipher.decrypt(&net_packet)?;
                            let sync_secret = message::SecretHandshakeRequest::parse_from_bytes(
                                rsa_secret_body.data(),
                            )?;
                            if sync_secret.key.len() == 32 {
                                let c = Aes256GcmCipher::new(
                                    sync_secret.key.try_into().unwrap(),
                                    Finger::new(&sync_secret.token),
                                );
                                if sender.is_none() {
                                    UDP_AES.insert(addr, c.clone());
                                } else {
                                    TCP_AES.insert(addr, c.clone());
                                }
                                let _ = aes_gcm_cipher.insert(c);
                            }
                        }
                    }
                    let mut rs = vec![0u8; 12 + ENCRYPTION_RESERVED];
                    let mut packet = NetPacket::new_encrypt(&mut rs)?;
                    packet.set_version(Version::V1);
                    packet.set_protocol(Protocol::Service);
                    packet.set_source(config.gateway);
                    packet.set_destination(source);
                    packet.set_transport_protocol(
                        service_packet::Protocol::SecretHandshakeResponse.into(),
                    );
                    packet.first_set_ttl(MAX_TTL);
                    packet.set_gateway_flag(true);
                    reply_vec(aes_gcm_cipher, &sender, main_udp, addr, rs).await?;
                }
                _ => {}
            }
        }
        Protocol::Control => {
            match control_packet::Protocol::from(net_packet.transport_protocol()) {
                control_packet::Protocol::AddrRequest => {
                    request_addr(aes_gcm_cipher, main_udp, addr, net_packet, sender).await?;
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}
async fn server_packet_handle(
    rsa_cipher: &Option<RsaCipher>,
    aes_gcm_cipher: &mut Option<Aes256GcmCipher>,
    context: &mut Context,
    main_udp: &UdpSocket,
    mut net_packet: NetPacket<&mut [u8]>,
    config: &ConfigInfo,
    addr: SocketAddr,
    sender: Option<&Sender<Vec<u8>>>,
) -> crate::error::Result<()> {
    let source = net_packet.source();
    let destination = net_packet.destination();
    match net_packet.protocol() {
        Protocol::Service => {
            match service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::PollDeviceList => {
                    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                        let (ips, epoch) = {
                            let lock = v.read();
                            let ips: Vec<message::DeviceInfo> = lock
                                .virtual_ip_map
                                .iter()
                                .filter(|&(_, dev)| dev.ip != context.virtual_ip)
                                .map(|(_, device_info)| {
                                    let mut dev = message::DeviceInfo::new();
                                    dev.virtual_ip = device_info.ip;
                                    dev.name = device_info.name.clone();
                                    let status: u8 = device_info.status.into();
                                    dev.device_status = status as u32;
                                    dev.client_secret = device_info.client_secret;
                                    dev
                                })
                                .collect();
                            let epoch = lock.epoch;
                            (ips, epoch)
                        };
                        let mut device_list = DeviceList::new();
                        device_list.epoch = epoch;
                        device_list.device_info_list = ips;
                        let bytes = device_list.write_to_bytes()?;
                        let mut vec = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
                        let mut device_list_packet = NetPacket::new_encrypt(&mut vec)?;
                        device_list_packet.set_version(Version::V1);
                        device_list_packet.set_protocol(Protocol::Service);
                        device_list_packet.set_transport_protocol(
                            service_packet::Protocol::PushDeviceList.into(),
                        );
                        device_list_packet.first_set_ttl(MAX_TTL);
                        device_list_packet.set_source(destination);
                        device_list_packet.set_destination(source);
                        device_list_packet.set_payload(&bytes)?;
                        device_list_packet.set_gateway_flag(true);
                        reply_vec(aes_gcm_cipher, &sender, main_udp, addr, vec).await?;
                    }
                }
                _ => {}
            }
        }
        Protocol::Control => {
            match control_packet::Protocol::from(net_packet.transport_protocol()) {
                control_packet::Protocol::Ping => {
                    let _ =
                        DEVICE_ID_SESSION.get(&(context.token.clone(), context.device_id.clone()));
                    if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                        let epoch = v.read().epoch;
                        net_packet.first_set_ttl(MAX_TTL);
                        net_packet.set_transport_protocol(control_packet::Protocol::Pong.into());
                        net_packet.set_source(destination);
                        net_packet.set_destination(source);
                        net_packet.set_gateway_flag(true);
                        let mut pong_packet =
                            control_packet::PongPacket::new(net_packet.payload_mut())?;
                        pong_packet.set_epoch(epoch as u16);
                        reply_buf(aes_gcm_cipher, &sender, main_udp, addr, net_packet).await?;
                    }
                }
                _ => {}
            }
        }
        Protocol::IpTurn => {
            match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                ip_turn_packet::Protocol::Ipv4Broadcast => {
                    //处理选择性广播,进过网关还原成原始广播
                    let broadcast_packet = BroadcastPacket::new(net_packet.payload())?;
                    return change_broadcast(
                        main_udp,
                        &context,
                        config.broadcast,
                        destination,
                        broadcast_packet,
                    )
                    .await;
                }
                ip_turn_packet::Protocol::Ipv4 => {
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
                                net_packet.set_gateway_flag(true);
                                reply_buf(aes_gcm_cipher, &sender, main_udp, addr, net_packet)
                                    .await?;
                            }
                        }
                        ipv4::protocol::Protocol::Igmp => {
                            crate::service::igmp_server::handle(
                                ipv4.payload(),
                                &context.token,
                                source,
                            )?;
                            //Igmp数据也会广播出去，让大家都知道谁加入什么组播
                            net_packet.set_destination(Ipv4Addr::new(224, 0, 0, 1));
                            broadcast_igmp(main_udp, &context, net_packet).await?;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        _ => {
            log::info!(
                "无效数据类型:{:?},Protocol={:?}",
                addr,
                net_packet.protocol()
            )
        }
    }
    Ok(())
}

async fn transmit_handle(
    context: &Context,
    main_udp: &UdpSocket,
    mut net_packet: NetPacket<&mut [u8]>,
    config: &ConfigInfo,
) -> crate::error::Result<()> {
    let destination = net_packet.destination();
    let client_secret = net_packet.is_encrypt();
    if net_packet.ttl() > 1 {
        net_packet.set_ttl(net_packet.ttl() - 1);
        if Protocol::IpTurn == net_packet.protocol() {
            match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                ip_turn_packet::Protocol::Ipv4 => {
                    //处理广播
                    if destination.is_broadcast() || config.broadcast == destination {
                        broadcast(main_udp, &context, net_packet.buffer(), None, &[]).await?;
                        return Ok(());
                    } else if destination.is_multicast() {
                        if let Some(multicast_info) =
                            crate::service::igmp_server::load(&context.token, destination)
                        {
                            broadcast(
                                main_udp,
                                &context,
                                net_packet.buffer(),
                                Some(&multicast_info),
                                &[],
                            )
                            .await?;
                        }
                        return Ok(());
                    }
                }
                ip_turn_packet::Protocol::Ipv4Broadcast => {}
                ip_turn_packet::Protocol::Unknown(_) => {}
            }
        }
        //其他的直接转发
        if let Some(peer) = DEVICE_ADDRESS.get(&(context.token.clone(), destination.into())) {
            let (peer_link, peer_context) = peer.value().clone();
            drop(peer);
            if peer_context.client_secret == client_secret {
                match peer_link {
                    PeerLink::Tcp(sender) => {
                        if let Err(e) = sender.send(net_packet.buffer().to_vec()).await {
                            log::warn!(
                                "src={},to={},err:{:?}",
                                net_packet.source(),
                                destination,
                                e
                            );
                        }
                    }
                    PeerLink::Udp(addr) => {
                        if let Err(e) = main_udp.send_to(net_packet.buffer(), addr).await {
                            log::warn!(
                                "src={},to={},err:{:?}",
                                net_packet.source(),
                                destination,
                                e
                            );
                        }
                    }
                }
            }
        } else {
            log::warn!(
                "目标不存在:src={},dest={}",
                net_packet.source(),
                destination
            );
        }
    }
    Ok(())
}

async fn reply_vec(
    aes_gcm_cipher: &Option<Aes256GcmCipher>,
    sender: &Option<&Sender<Vec<u8>>>,
    main_udp: &UdpSocket,
    addr: SocketAddr,
    mut buf: Vec<u8>,
) -> crate::error::Result<()> {
    if let Some(aes) = aes_gcm_cipher {
        let mut packet = NetPacket::new_encrypt(&mut buf)?;
        aes.encrypt_ipv4(&mut packet)?;
        let len = packet.data_len();
        buf.truncate(len);
    } else {
        let len = buf.len();
        buf.truncate(len - ENCRYPTION_RESERVED);
    }
    if let Some(sender) = sender {
        if let Err(e) = sender.send(buf).await {
            log::warn!("回复失败：{},err={:?}", addr, e);
        }
    } else {
        main_udp.send_to(&buf, addr).await?;
    }
    Ok(())
}

async fn reply_buf(
    aes_gcm_cipher: &Option<Aes256GcmCipher>,
    sender: &Option<&Sender<Vec<u8>>>,
    main_udp: &UdpSocket,
    addr: SocketAddr,
    mut net_packet: NetPacket<&mut [u8]>,
) -> crate::error::Result<()> {
    if let Some(aes) = aes_gcm_cipher {
        aes.encrypt_ipv4(&mut net_packet)?;
    }
    if let Some(sender) = sender {
        if let Err(e) = sender.send(net_packet.buffer().to_vec()).await {
            log::warn!("回复失败：{},err={:?}", addr, e);
        }
    } else {
        main_udp.send_to(net_packet.buffer(), addr).await?;
    }
    Ok(())
}

pub async fn handle(
    rsa_cipher: &Option<RsaCipher>,
    aes_gcm_cipher: &mut Option<Aes256GcmCipher>,
    context: &mut Option<Context>,
    main_udp: &UdpSocket,
    buf: &mut [u8],
    addr: SocketAddr,
    config: &ConfigInfo,
    sender: Option<&Sender<Vec<u8>>>,
) -> crate::error::Result<()> {
    let reg: u8 = service_packet::Protocol::RegistrationRequest.into();
    let handshake: u8 = service_packet::Protocol::HandshakeRequest.into();
    let secret_handshake: u8 = service_packet::Protocol::SecretHandshakeRequest.into();
    let addr_req: u8 = control_packet::Protocol::AddrRequest.into();
    match NetPacket::new(buf) {
        Ok(mut net_packet) => {
            if net_packet.source_ttl() < net_packet.ttl() {
                return Ok(());
            }
            let p = net_packet.transport_protocol();
            if net_packet.is_gateway() {
                if !(net_packet.protocol() == Protocol::Service
                    && (p == handshake || p == secret_handshake))
                {
                    //解密数据
                    if let Some(aes) = aes_gcm_cipher {
                        aes.decrypt_ipv4(&mut net_packet)?;
                    } else if net_packet.is_encrypt() {
                        let source = net_packet.source();
                        log::info!(
                            "NoKey,source={},dest={},addr={}",
                            source,
                            net_packet.destination(),
                            addr
                        );
                        let mut rs = vec![0u8; 12 + ENCRYPTION_RESERVED];
                        let mut packet = NetPacket::new_encrypt(&mut rs)?;
                        packet.set_version(Version::V1);
                        packet.set_protocol(Protocol::Error);
                        packet.set_transport_protocol(error_packet::Protocol::NoKey.into());
                        packet.first_set_ttl(MAX_TTL);
                        packet.set_source(config.gateway);
                        packet.set_destination(source);
                        packet.set_gateway_flag(true);
                        reply_vec(&None, &sender, main_udp, addr, rs).await?;
                        return Ok(());
                    }
                }
            } else if config.check_finger {
                if let Some(context) = context {
                    //不是服务端的包虽然不能解密，但是可以验证数据合法性
                    if net_packet.is_encrypt() {
                        let finger = Finger::new(&context.token);
                        finger.check_finger(&net_packet)?;
                    }
                }
            }
            if net_packet.is_gateway()
                && ((net_packet.protocol() == Protocol::Service
                    && (p == reg || p == handshake || p == secret_handshake))
                    || (net_packet.protocol() == Protocol::Control && p == addr_req))
            {
                server_packet_pre_handle(
                    context,
                    rsa_cipher,
                    aes_gcm_cipher,
                    main_udp,
                    net_packet,
                    config,
                    addr,
                    sender,
                )
                .await?;
            } else if let Some(context) = context {
                if net_packet.is_gateway() || net_packet.destination() == config.gateway {
                    //给网关的消息
                    server_packet_handle(
                        rsa_cipher,
                        aes_gcm_cipher,
                        context,
                        main_udp,
                        net_packet,
                        config,
                        addr,
                        sender,
                    )
                    .await?;
                } else {
                    //需要转发的数据
                    transmit_handle(context, main_udp, net_packet, config).await?;
                }
            } else {
                let source = net_packet.source();
                log::info!(
                    "Disconnect,source={},dest={},addr={}",
                    source,
                    net_packet.destination(),
                    addr
                );
                let mut rs = vec![0u8; 12 + ENCRYPTION_RESERVED];
                let mut packet = NetPacket::new_encrypt(&mut rs)?;
                packet.set_version(Version::V1);
                packet.set_protocol(Protocol::Error);
                packet.set_transport_protocol(error_packet::Protocol::Disconnect.into());
                packet.first_set_ttl(MAX_TTL);
                packet.set_source(config.gateway);
                packet.set_destination(source);
                packet.set_gateway_flag(true);
                reply_vec(aes_gcm_cipher, &sender, main_udp, addr, rs).await?;
            }
        }
        Err(e) => {
            log::warn!("数据错误:{},{:?}", addr, e);
        }
    }
    return Ok(());
}
