use crate::protocol::control_message::{
    ClientSimpleInfoList, ConfirmRegResponseMsg, ErrorResponseMsg, FastRegRequestMsg,
    FastRegResponseMsg, RegResponseMsg, RequestMessage, ResponseMessage, SelectiveBroadcast,
    SubnetSyncRequest, SubnetSyncResponse, SubscriptionConfigAck, SubscriptionPing,
};
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::rpc_message::rpc_message_request::RpcReqPayload;
use crate::protocol::rpc_message::rpc_message_response::RpcResPayload;
use crate::protocol::rpc_message::{ClientListResponse, RpcMessageRequest, RpcMessageResponse};
use crate::server::control_server::service::{
    ControlService, RegistrationStatus, Session, SubscriptionControlSession,
};
use anyhow::bail;
use bytes::{Bytes, BytesMut};
use pnet_packet::icmp::echo_request::EchoRequestPacket;
use pnet_packet::icmp::{IcmpCode, IcmpTypes, MutableIcmpPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use prost::Message;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::sync::mpsc::{Sender, WeakSender};

pub struct ControlHandler {
    control_service: ControlService,
    addr: SocketAddr,
    sender: WeakSender<Bytes>,
    session: Option<Session>,
    subscription_session: Option<SubscriptionControlSession>,
}

impl ControlHandler {
    pub fn new(
        control_service: ControlService,
        addr: SocketAddr,
        sender: WeakSender<Bytes>,
    ) -> Self {
        Self {
            control_service,
            addr,
            sender,
            session: None,
            subscription_session: None,
        }
    }

    pub async fn handle_reg(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        if self.session.is_some() || self.subscription_session.is_some() {
            bail!("Session is already active");
        }
        let request = RequestMessage::from_slice(buf)?;
        let Some(sender) = self.sender.upgrade() else {
            bail!("Sender is already dropped");
        };
        let reg = match request {
            RequestMessage::Reg(reg) => reg,
            RequestMessage::SubscriptionRegister(request) => {
                let response = match self
                    .control_service
                    .register_subscription_connection(request, sender.clone())
                    .await
                {
                    Ok((config, session)) => {
                        self.subscription_session = Some(session);
                        ResponseMessage::SubscriptionRegister(config)
                    }
                    Err(error) => ResponseMessage::Error(ErrorResponseMsg {
                        code: 403,
                        message: error.to_string(),
                    }),
                };
                sender.send(Bytes::from(response.encode())).await?;
                return Ok(());
            }
            RequestMessage::SubscriptionConfig(request) => {
                let response = match self
                    .control_service
                    .fetch_subscription_config(request)
                    .await
                {
                    Ok(config) => ResponseMessage::SubscriptionConfig(config),
                    Err(error) => ResponseMessage::Error(ErrorResponseMsg {
                        code: 403,
                        message: error.to_string(),
                    }),
                };
                sender.send(Bytes::from(response.encode())).await?;
                return Ok(());
            }
            _ => bail!("Expected registration or subscription configuration request"),
        };
        // Do not Debug-log registration requests: managed registrations contain
        // a reusable access token.
        log::info!(
            "registration request addr={}, network_code={}, device_id={}",
            self.addr,
            reg.network_code,
            reg.device_id
        );
        let registration_mode = reg.registration_mode;
        let session = match self.control_service.register(reg, sender.clone()).await {
            Ok(session) => session,
            Err(e) => {
                let msg_response = ErrorResponseMsg {
                    code: 400,
                    message: format!("{e}"),
                };
                let vec = ResponseMessage::Error(msg_response).encode();
                sender.send(Bytes::from(vec)).await?;
                return Ok(());
            }
        };
        log::info!(
            "register network_code={},device_id={},{}/{}, mode={:?}",
            session.network_code,
            session.device_id,
            session.ip,
            session.network_state.net_prefix_len(),
            registration_mode
        );
        let session = self.session.insert(session);

        let reg_msg_response = RegResponseMsg {
            ip: session.ip,
            prefix_len: session.network_state.net_prefix_len(),
            gateway: session.network_state.gateway(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            subnet_sync_supported: true,
            subscription_config_supported: false,
            subscription: None,
            server_instance_id: self.control_service.server_instance_id(),
            multi_link_supported: true,
            application_channel_supported: true,
        };
        let vec = ResponseMessage::Reg(reg_msg_response).encode();
        sender.send(Bytes::from(vec)).await?;
        if let Some((network_code, device_id)) = session.subscription_identity.clone()
            && let Err(error) = self
                .control_service
                .activate_subscription_session(&network_code, &device_id, session.random_id)
                .await
        {
            log::warn!("设备 {network_code}/{device_id} 注册后的受管配置补发失败: {error:#}");
        }
        Ok(())
    }

    /// 确认注册（预注册模式第二阶段）
    /// 先写 DB 再改状态，保证 Drop 时状态一致
    pub async fn handle_confirm_reg(&mut self) -> anyhow::Result<()> {
        let Some(session) = self.session.as_mut() else {
            bail!("Session is not active");
        };
        let Some(sender) = self.sender.upgrade() else {
            bail!("Sender is already dropped");
        };

        if session.registration_status != RegistrationStatus::PendingConfirmation {
            bail!("Session is not in pending confirmation state");
        }

        if let Err(e) = session
            .network_state
            .confirm_registration(&session.network_code, &session.device_id)
            .await
        {
            log::error!("Failed to save confirmed device: {:?}", e);
            let msg_response = ErrorResponseMsg {
                code: 500,
                message: format!("Failed to save registration: {e}"),
            };
            let vec = ResponseMessage::Error(msg_response).encode();
            sender.send(Bytes::from(vec)).await?;
            return Ok(());
        }

        session.registration_status = RegistrationStatus::Confirmed;

        log::info!(
            "Confirmed registration for network_code={}, device_id={}, ip={}",
            session.network_code,
            session.device_id,
            session.ip
        );

        let response = ConfirmRegResponseMsg { success: true };
        let vec = ResponseMessage::ConfirmReg(response).encode();
        sender.send(Bytes::from(vec)).await?;

        Ok(())
    }

    async fn handle_fast_reg(
        &mut self,
        request: FastRegRequestMsg,
        sender: &Sender<Bytes>,
    ) -> anyhow::Result<()> {
        let Some(session) = self.session.as_mut() else {
            bail!("Session is not active");
        };
        if session.registration_status != RegistrationStatus::Confirmed {
            bail!("Session is not confirmed");
        }

        let service = self.control_service.clone();
        let response = match service.fast_register(session, request.ip).await {
            Ok(()) => ResponseMessage::FastReg(FastRegResponseMsg { success: true }),
            Err(error) => ResponseMessage::Error(ErrorResponseMsg {
                code: 400,
                message: error.to_string(),
            }),
        };
        let response = Self::gateway_response_packet(MsgType::FastReg, &response.encode())?;
        sender.send(response).await?;
        Ok(())
    }

    fn gateway_response_packet(msg_type: MsgType, payload: &[u8]) -> anyhow::Result<Bytes> {
        let mut buf = BytesMut::zeroed(HEAD_LENGTH + payload.len());
        let mut packet = NetPacket::new(&mut buf)?;
        packet.set_msg_type(msg_type);
        packet.set_gateway_flag(true);
        packet.set_ttl(1);
        packet.set_payload(payload)?;
        Ok(buf.freeze())
    }

    pub async fn handle_gateway(&mut self, mut buf: BytesMut) -> anyhow::Result<()> {
        let mut packet = NetPacket::new(&mut buf)?;
        let msg_type = packet.msg_type()?;
        let Some(sender) = self.sender.upgrade() else {
            bail!("Sender is already dropped");
        };
        if packet.ttl() == 0 {
            return Ok(());
        }
        if msg_type == MsgType::FastReg {
            let request = match RequestMessage::from_slice(packet.payload())? {
                RequestMessage::FastReg(request) => request,
                _ => bail!("Expected fast registration request"),
            };
            return self.handle_fast_reg(request, &sender).await;
        }
        let Some(session) = self.session.as_ref() else {
            bail!("Session is not active");
        };
        match msg_type {
            MsgType::Turn => {
                if let Some(reply) = Self::handle_icmp_ping(&packet) {
                    _ = sender.try_send(reply);
                }
            }

            MsgType::PingTurn => {
                if packet.payload().len() == 8 {
                    packet.set_msg_type(MsgType::PongTurn);
                    _ = sender.try_send(buf.freeze());
                    return Ok(());
                }
                if packet.payload().len() != 8 + 8 {
                    return Ok(());
                }
                let data_version = u64::from_be_bytes(packet.payload()[8..].try_into()?);
                if (session.allow_ikev2
                    || session.allow_wireguard
                    || session.network_state.group_type()
                        == crate::server::control_server::db::GroupType::RemoteDesktop)
                    && let Some(peer_manager) = self.control_service.get_peer_manager()
                {
                    let mut list = session.network_state.full_client_simple_list(
                        session.ip,
                        session.allow_ikev2,
                        session.allow_wireguard,
                    );
                    let mut seen = list
                        .list
                        .iter()
                        .map(|client| client.ip)
                        .collect::<std::collections::HashSet<_>>();
                    for (ip, _, _, _, client_type) in
                        peer_manager.get_remote_devices(&session.network_code)
                    {
                        if ((client_type == crate::server::control_server::db::ClientType::Ikev2
                            && session.allow_ikev2)
                            || (client_type
                                == crate::server::control_server::db::ClientType::Wireguard
                                && session.allow_wireguard)
                            || (client_type
                                == crate::server::control_server::db::ClientType::RemoteDesktop
                                && session.network_state.group_type()
                                    == crate::server::control_server::db::GroupType::RemoteDesktop))
                            && seen.insert(ip)
                        {
                            list.list
                                .push(crate::protocol::control_message::ClientSimpleInfo {
                                ip,
                                online: true,
                                client_type: match client_type {
                                    crate::server::control_server::db::ClientType::Wireguard => {
                                        crate::protocol::control_message::ClientType::Wireguard
                                    }
                                    crate::server::control_server::db::ClientType::RemoteDesktop => crate::protocol::control_message::ClientType::RemoteDesktop,
                                    _ => crate::protocol::control_message::ClientType::Ikev2,
                                },
                            });
                        }
                    }
                    list.time = i64::from_be_bytes(packet.payload()[..8].try_into()?);
                    if let Some(buf) = Self::push_client_ips(list) {
                        _ = sender.try_send(buf);
                        return Ok(());
                    }
                }
                if let Some(mut list) = session.network_state.changed_client_simple_list(
                    session.ip,
                    data_version,
                    session.allow_ikev2,
                    session.allow_wireguard,
                ) {
                    list.time = i64::from_be_bytes(packet.payload()[..8].try_into()?);
                    if let Some(buf) = Self::push_client_ips(list) {
                        _ = sender.try_send(buf);
                        return Ok(());
                    }
                }
                packet.set_msg_type(MsgType::PongTurn);
                _ = sender.try_send(buf.freeze());
                return Ok(());
            }
            MsgType::Pong => {
                if packet.payload().len() == 8 {
                    let request_timestamp = u64::from_be_bytes(packet.payload().try_into()?);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let rtt = now.saturating_sub(request_timestamp);
                    let latency_ms = (rtt / 2) as u32;
                    self.control_service
                        .get_network_state_provider()
                        .update_client_latency(
                            &session.network_code,
                            session.ip,
                            session.random_id,
                            latency_ms,
                        );

                    log::debug!(
                        "Client latency updated: network_code={}, ip={}, latency={} ms",
                        session.network_code,
                        session.ip,
                        latency_ms
                    );
                }
            }
            MsgType::RpcReq => {
                self.handle_rpc(session, &sender, &packet)?;
            }
            MsgType::SubnetSyncReq => {
                let request = SubnetSyncRequest::from_slice(packet.payload())?;
                let (snapshot_hash, nodes) = self
                    .control_service
                    .subnet_snapshot(&session.network_code, session.ip);
                if request.known_hash != snapshot_hash {
                    let response = SubnetSyncResponse {
                        snapshot_hash,
                        nodes,
                    }
                    .encode();
                    let response =
                        Self::gateway_response_packet(MsgType::SubnetSyncRes, &response)?;
                    _ = sender.try_send(response);
                }
            }
            MsgType::SubscriptionConfigAck => {
                if session.subscription_server_proof.is_none() {
                    log::debug!("忽略未通过订阅链接验证的配置确认");
                } else if let Some((network_code, device_id)) = &session.subscription_identity {
                    let ack = SubscriptionConfigAck::from_slice(packet.payload())?;
                    let capabilities = self
                        .control_service
                        .acknowledge_subscription_config(
                            network_code,
                            device_id,
                            session.random_id,
                            ack,
                        )
                        .await?;
                    if let Some((allow_ikev2, allow_wireguard)) = capabilities
                        && let Some(session) = self.session.as_mut()
                    {
                        session.allow_ikev2 = allow_ikev2;
                        session.allow_wireguard = allow_wireguard;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn handle_data(&mut self, buf: BytesMut) -> anyhow::Result<()> {
        if let Some(subscription) = self.subscription_session.as_ref() {
            let Some(sender) = self.sender.upgrade() else {
                bail!("Sender is already dropped");
            };
            match RequestMessage::from_slice(&buf)? {
                RequestMessage::SubscriptionAck(ack) => {
                    self.control_service
                        .acknowledge_subscription_config(
                            &subscription.identity.0,
                            &subscription.identity.1,
                            subscription.random_id,
                            ack,
                        )
                        .await?;
                }
                RequestMessage::SubscriptionPing(SubscriptionPing { nonce }) => {
                    sender
                        .send(Bytes::from(
                            ResponseMessage::SubscriptionPong(SubscriptionPing { nonce }).encode(),
                        ))
                        .await?;
                }
                _ => bail!("unexpected message on subscription control connection"),
            }
            return Ok(());
        }
        let Some(session) = self.session.as_mut() else {
            bail!("Session is not active");
        };
        let Some(active_ip) = session.network_state.active_link_ip(
            session.ip,
            &session.client_instance_id,
            session.random_id,
        ) else {
            bail!("Session has been replaced by another client instance");
        };
        session.ip = active_ip;
        if session.registration_status == RegistrationStatus::PendingConfirmation {
            if let Ok(request) = RequestMessage::from_slice(&buf)
                && matches!(request, RequestMessage::ConfirmReg(_))
            {
                return self.handle_confirm_reg().await;
            }
            log::debug!("Ignoring data in pre-registration state");
            return Ok(());
        }

        let mut buf = buf;
        let packet_len = buf.len();
        let mut packet = NetPacket::new(&mut buf)?;
        let msg_type = packet.msg_type()?;
        let src = Ipv4Addr::from(packet.src_id());
        let dest = Ipv4Addr::from(packet.dest_id());
        if packet.is_gateway() {
            return self.handle_gateway(buf).await;
        }

        let session = self.session.as_ref().unwrap();

        session.network_state.record_tx_traffic(src, packet_len);

        if session
            .network_state
            .get_device_entry(&session.device_id)
            .is_some_and(|entry| {
                entry.client_type == crate::server::control_server::db::ClientType::RemoteDesktop
            })
            && !matches!(
                msg_type,
                MsgType::Application
                    | MsgType::Ping
                    | MsgType::Pong
                    | MsgType::PunchStart1
                    | MsgType::PunchStart2
                    | MsgType::PunchReq
                    | MsgType::PunchRes
            )
        {
            return Ok(());
        }
        match msg_type {
            MsgType::Application => {
                if src != session.ip
                    || self
                        .control_service
                        .client_type(&session.network_code, dest)
                        != Some(crate::server::control_server::db::ClientType::RemoteDesktop)
                    || !packet.decr_ttl()
                {
                    return Ok(());
                }
                let data = buf.freeze();
                let forwarded = if let Some(manager) = self.control_service.get_peer_manager() {
                    manager
                        .forward_with_best_route(&session.network_code, dest, data.clone())
                        .await
                } else {
                    false
                };
                if !forwarded && let Some(sender) = session.network_state.sender_map().get(&dest) {
                    session.network_state.record_rx_traffic(dest, data.len());
                    _ = sender.try_send(data);
                }
            }

            MsgType::Ikev2Relay => {
                if !session.allow_ikev2
                    || src != session.ip
                    || self
                        .control_service
                        .client_type(&session.network_code, dest)
                        != Some(crate::server::control_server::db::ClientType::Ikev2)
                {
                    return Ok(());
                }
                let Some(ipv4) = Ipv4Packet::new(packet.payload()) else {
                    return Ok(());
                };
                let header_length = ipv4.get_header_length() as usize * 4;
                if ipv4.get_version() != 4
                    || header_length < Ipv4Packet::minimum_packet_size()
                    || ipv4.get_total_length() as usize != packet.payload().len()
                    || !self.control_service.address_owned_by(
                        &session.network_code,
                        src,
                        ipv4.get_source(),
                    )
                    || !self.control_service.address_owned_by(
                        &session.network_code,
                        dest,
                        ipv4.get_destination(),
                    )
                {
                    return Ok(());
                }
                if !packet.decr_ttl() {
                    return Ok(());
                }
                let data = buf.freeze();
                let forwarded = if let Some(peer_manager) = self.control_service.get_peer_manager()
                {
                    peer_manager
                        .forward_with_best_route(&session.network_code, dest, data.clone())
                        .await
                } else {
                    false
                };
                if !forwarded && let Some(sender) = session.network_state.sender_map().get(&dest) {
                    session.network_state.record_rx_traffic(dest, data.len());
                    _ = sender.try_send(data);
                }
            }
            MsgType::WireGuardRelay => {
                if !session.allow_wireguard
                    || src != session.ip
                    || self
                        .control_service
                        .client_type(&session.network_code, dest)
                        != Some(crate::server::control_server::db::ClientType::Wireguard)
                {
                    return Ok(());
                }
                let Some(ipv4) = Ipv4Packet::new(packet.payload()) else {
                    return Ok(());
                };
                let header_length = ipv4.get_header_length() as usize * 4;
                if ipv4.get_version() != 4
                    || header_length < Ipv4Packet::minimum_packet_size()
                    || ipv4.get_total_length() as usize != packet.payload().len()
                    || !self.control_service.address_owned_by(
                        &session.network_code,
                        src,
                        ipv4.get_source(),
                    )
                    || !self.control_service.address_owned_by(
                        &session.network_code,
                        dest,
                        ipv4.get_destination(),
                    )
                {
                    return Ok(());
                }
                if !packet.decr_ttl() {
                    return Ok(());
                }
                let data = buf.freeze();
                let forwarded = if let Some(peer_manager) = self.control_service.get_peer_manager()
                {
                    peer_manager
                        .forward_with_best_route(&session.network_code, dest, data.clone())
                        .await
                } else {
                    false
                };
                if !forwarded && let Some(sender) = session.network_state.sender_map().get(&dest) {
                    session.network_state.record_rx_traffic(dest, data.len());
                    _ = sender.try_send(data);
                }
            }
            MsgType::Turn
            | MsgType::Ping
            | MsgType::Pong
            | MsgType::PunchStart1
            | MsgType::PunchStart2
            | MsgType::Quic => {
                if !packet.decr_ttl() {
                    return Ok(());
                }

                if let Some(peer_manager) = self.control_service.get_peer_manager() {
                    let network_code = session.network_code.clone();
                    let data = buf.freeze();

                    let forwarded = peer_manager
                        .forward_with_best_route(&network_code, dest, data.clone())
                        .await;

                    if !forwarded
                        && let Some(sender) = session.network_state.sender_map().get(&dest)
                    {
                        session.network_state.record_rx_traffic(dest, data.len());
                        _ = sender.try_send(data);
                    }
                } else {
                    let option = session
                        .network_state
                        .sender_map()
                        .get(&dest)
                        .map(|v| v.clone());
                    if let Some(sender) = option {
                        let data = buf.freeze();
                        session.network_state.record_rx_traffic(dest, data.len());
                        _ = sender.try_send(data);
                    }
                }
            }
            MsgType::Broadcast => {
                if !packet.decr_ttl() {
                    return Ok(());
                }
                let list: Vec<_> = session
                    .network_state
                    .sender_map()
                    .iter()
                    .filter(|v| v.key() != &src)
                    .map(|v| v.clone())
                    .collect();
                let buf = buf.freeze();
                for sender in list {
                    _ = sender.try_send(buf.clone());
                }

                // TODO: 广播到其他服务器（如果需要的话）
            }
            MsgType::ExcludeBroadcast => {
                let broadcast_packet = SelectiveBroadcast::from_slice(packet.payload())?;
                let mut packet = NetPacket::new(broadcast_packet.data)?;
                if !packet.decr_ttl() {
                    return Ok(());
                }
                let buf = Bytes::from(packet.into_buffer());
                let list: Vec<_> = session
                    .network_state
                    .sender_map()
                    .iter()
                    .filter(|v| !broadcast_packet.ips.contains(v.key()))
                    .filter(|v| v.key() != &src)
                    .map(|v| v.clone())
                    .collect();

                for sender in list {
                    _ = sender.try_send(buf.clone());
                }
            }
            MsgType::TargetBroadcast => {
                let broadcast_packet = SelectiveBroadcast::from_slice(packet.payload())?;
                let mut packet = NetPacket::new(broadcast_packet.data)?;
                if !packet.decr_ttl() {
                    return Ok(());
                }
                let buf = Bytes::from(packet.into_buffer());
                let list: Vec<_> = session
                    .network_state
                    .sender_map()
                    .iter()
                    .filter(|v| broadcast_packet.ips.contains(v.key()))
                    .filter(|v| v.key() != &src)
                    .map(|v| v.clone())
                    .collect();

                for sender in list {
                    _ = sender.try_send(buf.clone());
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn handle_rpc<B: AsRef<[u8]>>(
        &self,
        session: &Session,
        sender: &Sender<Bytes>,
        packet: &NetPacket<B>,
    ) -> anyhow::Result<()> {
        let req = RpcMessageRequest::decode(packet.payload())?;
        let Some(RpcReqPayload::ClientListReq(_)) = req.rpc_req_payload else {
            return Ok(());
        };
        let mut list = session.network_state.client_info_list(
            session.ip,
            session.allow_ikev2,
            session.allow_wireguard,
        );
        if let Some(manager) = self.control_service.get_peer_manager() {
            for device in manager.remote_client_infos(&session.network_code) {
                if !session.network_state.group_type().accepts(
                    crate::server::control_server::db::ClientType::from_i32(device.client_type),
                ) || device.ip == u32::from(session.ip)
                {
                    continue;
                }
                if let Some(local) = list.iter_mut().find(|d| d.id == device.id) {
                    if !local.online && device.online {
                        *local = device;
                    }
                } else {
                    list.push(device);
                }
            }
        }
        let response = RpcMessageResponse {
            id: req.id,
            rpc_res_payload: Some(RpcResPayload::ClientListRes(ClientListResponse { list })),
        }
        .encode_to_vec();
        let net_packet_len = HEAD_LENGTH + response.len();

        let mut reply_buf = BytesMut::zeroed(net_packet_len);
        let mut reply_net_packet = NetPacket::new(&mut reply_buf)?;
        reply_net_packet.set_msg_type(MsgType::RpcRes);
        reply_net_packet.set_gateway_flag(true);
        reply_net_packet.set_ttl(1);
        reply_net_packet.set_payload(&response)?;
        _ = sender.try_send(reply_buf.freeze());
        Ok(())
    }
    fn push_client_ips(list: ClientSimpleInfoList) -> Option<Bytes> {
        let bytes_mut = list.encode();
        let net_packet_len = HEAD_LENGTH + bytes_mut.len();
        let mut reply_buf = BytesMut::zeroed(net_packet_len);

        let mut reply_net_packet = NetPacket::new(&mut reply_buf).ok()?;
        reply_net_packet.set_msg_type(MsgType::PushClientIps);
        reply_net_packet.set_ttl(1);
        reply_net_packet.set_gateway_flag(true);
        reply_net_packet.set_payload(&bytes_mut).ok()?;

        Some(reply_buf.freeze())
    }

    fn handle_icmp_ping<B: AsRef<[u8]>>(packet: &NetPacket<B>) -> Option<Bytes> {
        let payload = packet.payload();
        let ipv4_packet = Ipv4Packet::new(payload)?;

        let ip_header_len = ipv4_packet.get_header_length() as usize * 4;
        let total_len = ipv4_packet.get_total_length() as usize;
        if ip_header_len < Ipv4Packet::minimum_packet_size()
            || ip_header_len > total_len
            || total_len > payload.len()
        {
            return None;
        }

        if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            return None;
        }

        let icmp_payload = &payload[ip_header_len..total_len];
        let echo_request = EchoRequestPacket::new(icmp_payload)?;
        if echo_request.get_icmp_type() != IcmpTypes::EchoRequest {
            return None;
        }

        let mut reply_ip_buf = vec![0u8; total_len];
        reply_ip_buf.copy_from_slice(&payload[..total_len]);

        // 交换 src/dst
        {
            let mut reply_ipv4 = MutableIpv4Packet::new(&mut reply_ip_buf)?;
            let src_ip = ipv4_packet.get_source();
            let dst_ip = ipv4_packet.get_destination();
            reply_ipv4.set_source(dst_ip);
            reply_ipv4.set_destination(src_ip);

            let checksum = pnet_packet::ipv4::checksum(&reply_ipv4.to_immutable());
            reply_ipv4.set_checksum(checksum);
        }

        {
            let icmp_buf = &mut reply_ip_buf[ip_header_len..];
            let mut reply_icmp = MutableIcmpPacket::new(icmp_buf)?;
            reply_icmp.set_icmp_type(IcmpTypes::EchoReply);
            reply_icmp.set_icmp_code(IcmpCode::new(0));

            let checksum = pnet_packet::icmp::checksum(&reply_icmp.to_immutable());
            reply_icmp.set_checksum(checksum);
        }

        let net_packet_len = HEAD_LENGTH + reply_ip_buf.len();
        let mut reply_buf = BytesMut::zeroed(net_packet_len);

        let mut reply_net_packet = NetPacket::new(&mut reply_buf).ok()?;
        reply_net_packet.set_msg_type(MsgType::Turn);
        reply_net_packet.set_gateway_flag(true);
        reply_net_packet.set_ttl(1);
        reply_net_packet.set_seq(packet.seq());
        reply_net_packet.set_payload(&reply_ip_buf).ok()?;
        Some(reply_buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::ControlHandler;
    use crate::protocol::control_message::{FastRegRequestMsg, RequestMessage};
    use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
    use bytes::BytesMut;
    use pnet_packet::icmp::IcmpTypes;
    use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet_packet::ipv4::MutableIpv4Packet;

    fn gateway_ping_packet(total_length: u16, header_length: u8) -> BytesMut {
        let mut buf = BytesMut::zeroed(HEAD_LENGTH + 28);
        let mut net_packet = NetPacket::new(&mut buf).expect("net packet");
        net_packet.set_msg_type(MsgType::Turn);
        net_packet.set_gateway_flag(true);
        net_packet.set_ttl(1);

        let payload = net_packet.payload_mut();
        let mut ipv4 = MutableIpv4Packet::new(payload).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(header_length);
        ipv4.set_total_length(total_length);
        ipv4.set_next_level_protocol(pnet_packet::ip::IpNextHeaderProtocols::Icmp);

        let mut echo = MutableEchoRequestPacket::new(&mut payload[20..]).expect("icmp packet");
        echo.set_icmp_type(IcmpTypes::EchoRequest);
        buf
    }

    #[test]
    fn malformed_icmp_total_length_is_rejected_without_panicking() {
        let buf = gateway_ping_packet(60, 5);
        let packet = NetPacket::new(buf).expect("net packet");
        assert!(ControlHandler::handle_icmp_ping(&packet).is_none());
    }

    #[test]
    fn malformed_icmp_header_length_is_rejected_without_panicking() {
        let buf = gateway_ping_packet(28, 15);
        let packet = NetPacket::new(buf).expect("net packet");
        assert!(ControlHandler::handle_icmp_ping(&packet).is_none());
    }

    #[test]
    fn valid_icmp_echo_request_gets_a_reply() {
        let buf = gateway_ping_packet(28, 5);
        let packet = NetPacket::new(buf).expect("net packet");
        assert!(ControlHandler::handle_icmp_ping(&packet).is_some());
    }

    #[test]
    fn fast_registration_is_wrapped_in_a_gateway_net_packet() {
        let ip = "10.26.0.9".parse().unwrap();
        let request = RequestMessage::FastReg(FastRegRequestMsg { ip }).encode();
        let bytes = ControlHandler::gateway_response_packet(MsgType::FastReg, &request)
            .expect("fast registration packet");
        let packet = NetPacket::new(bytes).expect("net packet");
        assert_eq!(packet.msg_type().unwrap(), MsgType::FastReg);
        assert!(packet.is_gateway());
        assert_eq!(packet.ttl(), 1);
        match RequestMessage::from_slice(packet.payload()).unwrap() {
            RequestMessage::FastReg(message) => assert_eq!(message.ip, ip),
            _ => panic!("unexpected request type"),
        }
    }
}
