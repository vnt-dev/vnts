use crate::protocol::control_message::{
    ClientSimpleInfoList, ConfirmRegResponseMsg, ErrorResponseMsg, RegResponseMsg, RequestMessage,
    ResponseMessage, SelectiveBroadcast,
};
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::rpc_message::rpc_message_request::RpcReqPayload;
use crate::protocol::rpc_message::rpc_message_response::RpcResPayload;
use crate::protocol::rpc_message::{ClientListResponse, RpcMessageRequest, RpcMessageResponse};
use crate::server::control_server::service::{ControlService, RegistrationStatus, Session};
use anyhow::bail;
use bytes::{Bytes, BytesMut};
use pnet_packet::Packet;
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
        }
    }

    pub async fn handle_reg(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        if self.session.is_some() {
            bail!("Session is already active");
        }
        let request = RequestMessage::from_slice(buf)?;
        let reg = match request {
            RequestMessage::Reg(reg) => reg,
            _ => bail!("Expected registration request"),
        };
        log::info!("addr={},{:?}", self.addr, reg);
        let Some(sender) = self.sender.upgrade() else {
            bail!("Sender is already dropped");
        };
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
        };
        let vec = ResponseMessage::Reg(reg_msg_response).encode();
        sender.send(Bytes::from(vec)).await?;
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
    pub async fn handle_gateway(&self, mut buf: BytesMut) -> anyhow::Result<()> {
        let Some(session) = self.session.as_ref() else {
            bail!("Session is not active");
        };
        let mut packet = NetPacket::new(&mut buf)?;
        let msg_type = packet.msg_type()?;
        let Some(sender) = self.sender.upgrade() else {
            bail!("Sender is already dropped");
        };
        if packet.ttl() == 0 {
            return Ok(());
        }
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
                if let Some(mut list) = session
                    .network_state
                    .changed_client_simple_list(session.ip, data_version)
                {
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
                        .update_client_latency(&session.network_code, session.ip, latency_ms);

                    log::debug!(
                        "Client latency updated: network_code={}, ip={}, latency={} ms",
                        session.network_code,
                        session.ip,
                        latency_ms
                    );
                }
            }
            MsgType::RpcReq => {
                Self::handle_rpc(session, &sender, &packet)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn handle_data(&mut self, buf: BytesMut) -> anyhow::Result<()> {
        if let Some(session) = self.session.as_ref() {
            if session.registration_status == RegistrationStatus::PendingConfirmation {
                if let Ok(request) = RequestMessage::from_slice(&buf) {
                    if matches!(request, RequestMessage::ConfirmReg(_)) {
                        return self.handle_confirm_reg().await;
                    }
                }
                log::debug!("Ignoring data in pre-registration state");
                return Ok(());
            }
        } else {
            bail!("Session is not active");
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

        match msg_type {
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

                    if !forwarded {
                        if let Some(sender) = session.network_state.sender_map().get(&dest) {
                            session.network_state.record_rx_traffic(dest, data.len());
                            _ = sender.try_send(data);
                        }
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
                let list: Vec<Sender<Bytes>> = session
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
                let list: Vec<Sender<Bytes>> = session
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
                let list: Vec<Sender<Bytes>> = session
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
        session: &Session,
        sender: &Sender<Bytes>,
        packet: &NetPacket<B>,
    ) -> anyhow::Result<()> {
        let req = RpcMessageRequest::decode(packet.payload())?;
        let Some(RpcReqPayload::ClientListReq(_)) = req.rpc_req_payload else {
            return Ok(());
        };
        let list = session.network_state.client_info_list(session.ip);
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

        if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            return None;
        }

        let icmp_payload = ipv4_packet.payload();
        let echo_request = EchoRequestPacket::new(icmp_payload)?;
        if echo_request.get_icmp_type() != IcmpTypes::EchoRequest {
            return None;
        }

        let ip_header_len = ipv4_packet.get_header_length() as usize * 4;
        let total_len = ipv4_packet.get_total_length() as usize;

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
