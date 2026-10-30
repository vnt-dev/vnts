#![allow(dead_code)]

use crate::protocol::ProtoToBytesMut;
use crate::protocol::control_message::proto::request_message::RequestPayload;
use crate::protocol::control_message::proto::response_message::ResponsePayload;
use anyhow::{anyhow, bail};
use bytes::BytesMut;
use ipnet::Ipv4Net;
use prost::Message;
use std::collections::HashSet;
use std::net::Ipv4Addr;

#[allow(clippy::enum_variant_names)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.control_message.rs"));
}

pub use proto::{ClientType, RegistrationMode, SubscriptionConfigApplyStatus};

#[derive(Debug, Clone)]
pub struct RegRequestMsg {
    pub client_type: ClientType,
    pub network_code: String,
    pub device_id: String,
    pub ip: Option<Ipv4Addr>,
    pub name: String,
    pub version: String,
    pub key_sign: Option<String>,
    pub ip_variable: bool,
    pub server_id: u32,
    pub registration_mode: RegistrationMode,
    pub advertised_subnets: Vec<Ipv4Net>,
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub subscription: Option<SubscriptionRegistration>,
    pub client_instance_id: Vec<u8>,
}
impl RegRequestMsg {
    pub const MAX_NETWORK_CODE_LEN: usize = 32;
    pub const MAX_DEVICE_ID_LEN: usize = 64;
    pub const MAX_NAME_LEN: usize = 128;
    pub const MAX_VERSION_LEN: usize = 32;
    pub fn check(&self) -> anyhow::Result<()> {
        if self.network_code.is_empty() {
            return Err(anyhow!("network_code cannot be empty"));
        }
        if self.network_code.len() > Self::MAX_NETWORK_CODE_LEN {
            return Err(anyhow!(
                "network_code length exceeds {} characters (current: {})",
                Self::MAX_NETWORK_CODE_LEN,
                self.network_code.len()
            ));
        }
        if self.device_id.is_empty() {
            return Err(anyhow!("device_id cannot be empty"));
        }
        if self.device_id.len() > Self::MAX_DEVICE_ID_LEN {
            return Err(anyhow!(
                "device_id length exceeds {} characters (current: {})",
                Self::MAX_DEVICE_ID_LEN,
                self.device_id.len()
            ));
        }

        if self.name.len() > Self::MAX_NAME_LEN {
            return Err(anyhow!(
                "name length exceeds {} characters (current: {})",
                Self::MAX_NAME_LEN,
                self.name.len()
            ));
        }

        if self.version.len() > Self::MAX_VERSION_LEN {
            return Err(anyhow!(
                "version length exceeds {} characters (current: {})",
                Self::MAX_VERSION_LEN,
                self.version.len()
            ));
        }

        if !self.client_instance_id.is_empty() && self.client_instance_id.len() != 32 {
            return Err(anyhow!("client_instance_id must contain 32 bytes"));
        }

        Ok(())
    }
    pub fn from(msg: proto::RegRequestMsg) -> anyhow::Result<Self> {
        let registration_mode = msg.registration_mode();
        let mut advertised_subnets = msg
            .advertised_subnets
            .into_iter()
            .map(ipv4_subnet_from_proto)
            .collect::<anyhow::Result<Vec<_>>>()?;
        advertised_subnets.sort_by_key(|net| (u32::from(net.network()), net.prefix_len()));
        advertised_subnets.dedup();
        Ok(Self {
            client_type: ClientType::try_from(msg.client_type)
                .map_err(|_| anyhow!("unknown client type"))?,
            network_code: msg.network_code,
            device_id: msg.device_id,
            ip: if msg.client_type == ClientType::RemoteDesktop as i32 {
                Some(
                    crate::connection_id::ConnectionId::from_encoded(
                        msg.connection_id.ok_or_else(|| anyhow!("缺少连接 ID"))?,
                    )?
                    .transport_key(),
                )
            } else {
                msg.ip.map(Into::into)
            },
            name: msg.name,
            version: msg.version,
            key_sign: msg.key_sign,
            ip_variable: msg.ip_variable,
            server_id: msg.server_id,
            registration_mode,
            advertised_subnets,
            allow_ikev2: msg.allow_ikev2,
            allow_wireguard: msg.allow_wireguard,
            subscription: msg.subscription.map(SubscriptionRegistration::from),
            client_instance_id: msg.client_instance_id,
        })
    }
    pub fn to(self) -> proto::RegRequestMsg {
        proto::RegRequestMsg {
            client_type: self.client_type as i32,
            network_code: self.network_code,
            device_id: self.device_id,
            connection_id: (self.client_type == ClientType::RemoteDesktop)
                .then(|| self.ip.map(u32::from))
                .flatten(),
            ip: if self.client_type == ClientType::RemoteDesktop {
                None
            } else {
                self.ip.map(u32::from)
            },
            name: self.name,
            version: self.version,
            key_sign: self.key_sign,
            ip_variable: self.ip_variable,
            server_id: self.server_id,
            registration_mode: self.registration_mode as i32,
            advertised_subnets: self
                .advertised_subnets
                .into_iter()
                .map(ipv4_subnet_to_proto)
                .collect(),
            allow_ikev2: self.allow_ikev2,
            allow_wireguard: self.allow_wireguard,
            subscription: self.subscription.map(SubscriptionRegistration::to),
            client_instance_id: self.client_instance_id,
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RegResponseMsg {
    pub connection_id: Option<u32>,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub server_version: String,
    pub subnet_sync_supported: bool,
    pub subscription_config_supported: bool,
    pub subscription: Option<SubscriptionServerProof>,
    pub server_instance_id: Vec<u8>,
    pub multi_link_supported: bool,
    pub application_channel_supported: bool,
}
impl RegResponseMsg {
    pub fn to(self) -> proto::RegResponseMsg {
        proto::RegResponseMsg {
            connection_id: self.connection_id,
            ip: if self.connection_id.is_some() {
                0
            } else {
                self.ip.into()
            },
            prefix_len: self.prefix_len as _,
            gateway: self.gateway.into(),
            server_version: self.server_version,
            subnet_sync_supported: self.subnet_sync_supported,
            subscription_config_supported: self.subscription_config_supported,
            subscription: self.subscription.map(SubscriptionServerProof::to),
            server_instance_id: self.server_instance_id,
            multi_link_supported: self.multi_link_supported,
            application_channel_supported: self.application_channel_supported,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionRegistration {
    pub network_code: String,
    pub device_id: String,
    pub client_nonce: Vec<u8>,
    pub client_proof: Vec<u8>,
    pub instance_id: Vec<u8>,
    pub applied_revision: u64,
}

impl SubscriptionRegistration {
    fn from(value: proto::SubscriptionRegistration) -> Self {
        Self {
            network_code: value.network_code,
            device_id: value.device_id,
            client_nonce: value.client_nonce,
            client_proof: value.client_proof,
            instance_id: value.instance_id,
            applied_revision: value.applied_revision,
        }
    }

    fn to(self) -> proto::SubscriptionRegistration {
        proto::SubscriptionRegistration {
            network_code: self.network_code,
            device_id: self.device_id,
            client_nonce: self.client_nonce,
            client_proof: self.client_proof,
            instance_id: self.instance_id,
            applied_revision: self.applied_revision,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionServerProof {
    pub server_nonce: Vec<u8>,
    pub server_proof: Vec<u8>,
    pub target_revision: u64,
}

impl SubscriptionServerProof {
    fn to(self) -> proto::SubscriptionServerProof {
        proto::SubscriptionServerProof {
            server_nonce: self.server_nonce,
            server_proof: self.server_proof,
            target_revision: self.target_revision,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionConfigFetchRequest {
    pub join_id: String,
    pub client_nonce: Vec<u8>,
    pub client_proof: Vec<u8>,
    pub instance_id: Vec<u8>,
    pub applied_revision: u64,
}

impl SubscriptionConfigFetchRequest {
    fn from(msg: proto::SubscriptionConfigFetchRequest) -> Self {
        Self {
            join_id: msg.join_id,
            client_nonce: msg.client_nonce,
            client_proof: msg.client_proof,
            instance_id: msg.instance_id,
            applied_revision: msg.applied_revision,
        }
    }
    fn to(self) -> proto::SubscriptionConfigFetchRequest {
        proto::SubscriptionConfigFetchRequest {
            join_id: self.join_id,
            client_nonce: self.client_nonce,
            client_proof: self.client_proof,
            instance_id: self.instance_id,
            applied_revision: self.applied_revision,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionRegisterRequest {
    pub join_id: String,
    pub client_nonce: Vec<u8>,
    pub client_proof: Vec<u8>,
    pub instance_id: Vec<u8>,
    pub applied_revision: u64,
}

impl SubscriptionRegisterRequest {
    fn from(msg: proto::SubscriptionRegisterRequest) -> Self {
        Self {
            join_id: msg.join_id,
            client_nonce: msg.client_nonce,
            client_proof: msg.client_proof,
            instance_id: msg.instance_id,
            applied_revision: msg.applied_revision,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SubscriptionPing {
    pub nonce: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionConfigEnvelope {
    pub connection_id: Option<u32>,
    pub revision: u64,
    pub toml: String,
    pub managed_ip: Ipv4Addr,
    pub managed_prefix_len: u8,
    pub managed_device_name: String,
    pub server_proof: SubscriptionServerProof,
    pub network_code: String,
    pub device_id: String,
    pub source_server_id: String,
    pub content_sha256: Vec<u8>,
}

impl SubscriptionConfigEnvelope {
    pub fn encode(self) -> BytesMut {
        self.to().encode_bytes_mut()
    }
    fn to(self) -> proto::SubscriptionConfigEnvelope {
        proto::SubscriptionConfigEnvelope {
            revision: self.revision,
            config: Some(proto::SubscriptionConfigV1 {
                toml: self.toml,
                connection_id: self.connection_id,
                managed_ip: if self.connection_id.is_some() {
                    0
                } else {
                    u32::from(self.managed_ip)
                },
                managed_prefix_len: self.managed_prefix_len.into(),
                managed_device_name: self.managed_device_name,
            }),
            server_proof: Some(self.server_proof.to()),
            network_code: self.network_code,
            device_id: self.device_id,
            source_server_id: self.source_server_id,
            content_sha256: self.content_sha256,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionConfigAck {
    pub revision: u64,
    pub status: SubscriptionConfigApplyStatus,
    pub error: String,
    pub overridden_fields: Vec<String>,
    pub apply_mode: String,
    pub changed_fields: Vec<String>,
    pub effective_device_name: String,
    pub effective_ip: Ipv4Addr,
    pub effective_prefix_len: u32,
    pub effective_output: Vec<Ipv4Net>,
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub allow_mapping: bool,
    pub effective_config_sha256: Vec<u8>,
}

impl SubscriptionConfigAck {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::SubscriptionConfigAck::decode(buf)?;
        Ok(Self {
            revision: msg.revision,
            status: msg.status(),
            error: msg.error,
            overridden_fields: msg.overridden_fields,
            apply_mode: msg.apply_mode,
            changed_fields: msg.changed_fields,
            effective_device_name: msg.effective_device_name,
            effective_ip: Ipv4Addr::from(msg.effective_connection_id.unwrap_or(msg.effective_ip)),
            effective_prefix_len: msg.effective_prefix_len,
            effective_output: msg
                .effective_output
                .into_iter()
                .map(ipv4_subnet_from_proto)
                .collect::<anyhow::Result<_>>()?,
            allow_ikev2: msg.allow_ikev2,
            allow_wireguard: msg.allow_wireguard,
            allow_mapping: msg.allow_mapping,
            effective_config_sha256: msg.effective_config_sha256,
        })
    }

    fn from_proto(msg: proto::SubscriptionConfigAck) -> anyhow::Result<Self> {
        Self::from_slice(msg.encode_to_vec().as_ref())
    }

    fn to(self) -> proto::SubscriptionConfigAck {
        proto::SubscriptionConfigAck {
            effective_connection_id: None,
            revision: self.revision,
            status: self.status as i32,
            error: self.error,
            overridden_fields: self.overridden_fields,
            apply_mode: self.apply_mode,
            changed_fields: self.changed_fields,
            effective_device_name: self.effective_device_name,
            effective_ip: self.effective_ip.into(),
            effective_prefix_len: self.effective_prefix_len,
            effective_output: self
                .effective_output
                .into_iter()
                .map(ipv4_subnet_to_proto)
                .collect(),
            allow_ikev2: self.allow_ikev2,
            allow_wireguard: self.allow_wireguard,
            allow_mapping: self.allow_mapping,
            effective_config_sha256: self.effective_config_sha256,
        }
    }
}

pub(crate) fn ipv4_subnet_to_proto(net: Ipv4Net) -> proto::Ipv4Subnet {
    let net = net.trunc();
    proto::Ipv4Subnet {
        network: net.network().into(),
        prefix_len: net.prefix_len().into(),
    }
}

pub(crate) fn ipv4_subnet_from_proto(net: proto::Ipv4Subnet) -> anyhow::Result<Ipv4Net> {
    let prefix_len = u8::try_from(net.prefix_len)?;
    Ok(Ipv4Net::new(Ipv4Addr::from(net.network), prefix_len)?.trunc())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeSubnetRoutes {
    pub ip: Ipv4Addr,
    pub subnets: Vec<Ipv4Net>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubnetSyncRequest {
    pub known_hash: Vec<u8>,
}

impl SubnetSyncRequest {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::SubnetSyncRequest::decode(buf)?;
        Ok(Self {
            known_hash: msg.known_hash,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubnetSyncResponse {
    pub snapshot_hash: Vec<u8>,
    pub nodes: Vec<NodeSubnetRoutes>,
}

impl SubnetSyncResponse {
    pub fn encode(self) -> BytesMut {
        proto::SubnetSyncResponse {
            snapshot_hash: self.snapshot_hash,
            nodes: self
                .nodes
                .into_iter()
                .map(|node| proto::NodeSubnetRoutes {
                    ip: node.ip.into(),
                    subnets: node.subnets.into_iter().map(ipv4_subnet_to_proto).collect(),
                })
                .collect(),
        }
        .encode_bytes_mut()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfirmRegMsg {}
impl ConfirmRegMsg {
    pub fn from(_msg: proto::ConfirmRegMsg) -> anyhow::Result<Self> {
        Ok(Self {})
    }
    pub fn to(self) -> proto::ConfirmRegMsg {
        proto::ConfirmRegMsg {}
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfirmRegResponseMsg {
    pub success: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FastRegRequestMsg {
    pub ip: Ipv4Addr,
}

impl FastRegRequestMsg {
    pub fn from(msg: proto::FastRegRequestMsg) -> anyhow::Result<Self> {
        Ok(Self {
            ip: if let Some(value) = msg.connection_id {
                crate::connection_id::ConnectionId::from_encoded(value)?.transport_key()
            } else {
                msg.ip.into()
            },
        })
    }

    pub fn to(self) -> proto::FastRegRequestMsg {
        proto::FastRegRequestMsg {
            ip: self.ip.into(),
            connection_id: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FastRegResponseMsg {
    pub success: bool,
}

impl FastRegResponseMsg {
    pub fn to(self) -> proto::FastRegResponseMsg {
        proto::FastRegResponseMsg {
            success: self.success,
        }
    }
}
impl ConfirmRegResponseMsg {
    pub fn from(msg: proto::ConfirmRegResponseMsg) -> anyhow::Result<Self> {
        Ok(Self {
            success: msg.success,
        })
    }
    pub fn to(self) -> proto::ConfirmRegResponseMsg {
        proto::ConfirmRegResponseMsg {
            success: self.success,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ErrorResponseMsg {
    pub code: u32,
    pub message: String,
}
impl ErrorResponseMsg {
    pub fn from(msg: proto::ErrorResponseMsg) -> anyhow::Result<Self> {
        Ok(Self {
            code: msg.code,
            message: msg.message,
        })
    }
    pub fn to(self) -> proto::ErrorResponseMsg {
        proto::ErrorResponseMsg {
            code: self.code,
            message: self.message,
        }
    }
}
#[derive(Debug, Clone)]
pub enum RequestMessage {
    Reg(RegRequestMsg),
    ConfirmReg(ConfirmRegMsg),
    FastReg(FastRegRequestMsg),
    SubscriptionConfig(SubscriptionConfigFetchRequest),
    SubscriptionRegister(SubscriptionRegisterRequest),
    SubscriptionAck(SubscriptionConfigAck),
    SubscriptionPing(SubscriptionPing),
}
impl RequestMessage {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::RequestMessage::decode(buf)?;
        let Some(payload) = msg.request_payload else {
            bail!("unsupported")
        };
        match payload {
            RequestPayload::Reg(reg) => Ok(RequestMessage::Reg(RegRequestMsg::from(reg)?)),
            RequestPayload::ConfirmReg(confirm) => {
                Ok(RequestMessage::ConfirmReg(ConfirmRegMsg::from(confirm)?))
            }
            RequestPayload::FastReg(fast_reg) => {
                Ok(RequestMessage::FastReg(FastRegRequestMsg::from(fast_reg)?))
            }
            RequestPayload::SubscriptionConfig(request) => Ok(RequestMessage::SubscriptionConfig(
                SubscriptionConfigFetchRequest::from(request),
            )),
            RequestPayload::SubscriptionRegister(request) => Ok(
                RequestMessage::SubscriptionRegister(SubscriptionRegisterRequest::from(request)),
            ),
            RequestPayload::SubscriptionAck(ack) => Ok(RequestMessage::SubscriptionAck(
                SubscriptionConfigAck::from_proto(ack)?,
            )),
            RequestPayload::SubscriptionPing(ping) => {
                Ok(RequestMessage::SubscriptionPing(SubscriptionPing {
                    nonce: ping.nonce,
                }))
            }
        }
    }
    pub fn encode(self) -> BytesMut {
        let request_payload = match self {
            RequestMessage::Reg(reg) => RequestPayload::Reg(reg.to()),
            RequestMessage::ConfirmReg(confirm) => RequestPayload::ConfirmReg(confirm.to()),
            RequestMessage::FastReg(fast_reg) => RequestPayload::FastReg(fast_reg.to()),
            RequestMessage::SubscriptionConfig(request) => {
                RequestPayload::SubscriptionConfig(request.to())
            }
            RequestMessage::SubscriptionRegister(_) => unreachable!("server-only decode"),
            RequestMessage::SubscriptionAck(ack) => RequestPayload::SubscriptionAck(ack.to()),
            RequestMessage::SubscriptionPing(ping) => {
                RequestPayload::SubscriptionPing(proto::SubscriptionPing { nonce: ping.nonce })
            }
        };
        proto::RequestMessage {
            request_payload: Some(request_payload),
        }
        .encode_bytes_mut()
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResponseMessage {
    Reg(RegResponseMsg),
    Error(ErrorResponseMsg),
    ConfirmReg(ConfirmRegResponseMsg),
    FastReg(FastRegResponseMsg),
    SubscriptionConfig(SubscriptionConfigEnvelope),
    SubscriptionRegister(SubscriptionConfigEnvelope),
    SubscriptionPush(SubscriptionConfigEnvelope),
    SubscriptionPong(SubscriptionPing),
}
impl ResponseMessage {
    pub fn encode(self) -> BytesMut {
        let response_payload = match self {
            ResponseMessage::Reg(reg) => ResponsePayload::Reg(reg.to()),
            ResponseMessage::Error(e) => ResponsePayload::Error(e.to()),
            ResponseMessage::ConfirmReg(confirm) => ResponsePayload::ConfirmReg(confirm.to()),
            ResponseMessage::FastReg(fast_reg) => ResponsePayload::FastReg(fast_reg.to()),
            ResponseMessage::SubscriptionConfig(config) => {
                ResponsePayload::SubscriptionConfig(config.to())
            }
            ResponseMessage::SubscriptionRegister(config) => {
                ResponsePayload::SubscriptionRegister(proto::SubscriptionRegisterResponse {
                    config: Some(config.to()),
                })
            }
            ResponseMessage::SubscriptionPush(config) => {
                ResponsePayload::SubscriptionPush(config.to())
            }
            ResponseMessage::SubscriptionPong(pong) => {
                ResponsePayload::SubscriptionPong(proto::SubscriptionPong { nonce: pong.nonce })
            }
        };
        proto::ResponseMessage {
            response_payload: Some(response_payload),
        }
        .encode_bytes_mut()
    }
}

pub struct SelectiveBroadcast {
    pub ips: HashSet<Ipv4Addr>,
    pub data: Vec<u8>,
}
impl SelectiveBroadcast {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::SelectiveBroadcast::decode(buf)?;
        Ok(Self {
            ips: msg.ips.into_iter().map(|v| v.into()).collect(),
            data: msg.data,
        })
    }
    pub fn encode(self) -> BytesMut {
        proto::SelectiveBroadcast {
            ips: self.ips.into_iter().map(|v| v.into()).collect(),
            data: self.data,
        }
        .encode_bytes_mut()
    }
}

#[derive(Debug, Clone)]
pub struct ClientSimpleInfo {
    pub ip: Ipv4Addr,
    pub online: bool,
    pub client_type: ClientType,
}
impl ClientSimpleInfo {
    pub fn from(msg: proto::ClientSimpleInfo) -> anyhow::Result<Self> {
        Ok(Self {
            ip: msg.ip.into(),
            online: msg.online,
            client_type: msg.client_type(),
        })
    }
    pub fn to(self) -> proto::ClientSimpleInfo {
        proto::ClientSimpleInfo {
            ip: self.ip.into(),
            online: self.online,
            client_type: self.client_type as i32,
        }
    }
}
#[derive(Debug)]
pub struct ClientSimpleInfoList {
    pub data_version: u64,
    pub list: Vec<ClientSimpleInfo>,
    pub is_all: bool,
    pub time: i64,
}
impl ClientSimpleInfoList {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::ClientSimpleInfoList::decode(buf)?;
        let mut list = Vec::with_capacity(msg.list.len());
        for x in msg.list {
            list.push(ClientSimpleInfo::from(x)?);
        }
        Ok(Self {
            data_version: msg.data_version,
            list,
            is_all: msg.is_all,
            time: msg.time,
        })
    }
    pub fn encode(self) -> BytesMut {
        let mut list = Vec::with_capacity(self.list.len());
        for x in self.list {
            list.push(x.to());
        }
        proto::ClientSimpleInfoList {
            data_version: self.data_version,
            list,
            is_all: self.is_all,
            time: self.time,
        }
        .encode_bytes_mut()
    }
}
