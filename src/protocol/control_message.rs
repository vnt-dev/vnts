#![allow(dead_code)]

use crate::protocol::ProtoToBytesMut;
use crate::protocol::control_message::proto::request_message::RequestPayload;
use crate::protocol::control_message::proto::response_message::ResponsePayload;
use anyhow::{anyhow, bail};
use bytes::BytesMut;
use prost::Message;
use std::collections::HashSet;
use std::net::Ipv4Addr;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.control_message.rs"));
}

pub use proto::RegistrationMode;

#[derive(Debug, Clone)]
pub struct RegRequestMsg {
    pub network_code: String,
    pub device_id: String,
    pub ip: Option<Ipv4Addr>,
    pub name: String,
    pub version: String,
    pub key_sign: Option<String>,
    pub ip_variable: bool,
    pub server_id: u32,
    pub registration_mode: RegistrationMode,
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

        Ok(())
    }
    pub fn from(msg: proto::RegRequestMsg) -> anyhow::Result<Self> {
        let registration_mode = msg.registration_mode();
        Ok(Self {
            network_code: msg.network_code,
            device_id: msg.device_id,
            ip: msg.ip.map(|ip| ip.into()),
            name: msg.name,
            version: msg.version,
            key_sign: msg.key_sign,
            ip_variable: msg.ip_variable,
            server_id: msg.server_id,
            registration_mode,
        })
    }
    pub fn to(self) -> proto::RegRequestMsg {
        proto::RegRequestMsg {
            network_code: self.network_code,
            device_id: self.device_id,
            ip: self.ip.map(|ip| ip.into()),
            name: self.name,
            version: self.version,
            key_sign: self.key_sign,
            ip_variable: self.ip_variable,
            server_id: self.server_id,
            registration_mode: self.registration_mode as i32,
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RegResponseMsg {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub server_version: String,
}
impl RegResponseMsg {
    pub fn to(self) -> proto::RegResponseMsg {
        proto::RegResponseMsg {
            ip: self.ip.into(),
            prefix_len: self.prefix_len as _,
            gateway: self.gateway.into(),
            server_version: self.server_version,
        }
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
        }
    }
    pub fn encode(self) -> BytesMut {
        let request_payload = match self {
            RequestMessage::Reg(reg) => RequestPayload::Reg(reg.to()),
            RequestMessage::ConfirmReg(confirm) => RequestPayload::ConfirmReg(confirm.to()),
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
}
impl ResponseMessage {
    pub fn encode(self) -> BytesMut {
        let response_payload = match self {
            ResponseMessage::Reg(reg) => ResponsePayload::Reg(reg.to()),
            ResponseMessage::Error(e) => ResponsePayload::Error(e.to()),
            ResponseMessage::ConfirmReg(confirm) => ResponsePayload::ConfirmReg(confirm.to()),
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
}
impl ClientSimpleInfo {
    pub fn from(msg: proto::ClientSimpleInfo) -> anyhow::Result<Self> {
        Ok(Self {
            ip: msg.ip.into(),
            online: msg.online,
        })
    }
    pub fn to(self) -> proto::ClientSimpleInfo {
        proto::ClientSimpleInfo {
            ip: self.ip.into(),
            online: self.online,
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
