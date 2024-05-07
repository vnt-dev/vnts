#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// 注册请求
    RegistrationRequest,
    /// 注册响应
    RegistrationResponse,
    /// 拉取设备列表
    PullDeviceList,
    /// 推送设备列表
    PushDeviceList,
    /// 和服务端握手
    HandshakeRequest,
    HandshakeResponse,
    SecretHandshakeRequest,
    SecretHandshakeResponse,
    /// 客户端上报状态
    ClientStatusInfo,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::RegistrationRequest,
            2 => Self::RegistrationResponse,
            3 => Self::PullDeviceList,
            4 => Self::PushDeviceList,
            5 => Self::HandshakeRequest,
            6 => Self::HandshakeResponse,
            7 => Self::SecretHandshakeRequest,
            8 => Self::SecretHandshakeResponse,
            9 => Self::ClientStatusInfo,
            val => Self::Unknown(val),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(val: Protocol) -> Self {
        match val {
            Protocol::RegistrationRequest => 1,
            Protocol::RegistrationResponse => 2,
            Protocol::PullDeviceList => 3,
            Protocol::PushDeviceList => 4,
            Protocol::HandshakeRequest => 5,
            Protocol::HandshakeResponse => 6,
            Protocol::SecretHandshakeRequest => 7,
            Protocol::SecretHandshakeResponse => 8,
            Protocol::ClientStatusInfo => 9,
            Protocol::Unknown(val) => val,
        }
    }
}
