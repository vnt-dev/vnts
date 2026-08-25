use bytes::BytesMut;
use prost::Message;

pub mod control_message;
pub mod ip_packet_protocol;
pub mod rpc_message;
pub mod server_message;

/// 为所有 protobuf Message 提供零拷贝编码
pub trait ProtoToBytesMut: Message {
    fn encode_bytes_mut(&self) -> BytesMut
    where
        Self: Sized,
    {
        let mut bytes_mut = BytesMut::with_capacity(self.encoded_len());
        self.encode_raw(&mut bytes_mut);
        bytes_mut
    }
}

impl<T: Message> ProtoToBytesMut for T {}
