mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.server_message.rs"));
}

pub use proto::server_message::Payload;
pub use proto::*;
