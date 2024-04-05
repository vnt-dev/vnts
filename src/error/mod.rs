#![allow(dead_code,clippy::enum_variant_names)]

use std::io;

use crossbeam::channel::RecvError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Io error")]
    Io(#[from] io::Error),
    #[error("Channel error")]
    Channel(#[from] RecvError),
    #[error("Protobuf error")]
    Protobuf(#[from] protobuf::Error),
    #[error("Disconnect")]
    Disconnect,
    #[error("No Key")]
    NoKey,
    #[error("Address Exhausted")]
    AddressExhausted,
    #[error("Token Error")]
    TokenError,
    #[error("Ip Already Exists")]
    IpAlreadyExists,
    #[error("Invalid Ip")]
    InvalidIp,
    #[error("Other")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
