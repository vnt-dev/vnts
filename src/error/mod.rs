#![allow(dead_code, clippy::enum_variant_names)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
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

pub type Result<T> = anyhow::Result<T>;
