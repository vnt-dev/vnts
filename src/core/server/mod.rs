use std::sync::Arc;
use std::{io, thread};

use actix_web::dev::WebService;
use tokio::net::{TcpListener, UdpSocket};

use crate::cipher::RsaCipher;
use crate::core::service::PacketHandler;
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;

mod tcp;
mod udp;
pub mod web;

pub async fn start(
    udp: std::net::UdpSocket,
    tcp: std::net::TcpListener,
    http: std::net::TcpListener,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
) -> io::Result<()> {
    let udp = Arc::new(UdpSocket::from_std(udp)?);
    let cache = AppCache::new();
    let handler = PacketHandler::new(
        cache.clone(),
        config.clone(),
        rsa_cipher.clone(),
        udp.clone(),
    );
    tcp::start(TcpListener::from_std(tcp)?, handler.clone()).await;
    udp::start(udp, handler.clone()).await;
    if let Err(e) = web::start(http, cache, config, rsa_cipher).await {
        log::error!("{:?}", e);
    }
    Ok(())
}
