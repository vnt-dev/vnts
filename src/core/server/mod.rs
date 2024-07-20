use std::io;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};

use crate::cipher::RsaCipher;
use crate::core::server::wire_guard::WireGuardGroup;
use crate::core::service::PacketHandler;
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;

mod tcp;
mod udp;
#[cfg(feature = "web")]
mod web;
mod websocket;
mod wire_guard;

pub async fn start(
    udp: std::net::UdpSocket,
    tcp: std::net::TcpListener,
    #[cfg(feature = "web")] http: Option<std::net::TcpListener>,
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
    let wg = WireGuardGroup::new(cache.clone(), config.clone(), udp.clone());
    let tcp_handle = tokio::spawn(tcp::start(TcpListener::from_std(tcp)?, handler.clone()));
    let udp_handle = tokio::spawn(udp::start(udp, handler.clone(), wg));
    #[cfg(not(feature = "web"))]
    let _ = tokio::try_join!(tcp_handle, udp_handle);
    #[cfg(feature = "web")]
    if let Some(http) = http {
        if let Err(e) = web::start(http, cache, config).await {
            log::error!("{:?}", e);
        }
    } else {
        let _ = tokio::try_join!(tcp_handle, udp_handle);
    }
    Ok(())
}
