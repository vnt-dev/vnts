pub mod control_server;
pub mod network_state_provider;
pub mod peer_server;

// 传输层
pub mod quic;
pub mod tcp;
pub mod tcp_websocket;
pub mod websocket;

use crate::server::control_server::service::ControlService;
use crate::server::quic::QuicConfig;
use crate::server::tcp::TcpConfig;
use crate::server::tcp_websocket::HybridConfig;
use crate::server::websocket::WebSocketConfig;
use anyhow::bail;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;

pub struct TurnConfig {
    pub tcp_bind: Option<SocketAddr>,
    pub quic_bind: Option<SocketAddr>,
    pub ws_bind: Option<SocketAddr>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

pub async fn turn_server_start(
    config: TurnConfig,
    control_service: ControlService,
) -> anyhow::Result<()> {
    if config.tcp_bind.is_none() && config.quic_bind.is_none() && config.ws_bind.is_none() {
        bail!("An address must be bound")
    }
    let (certs, key) = crate::utils::cert::get_cert_and_key(config.cert, config.key)?;
    for cert in certs.iter() {
        let mut hasher = Sha256::new();
        hasher.update(cert.as_ref());
        let calculated_hash: [u8; 32] = hasher.finalize().into();
        log::info!("Fingerprint: {}", hex::encode(&calculated_hash));
    }
    // TCP 和 WS 绑定同一地址时，使用混合监听自动检测协议
    if config.tcp_bind == config.ws_bind {
        if let Some(addr) = config.tcp_bind {
            tcp_websocket::listen(
                HybridConfig {
                    addr,
                    certs: certs.clone(),
                    key: key.clone_key(),
                },
                control_service.clone(),
            )
            .await?
        }
    } else {
        if let Some(tcp_bind) = config.tcp_bind {
            tcp::listen(
                TcpConfig {
                    addr: tcp_bind,
                    certs: certs.clone(),
                    key: key.clone_key(),
                },
                control_service.clone(),
            )
            .await?;
        }
        if let Some(ws_bind) = config.ws_bind {
            websocket::listen(
                WebSocketConfig {
                    addr: ws_bind,
                    certs: certs.clone(),
                    key: key.clone_key(),
                },
                control_service.clone(),
            )
            .await?;
        }
    }
    if let Some(quic_bind) = config.quic_bind {
        quic::listen(
            QuicConfig {
                addr: quic_bind,
                certs: certs.clone(),
                key: key.clone_key(),
            },
            control_service.clone(),
        )
        .await?;
    }

    Ok(())
}
