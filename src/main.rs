use crate::server::TurnConfig;
use crate::server::control_server::service::ControlService;
use crate::server::peer_server::PeerServerManager;
use crate::utils::config::{ConfigFile, LoadedConfig};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

mod http;
mod protocol;
mod server;
mod utils;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 配置文件路径，默认 ./config.toml
    #[arg(short, long)]
    conf: Option<PathBuf>,
    /// 输出配置文件示例
    #[clap(long)]
    pub conf_example: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if args.conf_example {
        utils::config::print_example();
        return;
    }
    utils::log::log_init("vnts2");
    log::info!("version: {:?}", env!("CARGO_PKG_VERSION"));
    let loaded = match ConfigFile::load_with_meta(args.conf) {
        Ok(conf) => conf,
        Err(e) => {
            log::error!("{e:?}");
            panic!("{e:?}")
        }
    };
    let LoadedConfig {
        path: config_path,
        config: conf,
        created_default,
    } = loaded;
    log::info!("Loaded config from {}", config_path.display());
    if created_default {
        log::warn!(
            "Config file did not exist. A default config was created at {}",
            config_path.display()
        );
    }
    if conf.persistence {
        if let Err(e) = server::control_server::db::init_db_pool().await {
            log::error!("{:?}", e);
        }
    }

    // 提前提取需要在 move 之后使用的字段
    let need_peer_manager = !conf.peer_servers.is_empty() || conf.web_bind.is_some();
    let peer_conf = PeerConf {
        persistence: conf.persistence,
        server_quic_bind: conf.server_quic_bind,
        peer_servers: conf.peer_servers.clone(),
        server_token: conf.server_token.clone(),
        cert: conf.cert.clone(),
        key: conf.key.clone(),
    };

    let turn_config = TurnConfig {
        tcp_bind: conf.tcp_bind,
        quic_bind: conf.quic_bind,
        ws_bind: conf.ws_bind,
        cert: conf.cert.clone(),
        key: conf.key.clone(),
    };

    let web_bind = conf.web_bind;
    let username = conf.username.unwrap_or_else(|| {
        log::warn!(
            "username is not set in {}. Falling back to default username 'admin'",
            config_path.display()
        );
        "admin".to_string()
    });
    let password = conf.password.unwrap_or_else(|| {
        log::warn!(
            "password is not set in {}. Falling back to default password",
            config_path.display()
        );
        "admin".to_string()
    });
    if let Some(bind_addr) = web_bind {
        let using_default_credentials = username == "admin" && password == "admin";
        log::info!(
            "Web auth loaded for {} with username '{}'",
            bind_addr,
            username
        );
        if using_default_credentials {
            log::warn!(
                "Web auth is still using default credentials admin/admin from {}",
                config_path.display()
            );
        }
    }

    log::info!(
        "Loaded {} bootstrap networks and {} bootstrap secrets from config",
        conf.custom_nets.len(),
        conf.network_secrets.len()
    );

    let control_service = ControlService::new(
        conf.custom_nets,
        conf.network_secrets,
        conf.white_list,
        Duration::from_secs(conf.lease_duration),
    )
    .await;

    if let Err(e) = server::turn_server_start(turn_config, control_service.clone()).await {
        log::error!("{:?}", e);
        panic!("{:?}", e)
    }

    if need_peer_manager {
        init_peer_manager(&peer_conf, &control_service).await;
    }

    if let Some(web_bind) = web_bind {
        http::web_server::start_http_server(control_service, username, password, web_bind).await
    }

    tokio::signal::ctrl_c().await.unwrap();
}

struct PeerConf {
    persistence: bool,
    server_quic_bind: Option<std::net::SocketAddr>,
    peer_servers: Vec<String>,
    server_token: Option<String>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

async fn init_peer_manager(conf: &PeerConf, control_service: &ControlService) {
    let server_token = conf
        .server_token
        .clone()
        .unwrap_or_else(|| "default_token".to_string());
    let network_state_provider = control_service.get_network_state_provider().clone();

    let peer_manager = Arc::new(PeerServerManager::new(server_token, network_state_provider));
    control_service.set_peer_manager(peer_manager.clone());

    if let Some(server_quic_bind) = conf.server_quic_bind {
        let (certs, key) =
            match crate::utils::cert::get_cert_and_key(conf.cert.clone(), conf.key.clone()) {
                Ok((certs, key)) => (certs, key),
                Err(e) => {
                    log::error!("Failed to load cert/key for peer server: {:?}", e);
                    panic!("{:?}", e)
                }
            };
        if let Err(e) = peer_manager
            .clone()
            .start_server(server_quic_bind, certs, key)
            .await
        {
            log::error!("Failed to start peer server: {:?}", e);
        } else {
            log::info!("Peer server started on {}", server_quic_bind);
        }
    }

    if conf.persistence {
        sync_peer_servers_to_db(&conf.peer_servers).await;
        if let Err(e) = peer_manager.clone().load_and_start_outbound_peers().await {
            log::error!("Failed to load and start outbound peers: {:?}", e);
        }
    } else {
        for peer_addr in conf.peer_servers.clone() {
            let manager = peer_manager.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                manager.connect_to_peer(peer_addr);
            });
        }
    }
}

/// 将配置文件中的 peer server 写入数据库（已存在的跳过）
async fn sync_peer_servers_to_db(peer_servers: &[String]) {
    use server::control_server::db::{PeerServerRecord, PeerServerSource};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for peer_addr in peer_servers {
        let record = PeerServerRecord {
            server_addr: peer_addr.clone(),
            source: PeerServerSource::Config,
            created_at: now,
        };
        match server::control_server::db::save_peer_server_if_not_exists(&record).await {
            Ok(true) => log::info!("Initialized peer server '{}' from config", peer_addr),
            Ok(false) => {}
            Err(e) => log::error!("Failed to save peer server {}: {}", peer_addr, e),
        }
    }
}
