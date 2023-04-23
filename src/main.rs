use std::collections::HashSet;
use std::net::{Ipv4Addr, UdpSocket};
use std::thread;

use clap::Parser;

pub mod error;
pub mod proto;
pub mod protocol;
pub mod service;

/// 默认网关信息
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 26, 0, 1);
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

#[derive(Parser, Debug, Clone)]
pub struct StartArgs {
    /// 指定端口
    #[arg(long)]
    port: Option<u16>,
    /// token白名单，例如 --white-token 1234 --white-token 123
    #[arg(long)]
    white_token: Option<Vec<String>>,
    /// 网关，例如 --gateway 10.10.0.1
    #[arg(long)]
    gateway: Option<String>,
    /// 子网掩码，例如 --netmask 255.255.255.0
    #[arg(long)]
    netmask: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConfigInfo {
    pub port: u16,
    pub white_token: Option<HashSet<String>>,
    pub gateway: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

fn log_init() {
    let home = dirs::home_dir().unwrap().join(".switch_server");
    if !home.exists() {
        std::fs::create_dir(&home).expect(" Failed to create '.switch' directory");
    }
    let logfile = log4rs::append::file::FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{d(%+)(utc)} [{f}:{L}] {h({l})} {M}:{m}{n}\n",
        )))
        .build(home.join("switch_server_v1.1.log"))
        .unwrap();
    let config = log4rs::Config::builder()
        .appender(log4rs::config::Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            log4rs::config::Root::builder()
                .appender("logfile")
                .build(log::LevelFilter::Info),
        )
        .unwrap();
    let _ = log4rs::init_config(config);
}

fn main() {
    let args = StartArgs::parse();
    let port = args.port.unwrap_or(29871);
    println!("端口：{}", port);
    let white_token = if let Some(white_token) = args.white_token {
        Some(HashSet::from_iter(white_token.into_iter()))
    } else {
        None
    };
    println!("白名单：{:?}", white_token);
    let gateway = if let Some(gateway) = args.gateway {
        gateway.parse::<Ipv4Addr>().expect("网关错误，必须为有效的ipv4地址")
    } else {
        GATEWAY
    };
    println!("网关：{:?}", gateway);
    if gateway.is_broadcast() || gateway.is_unspecified() {
        println!("网关错误");
        return;
    }
    if !gateway.is_private() {
        println!("Warning 网关不是一个私有地址：{:?}", gateway);
    }
    let netmask = if let Some(netmask) = args.netmask {
        netmask.parse::<Ipv4Addr>().expect("子网掩码错误，必须为有效的ipv4地址")
    } else {
        NETMASK
    };
    println!("子网掩码：{:?}", netmask);
    if netmask.is_broadcast() || netmask.is_unspecified() || !(!u32::from_be_bytes(netmask.octets()) + 1).is_power_of_two() {
        println!("子网掩码错误");
        return;
    }

    let broadcast = (!u32::from_be_bytes(netmask.octets()))
        | u32::from_be_bytes(gateway.octets());
    let broadcast = Ipv4Addr::from(broadcast);
    let config = ConfigInfo {
        port,
        white_token,
        gateway,
        broadcast,
        netmask,
    };
    log_init();
    let udp = UdpSocket::bind("0.0.0.0:29871").unwrap();
    log::info!("启动成功,udp:{:?}",udp.local_addr().unwrap());
    println!("启动成功,udp:{:?}", udp.local_addr().unwrap());
    log::info!("config:{:?}",config);
    let num = if let Ok(num) = thread::available_parallelism() {
        num.get() * 2
    } else {
        2
    };
    for _ in 0..num {
        let udp = udp.try_clone().unwrap();
        let config = config.clone();
        thread::spawn(move || {
            service::handle_loop(udp, config);
        });
    }

    service::handle_loop(udp, config);
}
