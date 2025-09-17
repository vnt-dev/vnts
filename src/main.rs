use aes_gcm::aead::rand_core::RngCore;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose;
use base64::Engine;
use boringtun::x25519::{PublicKey, StaticSecret};
use clap::Parser;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::cipher::RsaCipher;

mod cipher;
mod core;
mod error;
mod generated_serial_number;
mod proto;
mod protocol;

pub const VNT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 默认网关信息
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 26, 0, 1);
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// vnt服务端,
/// 默认情况服务日志输出在 './log/'下,可通过编写'./log/log4rs.yaml'文件自定义日志配置
#[derive(Parser, Debug, Clone)]
#[command(version)]
pub struct StartArgs {
    /// 指定服务监听的IP地址，默认监听所有地址
    #[arg(long)]
    host: Option<String>,
    /// 指定端口，默认29872
    #[arg(short, long)]
    port: Option<u16>,
    /// token白名单，例如 --white-token 1234 --white-token 123
    #[arg(short, long)]
    white_token: Option<Vec<String>>,
    /// 网关，例如 --gateway 10.10.0.1
    #[arg(short, long)]
    gateway: Option<String>,
    /// 子网掩码，例如 --netmask 255.255.255.0
    #[arg(short = 'm', long)]
    netmask: Option<String>,
    ///开启指纹校验，开启后只会转发指纹正确的客户端数据包，增强安全性，这会损失一部分性能
    #[arg(short, long, default_value_t = false)]
    finger: bool,
    /// log路径，默认为当前程序路径，为/dev/null时表示不输出log
    #[arg(short, long)]
    log_path: Option<String>,
    #[cfg(feature = "web")]
    ///web后台端口，默认29870，如果设置为0则表示不启动web后台
    #[arg(short = 'P', long)]
    web_port: Option<u16>,
    #[cfg(feature = "web")]
    /// web后台用户名，默认为admin
    #[arg(short = 'U', long)]
    username: Option<String>,
    #[cfg(feature = "web")]
    /// web后台用户密码，默认为admin
    #[arg(short = 'W', long)]
    password: Option<String>,
    /// wg私钥，使用base64编码
    #[arg(long = "wg")]
    wg_secret_key: Option<String>,
}

#[derive(Clone)]
pub struct ConfigInfo {
    pub port: u16,
    pub white_token: Option<HashSet<String>>,
    pub gateway: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub check_finger: bool,
    #[cfg(feature = "web")]
    pub username: String,
    #[cfg(feature = "web")]
    pub password: String,
    pub wg_secret_key: StaticSecret,
    pub wg_public_key: PublicKey,
}
impl Debug for ConfigInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigInfo")
            .field("port", &self.port)
            .field("white_token", &self.white_token)
            .field("gateway", &self.gateway)
            .field("broadcast", &self.broadcast)
            .field("netmask", &self.netmask)
            .field("check_finger", &self.check_finger)
            .field(
                "wg_secret_key",
                &general_purpose::STANDARD.encode(&self.wg_secret_key),
            )
            .field(
                "wg_public_key",
                &general_purpose::STANDARD.encode(&self.wg_public_key),
            )
            .finish()
    }
}

fn log_init(root_path: PathBuf, log_path: Option<String>) {
    let log_path = match log_path {
        None => root_path.join("log"),
        Some(log_path) => {
            if &log_path == "/dev/null" {
                return;
            }
            PathBuf::from(log_path)
        }
    };
    if !log_path.exists() {
        let _ = std::fs::create_dir(&log_path);
    }

    let log_config = log_path.join("log4rs.yaml");
    if !log_config.exists() {
        if let Ok(mut f) = std::fs::File::create(&log_config) {
            let log_path = log_path.to_str().unwrap();
            let c = format!(
                "refresh_rate: 30 seconds
appenders:
  rolling_file:
    kind: rolling_file
    path: {}/vnts.log
    append: true
    encoder:
      pattern: \"{{d}} [{{f}}:{{L}}] {{h({{l}})}} {{M}}:{{m}}{{n}}\"
    policy:
      kind: compound
      trigger:
        kind: size
        limit: 10 mb
      roller:
        kind: fixed_window
        pattern: {}/vnts.{{}}.log
        base: 1
        count: 5

root:
  level: info
  appenders:
    - rolling_file",
                log_path, log_path
            );
            let _ = f.write_all(c.as_bytes());
        }
    }
    let _ = log4rs::init_file(log_config, Default::default());
}

pub fn app_root() -> PathBuf {
    match std::env::current_exe() {
        Ok(path) => {
            if let Some(v) = path.as_path().parent() {
                v.to_path_buf()
            } else {
                log::warn!("current_exe parent none:{:?}", path);
                PathBuf::new()
            }
        }
        Err(e) => {
            log::warn!("current_exe err:{:?}", e);
            PathBuf::new()
        }
    }
}

#[tokio::main]
async fn main() {
    println!("version: {}", VNT_VERSION);
    println!("Serial: {}", generated_serial_number::SERIAL_NUMBER);
    let args = StartArgs::parse();
    let root_path = app_root();
    log_init(root_path.clone(), args.log_path);
    let port = args.port.unwrap_or(29872);
    let host = args.host;
    #[cfg(feature = "web")]
    let web_port = {
        let web_port = args.web_port.unwrap_or(29870);
        println!("端口: {}", port);
        if web_port != 0 {
            println!("web端口: {}", web_port);
            if web_port == port {
                panic!("web-port == port");
            }
        } else {
            println!("不启用web后台")
        }
        web_port
    };

    let white_token = args
        .white_token
        .map(|white_token| HashSet::from_iter(white_token.into_iter()));
    println!("token白名单: {:?}", white_token);
    let gateway = if let Some(gateway) = args.gateway {
        match gateway.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(e) => {
                log::error!("网关错误，必须为有效的ipv4地址 gateway={},e={}", gateway, e);
                panic!("网关错误，必须为有效的ipv4地址")
            }
        }
    } else {
        GATEWAY
    };
    println!("网关: {:?}", gateway);
    if gateway.is_unspecified() {
        println!("网关地址无效");
        log::error!("网关错误，必须为有效的ipv4地址 gateway={}", gateway);
        return;
    }
    if gateway.is_broadcast() {
        println!("网关错误，不能为广播地址");
        log::error!("网关错误，不能为广播地址 gateway={}", gateway);
        return;
    }
    if gateway.is_multicast() {
        println!("网关错误，不能为组播地址");
        log::error!("网关错误，不能为组播地址 gateway={}", gateway);
        return;
    }
    if !gateway.is_private() {
        println!(
            "Warning 不是一个私有地址：{:?}，将有可能和公网ip冲突",
            gateway
        );
        log::warn!("网关错误，不是一个私有地址 gateway={}", gateway);
    }
    let netmask = if let Some(netmask) = args.netmask {
        match netmask.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(e) => {
                log::error!(
                    "子网掩码错误，必须为有效的ipv4地址 netmask={},e={}",
                    netmask,
                    e
                );
                panic!("子网掩码错误，必须为有效的ipv4地址")
            }
        }
    } else {
        NETMASK
    };
    println!("子网掩码: {:?}", netmask);
    if netmask.is_broadcast()
        || netmask.is_unspecified()
        || !(!u32::from_be_bytes(netmask.octets()) + 1).is_power_of_two()
    {
        println!("子网掩码错误");
        log::error!("子网掩码错误 netmask={}", netmask);
        return;
    }

    let broadcast = (!u32::from_be_bytes(netmask.octets())) | u32::from_be_bytes(gateway.octets());
    let broadcast = Ipv4Addr::from(broadcast);
    let check_finger = args.finger;
    if check_finger {
        println!("转发校验数据指纹，客户端必须增加--finger参数");
    }
    let wg_secret_key: [u8; 32] = if let Some(wg_secret_key) = args.wg_secret_key {
        let wg_secret_key = general_purpose::STANDARD
            .decode(wg_secret_key)
            .context("wg私钥错误")
            .unwrap();
        wg_secret_key
            .try_into()
            .map_err(|_| anyhow!("wg私钥错误"))
            .unwrap()
    } else {
        let mut wg_secret_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut wg_secret_key);
        wg_secret_key
    };
    let wg_secret_key = boringtun::x25519::StaticSecret::from(wg_secret_key);
    let wg_public_key = boringtun::x25519::PublicKey::from(&wg_secret_key);
    let config = ConfigInfo {
        port,
        white_token,
        gateway,
        broadcast,
        netmask,
        check_finger,
        #[cfg(feature = "web")]
        username: args.username.unwrap_or_else(|| "admin".into()),
        #[cfg(feature = "web")]
        password: args.password.unwrap_or_else(|| "admin".into()),
        wg_secret_key,
        wg_public_key,
    };
    let rsa = match RsaCipher::new(root_path) {
        Ok(rsa) => {
            println!("密钥指纹: {}", rsa.finger());
            Some(rsa)
        }
        Err(e) => {
            log::error!("获取密钥错误：{:?}", e);
            panic!("获取密钥错误:{}", e);
        }
    };
    log::info!("config:{:?}", config);
    let udp = create_udp(port, host.as_deref()).unwrap();
    log::info!("监听host:{:?},监听udp端口: {:?}",host, port);
    println!("监听host:{:?},监听udp端口: {:?}", host, port);
    let tcp = create_tcp(port, host.as_deref()).unwrap();
    log::info!("监听host:{:?},tcp/ws端口: {:?}",host, port);
    println!("监听host:{:?},监听tcp/ws端口: {:?}",host, port);
    #[cfg(feature = "web")]
    let http = if web_port != 0 {
        let http = create_tcp(web_port, host.as_deref()).unwrap();
        log::info!("监听http端口: {:?}", web_port);
        println!("监听http端口: {:?}", web_port);
        Some(http)
    } else {
        None
    };
    let config = config.clone();
    if let Err(e) = core::start(
        udp,
        tcp,
        #[cfg(feature = "web")]
        http,
        config,
        rsa,
    )
    .await
    {
        log::error!("{:?}", e)
    }
}

fn create_tcp(port: u16, host: Option<&str>) -> io::Result<std::net::TcpListener> {
    let address_str = match host {
        Some(h) => format!("{}:{}", h, port),
        None => format!("[::]:{}", port),
    };
    let address: std::net::SocketAddr = address_str.parse().unwrap();
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = io_convert(
        socket2::Socket::new(domain, socket2::Type::STREAM, None),
        |e| format!("new STREAM {:?}", e),
    )?;
    if domain == socket2::Domain::IPV6 {
        io_convert(socket.set_only_v6(false), |e| {
            format!("set_only_v6 {:?}", e)
        })?;
    }
    io_convert(socket.set_reuse_address(true), |e| {
        format!("set_reuse_address {:?}", e)
    })?;
    io_convert(socket.set_nonblocking(true), |e| {
        format!("set_nonblocking {:?}", e)
    })?;
    io_convert(socket.bind(&address.into()), |e| {
        format!("bind {:?},{:?}", address, e)
    })?;
    io_convert(socket.listen(1024), |e| {
        format!("listen {:?},{:?}", address, e)
    })?;
    Ok(socket.into())
}

fn create_udp(port: u16, host: Option<&str>) -> io::Result<std::net::UdpSocket> {
    let address_str = match host {
        Some(h) => format!("{}:{}", h, port),
        None => format!("[::]:{}", port),
    };
    let address: std::net::SocketAddr = address_str.parse().unwrap();
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = io_convert(
        socket2::Socket::new(domain, socket2::Type::DGRAM, None),
        |e| format!("new DGRAM {:?}", e),
    )?;
    if domain == socket2::Domain::IPV6 {
        io_convert(socket.set_only_v6(false), |e| {
            format!("set_only_v6 {:?}", e)
        })?;
    }
    io_convert(socket.set_reuse_address(true), |e| {
        format!("set_reuse_address {:?}", e)
    })?;
    io_convert(socket.set_nonblocking(true), |e| {
        format!("set_nonblocking {:?}", e)
    })?;
    io_convert(socket.bind(&address.into()), |e| {
        format!("bind {:?},{:?}", address, e)
    })?;
    Ok(socket.into())
}

#[inline]
pub fn io_convert<T, R: Display, F: FnOnce(&io::Error) -> R>(
    rs: io::Result<T>,
    f: F,
) -> io::Result<T> {
    rs.map_err(|e| io::Error::new(e.kind(), format!("{},internal error:{:?}", f(&e), e)))
}
