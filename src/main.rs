use std::net::UdpSocket;
use std::thread;

pub mod error;
pub mod proto;
pub mod protocol;
pub mod service;

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
    log_init();
    let udp = UdpSocket::bind("0.0.0.0:29871").unwrap();
    log::info!("启动:{:?}",udp.local_addr().unwrap());
    let num = if let Ok(num) = thread::available_parallelism() {
        num.get() * 2
    } else {
        2
    };
    for _ in 0..num {
        let udp = udp.try_clone().unwrap();
        thread::spawn(move || {
            service::handle_loop(udp);
        });
    }

    service::handle_loop(udp);
}
