use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::ConfigInfo;
use crate::service::main_service::{Context, UDP_SESSION};
use crate::service::main_service::common::handle;

pub async fn start_udp(main_udp: Arc<UdpSocket>, config: ConfigInfo) {
    loop {
        let mut buf = vec![0u8; 10240];
        match main_udp.recv_from(&mut buf[4..]).await {
            Ok((len, addr)) => {
                let main_udp = main_udp.clone();
                let config = config.clone();
                let mut context = UDP_SESSION.get(&addr).unwrap_or_else(|| {
                    Context {
                        token: "".to_string(),
                        virtual_ip: 0,
                        id: 0,
                        device_id: "".to_string(),
                    }
                });
                tokio::spawn(async move {
                    match handle(&mut context, &main_udp, &mut buf[..len + 4], addr, &config, None).await {
                        Ok(_) => {}
                        Err(e) => {
                            log::info!("udp数据处理失败:{:?},{:?}",addr,e);
                        }
                    }
                });
            }
            Err(e) => {
                log::error!("{:?}", e)
            }
        }
    }
}