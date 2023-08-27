use std::sync::Arc;

use crate::cipher::RsaCipher;
use tokio::net::UdpSocket;

use crate::service::main_service::common::handle;
use crate::service::main_service::{UDP_AES, UDP_SESSION};
use crate::ConfigInfo;

pub async fn start_udp(
    main_udp: Arc<UdpSocket>,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
) {
    loop {
        let mut buf = vec![0u8; 10240];
        match main_udp.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let main_udp = main_udp.clone();
                let config = config.clone();
                let rsa_cipher = rsa_cipher.clone();
                let mut context = UDP_SESSION.get(&addr);
                let mut aes = UDP_AES.get(&addr);
                tokio::spawn(async move {
                    match handle(
                        &rsa_cipher,
                        &mut aes,
                        &mut context,
                        &main_udp,
                        &mut buf[..len],
                        addr,
                        &config,
                        None,
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            log::info!("udp数据处理失败:{:?},{:?}", addr, e);
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
