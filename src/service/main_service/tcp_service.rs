use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{channel, Sender};

use crate::cipher::{Aes256GcmCipher, RsaCipher};
use crate::service::main_service::common::handle;
use crate::service::main_service::{
    Context, PeerDeviceStatus, DEVICE_ADDRESS, TCP_AES, VIRTUAL_NETWORK,
};
use crate::ConfigInfo;

pub async fn start_tcp(
    tcp: TcpListener,
    main_udp: Arc<UdpSocket>,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
) {
    loop {
        let (stream, addr) = match tcp.accept().await {
            Ok(rs) => rs,
            Err(e) => {
                log::warn!("tcp accept err:{:?}", e);
                continue;
            }
        };
        log::info!("tcp连接 {}", addr);
        let (r, mut w) = stream.into_split();

        let (sender, mut receiver) = channel::<Vec<u8>>(100);
        tokio::spawn(async move {
            let mut head = [0; 4];
            while let Some(data) = receiver.recv().await {
                let len = data.len();
                head[2] = (len >> 8) as u8;
                head[3] = (len & 0xFF) as u8;
                if let Err(e) = w.write_all(&head).await {
                    log::info!("发送失败,链接终止:{:?},{:?}", addr, e);
                }
                if let Err(e) = w.write_all(&data).await {
                    log::info!("发送失败,链接终止:{:?},{:?}", addr, e);
                    break;
                }
            }
            let _ = w.shutdown().await;
        });
        let main_udp = main_udp.clone();
        let config = config.clone();
        let rsa_cipher = rsa_cipher.clone();
        tokio::spawn(async move {
            let mut context: Option<Context> = None;
            let mut aes_gcm_cipher: Option<Aes256GcmCipher> = None;
            if let Err(e) = tcp_handle(
                rsa_cipher,
                &mut aes_gcm_cipher,
                &mut context,
                config,
                r,
                addr,
                sender,
                main_udp,
            )
            .await
            {
                log::info!("接收失败,链接终止:{:?},{:?}", addr, e);
            }
            TCP_AES.remove(&addr);
            if let Some(context) = context {
                if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                    let mut lock = v.write();
                    if let Some(item) = lock.virtual_ip_map.get_mut(&context.device_id) {
                        if item.id != context.id {
                            return;
                        }
                        item.status = PeerDeviceStatus::Offline;
                        DEVICE_ADDRESS.remove(&(context.token, context.virtual_ip));
                        lock.epoch += 1;
                    }
                }
            }
        });
    }
}

async fn tcp_handle(
    rsa_cipher: Option<RsaCipher>,
    aes_gcm_cipher: &mut Option<Aes256GcmCipher>,
    context: &mut Option<Context>,
    config: ConfigInfo,
    mut read: OwnedReadHalf,
    addr: SocketAddr,
    sender: Sender<Vec<u8>>,
    main_udp: Arc<UdpSocket>,
) -> io::Result<()> {
    let mut head = [0; 4];
    let mut buf = [0; 10240];
    loop {
        read.read_exact(&mut head).await?;
        let len = (((head[2] as u16) << 8) | head[3] as u16) as usize;
        if len < 12 || len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "length overflow",
            ));
        }
        read.read_exact(&mut buf[..len]).await?;
        if let Err(e) = handle(
            &rsa_cipher,
            aes_gcm_cipher,
            context,
            &main_udp,
            &mut buf[..len],
            addr,
            &config,
            Some(&sender),
        )
        .await
        {
            log::info!("tcp数据处理失败:{:?},{:?}", addr, e);
        }
    }
}
