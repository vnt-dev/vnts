use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::mpsc::{channel, Sender};

use crate::ConfigInfo;
use crate::service::main_service::{Context, DEVICE_ADDRESS, PeerDeviceStatus, VIRTUAL_NETWORK};
use crate::service::main_service::common::handle;

pub async fn start_tcp(tcp: TcpListener, main_udp: Arc<UdpSocket>, config: ConfigInfo) -> io::Result<()> {
    loop {
        let (stream, addr) = match tcp.accept().await {
            Ok(rs) => { rs }
            Err(e) => {
                log::warn!("tcp accept err:{:?}",e);
                continue;
            }
        };
        log::info!("tcp连接 {}",addr);
        let (r, mut w) = stream.into_split();

        let (sender, mut receiver) = channel::<Vec<u8>>(100);
        tokio::spawn(async move {
            while let Some(mut data) = receiver.recv().await {
                if data.len() >= 4 {
                    let len = data.len() - 4;
                    data[2] = (len >> 8) as u8;
                    data[3] = (len & 0xFF) as u8;
                    if let Err(e) = w.write_all(&data).await {
                        log::info!("发送失败,链接终止:{:?},{:?}",addr,e);
                        break;
                    }
                }
            }
            let _ = w.shutdown().await;
        });
        let main_udp = main_udp.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let mut context = Context {
                token: "".to_string(),
                virtual_ip: 0,
                id: 0,
                device_id: "".to_string(),
            };
            if let Err(e) = tcp_handle(&mut context, config, r, addr, sender, main_udp).await {
                log::info!("接收失败,链接终止:{:?},{:?}",addr,e);
            }
            if context.virtual_ip != 0 && context.id != 0 {
                if let Some(v) = VIRTUAL_NETWORK.get(&context.token) {
                    let mut lock = v.write();
                    if let Some(mut item) = lock.virtual_ip_map.get_mut(&context.device_id) {
                        if item.id != context.id {
                            return;
                        }
                        item.status = PeerDeviceStatus::Offline;
                        DEVICE_ADDRESS.invalidate(&(context.token, context.virtual_ip));
                    }
                    lock.epoch += 1;
                }
            }
        });
    }
}


async fn tcp_handle(context: &mut Context, config: ConfigInfo, mut read: OwnedReadHalf, addr: SocketAddr, sender: Sender<Vec<u8>>, main_udp: Arc<UdpSocket>) -> io::Result<()> {
    let mut buf = [0; 10240];
    loop {
        read.read_exact(&mut buf[..4]).await?;
        let len = 4 + (((buf[2] as u16) << 8) | buf[3] as u16) as usize;
        read.read_exact(&mut buf[4..len]).await?;
        if let Err(e) = handle(context, &main_udp, &mut buf[..len], addr, &config, Some(&sender)).await {
            log::info!("tcp数据处理失败:{:?},{:?}",addr,e);
        }
    }
}

