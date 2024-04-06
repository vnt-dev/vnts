use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::{select, signal};

use crate::core::service::PacketHandler;
use crate::protocol::NetPacket;

pub async fn start(main_udp: Arc<UdpSocket>, handler: PacketHandler) -> io::Result<()> {
    let state = Arc::new((AtomicUsize::new(0), Notify::new()));

    let udp = main_udp.clone();
    loop {
        let mut buf = vec![0; 65536];
        select! {
            handle = udp.recv_from(&mut buf) =>{

                let state = state.clone();
                state.0.fetch_add(1, Ordering::Relaxed);
                // log::info!("Udp State++: {state:?}");

        match handle {
            Ok((len, addr)) => {
                let handler = handler.clone();
                let udp = main_udp.clone();
                tokio::spawn(async move {
                    match NetPacket::new(&mut buf[..len]) {
                        Ok(net_packet) => {
                            if let Some(rs) = handler.handle(net_packet, addr, &None).await {
                                let _ = udp.send_to(rs.buffer(), addr).await;
                            }
                        }
                        Err(e) => {
                            log::error!("{:?}", e)
                        }
                    }
                });
            }
            Err(e) => {
                log::error!("{:?}", e)
            }
        }


                if state.0.fetch_sub(1, Ordering::Relaxed) == 1 {
                    state.1.notify_one();
                }
                // log::info!("Udp State--: {state:?}");
            }
            _shutdown = signal::ctrl_c() => {
                log::info!("ctrl_c is pressed, exit");
                let timer = tokio::time::sleep(Duration::from_secs(30));
                // notified by the last active task
                let notification = state.1.notified();

                // if the count isn't zero, we have to wait
                if state.0.load(Ordering::Relaxed) != 0 {
                    // wait for either the timer or notification to resolve
                    select! {
                        _ = timer => {}
                        _ = notification => {}
                    }
                } else {
                    return Ok(());
                }
            }
        }
    }
}
