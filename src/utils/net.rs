//! Listener helpers with a portable dual-stack default for wildcard IPv6 binds.

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};

fn socket(addr: SocketAddr, socket_type: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), socket_type, Some(protocol))?;

    // OS defaults differ: notably, Windows creates IPv6-only wildcard sockets unless
    // IPV6_V6ONLY is explicitly disabled. Keep `[::]:port` consistently dual-stack.
    if let SocketAddr::V6(addr) = addr
        && addr.ip().is_unspecified()
    {
        socket.set_only_v6(false)?;
    }

    Ok(socket)
}

pub fn bind_tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket(addr, Type::STREAM, Protocol::TCP)?;
    // Allow Unix listeners to restart while old connections are in TIME_WAIT.
    // Set this before bind, including on the original listener. Windows gives
    // SO_REUSEADDR different port-sharing semantics, so retain its defaults.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into()).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to bind TCP listener {addr}: {error}"),
        )
    })?;
    socket.listen(1024)?;
    let listener: TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub fn bind_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket(addr, Type::DGRAM, Protocol::UDP)?;
    socket.bind(&addr.into()).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to bind UDP socket {addr}: {error}"),
        )
    })?;
    let socket: UdpSocket = socket.into();
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_ipv6_socket_is_not_ipv6_only() {
        let addr = "[::]:0".parse().expect("valid IPv6 wildcard address");
        let socket = socket(addr, Type::STREAM, Protocol::TCP).expect("create dual-stack socket");
        assert!(!socket.only_v6().expect("read IPV6_V6ONLY"));
    }

    #[test]
    fn active_tcp_listener_cannot_be_bound_twice() {
        let listener = bind_tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let error = bind_tcp_listener(addr).expect_err("live listener must retain its port");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains(&format!("TCP listener {addr}")));
    }

    #[test]
    fn active_udp_socket_cannot_be_bound_twice() {
        let socket = bind_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = socket.local_addr().unwrap();
        let error = bind_udp_socket(addr).expect_err("live UDP socket must retain its port");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains(&format!("UDP socket {addr}")));
    }

    #[cfg(unix)]
    #[test]
    fn tcp_listener_can_restart_with_connections_in_time_wait() {
        use std::io::Read;
        use std::net::{Shutdown, TcpStream};
        use std::time::Duration;

        for (bind, ipv4_client) in [("127.0.0.1:0", true), ("[::]:0", false), ("[::]:0", true)] {
            let listener = bind_tcp_listener(bind.parse().unwrap()).unwrap();
            listener.set_nonblocking(false).unwrap();
            let addr = listener.local_addr().unwrap();
            let connect_addr = if ipv4_client {
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, addr.port()))
            } else {
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port()))
            };
            let mut client = TcpStream::connect(connect_addr).unwrap();
            let (mut connection, _) = listener.accept().unwrap();
            connection.set_nonblocking(false).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();

            // Let the server actively close and receive the peer's FIN, leaving
            // its local port in TIME_WAIT even after all descriptors are closed.
            connection.shutdown(Shutdown::Write).unwrap();
            client.read_to_end(&mut Vec::new()).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            connection.read_to_end(&mut Vec::new()).unwrap();
            drop(connection);
            drop(client);
            drop(listener);

            let restarted =
                bind_tcp_listener(addr).expect("rebind while old connections are in TIME_WAIT");
            assert_eq!(restarted.local_addr().unwrap(), addr);
        }
    }
}
