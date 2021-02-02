use crate::conversion::{to_nb, SocketAddr};
use crate::SocketState;
use embedded_nal::nb;
use embedded_nal::{UdpClient, UdpServer};
use std::io::{self, Error};
use std::net::{self, IpAddr, Ipv4Addr, Ipv6Addr};

pub struct UdpSocket {
    state: SocketState<net::UdpSocket>,
}

impl UdpSocket {
    fn new() -> Self {
        Self {
            state: SocketState::new(),
        }
    }
}

impl UdpClient for crate::Stack {
    type UdpSocket = UdpSocket;
    type Error = Error;

    fn socket(&self) -> Result<Self::UdpSocket, Self::Error> {
        Ok(UdpSocket::new())
    }

    fn connect(
        &self,
        socket: &mut Self::UdpSocket,
        remote: embedded_nal::SocketAddr,
    ) -> std::io::Result<()> {
        let any = match remote {
            embedded_nal::SocketAddr::V4(_) => {
                net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }
            embedded_nal::SocketAddr::V6(_) => {
                net::SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            }
        };

        let sock = net::UdpSocket::bind(any)?;

        sock.set_nonblocking(true)?;

        sock.connect(SocketAddr::from(remote))?;
        socket.state = SocketState::Connected(sock);
        Ok(())
    }

    fn send(&self, socket: &mut Self::UdpSocket, buffer: &[u8]) -> nb::Result<(), Self::Error> {
        let sock = socket.state.get_running()?;
        sock.send(buffer).map(drop).map_err(to_nb)
    }

    fn receive(
        &self,
        socket: &mut Self::UdpSocket,
        buffer: &mut [u8],
    ) -> nb::Result<(usize, embedded_nal::SocketAddr), Self::Error> {
        let sock = socket.state.get_any()?;
        sock.recv_from(buffer)
            .map(|(length, peer_addr)| (length, SocketAddr::from(peer_addr).into()))
            .map_err(to_nb)
    }

    fn close(&self, _: Self::UdpSocket) -> io::Result<()> {
        // No-op: Socket gets closed when it is freed
        //
        // Could wrap it in an Option, but really that'll only make things messier; users will
        // probably drop the socket anyway after closing, and can't expect it to be usable with
        // this API.
        Ok(())
    }
}

impl UdpServer for crate::Stack {
    fn bind(&self, socket: &mut UdpSocket, port: u16) -> Result<(), Error> {
        let anyaddressthisport = net::SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);

        let sock = net::UdpSocket::bind(anyaddressthisport)?;

        sock.set_nonblocking(true)?;

        socket.state = SocketState::Bound(sock);
        Ok(())
    }
    fn send_to(&self, socket: &mut UdpSocket, remote: embedded_nal::SocketAddr, buffer: &[u8]) -> Result<(), nb::Error<Error>> {
        let sock = socket.state.get_bound()?;
        sock.send_to(buffer, SocketAddr::from(remote)).map(drop).map_err(to_nb)
    }
}
