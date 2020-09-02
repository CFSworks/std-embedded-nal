use embedded_nal::nb;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use crate::conversion::*;

impl embedded_nal::UdpStack for crate::Stack {
    type UdpSocket = UdpSocket;
    type Error = std::io::Error;

    fn open(
        &self,
        remote: embedded_nal::SocketAddr,
        mode: embedded_nal::Mode,
    ) -> std::io::Result<UdpSocket> {
        let any = match remote {
            embedded_nal::SocketAddr::V4(_) => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }
            embedded_nal::SocketAddr::V6(_) => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            }
        };
        let sock = std::net::UdpSocket::bind(any)?;
        sock.connect(nal_to_std_sockaddr(remote))?;

        match mode {
            embedded_nal::Mode::NonBlocking => {
                sock.set_nonblocking(true)?;
            }
            embedded_nal::Mode::Blocking => {
                sock.set_nonblocking(false)?;
                sock.set_read_timeout(None)?;
                sock.set_write_timeout(None)?;
            }
            embedded_nal::Mode::Timeout(millis) => {
                sock.set_nonblocking(false)?;
                sock.set_read_timeout(Some(std::time::Duration::from_millis(millis.into())))?;
                sock.set_write_timeout(Some(std::time::Duration::from_millis(millis.into())))?;
            }
        }

        Ok(sock)
    }
    fn write(
        &self,
        socket: &mut UdpSocket,
        buffer: &[u8],
    ) -> Result<(), nb::Error<std::io::Error>> {
        socket
            .send(buffer)
            .map(|s| {
                if s == buffer.len() {
                    ()
                } else {
                    panic!("Send worked but did not send everything")
                }
            })
            .map_err(std_to_nal_error)
    }
    fn read(
        &self,
        socket: &mut UdpSocket,
        buffer: &mut [u8],
    ) -> Result<usize, nb::Error<std::io::Error>> {
        socket.recv(buffer).map_err(std_to_nal_error)
    }

    fn close(&self, _: UdpSocket) -> Result<(), std::io::Error> {
        // No-op: Socket gets closed when it is freed
        //
        // Could wrap it in an Option, but really that'll only make things messier; users will
        // probably drop the socket anyway after closing, and can't expect it to be usable with
        // this API.
        Ok(())
    }
}
