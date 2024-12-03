//! UDP implementation on the standard stack for embedded-nal-async

use std::io::Error;
use std::net::{IpAddr, SocketAddr};

use std::os::unix::io::AsRawFd;

pub struct ConnectedSocket(async_std::net::UdpSocket);
pub struct UniquelyBoundSocket {
    socket: async_std::net::UdpSocket,
    // By storing this, we avoid the whole recvmsg hell, which we can because there's really only
    // one relevant address. (Alternatively, we could call `.local_addr()` over and over).
    bound_address: SocketAddr,
}
pub struct MultiplyBoundSocket {
    socket: async_io::Async<std::net::UdpSocket>,
    // Storing this so we can return a full SocketAddr, even though pktinfo doesn't provide that
    // information
    port: u16,
}

impl embedded_nal_async::UdpStack for crate::Stack {
    type Error = Error;
    type Connected = ConnectedSocket;
    type UniquelyBound = UniquelyBoundSocket;
    type MultiplyBound = MultiplyBoundSocket;

    async fn connect_from(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(SocketAddr, Self::Connected), Self::Error> {
        let sock = async_std::net::UdpSocket::bind(local).await?;

        sock.connect(remote).await?;

        let final_local = sock.local_addr()?;

        Ok((final_local, ConnectedSocket(sock)))
    }

    async fn bind_single(
        &self,
        local: SocketAddr,
    ) -> Result<(SocketAddr, Self::UniquelyBound), Self::Error> {
        let sock = async_std::net::UdpSocket::bind(local).await?;

        let final_local = sock.local_addr()?;

        Ok((
            final_local,
            UniquelyBoundSocket {
                socket: sock,
                bound_address: final_local,
            },
        ))
    }

    async fn bind_multiple(&self, local: SocketAddr) -> Result<Self::MultiplyBound, Self::Error> {
        let is_v4 = matches!(&local, SocketAddr::V4(_));

        let mut sock = async_io::Async::<std::net::UdpSocket>::bind(local)?;

        let plain_sock = sock.get_mut();

        if is_v4 {
            nix::sys::socket::setsockopt(
                &plain_sock,
                nix::sys::socket::sockopt::Ipv4PacketInfo,
                &true,
            )?;
        } else {
            nix::sys::socket::setsockopt(
                &plain_sock,
                nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
                &true,
            )?;
        }

        let mut local_port = local.port();
        if local_port == 0 {
            local_port = plain_sock.local_addr()?.port();
        }

        Ok(MultiplyBoundSocket {
            socket: sock,
            port: local_port,
        })
    }
}

impl embedded_nal_async::ConnectedUdp for ConnectedSocket {
    type Error = Error;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let sent_len = self.0.send(data).await?;
        assert!(
            sent_len == data.len(),
            "Datagram was not sent in a single operation"
        );
        Ok(())
    }

    async fn receive_into(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.recv(buffer).await
    }
}

impl embedded_nal_async::UnconnectedUdp for UniquelyBoundSocket {
    type Error = Error;

    async fn send(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        debug_assert!(
            local == self.bound_address,
            "A socket created from bind_single must always provide its original local address (or the one returned from a receive) in send"
        );
        let sent_len = self.socket.send_to(data, remote).await?;
        assert!(
            sent_len == data.len(),
            "Datagram was not sent in a single operation"
        );
        Ok(())
    }

    async fn receive_into(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, SocketAddr), Self::Error> {
        let (length, remote) = self.socket.recv_from(buffer).await?;
        Ok((length, self.bound_address, remote))
    }
}

impl embedded_nal_async::UnconnectedUdp for MultiplyBoundSocket {
    type Error = Error;

    async fn send(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        if local.port() != 0 {
            debug_assert_eq!(
                local.port(),
                self.port,
                "Packets can only be sent from the locally bound to port"
            );
        }
        match remote {
            // The whole cases are distinct as send_msg is polymorphic
            SocketAddr::V6(remote) => {
                // Taking this step on foot due to https://github.com/nix-rust/nix/issues/1754
                let remote = nix::sys::socket::SockaddrIn6::from(remote);
                let local_ip = match local.ip() {
                    IpAddr::V6(a) => a,
                    _ => panic!("Type requires IPv6 addresses"),
                };
                let local_pktinfo = nix::libc::in6_pktinfo {
                    ipi6_addr: nix::libc::in6_addr {
                        s6_addr: local_ip.octets(),
                    },
                    // FIXME discarding zone info
                    ipi6_ifindex: 0,
                };
                let control = [nix::sys::socket::ControlMessage::Ipv6PacketInfo(
                    &local_pktinfo,
                )];
                self.socket
                    .write_with(|s| {
                        let sent_len = nix::sys::socket::sendmsg(
                            s.as_raw_fd(),
                            &[std::io::IoSlice::new(data)],
                            // FIXME this ignores the IP part of the local address
                            &control,
                            nix::sys::socket::MsgFlags::empty(),
                            Some(&remote),
                        )?;
                        assert!(
                            sent_len == data.len(),
                            "Datagram was not sent in a single operation"
                        );
                        Ok(())
                    })
                    .await
            }
            SocketAddr::V4(remote) => {
                // Taking this step on foot due to https://github.com/nix-rust/nix/issues/1754
                let remote = nix::sys::socket::SockaddrIn::from(remote);
                let local_ip = match local.ip() {
                    IpAddr::V4(a) => a,
                    _ => panic!("Type requires IPv4 addresses"),
                };
                let local_pktinfo = nix::libc::in_pktinfo {
                    ipi_addr: nix::libc::in_addr {
                        s_addr: local_ip.into(),
                    },
                    ipi_spec_dst: nix::libc::in_addr {
                        s_addr: local_ip.into(),
                    },
                    // FIXME discarding zone info
                    ipi_ifindex: 0,
                };
                let control = [nix::sys::socket::ControlMessage::Ipv4PacketInfo(
                    &local_pktinfo,
                )];
                self.socket
                    .write_with(|s| {
                        let sent_len = nix::sys::socket::sendmsg(
                            s.as_raw_fd(),
                            &[std::io::IoSlice::new(data)],
                            // FIXME this ignores the IP part of the local address
                            &control,
                            nix::sys::socket::MsgFlags::empty(),
                            Some(&remote),
                        )?;
                        assert!(
                            sent_len == data.len(),
                            "Datagram was not sent in a single operation"
                        );
                        Ok(())
                    })
                    .await
            }
        }
    }

    async fn receive_into(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, SocketAddr), Self::Error> {
        let (length, remote, local) = self.socket.read_with(|s| {
            let mut iov = [std::io::IoSliceMut::new(buffer)];
            let mut cmsg = nix::cmsg_space!(nix::libc::in6_pktinfo);
            let received = nix::sys::socket::recvmsg(
                s.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                nix::sys::socket::MsgFlags::MSG_TRUNC,
                )
                .map_err(Error::from)?;
            let local = match received.cmsgs().next() {
                Some(nix::sys::socket::ControlMessageOwned::Ipv6PacketInfo(pi)) => {
                    SocketAddr::new(pi.ipi6_addr.s6_addr.into(), self.port)
                },
                Some(nix::sys::socket::ControlMessageOwned::Ipv4PacketInfo(pi)) => {
                    SocketAddr::new(async_std::net::Ipv4Addr::from(pi.ipi_addr.s_addr).into(), self.port)
                },
                _ => panic!("Operating system failed to send IPv4/IPv6 packet info after acknowledging the socket option")
            };
            Ok((received.bytes, received.address, local))
        }).await?;

        let remote: nix::sys::socket::SockaddrStorage =
            remote.expect("recvmsg on UDP always returns a remote address");
        // Taking this step on foot due to https://github.com/nix-rust/nix/issues/1754
        let remote = match (remote.as_sockaddr_in6(), remote.as_sockaddr_in()) {
            (Some(remote), None) => SocketAddr::V6(std::net::SocketAddrV6::new(
                remote.ip(),
                remote.port(),
                remote.flowinfo(),
                remote.scope_id(),
            )),
            (None, Some(remote)) => SocketAddr::V4(std::net::SocketAddrV4::new(
                remote.ip().into(),
                remote.port(),
            )),
            _ => panic!("Unexpected address type"),
        };

        // We could probably shorten things by going more directly from SockaddrLike
        Ok((length, local, remote))
    }
}
