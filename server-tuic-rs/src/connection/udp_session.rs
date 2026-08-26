use std::{
	io::Error as IoError,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
	sync::{Arc, Weak},
};

use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
	net::UdpSocket,
	sync::{RwLock as AsyncRwLock, oneshot},
};
use tracing::debug;
use tuic::Address;

use super::Connection;
use crate::{AppContext, error::Error, utils::FutResultExt};

pub struct UdpSession {
	ctx:       Arc<AppContext>,
	assoc_id:  u16,
	conn:      Connection,
	socket_v4: UdpSocket,
	socket_v6: Option<UdpSocket>,
	close:     AsyncRwLock<Option<oneshot::Sender<()>>>,
}

impl UdpSession {
	// spawn a task which actually owns itself, then return its wake reference.
	pub fn new(ctx: Arc<AppContext>, conn: Connection, assoc_id: u16) -> Result<Weak<Self>, Error> {
		let socket_v4 = {
			let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
				.map_err(|err| Error::Socket("failed to create UDP associate IPv4 socket", err))?;

			socket
				.set_nonblocking(true)
				.map_err(|err| Error::Socket("failed setting UDP associate IPv4 socket as non-blocking", err))?;

			socket
				.bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))))
				.map_err(|err| Error::Socket("failed to bind UDP associate IPv4 socket", err))?;

			UdpSocket::from_std(StdUdpSocket::from(socket))?
		};

		let socket_v6 = if ctx.cfg.udp_relay_ipv6 {
			let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
				.map_err(|err| Error::Socket("failed to create UDP associate IPv6 socket", err))?;

			socket
				.set_nonblocking(true)
				.map_err(|err| Error::Socket("failed setting UDP associate IPv6 socket as non-blocking", err))?;

			socket
				.set_only_v6(true)
				.map_err(|err| Error::Socket("failed setting UDP associate IPv6 socket as IPv6-only", err))?;

			socket
				.bind(&SockAddr::from(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))))
				.map_err(|err| Error::Socket("failed to bind UDP associate IPv6 socket", err))?;

			Some(UdpSocket::from_std(StdUdpSocket::from(socket))?)
		} else {
			None
		};

		let (tx, rx) = oneshot::channel();

		let session = Arc::new(Self {
			ctx: ctx.clone(),
			conn,
			assoc_id,
			socket_v4,
			socket_v6,
			close: AsyncRwLock::new(Some(tx)),
		});

		let session_listening = session.clone();
		// UdpSession's real owner.
		let listen = async move {
			let mut rx = rx;
			let mut timeout = tokio::time::interval(ctx.cfg.stream_timeout);
			timeout.reset();

			loop {
				let next;
				tokio::select! {
					recv = session_listening.recv() => next = recv,
					// Parent QUIC connection dropped without a proper `UDP-DROP`: tear down
					// immediately instead of lingering until `stream_timeout` (or forever, if
					// the target keeps sending and resetting the timeout).
					_ = session_listening.conn.inner.closed() => {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] parent connection closed, cleaning up",
							id = session_listening.conn.id(),
							addr = session_listening.conn.inner.remote_address(),
							user = session_listening.conn.auth,
						);
						break;
					},
					// Avoid client didn't send `UDP-DROP` properly
					_ = timeout.tick() => {
						session_listening.close().await;
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] UDP session timeout",
							id = session_listening.conn.id(),
							addr = session_listening.conn.inner.remote_address(),
							user = session_listening.conn.auth,
						);
						continue;
					},
					// `UDP-DROP`
					_ = &mut rx => break
				}
				timeout.reset();
				let (pkt, addr) = match next {
					Ok(v) => v,
					Err(err) => {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] outbound listening error: {err}",
							id = session_listening.conn.id(),
							addr = session_listening.conn.inner.remote_address(),
							user = session_listening.conn.auth,
						);
						continue;
					}
				};

				tokio::spawn(
					session_listening
						.conn
						.clone()
						.relay_packet(pkt, Address::SocketAddress(addr), session_listening.assoc_id)
						.log_err(),
				);
			}
			// Only drop our own map entry. If this assoc_id was re-used and replaced by a
			// newer session while we were shutting down, leave that entry intact.
			let self_weak = Arc::downgrade(&session_listening);
			let mut sessions = session_listening.conn.udp_sessions.write().await;
			if sessions.get(&assoc_id).is_some_and(|entry| entry.ptr_eq(&self_weak)) {
				sessions.remove(&assoc_id);
			}
		};

		tokio::spawn(listen);
		Ok(Arc::downgrade(&session))
	}

	/// Send `pkt` to the first reachable target, trying candidates in preferred
	/// order (see [`send_to_first`]). Passing more than one target lets the
	/// caller express a family fallback (e.g. Prefer64's `[v6, v4]`).
	pub async fn send(&self, pkt: Bytes, targets: &[SocketAddr]) -> Result<(), Error> {
		send_to_first(&self.socket_v4, self.socket_v6.as_ref(), &pkt, targets).await
	}

	async fn recv(&self) -> Result<(Bytes, SocketAddr), IoError> {
		let recv = async |socket: &UdpSocket| -> Result<(Bytes, SocketAddr), IoError> {
			let mut buf = vec![0u8; self.ctx.cfg.max_external_packet_size];
			let (n, addr) = socket.recv_from(&mut buf).await?;
			let addr = normalize_v4_mapped(addr);
			buf.truncate(n);
			Ok((Bytes::from(buf), addr))
		};

		if let Some(socket_v6) = &self.socket_v6 {
			tokio::select! {
				res = recv(&self.socket_v4) => res,
				res = recv(socket_v6) => res,
			}
		} else {
			recv(&self.socket_v4).await
		}
	}

	pub async fn close(&self) {
		if let Some(v) = self.close.write().await.take() {
			_ = v.send(());
		}
	}
}

/// Normalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) back to plain IPv4
/// so it is routed to the IPv4 socket. The IPv6 socket is bound
/// `set_only_v6(true)`, so a mapped address would otherwise fail to send.
fn normalize_v4_mapped(addr: SocketAddr) -> SocketAddr {
	if let SocketAddr::V6(v6) = addr
		&& let Some(v4) = v6.ip().to_ipv4_mapped()
	{
		return SocketAddr::new(IpAddr::V4(v4), v6.port());
	}
	addr
}

/// Send `pkt` to the first reachable target, trying candidates in order and
/// advancing to the next on any send error. IPv6 targets require `socket_v6`;
/// when it is absent (IPv6 relay disabled) the IPv6 attempt errors and the loop
/// falls back to the next candidate — this is how a Prefer64 target degrades to
/// IPv4. Returns the last error if every candidate fails.
async fn send_to_first(
	socket_v4: &UdpSocket,
	socket_v6: Option<&UdpSocket>,
	pkt: &[u8],
	targets: &[SocketAddr],
) -> Result<(), Error> {
	let mut last_err = None;
	for &target in targets {
		let addr = normalize_v4_mapped(target);
		let res = match addr {
			SocketAddr::V4(_) => socket_v4.send_to(pkt, addr).await.map_err(Error::from),
			SocketAddr::V6(_) => match socket_v6 {
				Some(sock) => sock.send_to(pkt, addr).await.map_err(Error::from),
				None => Err(Error::UdpRelayIpv6Disabled(addr)),
			},
		};
		match res {
			Ok(_) => return Ok(()),
			Err(err) => last_err = Some(err),
		}
	}
	Err(last_err.unwrap_or_else(|| {
		Error::Socket(
			"no UDP target address",
			IoError::new(std::io::ErrorKind::InvalidInput, "empty target list"),
		)
	}))
}

#[cfg(test)]
mod tests {
	use std::{
		net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
		time::Duration,
	};

	use tokio::net::UdpSocket;

	use super::{Error, send_to_first};

	async fn recv_with_timeout(server: &UdpSocket) -> Vec<u8> {
		let mut buf = [0u8; 16];
		let (n, _) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf))
			.await
			.expect("server must receive before timeout")
			.expect("recv_from ok");
		buf[..n].to_vec()
	}

	#[tokio::test]
	async fn falls_back_to_ipv4_when_ipv6_socket_absent() {
		// Prefer64 ordering [v6, v4] with no IPv6 socket: the v6 attempt errors
		// and the datagram must still be delivered via the IPv4 fallback.
		let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let port = server.local_addr().unwrap().port();
		let sender_v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

		let targets = [
			SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
			SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
		];

		send_to_first(&sender_v4, None, b"ping", &targets)
			.await
			.expect("must deliver via IPv4 fallback");

		assert_eq!(recv_with_timeout(&server).await, b"ping");
	}

	#[tokio::test]
	async fn ipv4_mapped_ipv6_target_routes_to_ipv4_socket() {
		// A `::ffff:127.0.0.1` target with only a v4 socket must be normalized
		// to IPv4 and delivered, not rejected as IPv6.
		let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let port = server.local_addr().unwrap().port();
		let sender_v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

		let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), port);
		send_to_first(&sender_v4, None, b"map", &[mapped])
			.await
			.expect("mapped target must route to the v4 socket");

		assert_eq!(recv_with_timeout(&server).await, b"map");
	}

	#[tokio::test]
	async fn errors_when_all_targets_fail() {
		// Only an IPv6 target but no IPv6 socket: no candidate can be sent.
		let sender_v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let target = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);

		let err = send_to_first(&sender_v4, None, b"x", &[target])
			.await
			.expect_err("must fail when the only target is unreachable");
		assert!(matches!(err, Error::UdpRelayIpv6Disabled(_)));
	}
}
