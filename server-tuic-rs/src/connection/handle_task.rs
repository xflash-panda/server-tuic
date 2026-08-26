use std::{
	collections::hash_map::Entry,
	net::{IpAddr, Ipv4Addr, SocketAddr},
};

use bytes::Bytes;
use eyre::eyre;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use tuic::{
	Address, is_private_ip,
	quinn::{Authenticate, Connect, Packet},
};

use super::{Connection, ERROR_CODE, UdpSession};
use crate::{
	acl::{Addr, DirectMode, OutboundHandler, Protocol},
	dns::{ResolveDecision, resolve_decision},
	io::copy_io,
	stats,
	utils::UdpRelayMode,
};

impl Connection {
	fn should_drop_address(&self, addr: &SocketAddr) -> bool {
		// Built-in safety: drop localhost/private if configured
		if self.ctx.cfg.experimental.drop_loopback && addr.ip().is_loopback() {
			return true;
		}
		if self.ctx.cfg.experimental.drop_private && is_private_ip(&addr.ip()) {
			return true;
		}
		false
	}

	pub async fn handle_authenticate(&self, auth: Authenticate) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] [AUTH] {auth_uuid}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			auth_uuid = auth.uuid(),
		);
	}

	pub async fn handle_connect(&self, mut conn: Connect) {
		let target_addr = conn.addr().to_string();

		debug!(
			"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} ",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		let process = async {
			// Match against ACL engine
			let outbound = self.get_outbound_handler(conn.addr(), Protocol::TCP);

			// Handle reject early
			if outbound.is_reject() {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} rejected by ACL",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
				);
				_ = conn.reset(ERROR_CODE);
				return Ok(());
			}

			// Convert Address to acl-engine-rs Addr
			let mut acl_addr = address_to_acl_addr(conn.addr());

			// Front-load DNS resolution for Direct + domain targets so the
			// userland cache absorbs repeat lookups instead of `Direct`'s own
			// `tokio::net::lookup_host`. Failure here means we never call
			// `dial_tcp`, so the fallback path inside `Direct` is unreachable.
			if let ResolveDecision::Cache(domain) = resolve_decision(outbound.as_ref(), conn.addr()) {
				match self.ctx.dns_resolver.resolve_to_info(domain).await {
					Ok(info) => acl_addr = acl_addr.with_resolve_info(info),
					Err(err) => {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} dns resolve failed: {err}",
							id = self.id(),
							addr = self.inner.remote_address(),
							user = self.auth,
						);
						_ = conn.reset(ERROR_CODE);
						return Ok(());
					}
				}
			}

			// Use acl-engine-rs's async outbound to dial TCP
			let tcp_conn = outbound
				.as_async_outbound()
				.dial_tcp(&mut acl_addr)
				.await
				.map_err(|e| eyre!("Failed to connect: {}", e))?;

			// Check if the peer address should be blocked (experimental filters)
			// Only check for Direct outbound - for proxied connections (Socks5, etc.),
			// peer_addr() returns the proxy server address, not the actual target
			if outbound.is_direct() {
				if let Ok(peer_addr) = tcp_conn.peer_addr() {
					if self.should_drop_address(&peer_addr) {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} blocked (loopback/private)",
							id = self.id(),
							addr = self.inner.remote_address(),
							user = self.auth,
						);
						_ = conn.reset(ERROR_CODE);
						return Ok(());
					}
				}
			}

			// Convert to tokio-compatible stream for copy_io
			let mut stream = tcp_conn;

			// Copy data bidirectionally
			let (tx, rx, err) = copy_io(&mut conn, &mut stream).await;
			if err.is_some() {
				_ = conn.reset(ERROR_CODE);
			} else {
				_ = conn.finish().await;
			}
			_ = stream.shutdown().await;

			// Record traffic stats
			if self.auth.is_authenticated() {
				let uid = self.auth.get_uid();
				stats::req_incr(&self.ctx, uid);
				stats::traffic_tx(&self.ctx, uid, tx);
				stats::traffic_rx(&self.ctx, uid, rx);
			}

			if let Some(err) = err {
				return Err(err.into());
			}

			eyre::Ok(())
		};

		match process.await {
			Ok(()) => {}
			Err(err) => debug!(
				"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
			),
		}
	}

	/// Get outbound handler for the given address and protocol
	fn get_outbound_handler(&self, addr: &Address, protocol: Protocol) -> std::sync::Arc<OutboundHandler> {
		if let Some(acl_engine) = &self.ctx.cfg.acl_engine {
			// Extract host and port from address
			// Declare ip_string outside the match so it outlives the borrow in (host, port)
			let ip_string;
			let (host, port) = match addr {
				Address::DomainAddress(domain, port) => (domain.as_str(), *port),
				Address::SocketAddress(addr) => {
					ip_string = addr.ip().to_string();
					(ip_string.as_str(), addr.port())
				}
				Address::None => ("", 0),
			};

			// Match using ACL engine
			match acl_engine.match_host(host, port, protocol) {
				Some(handler) => handler,
				None => {
					// No match, use default direct
					std::sync::Arc::new(OutboundHandler::Direct(std::sync::Arc::new(
						crate::acl::DirectOutbound::with_mode(DirectMode::Auto),
					)))
				}
			}
		} else {
			// No ACL engine, use default direct
			std::sync::Arc::new(OutboundHandler::Direct(std::sync::Arc::new(
				crate::acl::DirectOutbound::with_mode(DirectMode::Auto),
			)))
		}
	}

	pub async fn handle_packet(&self, pkt: Packet, mode: UdpRelayMode) {
		let assoc_id = pkt.assoc_id();
		let pkt_id = pkt.pkt_id();
		let frag_id = pkt.frag_id();
		let frag_total = pkt.frag_total();

		debug!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment \
			 {frag_id}/{frag_total}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			frag_id = frag_id + 1,
		);

		self.udp_relay_mode.store(Some(mode).into());

		let (pkt, addr, assoc_id) = match pkt.accept().await {
			Ok(None) => return,
			Ok(Some(res)) => res,
			Err(err) => {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment \
					 {frag_id}/{frag_total}: {err}",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					frag_id = frag_id + 1,
				);
				return;
			}
		};

		let process = async {
			debug!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				src_addr = addr,
			);

			let guard = self.udp_sessions.read().await;
			let session = guard.get(&assoc_id).map(|v| v.to_owned());
			drop(guard);
			let session = match session {
				Some(v) => v,
				None => match self.udp_sessions.write().await.entry(assoc_id) {
					Entry::Occupied(entry) => entry.get().clone(),
					Entry::Vacant(entry) => {
						let session = UdpSession::new(self.ctx.clone(), self.clone(), assoc_id)?;
						entry.insert(session.clone());
						session
					}
				},
			};

			// Match against ACL engine for UDP
			let outbound = self.get_outbound_handler(&addr, Protocol::UDP);

			// Handle reject
			if outbound.is_reject() {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr} \
					 rejected by ACL",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					src_addr = addr,
				);
				return Ok(());
			}

			// Check UDP support
			if !outbound.allows_udp() {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr} \
					 blocked (UDP not allowed for this outbound)",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					src_addr = addr,
				);
				return Ok(());
			}

			// tuic relays UDP through its own UdpSession using the node's local
			// sockets, which only correctly represents a Direct outbound. A proxied
			// outbound (socks5/http) can't be honored for UDP without sending from
			// the node directly — that would bypass the proxy and leak the node's
			// real IP — so reject UDP for proxied outbounds instead of bypassing.
			if !outbound.is_direct() {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr} \
					 blocked (UDP not supported for proxied outbound)",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					src_addr = addr,
				);
				return Ok(());
			}

			let mut acl_addr = address_to_acl_addr(&addr);

			// Front-load DNS resolution (same rationale as the TCP path). On
			// failure we drop the packet — no fallback to Direct's internal
			// resolver — and the UdpSession remains idle until the client
			// retries.
			if let ResolveDecision::Cache(domain) = resolve_decision(outbound.as_ref(), &addr) {
				match self.ctx.dns_resolver.resolve_to_info(domain).await {
					Ok(info) => acl_addr = acl_addr.with_resolve_info(info),
					Err(err) => {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to \
							 {src_addr} dns resolve failed: {err}",
							id = self.id(),
							addr = self.inner.remote_address(),
							user = self.auth,
							src_addr = addr,
						);
						return Ok(());
					}
				}
			}

			// Ordered send targets honoring the Direct family-selection mode
			// (Prefer64/Prefer46/Only*). Slot 0 is the preferred family; slot 1 is
			// the other family, tried as a send-time fallback — the UDP analogue of
			// v0.4.6's TCP connection-level Prefer fallback.
			let candidates = udp_target_candidates(outbound.direct_mode(), &acl_addr);
			if candidates.iter().all(Option::is_none) {
				// Nothing resolved to a usable address for this mode (e.g. an
				// Only4 outbound whose target has only an AAAA record).
				return Err(eyre!("no usable UDP target address").into());
			}

			// Collect the send targets on the stack (allocation-free hot path).
			// Apply the experimental drop filter to *every* candidate we might fall
			// back to, so a fallback family can't reach a private/loopback host the
			// primary check would have blocked. (Only Direct reaches here.)
			let mut targets = [SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0); 2];
			let mut target_count = 0;
			for target in candidates.into_iter().flatten() {
				if self.should_drop_address(&target) {
					continue;
				}
				targets[target_count] = target;
				target_count += 1;
			}
			if target_count == 0 {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr} \
					 blocked (loopback/private)",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					src_addr = addr,
				);
				return Ok(());
			}
			let targets = &targets[..target_count];

			// Record traffic and request stats for UDP outbound
			if self.auth.is_authenticated() {
				let uid = self.auth.get_uid();
				stats::req_incr(&self.ctx, uid);
				stats::traffic_tx(&self.ctx, uid, pkt.len());
			}

			if let Some(session) = session.upgrade() {
				session.send(pkt, targets).await
			} else {
				Err(eyre!("UdpSession dropped already").into())
			}
		};

		if let Err(err) = process.await {
			debug!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				src_addr = addr,
			);
		}
	}

	pub async fn handle_dissociate(&self, assoc_id: u16) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-DROP] [{assoc_id:#06x}]",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		if let Some(session) = self.udp_sessions.write().await.remove(&assoc_id)
			&& let Some(session) = session.upgrade()
		{
			session.close().await;
		}
	}

	pub async fn handle_heartbeat(&self) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] [HB]",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);
	}

	pub async fn relay_packet(self, pkt: Bytes, addr: Address, assoc_id: u16) -> eyre::Result<()> {
		let addr_display = addr.to_string();

		debug!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-IN] [{assoc_id:#06x}] [to-{mode}] from {src_addr}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			mode = self.udp_relay_mode.load().unwrap(),
			src_addr = addr_display,
		);

		// Record traffic stats for UDP inbound
		if self.auth.is_authenticated() {
			stats::traffic_rx(&self.ctx, self.auth.get_uid(), pkt.len());
		}

		let res = match self.udp_relay_mode.load().unwrap() {
			UdpRelayMode::Native => self.model.packet_native(pkt, addr, assoc_id),
			UdpRelayMode::Quic => self.model.packet_quic(pkt, addr, assoc_id).await,
		};

		if let Err(err) = res {
			debug!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-IN] [{assoc_id:#06x}] [to-{mode}] from {src_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				mode = self.udp_relay_mode.load().unwrap(),
				src_addr = addr_display,
			);
		}
		Ok(())
	}
}

/// Ordered UDP send targets for a resolved address, honoring the Direct
/// family-selection `mode`. Slot 0 is the preferred family; slot 1 (if
/// resolved) is the other family used as a send-time fallback, mirroring
/// acl-engine's Prefer64/Prefer46 UDP semantics. `None` (non-Direct outbound)
/// and Auto/Prefer46 prefer IPv4 for compatibility. Targets without
/// `resolve_info` (IP literals) fall back to parsing the host string into a
/// single candidate.
///
/// Returns a fixed-size array (allocation-free on the per-datagram hot path);
/// `None` slots are skipped by callers via `.flatten()`.
fn udp_target_candidates(mode: Option<DirectMode>, acl_addr: &Addr) -> [Option<SocketAddr>; 2] {
	let port = acl_addr.port();

	// Prefer explicit resolve_info; otherwise treat an IP-literal host as a
	// single resolved address of its own family. Parsing the host as an IpAddr
	// (rather than `format!("{host}:{port}")`) handles IPv6 literals, which need
	// bracketing in the `host:port` form.
	let (v4, v6) = if let Some(info) = acl_addr.resolve_info().as_ref() {
		(
			info.ipv4.map(|ip| SocketAddr::new(IpAddr::V4(ip), port)),
			info.ipv6.map(|ip| SocketAddr::new(IpAddr::V6(ip), port)),
		)
	} else {
		match acl_addr.host().parse::<IpAddr>() {
			Ok(ip @ IpAddr::V4(_)) => (Some(SocketAddr::new(ip, port)), None),
			Ok(ip @ IpAddr::V6(_)) => (None, Some(SocketAddr::new(ip, port))),
			Err(_) => (None, None),
		}
	};

	match mode {
		Some(DirectMode::Prefer64) => [v6, v4],
		Some(DirectMode::Only6) => [v6, None],
		Some(DirectMode::Only4) => [v4, None],
		// Auto | Prefer46 | None (non-Direct): IPv4 first for compatibility.
		_ => [v4, v6],
	}
}

/// Convert tuic Address to acl-engine-rs Addr
fn address_to_acl_addr(addr: &Address) -> Addr {
	match addr {
		Address::DomainAddress(domain, port) => Addr::new(domain.as_str(), *port),
		Address::SocketAddress(sock_addr) => Addr::new(sock_addr.ip().to_string(), sock_addr.port()),
		Address::None => Addr::new("", 0),
	}
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

	use acl_engine_rs::outbound::{DirectMode, ResolveInfo};

	use super::*;

	fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
		SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
	}

	fn v6_localhost(port: u16) -> SocketAddr {
		SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
	}

	fn dual_addr(port: u16) -> Addr {
		Addr::new("dual.example", port).with_resolve_info(ResolveInfo {
			ipv4:  Some(Ipv4Addr::new(1, 2, 3, 4)),
			ipv6:  Some(Ipv6Addr::LOCALHOST),
			error: None,
		})
	}

	#[test]
	fn prefer64_orders_ipv6_then_ipv4() {
		let addr = dual_addr(443);
		assert_eq!(
			udp_target_candidates(Some(DirectMode::Prefer64), &addr),
			[Some(v6_localhost(443)), Some(v4(1, 2, 3, 4, 443))]
		);
	}

	#[test]
	fn prefer46_orders_ipv4_then_ipv6() {
		let addr = dual_addr(443);
		assert_eq!(
			udp_target_candidates(Some(DirectMode::Prefer46), &addr),
			[Some(v4(1, 2, 3, 4, 443)), Some(v6_localhost(443))]
		);
	}

	#[test]
	fn auto_and_non_direct_prefer_ipv4_then_ipv6() {
		let addr = dual_addr(443);
		let expected = [Some(v4(1, 2, 3, 4, 443)), Some(v6_localhost(443))];
		assert_eq!(udp_target_candidates(Some(DirectMode::Auto), &addr), expected);
		// `None` == non-Direct outbound: keep the compatibility-first v4 order.
		assert_eq!(udp_target_candidates(None, &addr), expected);
	}

	#[test]
	fn only6_and_only4_yield_single_family() {
		let addr = dual_addr(443);
		assert_eq!(
			udp_target_candidates(Some(DirectMode::Only6), &addr),
			[Some(v6_localhost(443)), None]
		);
		assert_eq!(
			udp_target_candidates(Some(DirectMode::Only4), &addr),
			[Some(v4(1, 2, 3, 4, 443)), None]
		);
	}

	#[test]
	fn missing_preferred_family_is_skipped() {
		// Prefer64 with a v4-only resolution: no IPv6 candidate, so slot 0 is
		// None and only the IPv4 target remains (callers skip None via flatten).
		let addr = Addr::new("v4.example", 53).with_resolve_info(ResolveInfo::from_ipv4(Ipv4Addr::new(9, 9, 9, 9)));
		assert_eq!(
			udp_target_candidates(Some(DirectMode::Prefer64), &addr),
			[None, Some(v4(9, 9, 9, 9, 53))]
		);
	}

	#[test]
	fn ip_literal_without_resolve_info_parses_host() {
		// SocketAddress targets carry no resolve_info; the host string is a
		// literal IP that must be parsed into a single candidate.
		let addr = Addr::new("203.0.113.7", 8080);
		assert_eq!(
			udp_target_candidates(Some(DirectMode::Auto), &addr),
			[Some(v4(203, 0, 113, 7, 8080)), None]
		);
	}

	#[test]
	fn ipv6_literal_without_resolve_info_is_parsed() {
		// An IPv6-literal target with no resolve_info must still yield a
		// candidate. Naive `format!("{host}:{port}")` produces an unbracketed,
		// unparseable string for IPv6 — the host has to be parsed as an IpAddr.
		// Prefer64 puts the (only) v6 candidate in slot 0.
		let addr = Addr::new("2606:4700:4700::1111", 443);
		let expected = SocketAddr::new(IpAddr::V6("2606:4700:4700::1111".parse().unwrap()), 443);
		assert_eq!(
			udp_target_candidates(Some(DirectMode::Prefer64), &addr),
			[Some(expected), None]
		);
	}

	#[test]
	fn only4_with_ipv6_literal_yields_no_target() {
		// Family mode applies to IP literals too: an Only4 outbound cannot use an
		// IPv6-literal target, so there is no candidate (the packet is dropped).
		let addr = Addr::new("2606:4700:4700::1111", 443);
		assert_eq!(udp_target_candidates(Some(DirectMode::Only4), &addr), [None, None]);
	}
}
