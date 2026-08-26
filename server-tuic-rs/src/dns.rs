//! DNS resolution cache for proxied targets.
//!
//! Wraps [`dns_cache_rs::DnsCache`] and converts results into
//! [`acl_engine_rs::outbound::ResolveInfo`] so we can pre-populate
//! `Addr::resolve_info` before calling `dial_tcp`/`dial_udp` — bypassing
//! `Direct`'s built-in `tokio::net::lookup_host`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use acl_engine_rs::outbound::ResolveInfo;
use dns_cache_rs::{DnsCache, DnsError};
use tuic::Address;

use crate::acl::OutboundHandler;

/// Decision computed at the call site (handle_connect / handle_packet) about
/// whether to consult the userland DNS cache before dialing.
///
/// `Cache(domain)` borrows the domain string out of the [`Address`] —
/// no allocation in the hot path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResolveDecision<'a> {
	Cache(&'a str),
	Skip,
}

/// Cache only when the outbound is `Direct` AND the address is a domain name
/// (not an IP literal masquerading as a `DomainAddress`). Everything else —
/// `Socks5`, `Http`, `Reject`, `SocketAddress`, `Address::None` — passes
/// straight through unchanged.
#[must_use]
pub(crate) fn resolve_decision<'a>(outbound: &OutboundHandler, addr: &'a Address) -> ResolveDecision<'a> {
	match (outbound, addr) {
		(OutboundHandler::Direct(_), Address::DomainAddress(domain, _)) if domain.parse::<IpAddr>().is_err() => {
			ResolveDecision::Cache(domain.as_str())
		}
		_ => ResolveDecision::Skip,
	}
}

#[derive(Debug)]
pub struct DnsResolver {
	cache: DnsCache,
}

impl DnsResolver {
	pub(crate) fn new() -> Self {
		Self { cache: DnsCache::new() }
	}

	#[cfg(test)]
	fn with_cache(cache: DnsCache) -> Self {
		Self { cache }
	}

	/// Resolve `host` via the cache and convert into `ResolveInfo` (first IPv4
	/// and first IPv6 of each family). Returns `NotFound` if the resolver
	/// produced zero addresses.
	pub(crate) async fn resolve_to_info(&self, host: &str) -> Result<ResolveInfo, DnsError> {
		let ips = self.cache.resolve(host).await?;
		let (ipv4, ipv6) = split_ipv4_ipv6(&ips);
		if ipv4.is_none() && ipv6.is_none() {
			return Err(DnsError::NotFound(host.to_string()));
		}
		Ok(ResolveInfo { ipv4, ipv6, error: None })
	}
}

impl Default for DnsResolver {
	fn default() -> Self {
		Self::new()
	}
}

fn split_ipv4_ipv6(ips: &[IpAddr]) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
	let mut v4 = None;
	let mut v6 = None;
	for ip in ips {
		match ip {
			IpAddr::V4(a) if v4.is_none() => v4 = Some(*a),
			IpAddr::V6(a) if v6.is_none() => v6 = Some(*a),
			_ => {}
		}
		if v4.is_some() && v6.is_some() {
			break;
		}
	}
	(v4, v6)
}

#[cfg(test)]
mod tests {
	use std::{
		net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
		sync::Arc,
		time::Duration,
	};

	use acl_engine_rs::outbound::{Http, Reject, Socks5};
	use dns_cache_rs::{DnsCache, MockResolver};
	use tuic::Address;

	use super::*;
	use crate::acl::OutboundHandler;

	fn build_resolver(mock: Arc<MockResolver>) -> DnsResolver {
		let cache = DnsCache::builder().resolver_arc(mock).build().expect("DnsCache build");
		DnsResolver::with_cache(cache)
	}

	fn direct_handler() -> OutboundHandler {
		OutboundHandler::Direct(Arc::new(crate::acl::DirectOutbound::with_mode(
			acl_engine_rs::outbound::DirectMode::Auto,
		)))
	}

	fn socks5_handler() -> OutboundHandler {
		OutboundHandler::Socks5 {
			inner:     Arc::new(Socks5::new("127.0.0.1:1080")),
			allow_udp: false,
		}
	}

	fn http_handler() -> OutboundHandler {
		OutboundHandler::Http(Arc::new(Http::from_url("http://127.0.0.1:8080").expect("http url")))
	}

	fn reject_handler() -> OutboundHandler {
		OutboundHandler::Reject(Arc::new(Reject::new()))
	}

	#[test]
	fn split_v4_only() {
		let ips = [IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];
		let (v4, v6) = split_ipv4_ipv6(&ips);
		assert_eq!(v4, Some(Ipv4Addr::new(1, 2, 3, 4)));
		assert_eq!(v6, None);
	}

	#[test]
	fn split_v6_only() {
		let ips = [IpAddr::V6(Ipv6Addr::LOCALHOST)];
		let (v4, v6) = split_ipv4_ipv6(&ips);
		assert_eq!(v4, None);
		assert_eq!(v6, Some(Ipv6Addr::LOCALHOST));
	}

	#[test]
	fn split_mixed_picks_first_of_each() {
		let ips = [
			IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
			IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
			IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
			IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)),
		];
		let (v4, v6) = split_ipv4_ipv6(&ips);
		assert_eq!(v4, Some(Ipv4Addr::new(1, 1, 1, 1)));
		assert_eq!(v6, Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
	}

	#[tokio::test]
	async fn resolve_to_info_v4_only() {
		let mock = Arc::new(MockResolver::new());
		mock.set("example.com", Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]));
		let resolver = build_resolver(mock);

		let info = resolver.resolve_to_info("example.com").await.expect("resolve");

		assert_eq!(info.ipv4, Some(Ipv4Addr::new(1, 2, 3, 4)));
		assert_eq!(info.ipv6, None);
		assert!(info.error.is_none());
	}

	#[tokio::test]
	async fn resolve_to_info_mixed() {
		let mock = Arc::new(MockResolver::new());
		mock.set(
			"dual.example",
			Ok(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), IpAddr::V6(Ipv6Addr::LOCALHOST)]),
		);
		let resolver = build_resolver(mock);

		let info = resolver.resolve_to_info("dual.example").await.expect("resolve");

		assert_eq!(info.ipv4, Some(Ipv4Addr::new(9, 9, 9, 9)));
		assert_eq!(info.ipv6, Some(Ipv6Addr::LOCALHOST));
		assert!(info.error.is_none());
	}

	#[tokio::test]
	async fn resolve_to_info_not_found_propagates_err() {
		let mock = Arc::new(MockResolver::new());
		mock.set("missing.example", Err(DnsError::NotFound("missing.example".to_string())));
		let resolver = build_resolver(mock);

		let err = resolver.resolve_to_info("missing.example").await.expect_err("expected err");

		assert!(matches!(err, DnsError::NotFound(_)));
	}

	#[tokio::test]
	async fn resolve_to_info_timeout_propagates_err() {
		let mock = Arc::new(MockResolver::new());
		mock.set("slow.example", Err(DnsError::Timeout(Duration::from_secs(2))));
		let resolver = build_resolver(mock);

		let err = resolver.resolve_to_info("slow.example").await.expect_err("expected err");

		assert!(matches!(err, DnsError::Timeout(_)));
	}

	#[tokio::test]
	async fn resolve_to_info_invalid_host_propagates_err() {
		// DnsCache rejects empty hosts before consulting the resolver — verify the
		// error surfaces unchanged through resolve_to_info.
		let mock = Arc::new(MockResolver::new());
		let resolver = build_resolver(mock);

		let err = resolver.resolve_to_info("").await.expect_err("expected err");

		assert!(matches!(err, DnsError::InvalidHost(_)));
	}

	#[tokio::test]
	async fn resolve_to_info_caches_second_call() {
		let mock = Arc::new(MockResolver::new());
		mock.set("cached.example", Ok(vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]));
		let resolver = build_resolver(mock.clone());

		resolver.resolve_to_info("cached.example").await.expect("first");
		resolver.resolve_to_info("cached.example").await.expect("second");

		assert_eq!(mock.call_count("cached.example"), 1);
	}

	#[tokio::test]
	async fn resolve_to_info_singleflight() {
		let mock = Arc::new(MockResolver::new());
		mock.set("sf.example", Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]));
		// Add a small delay so concurrent calls overlap inside the resolver.
		mock.set_delay(Some(Duration::from_millis(50)));
		let resolver = Arc::new(build_resolver(mock.clone()));

		let mut handles = Vec::with_capacity(16);
		for _ in 0..16 {
			let r = resolver.clone();
			handles.push(tokio::spawn(async move { r.resolve_to_info("sf.example").await }));
		}
		for h in handles {
			h.await.expect("join").expect("resolve");
		}

		assert_eq!(mock.call_count("sf.example"), 1);
	}

	#[test]
	fn direct_domain_returns_cache() {
		let outbound = direct_handler();
		let addr = Address::DomainAddress("example.com".to_string(), 443);
		match resolve_decision(&outbound, &addr) {
			ResolveDecision::Cache(host) => assert_eq!(host, "example.com"),
			ResolveDecision::Skip => panic!("expected Cache for Direct + DomainAddress"),
		}
	}

	#[test]
	fn direct_ip_literal_returns_skip() {
		// IP literal disguised as a DomainAddress — Direct's own try_resolve_from_ip
		// handles this, so the cache layer skips.
		let outbound = direct_handler();
		let addr = Address::DomainAddress("1.2.3.4".to_string(), 443);
		assert_eq!(resolve_decision(&outbound, &addr), ResolveDecision::Skip);
	}

	#[test]
	fn direct_socket_address_returns_skip() {
		let outbound = direct_handler();
		let addr = Address::SocketAddress(SocketAddr::from(([1, 2, 3, 4], 443)));
		assert_eq!(resolve_decision(&outbound, &addr), ResolveDecision::Skip);
	}

	#[test]
	fn direct_address_none_returns_skip() {
		let outbound = direct_handler();
		let addr = Address::None;
		assert_eq!(resolve_decision(&outbound, &addr), ResolveDecision::Skip);
	}

	#[test]
	fn socks5_domain_returns_skip() {
		let outbound = socks5_handler();
		let addr = Address::DomainAddress("example.com".to_string(), 443);
		assert_eq!(resolve_decision(&outbound, &addr), ResolveDecision::Skip);
	}

	#[test]
	fn http_domain_returns_skip() {
		let outbound = http_handler();
		let addr = Address::DomainAddress("example.com".to_string(), 443);
		assert_eq!(resolve_decision(&outbound, &addr), ResolveDecision::Skip);
	}

	#[test]
	fn reject_domain_returns_skip() {
		let outbound = reject_handler();
		let addr = Address::DomainAddress("example.com".to_string(), 443);
		assert_eq!(resolve_decision(&outbound, &addr), ResolveDecision::Skip);
	}
}
