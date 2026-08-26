use std::{collections::HashMap, num::NonZero, path::Path, sync::Arc, time::Duration};

// Re-export types from acl-engine-rs
pub use acl_engine_rs::{
	AutoGeoLoader,
	GeoIpFormat,
	GeoSiteFormat,
	HostInfo,
	NilGeoLoader,
	Protocol,
	// Async outbound types
	outbound::{Addr, AsyncOutbound, AsyncTcpConn, Direct, DirectMode, DirectOptions, Http, Reject, Socks5},
};
use eyre::{Context, Result};
use serde::{Deserialize, Serialize};

/// ACL configuration loaded from YAML file
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AclConfig {
	/// List of outbound configurations
	#[serde(default)]
	pub outbounds: Vec<OutboundEntry>,

	/// ACL rules configuration
	#[serde(default)]
	pub acl: AclRules,
}

/// Single outbound entry
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct OutboundEntry {
	/// Outbound name (used in rules)
	pub name: String,

	/// Outbound type
	#[serde(rename = "type")]
	pub outbound_type: String,

	/// Type-specific configuration (flattened)
	#[serde(flatten)]
	pub config: OutboundEntryConfig,
}

/// Outbound configuration variants
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum OutboundEntryConfig {
	/// SOCKS5 proxy configuration
	Socks5 { socks5: Socks5Config },
	/// HTTP proxy configuration
	Http { http: HttpConfig },
	/// Direct connection configuration
	Direct {
		#[serde(skip_serializing_if = "Option::is_none")]
		direct: Option<DirectConfig>,
	},
}

/// Direct connection configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct DirectConfig {
	/// IP mode: auto, 4 (v4only), 6 (v6only), 64 (prefer6), 46 (prefer4)
	#[serde(default)]
	pub mode: IpMode,

	/// Bind to specific local IPv4 address
	#[serde(default, skip_serializing_if = "Option::is_none", rename = "bindIPv4")]
	pub bind_ipv4: Option<String>,

	/// Bind to specific local IPv6 address
	#[serde(default, skip_serializing_if = "Option::is_none", rename = "bindIPv6")]
	pub bind_ipv6: Option<String>,

	/// Bind to network device (Linux only, mutually exclusive with
	/// bindIPv4/bindIPv6)
	#[serde(default, skip_serializing_if = "Option::is_none", rename = "bindDevice")]
	pub bind_device: Option<String>,

	/// Enable TCP Fast Open (Linux/macOS)
	#[serde(default, rename = "fastOpen")]
	pub fast_open: bool,

	/// Disable Nagle's algorithm (default: true)
	#[serde(default = "default_true", rename = "tcpNodelay")]
	pub tcp_nodelay: bool,

	/// TCP keepalive interval in seconds (default: 60, null to disable)
	#[serde(
		default = "default_keepalive",
		skip_serializing_if = "Option::is_none",
		rename = "tcpKeepalive"
	)]
	pub tcp_keepalive: Option<u64>,

	/// Connection timeout in seconds (0 = use acl-engine's default of 10s)
	#[serde(default, rename = "connectTimeout")]
	pub connect_timeout: u64,
}

fn default_true() -> bool {
	true
}

fn default_keepalive() -> Option<u64> {
	Some(60)
}

/// IP mode for direct connections
#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpMode {
	#[serde(rename = "auto")]
	#[default]
	Auto,
	#[serde(rename = "4")]
	V4Only,
	#[serde(rename = "6")]
	V6Only,
	#[serde(rename = "64")]
	Prefer64,
	#[serde(rename = "46")]
	Prefer46,
}

impl From<IpMode> for DirectMode {
	fn from(mode: IpMode) -> Self {
		match mode {
			IpMode::Auto => DirectMode::Auto,
			IpMode::V4Only => DirectMode::Only4,
			IpMode::V6Only => DirectMode::Only6,
			IpMode::Prefer64 => DirectMode::Prefer64,
			IpMode::Prefer46 => DirectMode::Prefer46,
		}
	}
}

/// SOCKS5 proxy configuration
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Socks5Config {
	/// SOCKS5 server address (e.g., "127.0.0.1:1080")
	pub addr: String,

	/// Optional username for authentication
	#[serde(skip_serializing_if = "Option::is_none")]
	pub username: Option<String>,

	/// Optional password for authentication
	#[serde(skip_serializing_if = "Option::is_none")]
	pub password: Option<String>,

	/// Whether to allow UDP relay
	#[serde(default)]
	pub allow_udp: bool,
}

/// HTTP proxy configuration
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct HttpConfig {
	/// HTTP proxy URL (e.g., "http://127.0.0.1:8080" or "http://user:pass@127.0.0.1:8080")
	/// Supports both http:// and https:// schemes
	pub url: String,

	/// Skip TLS certificate verification (for https:// proxies)
	#[serde(default)]
	pub insecure: bool,
}

/// ACL rules configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct AclRules {
	/// Inline rules as strings (e.g., "direct(all)")
	#[serde(default)]
	pub inline: Vec<String>,
}

/// A `Direct` outbound paired with its family-selection mode.
///
/// acl-engine's `Direct` keeps its `mode` field private with no accessor, so we
/// retain a copy here — set from the same options at construction — for the UDP
/// relay path, which orders send targets by family preference (Prefer64/
/// Prefer46/Only*).
pub struct DirectOutbound {
	inner: Direct,
	mode:  DirectMode,
}

impl DirectOutbound {
	/// Build from full [`DirectOptions`]. `mode` is taken from the same options
	/// used to construct the inner `Direct`, so the copy retained here can
	/// never diverge from the dialer's actual behavior.
	pub(crate) fn from_options(opts: DirectOptions) -> Result<Self> {
		let mode = opts.mode;
		let inner = Direct::with_options(opts).map_err(|e| eyre::eyre!("Failed to create direct outbound: {}", e))?;
		Ok(Self { inner, mode })
	}

	/// Build a `Direct` with only a family-selection mode (all other options
	/// default). Infallible; `mode` is single-sourced, so no divergence.
	pub(crate) fn with_mode(mode: DirectMode) -> Self {
		Self {
			inner: Direct::with_mode(mode),
			mode,
		}
	}
}

/// Wrapper for async outbound handlers from acl-engine-rs
#[derive(Clone)]
pub enum OutboundHandler {
	/// Direct connection using acl-engine-rs's Direct
	Direct(Arc<DirectOutbound>),
	/// SOCKS5 proxy using acl-engine-rs's Socks5
	Socks5 { inner: Arc<Socks5>, allow_udp: bool },
	/// HTTP proxy using acl-engine-rs's Http
	Http(Arc<Http>),
	/// Reject connection using acl-engine-rs's Reject
	Reject(Arc<Reject>),
}

impl std::fmt::Debug for OutboundHandler {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			OutboundHandler::Direct(_) => write!(f, "OutboundHandler::Direct"),
			OutboundHandler::Socks5 { allow_udp, .. } => write!(f, "OutboundHandler::Socks5 {{ allow_udp: {} }}", allow_udp),
			OutboundHandler::Http(_) => write!(f, "OutboundHandler::Http"),
			OutboundHandler::Reject(_) => write!(f, "OutboundHandler::Reject"),
		}
	}
}

impl OutboundHandler {
	/// Create OutboundHandler from OutboundEntry
	pub fn from_entry(entry: &OutboundEntry) -> Result<Self> {
		match entry.outbound_type.as_str() {
			"direct" => match &entry.config {
				OutboundEntryConfig::Direct { direct } => {
					let cfg = direct.as_ref().cloned().unwrap_or_default();
					let opts = DirectOptions {
						mode:          cfg.mode.into(),
						bind_ip4:      cfg.bind_ipv4.as_deref().and_then(|s| s.parse().ok()),
						bind_ip6:      cfg.bind_ipv6.as_deref().and_then(|s| s.parse().ok()),
						bind_device:   cfg.bind_device,
						fast_open:     cfg.fast_open,
						tcp_nodelay:   cfg.tcp_nodelay,
						tcp_keepalive: cfg.tcp_keepalive.map(Duration::from_secs),
						// 0 => None => acl-engine default (10s); otherwise the configured seconds.
						timeout:       (cfg.connect_timeout != 0).then(|| Duration::from_secs(cfg.connect_timeout)),
					};
					Ok(OutboundHandler::Direct(Arc::new(DirectOutbound::from_options(opts)?)))
				}
				_ => eyre::bail!("Invalid config for direct outbound '{}'", entry.name),
			},
			"socks5" => match &entry.config {
				OutboundEntryConfig::Socks5 { socks5 } => {
					let inner = if let (Some(username), Some(password)) = (&socks5.username, &socks5.password) {
						Socks5::with_auth(&socks5.addr, username, password)
							.map_err(|e| eyre::eyre!("Failed to create SOCKS5 proxy with auth: {}", e))?
					} else {
						Socks5::new(&socks5.addr)
					};
					Ok(OutboundHandler::Socks5 {
						inner:     Arc::new(inner),
						allow_udp: socks5.allow_udp,
					})
				}
				_ => eyre::bail!("Invalid config for socks5 outbound '{}'", entry.name),
			},
			"http" => match &entry.config {
				OutboundEntryConfig::Http { http } => {
					let inner = Http::from_url(&http.url).map_err(|e| eyre::eyre!("Failed to parse HTTP proxy URL: {}", e))?;
					Ok(OutboundHandler::Http(Arc::new(inner)))
				}
				_ => eyre::bail!("Invalid config for http outbound '{}'", entry.name),
			},
			"reject" => Ok(OutboundHandler::Reject(Arc::new(Reject::new()))),
			unknown => eyre::bail!("Unknown outbound type '{}' for outbound '{}'", unknown, entry.name),
		}
	}

	/// Check if this handler is a reject type
	pub fn is_reject(&self) -> bool {
		matches!(self, OutboundHandler::Reject(_))
	}

	/// Check if this handler is a Direct outbound. tuic can only relay UDP for
	/// Direct outbounds (via its own sockets); proxied outbounds must resolve
	/// and connect through the proxy, which the UDP path cannot do.
	pub fn is_direct(&self) -> bool {
		matches!(self, OutboundHandler::Direct(_))
	}

	/// Family-selection mode for a `Direct` outbound, used by the UDP relay
	/// path to order send targets by family preference. Returns `None` for
	/// proxied/reject outbounds, which resolve the target family themselves.
	pub fn direct_mode(&self) -> Option<DirectMode> {
		match self {
			OutboundHandler::Direct(d) => Some(d.mode),
			_ => None,
		}
	}

	/// Check if UDP is allowed for this handler
	pub fn allows_udp(&self) -> bool {
		match self {
			OutboundHandler::Direct(_) => true,
			OutboundHandler::Socks5 { allow_udp, .. } => *allow_udp,
			OutboundHandler::Http(_) => false, // HTTP proxy doesn't support UDP
			OutboundHandler::Reject(_) => false,
		}
	}

	/// Get the async outbound implementation for TCP
	pub fn as_async_outbound(&self) -> &dyn AsyncOutbound {
		match self {
			OutboundHandler::Direct(d) => &d.inner,
			OutboundHandler::Socks5 { inner, .. } => inner.as_ref(),
			OutboundHandler::Http(h) => h.as_ref(),
			OutboundHandler::Reject(r) => r.as_ref(),
		}
	}
}

/// ACL Engine wrapper
pub struct AclEngine {
	// Compiled rule set from acl-engine-rs
	compiled:  acl_engine_rs::CompiledRuleSet<Arc<OutboundHandler>>,
	// Keep outbounds map for reference
	outbounds: HashMap<String, Arc<OutboundHandler>>,
}

impl AclEngine {
	/// Create new ACL engine from configuration
	pub async fn new(acl_config: AclConfig, data_dir: impl AsRef<Path>, refresh_geodata: bool) -> Result<Self> {
		// Parse outbounds into handler map
		let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();

		for entry in &acl_config.outbounds {
			let handler =
				OutboundHandler::from_entry(entry).with_context(|| format!("Failed to parse outbound '{}'", entry.name))?;
			outbounds.insert(entry.name.clone(), Arc::new(handler));
		}

		// If no outbounds defined, create default direct outbound
		if outbounds.is_empty() {
			tracing::debug!("No outbounds defined, creating default direct outbound");
			outbounds.insert(
				"default".to_string(),
				Arc::new(OutboundHandler::Direct(Arc::new(DirectOutbound::with_mode(DirectMode::Auto)))),
			);
		}

		// Always register built-in outbounds so they can be used in rules without
		// explicit definition
		outbounds
			.entry("reject".to_string())
			.or_insert_with(|| Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))));
		outbounds
			.entry("direct".to_string())
			.or_insert_with(|| Arc::new(OutboundHandler::Direct(Arc::new(DirectOutbound::with_mode(DirectMode::Auto)))));

		// Get rules or use default
		let rules = if acl_config.acl.inline.is_empty() {
			tracing::debug!("No ACL rules defined, using default 'default(all)' rule");
			vec!["default(all)".to_string()]
		} else {
			acl_config.acl.inline.clone()
		};

		// Parse rules text
		let rules_text = rules.join("\n");
		let text_rules = acl_engine_rs::parse_rules(&rules_text).with_context(|| "Failed to parse ACL rules")?;

		// Create AutoGeoLoader with MMDB for GeoIP and Sing (DB) for GeoSite
		let mut geo_loader = AutoGeoLoader::new()
			.with_data_dir(data_dir)
			.with_geoip(GeoIpFormat::Mmdb)
			.with_geosite(GeoSiteFormat::Sing);

		// Force refresh geodata if requested
		if refresh_geodata {
			geo_loader = geo_loader.with_update_interval(Duration::ZERO);
		}

		// Compile rules with outbound map and AutoGeoLoader
		let compiled = acl_engine_rs::compile(&text_rules, &outbounds, NonZero::new(1024).unwrap(), &geo_loader)
			.with_context(|| "Failed to compile ACL rules")?;

		tracing::info!(
			"ACL engine initialized with {} outbounds and {} rules",
			outbounds.len(),
			compiled.rule_count()
		);

		Ok(Self { compiled, outbounds })
	}

	/// Match a host against ACL rules
	pub fn match_host(&self, host: &str, port: u16, protocol: Protocol) -> Option<Arc<OutboundHandler>> {
		// Create HostInfo from domain or IP
		let host_info = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
			match ip {
				std::net::IpAddr::V4(v4) => acl_engine_rs::HostInfo::new("", Some(v4), None),
				std::net::IpAddr::V6(v6) => acl_engine_rs::HostInfo::new("", None, Some(v6)),
			}
		} else {
			acl_engine_rs::HostInfo::from_name(host)
		};

		// Match against compiled rules
		match self.compiled.match_host(&host_info, protocol, port) {
			Some(result) => Some(result.outbound.clone()),
			None => {
				// No match, try to return default outbound
				self.outbounds
					.get("default")
					.or_else(|| self.outbounds.get("direct"))
					.or_else(|| self.outbounds.values().next())
					.cloned()
			}
		}
	}
}

/// Create a default ACL engine with direct routing for all traffic
pub async fn create_default_engine(data_dir: impl AsRef<Path>, refresh_geodata: bool) -> Result<AclEngine> {
	let default_config = AclConfig {
		outbounds: vec![OutboundEntry {
			name:          "default".to_string(),
			outbound_type: "direct".to_string(),
			config:        OutboundEntryConfig::Direct {
				direct: Some(DirectConfig {
					mode: IpMode::Auto,
					..Default::default()
				}),
			},
		}],
		acl:       AclRules {
			inline: vec!["default(all)".to_string()],
		},
	};

	AclEngine::new(default_config, data_dir, refresh_geodata).await
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_parse_basic_acl_config() {
		let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct:
      mode: auto

acl:
  inline:
    - direct(all)
"#;
		let config: AclConfig = serde_yaml::from_str(yaml).expect("Failed to parse YAML");
		assert_eq!(config.outbounds.len(), 1);
		assert_eq!(config.outbounds[0].name, "direct");
		assert_eq!(config.acl.inline.len(), 1);
		assert_eq!(config.acl.inline[0], "direct(all)");
	}

	#[tokio::test]
	async fn test_parse_socks5_config() {
		let yaml = r#"
outbounds:
  - name: proxy
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
      username: user
      password: pass
      allow_udp: true

acl:
  inline:
    - proxy(all)
"#;
		let config: AclConfig = serde_yaml::from_str(yaml).expect("Failed to parse YAML");
		assert_eq!(config.outbounds.len(), 1);
		assert_eq!(config.outbounds[0].name, "proxy");
		assert_eq!(config.outbounds[0].outbound_type, "socks5");

		match &config.outbounds[0].config {
			OutboundEntryConfig::Socks5 { socks5 } => {
				assert_eq!(socks5.addr, "127.0.0.1:1080");
				assert_eq!(socks5.username, Some("user".to_string()));
				assert_eq!(socks5.password, Some("pass".to_string()));
				assert!(socks5.allow_udp);
			}
			_ => panic!("Expected Socks5 config"),
		}
	}

	#[tokio::test]
	async fn test_acl_engine_creation() {
		let temp_dir = tempfile::tempdir().unwrap();
		let config = AclConfig {
			outbounds: vec![OutboundEntry {
				name:          "direct".to_string(),
				outbound_type: "direct".to_string(),
				config:        OutboundEntryConfig::Direct {
					direct: Some(DirectConfig {
						mode: IpMode::Auto,
						..Default::default()
					}),
				},
			}],
			acl:       AclRules {
				inline: vec!["direct(all)".to_string()],
			},
		};

		let engine = AclEngine::new(config, temp_dir.path(), false)
			.await
			.expect("Failed to create ACL engine");

		// Test matching a domain
		let result = engine.match_host("example.com", 80, Protocol::TCP);
		assert!(result.is_some());
		assert!(matches!(result.unwrap().as_ref(), OutboundHandler::Direct(_)));
	}

	#[tokio::test]
	async fn test_acl_reject_handler() {
		let temp_dir = tempfile::tempdir().unwrap();
		let config = AclConfig {
			outbounds: vec![
				OutboundEntry {
					name:          "reject".to_string(),
					outbound_type: "reject".to_string(),
					config:        OutboundEntryConfig::Direct { direct: None },
				},
				OutboundEntry {
					name:          "direct".to_string(),
					outbound_type: "direct".to_string(),
					config:        OutboundEntryConfig::Direct {
						direct: Some(DirectConfig {
							mode: IpMode::Auto,
							..Default::default()
						}),
					},
				},
			],
			acl:       AclRules {
				inline: vec!["reject(all, udp/443)".to_string(), "direct(all)".to_string()],
			},
		};

		let engine = AclEngine::new(config, temp_dir.path(), false)
			.await
			.expect("Failed to create ACL engine");

		// Test UDP/443 is rejected
		let result = engine.match_host("example.com", 443, Protocol::UDP);
		assert!(result.is_some());
		assert!(result.unwrap().is_reject());

		// Test TCP/443 is not rejected
		let result = engine.match_host("example.com", 443, Protocol::TCP);
		assert!(result.is_some());
		assert!(matches!(result.unwrap().as_ref(), OutboundHandler::Direct(_)));
	}

	#[tokio::test]
	async fn test_create_default_engine() {
		let temp_dir = tempfile::tempdir().unwrap();
		let engine = create_default_engine(temp_dir.path(), false)
			.await
			.expect("Failed to create default engine");

		// Test that default engine allows everything
		let result = engine.match_host("example.com", 80, Protocol::TCP);
		assert!(result.is_some());
		assert!(matches!(result.unwrap().as_ref(), OutboundHandler::Direct(_)));
	}

	/// Test match_host with IPv4 and IPv6 addresses (regression: IPv6 caused
	/// panic)
	#[tokio::test]
	async fn test_match_host_with_ip_addresses() {
		let temp_dir = tempfile::tempdir().unwrap();
		let config = AclConfig {
			outbounds: vec![OutboundEntry {
				name:          "direct".to_string(),
				outbound_type: "direct".to_string(),
				config:        OutboundEntryConfig::Direct {
					direct: Some(DirectConfig {
						mode: IpMode::Auto,
						..Default::default()
					}),
				},
			}],
			acl:       AclRules {
				inline: vec!["direct(all)".to_string()],
			},
		};

		let engine = AclEngine::new(config, temp_dir.path(), false)
			.await
			.expect("Failed to create ACL engine");

		// IPv4 should not panic
		let result = engine.match_host("1.1.1.1", 443, Protocol::TCP);
		assert!(result.is_some(), "IPv4 address should match");

		// IPv6 should not panic (this was the bug: unwrap on Ipv4Addr parse of IPv6)
		let result = engine.match_host("2606:4700:4700::1111", 443, Protocol::TCP);
		assert!(result.is_some(), "IPv6 address should match");

		// IPv6 loopback
		let result = engine.match_host("::1", 80, Protocol::TCP);
		assert!(result.is_some(), "IPv6 loopback should match");
	}

	#[test]
	fn test_ip_mode_serialization() {
		assert_eq!(serde_yaml::to_string(&IpMode::Auto).unwrap().trim(), "auto");
		assert_eq!(serde_yaml::to_string(&IpMode::V4Only).unwrap().trim(), "'4'");
		assert_eq!(serde_yaml::to_string(&IpMode::V6Only).unwrap().trim(), "'6'");
	}

	#[test]
	fn test_ip_mode_deserialization() {
		let auto: IpMode = serde_yaml::from_str("auto").unwrap();
		assert_eq!(auto, IpMode::Auto);

		let v4: IpMode = serde_yaml::from_str("\"4\"").unwrap();
		assert_eq!(v4, IpMode::V4Only);

		let v6: IpMode = serde_yaml::from_str("\"6\"").unwrap();
		assert_eq!(v6, IpMode::V6Only);
	}

	#[test]
	fn test_direct_config_parses_connect_timeout() {
		let cfg: DirectConfig = serde_yaml::from_str("mode: auto\nconnectTimeout: 5\n").expect("parse");
		assert_eq!(cfg.connect_timeout, 5);
	}

	#[test]
	fn test_direct_config_connect_timeout_defaults_to_zero() {
		// Absent connectTimeout means "use acl-engine's default" (10s), encoded as 0.
		let cfg: DirectConfig = serde_yaml::from_str("mode: auto\n").expect("parse");
		assert_eq!(cfg.connect_timeout, 0);
	}

	/// A direct outbound with an explicit connectTimeout constructs
	/// successfully (the value is wired into DirectOptions.timeout in
	/// `from_entry`).
	#[test]
	fn test_direct_config_connect_timeout_builds_handler() {
		let entry = OutboundEntry {
			name:          "direct".to_string(),
			outbound_type: "direct".to_string(),
			config:        OutboundEntryConfig::Direct {
				direct: Some(DirectConfig {
					connect_timeout: 3,
					..Default::default()
				}),
			},
		};
		let handler = OutboundHandler::from_entry(&entry).expect("handler builds with connectTimeout");
		assert!(matches!(handler, OutboundHandler::Direct(_)));
	}

	/// Test ACL rule matching based on acl-o.yaml style config
	#[tokio::test]
	async fn test_acl_rule_matching_with_socks5_outbound() {
		let temp_dir = tempfile::tempdir().unwrap();

		// Create config similar to acl-o.yaml
		let config = AclConfig {
			outbounds: vec![OutboundEntry {
				name:          "warp".to_string(),
				outbound_type: "socks5".to_string(),
				config:        OutboundEntryConfig::Socks5 {
					socks5: Socks5Config {
						addr:      "127.0.0.1:40000".to_string(),
						username:  None,
						password:  None,
						allow_udp: false,
					},
				},
			}],
			acl:       AclRules {
				inline: vec![
					"reject(all, udp/443)".to_string(),
					"warp(all, tcp/22)".to_string(),
					"warp(suffix:google.com)".to_string(),
					"direct(all)".to_string(),
				],
			},
		};

		let engine = AclEngine::new(config, temp_dir.path(), false)
			.await
			.expect("Failed to create ACL engine");

		// Test 1: UDP/443 should be rejected
		let result = engine.match_host("example.com", 443, Protocol::UDP);
		assert!(result.is_some());
		assert!(result.unwrap().is_reject(), "UDP/443 should be rejected");

		// Test 2: TCP/22 should go through warp (socks5)
		let result = engine.match_host("example.com", 22, Protocol::TCP);
		assert!(result.is_some());
		assert!(
			matches!(result.unwrap().as_ref(), OutboundHandler::Socks5 { .. }),
			"TCP/22 should go through socks5"
		);

		// Test 3: google.com should go through warp (socks5) - suffix match
		let result = engine.match_host("www.google.com", 443, Protocol::TCP);
		assert!(result.is_some());
		assert!(
			matches!(result.unwrap().as_ref(), OutboundHandler::Socks5 { .. }),
			"google.com should go through socks5 via suffix match"
		);

		// Test 4: Other traffic should go direct
		let result = engine.match_host("example.com", 80, Protocol::TCP);
		assert!(result.is_some());
		assert!(
			matches!(result.unwrap().as_ref(), OutboundHandler::Direct(_)),
			"Other traffic should go direct"
		);
	}

	/// Test actual TCP connection through Direct outbound
	#[tokio::test]
	async fn test_direct_outbound_tcp_connection() {
		use tokio::{
			io::{AsyncReadExt, AsyncWriteExt},
			net::TcpListener,
		};

		// Create a local TCP server
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let port = listener.local_addr().unwrap().port();

		// Spawn server task
		let server_handle = tokio::spawn(async move {
			let (mut socket, _) = listener.accept().await.unwrap();
			let mut buf = [0u8; 1024];
			let n = socket.read(&mut buf).await.unwrap();
			// Echo back
			socket.write_all(&buf[..n]).await.unwrap();
		});

		// Create Direct outbound
		let handler = OutboundHandler::Direct(Arc::new(DirectOutbound::with_mode(DirectMode::Auto)));

		// Dial TCP using AsyncOutbound
		let mut addr = Addr::new("127.0.0.1", port);
		let tcp_conn_result = handler.as_async_outbound().dial_tcp(&mut addr).await;
		assert!(tcp_conn_result.is_ok(), "Failed to dial TCP: {:?}", tcp_conn_result.err());

		let mut tcp_conn = tcp_conn_result.unwrap();

		// Send data
		let test_data = b"Hello, World!";
		tcp_conn.write_all(test_data).await.expect("Failed to write");

		// Read response
		let mut response = vec![0u8; test_data.len()];
		tcp_conn.read_exact(&mut response).await.expect("Failed to read");

		assert_eq!(&response, test_data, "Echo response mismatch");

		// Wait for server to finish
		server_handle.await.unwrap();
	}

	/// Prefer64 direct TCP dials IPv6 first but must fall back to IPv4 when the
	/// IPv6 route is dead (host has an AAAA record yet no working v6 path).
	/// Exercised through tuic's `OutboundHandler` with tuic-supplied
	/// `resolve_info` and a v4-only listener: `[::1]:port` is refused,
	/// `127.0.0.1:port` accepts. Regression guard for the v0.4.6
	/// connection-level Prefer fallback reaching tuic's TCP path (would fail
	/// on v0.4.5).
	#[tokio::test]
	async fn test_direct_prefer64_tcp_falls_back_to_ipv4() {
		use std::net::{Ipv4Addr, Ipv6Addr};

		use acl_engine_rs::outbound::ResolveInfo;
		use tokio::net::TcpListener;

		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let port = listener.local_addr().unwrap().port();
		let accept = tokio::spawn(async move { listener.accept().await.ok() });

		let handler = OutboundHandler::Direct(Arc::new(DirectOutbound::with_mode(DirectMode::Prefer64)));

		let mut acl_addr = Addr::new("dual.example", port).with_resolve_info(ResolveInfo {
			ipv4:  Some(Ipv4Addr::LOCALHOST),
			ipv6:  Some(Ipv6Addr::LOCALHOST),
			error: None,
		});

		let result = handler.as_async_outbound().dial_tcp(&mut acl_addr).await;
		assert!(
			result.is_ok(),
			"Prefer64 must fall back to IPv4 when the IPv6 dial fails: {:?}",
			result.err().map(|e| e.to_string())
		);

		drop(result);
		accept.await.ok();
	}

	/// Test that AsyncTcpConn from outbound works with tokio I/O
	#[tokio::test]
	async fn test_async_tcp_conn_bidirectional_io() {
		use tokio::{
			io::{AsyncReadExt, AsyncWriteExt},
			net::TcpListener,
		};

		// Create a local TCP server that echoes back
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let port = listener.local_addr().unwrap().port();

		let server_handle = tokio::spawn(async move {
			let (mut socket, _) = listener.accept().await.unwrap();
			let mut buf = [0u8; 1024];
			let n = socket.read(&mut buf).await.unwrap();
			// Echo back with prefix
			let response = format!("ECHO:{}", String::from_utf8_lossy(&buf[..n]));
			socket.write_all(response.as_bytes()).await.unwrap();
		});

		// Create Direct outbound and dial
		let handler = OutboundHandler::Direct(Arc::new(DirectOutbound::with_mode(DirectMode::Auto)));
		let mut addr = Addr::new("127.0.0.1", port);
		let mut tcp_conn = handler.as_async_outbound().dial_tcp(&mut addr).await.unwrap();

		// Send data
		tcp_conn.write_all(b"test").await.unwrap();

		// Read response - AsyncTcpConn implements AsyncRead
		let mut response = vec![0u8; 64];
		let n = tcp_conn.read(&mut response).await.unwrap();

		let response_str = String::from_utf8_lossy(&response[..n]);
		assert_eq!(response_str, "ECHO:test", "Response mismatch");

		server_handle.await.unwrap();
	}

	/// Test that socks5 outbound handler can be constructed and used
	#[tokio::test]
	async fn test_socks5_outbound_handler_construction() {
		let entry = OutboundEntry {
			name:          "test-socks5".to_string(),
			outbound_type: "socks5".to_string(),
			config:        OutboundEntryConfig::Socks5 {
				socks5: Socks5Config {
					addr:      "127.0.0.1:1080".to_string(),
					username:  Some("user".to_string()),
					password:  Some("pass".to_string()),
					allow_udp: true,
				},
			},
		};

		let handler = OutboundHandler::from_entry(&entry).expect("Failed to create handler");

		// Verify it's a Socks5 handler
		assert!(matches!(handler, OutboundHandler::Socks5 { .. }));

		// Verify UDP is allowed
		assert!(handler.allows_udp());

		// Verify it's not reject
		assert!(!handler.is_reject());
	}

	/// Test that http outbound handler can be constructed
	#[tokio::test]
	async fn test_http_outbound_handler_construction() {
		let entry = OutboundEntry {
			name:          "test-http".to_string(),
			outbound_type: "http".to_string(),
			config:        OutboundEntryConfig::Http {
				http: HttpConfig {
					url:      "http://127.0.0.1:8080".to_string(),
					insecure: false,
				},
			},
		};

		let handler = OutboundHandler::from_entry(&entry).expect("Failed to create handler");

		// Verify it's an Http handler
		assert!(matches!(handler, OutboundHandler::Http(_)));

		// Verify UDP is NOT allowed (HTTP doesn't support UDP)
		assert!(!handler.allows_udp());

		// Verify it's not reject
		assert!(!handler.is_reject());
	}

	/// Test http outbound with authentication
	#[tokio::test]
	async fn test_http_outbound_with_auth() {
		let entry = OutboundEntry {
			name:          "test-http-auth".to_string(),
			outbound_type: "http".to_string(),
			config:        OutboundEntryConfig::Http {
				http: HttpConfig {
					url:      "http://user:pass@127.0.0.1:8080".to_string(),
					insecure: false,
				},
			},
		};

		let handler = OutboundHandler::from_entry(&entry).expect("Failed to create handler with auth");
		assert!(matches!(handler, OutboundHandler::Http(_)));
	}

	/// Test http config parsing from YAML
	#[tokio::test]
	async fn test_parse_http_config() {
		let yaml = r#"
outbounds:
  - name: proxy
    type: http
    http:
      url: http://user:pass@192.168.1.1:8080
      insecure: true

acl:
  inline:
    - proxy(all)
"#;
		let config: AclConfig = serde_yaml::from_str(yaml).expect("Failed to parse YAML");
		assert_eq!(config.outbounds.len(), 1);
		assert_eq!(config.outbounds[0].name, "proxy");
		assert_eq!(config.outbounds[0].outbound_type, "http");

		match &config.outbounds[0].config {
			OutboundEntryConfig::Http { http } => {
				assert_eq!(http.url, "http://user:pass@192.168.1.1:8080");
				assert!(http.insecure);
			}
			_ => panic!("Expected Http config"),
		}
	}

	/// Direct outbound reports its configured family-selection mode so the UDP
	/// relay path can order send targets by family preference.
	#[test]
	fn test_direct_mode_reports_configured_mode() {
		let handler = OutboundHandler::Direct(Arc::new(DirectOutbound::with_mode(DirectMode::Prefer64)));
		assert_eq!(handler.direct_mode(), Some(DirectMode::Prefer64));

		let auto = OutboundHandler::Direct(Arc::new(DirectOutbound::with_mode(DirectMode::Auto)));
		assert_eq!(auto.direct_mode(), Some(DirectMode::Auto));
	}

	/// `is_direct` is true only for Direct outbounds; the UDP relay uses it to
	/// refuse proxied outbounds (which tuic cannot relay via its own sockets).
	#[test]
	fn test_is_direct_only_for_direct() {
		let direct = OutboundHandler::Direct(Arc::new(DirectOutbound::with_mode(DirectMode::Auto)));
		assert!(direct.is_direct());

		let socks = OutboundHandler::Socks5 {
			inner:     Arc::new(Socks5::new("127.0.0.1:1080")),
			allow_udp: true,
		};
		assert!(!socks.is_direct());

		let http = OutboundHandler::Http(Arc::new(Http::from_url("http://127.0.0.1:8080").unwrap()));
		assert!(!http.is_direct());

		let reject = OutboundHandler::Reject(Arc::new(Reject::new()));
		assert!(!reject.is_direct());
	}

	/// Non-Direct outbounds do local family selection through the proxy, not
	/// tuic, so they report no mode.
	#[test]
	fn test_direct_mode_none_for_non_direct() {
		let socks = OutboundHandler::Socks5 {
			inner:     Arc::new(Socks5::new("127.0.0.1:1080")),
			allow_udp: true,
		};
		assert_eq!(socks.direct_mode(), None);

		let http = OutboundHandler::Http(Arc::new(Http::from_url("http://127.0.0.1:8080").unwrap()));
		assert_eq!(http.direct_mode(), None);

		let reject = OutboundHandler::Reject(Arc::new(Reject::new()));
		assert_eq!(reject.direct_mode(), None);
	}

	/// Test ACL rule matching with http outbound
	#[tokio::test]
	async fn test_acl_rule_matching_with_http_outbound() {
		let temp_dir = tempfile::tempdir().unwrap();

		let config = AclConfig {
			outbounds: vec![OutboundEntry {
				name:          "httpproxy".to_string(),
				outbound_type: "http".to_string(),
				config:        OutboundEntryConfig::Http {
					http: HttpConfig {
						url:      "http://127.0.0.1:8080".to_string(),
						insecure: false,
					},
				},
			}],
			acl:       AclRules {
				inline: vec!["httpproxy(suffix:example.com)".to_string(), "direct(all)".to_string()],
			},
		};

		let engine = AclEngine::new(config, temp_dir.path(), false)
			.await
			.expect("Failed to create ACL engine");

		// Test: example.com should go through http proxy
		let result = engine.match_host("www.example.com", 443, Protocol::TCP);
		assert!(result.is_some());
		assert!(
			matches!(result.unwrap().as_ref(), OutboundHandler::Http(_)),
			"example.com should go through http proxy"
		);

		// Test: other traffic should go direct
		let result = engine.match_host("google.com", 80, Protocol::TCP);
		assert!(result.is_some());
		assert!(
			matches!(result.unwrap().as_ref(), OutboundHandler::Direct(_)),
			"Other traffic should go direct"
		);
	}
}
