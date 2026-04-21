//! DNS resolver pinned to Cloudflare 1.1.1.1, bypassing the OS resolver.

use std::sync::Arc;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// A DNS resolver that queries Cloudflare's public nameservers (1.1.1.1) via
/// hickory, with an empty search-domain list and zero cache.
///
/// ### Why this exists
///
/// `reqwest`'s built-in hickory integration inherits the system `resolv.conf`.
/// On developer laptops and many consumer wifi networks, `resolv.conf` contains
/// a search-domain suffix (commonly the wifi SSID) that hickory will append to
/// any hostname lookup. A query for `foo.trycloudflare.com` ends up looking up
/// `foo.trycloudflare.com.<wifi-name>.` — which does not resolve — and the
/// control plane's healthcheck of a freshly-created tunnel fails intermittently.
///
/// Passing this resolver to `reqwest::ClientBuilder::dns_resolver` routes around
/// the OS entirely: queries go straight to 1.1.1.1 over the hickory stub resolver,
/// with a zero-size cache so retries during a tunnel's DNS-propagation window see
/// a fresh answer rather than a negatively-cached `NXDOMAIN`.
///
/// Configuration is deliberately not exposed — the single `new()` constructor
/// is the only supported form. When a second caller surfaces that needs a
/// different knob, add a focused setter rather than re-exporting
/// `hickory_resolver::config::ResolverOpts`.
#[derive(Clone)]
pub struct CloudflareDnsResolver {
    inner: Arc<TokioAsyncResolver>,
}

impl CloudflareDnsResolver {
    /// Construct a resolver with AEX-standard settings:
    ///
    /// - Nameservers: `ResolverConfig::cloudflare()` (1.1.1.1, 1.0.0.1 + v6).
    /// - Cache size: `0` (every lookup hits the upstream NS).
    /// - ndots: `1` (short hostnames never fall into an accidental search path).
    pub fn new() -> Self {
        let (config, opts) = cloudflare_config();
        let inner = TokioAsyncResolver::tokio(config, opts);
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl Default for CloudflareDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl reqwest::dns::Resolve for CloudflareDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.inner.clone();
        Box::pin(async move {
            let hostname = name.as_str().to_string();
            let lookup = resolver
                .lookup_ip(hostname.as_str())
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            // Materialise into an owned Vec so the iterator doesn't borrow from
            // `lookup` (which is dropped at the end of the closure).
            let addrs: Vec<std::net::SocketAddr> = lookup
                .iter()
                .map(|ip| std::net::SocketAddr::new(ip, 0))
                .collect();
            let iter: Box<dyn Iterator<Item = std::net::SocketAddr> + Send> =
                Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Extracted so tests can assert the exact knobs AEX commits to without
/// having to construct a real resolver.
fn cloudflare_config() -> (ResolverConfig, ResolverOpts) {
    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    opts.ndots = 1;
    (ResolverConfig::cloudflare(), opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_opts_zero_cache_and_single_ndot() {
        let (_config, opts) = cloudflare_config();
        assert_eq!(opts.cache_size, 0, "cache must be disabled");
        assert_eq!(
            opts.ndots, 1,
            "ndots must be 1 to prevent search-domain append"
        );
    }

    #[test]
    fn cloudflare_config_has_name_servers() {
        let (config, _) = cloudflare_config();
        // Trust hickory's ResolverConfig::cloudflare() to give us Cloudflare's
        // IPs. We just assert the config is non-empty so a future hickory bump
        // that ships an empty cloudflare() config would fail CI.
        let servers = config.name_servers();
        assert!(
            !servers.is_empty(),
            "ResolverConfig::cloudflare() must produce at least one name server"
        );
    }

    #[test]
    fn resolver_constructs_without_panic() {
        let _r = CloudflareDnsResolver::new();
    }

    #[test]
    fn default_and_new_are_equivalent_constructors() {
        let _a = CloudflareDnsResolver::new();
        let _b = CloudflareDnsResolver::default();
    }

    #[tokio::test]
    #[ignore = "requires outbound 1.1.1.1 UDP/53; run locally via `cargo test -- --ignored`"]
    async fn resolves_public_hostname_via_cloudflare() {
        use reqwest::dns::Resolve;
        let r = CloudflareDnsResolver::new();
        let name: reqwest::dns::Name = "one.one.one.one".parse().unwrap();
        let iter = r.resolve(name).await.expect("lookup must succeed");
        let addrs: Vec<_> = iter.collect();
        assert!(!addrs.is_empty(), "expected at least one resolved address");
    }
}
