//! Pre-configured `reqwest::Client` factory for AEX components.

use std::sync::Arc;
use std::time::Duration;

use crate::dns::CloudflareDnsResolver;

/// Default per-request timeout applied by [`build_http_client`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a `reqwest::Client` with AEX defaults:
///
/// - DNS resolver: [`CloudflareDnsResolver`] (bypasses system resolver).
/// - Request timeout: [`DEFAULT_TIMEOUT`] (30 s).
/// - TLS: rustls (`reqwest`'s `rustls-tls` feature must be enabled in the root
///   `[workspace.dependencies]` block).
/// - User-Agent: `aex-<component_name>/<crate-version>`.
///
/// `component_name` identifies the caller for observability and for HTTP
/// correlation at peer endpoints. Conventionally one of `"control-plane"`,
/// `"data-plane"`, `"sdk"`.
///
/// Returns `Err` only on TLS stack initialization failure — realistic in
/// minimal embedded targets, effectively unreachable on AEX's Linux / macOS
/// dev and production targets. Callers decide whether to propagate or
/// `.expect()`; the explicit `Result` keeps any surprise panic out of the
/// factory itself.
pub fn build_http_client(component_name: &str) -> reqwest::Result<reqwest::Client> {
    build_http_client_with_timeout(component_name, DEFAULT_TIMEOUT)
}

/// Like [`build_http_client`] but with a caller-supplied per-request timeout.
///
/// Use when the 30 s default is inappropriate — for example, health probes that
/// want tight seconds-level limits, or long file transfers that need minutes.
pub fn build_http_client_with_timeout(
    component_name: &str,
    timeout: Duration,
) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .dns_resolver(Arc::new(CloudflareDnsResolver::new()))
        .user_agent(format!(
            "aex-{}/{}",
            component_name,
            env!("CARGO_PKG_VERSION")
        ))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_default_client() {
        let _c = build_http_client("test").expect("client builds on supported platforms");
    }

    #[test]
    fn builds_with_custom_timeout() {
        let _c = build_http_client_with_timeout("test", Duration::from_secs(5))
            .expect("client builds on supported platforms");
    }

    #[test]
    fn default_timeout_is_thirty_seconds() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    }
}
