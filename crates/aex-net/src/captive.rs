//! Captive-portal and degraded-network detection via consensus of three
//! standard probe endpoints.
//!
//! ```text
//!     detect_network_state(client)
//!              │
//!              ▼
//!     ┌─────────────────────┐
//!     │  tokio::join!       │
//!     │  ┌────────────────┐ │
//!     │  │ probe Apple    │ │   HTTP GET captive.apple.com/hotspot-detect.html
//!     │  │ probe Google   │ │   HTTP GET www.google.com/generate_204
//!     │  │ probe MS NCSI  │ │   HTTP GET www.msftncsi.com/ncsi.txt
//!     │  └────────────────┘ │
//!     └─────────────────────┘
//!              │
//!              ▼  three ProbeVerdicts
//!        consensus rules (first match wins):
//!        · any Captive  → NetworkState::CaptivePortal
//!        · all Ok       → NetworkState::Direct
//!        · all Failed   → NetworkState::Unknown
//!        · otherwise    → NetworkState::Limited
//! ```

use std::time::Duration;

use serde::Serialize;

/// High-level network reachability state.
///
/// Emitted by the AEX data-plane binary on stdout as
/// `AEX_NETWORK_STATE=<value>` (Delight #5) so orchestrators can surface
/// captive-portal conditions to end users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkState {
    /// All three probes returned the expected response — network is unrestricted.
    Direct,
    /// At least one probe saw a redirect or a login-page body; a captive portal
    /// is almost certainly in front of the network.
    CaptivePortal,
    /// Probes reached endpoints but at least one response was unexpected
    /// (wrong status, body mismatch). Network works but interfering DPI or
    /// routing may be present.
    Limited,
    /// Probes did not complete (timeouts or DNS failure). Connectivity is
    /// absent or being actively dropped.
    Unknown,
}

impl NetworkState {
    /// String form used by the `AEX_NETWORK_STATE=<value>` stdout flag.
    pub fn as_stdout_value(self) -> &'static str {
        match self {
            NetworkState::Direct => "direct",
            NetworkState::CaptivePortal => "captive_portal",
            NetworkState::Limited => "limited",
            NetworkState::Unknown => "unknown",
        }
    }
}

/// Per-probe verdict. Internal; callers only see the aggregate [`NetworkState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeVerdict {
    Ok,
    Captive,
    Unexpected,
    Failed,
}

/// Maximum time a single probe will wait for a response. The three probes
/// run in parallel, so total wall-clock is bounded by this value (plus any
/// TLS handshake overhead, which is negligible for plain HTTP probes).
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Apple's standard captive-portal probe.
const APPLE_URL: &str = "http://captive.apple.com/hotspot-detect.html";
/// Google's standard 204 endpoint.
const GOOGLE_URL: &str = "http://www.google.com/generate_204";
/// Microsoft NCSI probe.
const MS_URL: &str = "http://www.msftncsi.com/ncsi.txt";

/// Expected Apple body fragment when network is unrestricted.
const APPLE_EXPECTED_BODY_FRAGMENT: &str = "Success";
/// Expected Microsoft NCSI body (exact match after trimming).
const MS_EXPECTED_BODY: &str = "Microsoft NCSI";

/// Detect whether a captive portal or other restriction is present.
///
/// Runs three well-known probes in parallel and classifies via consensus:
///
/// | Probe                                | Expected on clean network |
/// |--------------------------------------|---------------------------|
/// | `captive.apple.com/hotspot-detect.html` | 200 OK + body containing `Success` |
/// | `www.google.com/generate_204`           | 204 No Content            |
/// | `www.msftncsi.com/ncsi.txt`             | 200 OK + body `Microsoft NCSI` |
///
/// Returns by value; there is no error case — a probe failure is itself
/// evidence about the network, not a failure of the detector.
pub async fn detect_network_state(client: &reqwest::Client) -> NetworkState {
    detect_with_urls(client, APPLE_URL, GOOGLE_URL, MS_URL).await
}

/// Probe-URL-parametrised detection path. Exposed at crate scope so unit tests
/// can point the probes at a local axum mock instead of the real internet.
async fn detect_with_urls(
    client: &reqwest::Client,
    apple_url: &str,
    google_url: &str,
    ms_url: &str,
) -> NetworkState {
    let (apple, google, ms) = tokio::join!(
        probe_apple(client, apple_url),
        probe_google(client, google_url),
        probe_ms(client, ms_url),
    );
    consensus([apple, google, ms])
}

fn consensus(results: [ProbeVerdict; 3]) -> NetworkState {
    if results.contains(&ProbeVerdict::Captive) {
        return NetworkState::CaptivePortal;
    }
    if results.iter().all(|v| *v == ProbeVerdict::Ok) {
        return NetworkState::Direct;
    }
    if results.iter().all(|v| *v == ProbeVerdict::Failed) {
        return NetworkState::Unknown;
    }
    // Any mixed state without a captive signal is Limited: we have
    // *some* evidence the network is reachable but can't confirm all
    // three canonical endpoints behave as expected.
    NetworkState::Limited
}

async fn probe_apple(client: &reqwest::Client, url: &str) -> ProbeVerdict {
    match client.get(url).timeout(PROBE_TIMEOUT).send().await {
        Ok(resp) => classify_apple_response(resp).await,
        Err(_) => ProbeVerdict::Failed,
    }
}

async fn classify_apple_response(resp: reqwest::Response) -> ProbeVerdict {
    if resp.status().is_redirection() {
        return ProbeVerdict::Captive;
    }
    if !resp.status().is_success() {
        return ProbeVerdict::Unexpected;
    }
    match resp.text().await {
        Ok(body) if body.contains(APPLE_EXPECTED_BODY_FRAGMENT) => ProbeVerdict::Ok,
        Ok(_) => ProbeVerdict::Captive,
        Err(_) => ProbeVerdict::Failed,
    }
}

async fn probe_google(client: &reqwest::Client, url: &str) -> ProbeVerdict {
    match client.get(url).timeout(PROBE_TIMEOUT).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_redirection() {
                ProbeVerdict::Captive
            } else if status.as_u16() == 204 {
                ProbeVerdict::Ok
            } else {
                ProbeVerdict::Unexpected
            }
        }
        Err(_) => ProbeVerdict::Failed,
    }
}

async fn probe_ms(client: &reqwest::Client, url: &str) -> ProbeVerdict {
    match client.get(url).timeout(PROBE_TIMEOUT).send().await {
        Ok(resp) => {
            if resp.status().is_redirection() {
                return ProbeVerdict::Captive;
            }
            if !resp.status().is_success() {
                return ProbeVerdict::Unexpected;
            }
            match resp.text().await {
                Ok(body) if body.trim() == MS_EXPECTED_BODY => ProbeVerdict::Ok,
                Ok(_) => ProbeVerdict::Captive,
                Err(_) => ProbeVerdict::Failed,
            }
        }
        Err(_) => ProbeVerdict::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    // ---------------- pure unit tests on consensus logic ----------------

    #[test]
    fn stdout_values_are_stable() {
        assert_eq!(NetworkState::Direct.as_stdout_value(), "direct");
        assert_eq!(
            NetworkState::CaptivePortal.as_stdout_value(),
            "captive_portal"
        );
        assert_eq!(NetworkState::Limited.as_stdout_value(), "limited");
        assert_eq!(NetworkState::Unknown.as_stdout_value(), "unknown");
    }

    #[test]
    fn all_ok_is_direct() {
        assert_eq!(
            consensus([ProbeVerdict::Ok, ProbeVerdict::Ok, ProbeVerdict::Ok]),
            NetworkState::Direct
        );
    }

    #[test]
    fn any_captive_dominates() {
        assert_eq!(
            consensus([ProbeVerdict::Ok, ProbeVerdict::Captive, ProbeVerdict::Ok]),
            NetworkState::CaptivePortal
        );
    }

    #[test]
    fn unexpected_downgrades_to_limited() {
        assert_eq!(
            consensus([ProbeVerdict::Ok, ProbeVerdict::Unexpected, ProbeVerdict::Ok]),
            NetworkState::Limited
        );
    }

    #[test]
    fn all_failed_is_unknown() {
        assert_eq!(
            consensus([
                ProbeVerdict::Failed,
                ProbeVerdict::Failed,
                ProbeVerdict::Failed
            ]),
            NetworkState::Unknown
        );
    }

    #[test]
    fn mixed_failure_and_ok_is_limited() {
        assert_eq!(
            consensus([ProbeVerdict::Ok, ProbeVerdict::Failed, ProbeVerdict::Failed]),
            NetworkState::Limited
        );
    }

    #[test]
    fn only_unexpected_with_no_ok_is_limited() {
        assert_eq!(
            consensus([
                ProbeVerdict::Unexpected,
                ProbeVerdict::Failed,
                ProbeVerdict::Failed
            ]),
            NetworkState::Limited
        );
    }

    // ---------------- end-to-end tests via a local axum mock ----------------
    //
    // The mock serves one route per behaviour we want to reproduce. Individual
    // test cases compose three routes (one per probe slot) to model real
    // captive / limited / direct scenarios.

    #[derive(Clone, Default)]
    struct MockRoutes {
        apple_body: Arc<String>,
        ms_body: Arc<String>,
    }

    async fn apple_ok(State(s): State<MockRoutes>) -> impl IntoResponse {
        (StatusCode::OK, (*s.apple_body).clone())
    }

    async fn apple_captive_body(State(_): State<MockRoutes>) -> impl IntoResponse {
        (StatusCode::OK, "Please log in to continue".to_string())
    }

    async fn apple_redirect() -> impl IntoResponse {
        let mut h = HeaderMap::new();
        h.insert(
            "location",
            HeaderValue::from_static("http://login.example/"),
        );
        (StatusCode::FOUND, h)
    }

    async fn apple_server_error() -> impl IntoResponse {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    async fn google_204() -> impl IntoResponse {
        StatusCode::NO_CONTENT
    }

    async fn google_200() -> impl IntoResponse {
        (StatusCode::OK, "intercepted")
    }

    async fn google_redirect() -> impl IntoResponse {
        let mut h = HeaderMap::new();
        h.insert(
            "location",
            HeaderValue::from_static("http://login.example/"),
        );
        (StatusCode::FOUND, h)
    }

    async fn ms_ok(State(s): State<MockRoutes>) -> impl IntoResponse {
        (StatusCode::OK, (*s.ms_body).clone())
    }

    async fn ms_wrong_body(State(_): State<MockRoutes>) -> impl IntoResponse {
        (StatusCode::OK, "something else".to_string())
    }

    /// Spawn a throw-away axum server on an ephemeral port. Returns the bound
    /// address and a shutdown sender. Test drops the shutdown on completion.
    async fn spawn_mock(routes: MockRoutes) -> (SocketAddr, oneshot::Sender<()>) {
        let app = Router::new()
            .route("/apple_ok", get(apple_ok))
            .route("/apple_captive_body", get(apple_captive_body))
            .route("/apple_redirect", get(apple_redirect))
            .route("/apple_500", get(apple_server_error))
            .route("/google_204", get(google_204))
            .route("/google_200", get(google_200))
            .route("/google_redirect", get(google_redirect))
            .route("/ms_ok", get(ms_ok))
            .route("/ms_wrong", get(ms_wrong_body))
            .with_state(routes);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        (addr, tx)
    }

    /// Build a reqwest client that does not auto-follow redirects, so a 302
    /// stays a 302 and our probe classifier sees it.
    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn direct_when_all_three_probes_pass() {
        let (addr, _tx) = spawn_mock(MockRoutes {
            apple_body: Arc::new("<HTML>Success</HTML>".into()),
            ms_body: Arc::new("Microsoft NCSI".into()),
        })
        .await;
        let client = test_client();
        let r = detect_with_urls(
            &client,
            &format!("http://{addr}/apple_ok"),
            &format!("http://{addr}/google_204"),
            &format!("http://{addr}/ms_ok"),
        )
        .await;
        assert_eq!(r, NetworkState::Direct);
    }

    #[tokio::test]
    async fn captive_when_apple_redirects() {
        let (addr, _tx) = spawn_mock(MockRoutes {
            apple_body: Arc::new("Success".into()),
            ms_body: Arc::new("Microsoft NCSI".into()),
        })
        .await;
        let client = test_client();
        let r = detect_with_urls(
            &client,
            &format!("http://{addr}/apple_redirect"),
            &format!("http://{addr}/google_204"),
            &format!("http://{addr}/ms_ok"),
        )
        .await;
        assert_eq!(r, NetworkState::CaptivePortal);
    }

    #[tokio::test]
    async fn captive_when_apple_returns_login_body() {
        let (addr, _tx) = spawn_mock(MockRoutes {
            apple_body: Arc::new("unused".into()),
            ms_body: Arc::new("Microsoft NCSI".into()),
        })
        .await;
        let client = test_client();
        let r = detect_with_urls(
            &client,
            &format!("http://{addr}/apple_captive_body"),
            &format!("http://{addr}/google_204"),
            &format!("http://{addr}/ms_ok"),
        )
        .await;
        assert_eq!(r, NetworkState::CaptivePortal);
    }

    #[tokio::test]
    async fn limited_when_google_returns_200_instead_of_204() {
        let (addr, _tx) = spawn_mock(MockRoutes {
            apple_body: Arc::new("Success".into()),
            ms_body: Arc::new("Microsoft NCSI".into()),
        })
        .await;
        let client = test_client();
        let r = detect_with_urls(
            &client,
            &format!("http://{addr}/apple_ok"),
            &format!("http://{addr}/google_200"),
            &format!("http://{addr}/ms_ok"),
        )
        .await;
        assert_eq!(r, NetworkState::Limited);
    }

    #[tokio::test]
    async fn limited_when_ms_body_mismatches() {
        let (addr, _tx) = spawn_mock(MockRoutes {
            apple_body: Arc::new("Success".into()),
            ms_body: Arc::new("unused".into()),
        })
        .await;
        let client = test_client();
        let r = detect_with_urls(
            &client,
            &format!("http://{addr}/apple_ok"),
            &format!("http://{addr}/google_204"),
            &format!("http://{addr}/ms_wrong"),
        )
        .await;
        // MS with wrong body → Captive signal (body present but unexpected ≈ login page).
        assert_eq!(r, NetworkState::CaptivePortal);
    }

    #[tokio::test]
    async fn limited_when_apple_returns_5xx() {
        let (addr, _tx) = spawn_mock(MockRoutes {
            apple_body: Arc::new("unused".into()),
            ms_body: Arc::new("Microsoft NCSI".into()),
        })
        .await;
        let client = test_client();
        let r = detect_with_urls(
            &client,
            &format!("http://{addr}/apple_500"),
            &format!("http://{addr}/google_204"),
            &format!("http://{addr}/ms_ok"),
        )
        .await;
        assert_eq!(r, NetworkState::Limited);
    }

    #[tokio::test]
    async fn unknown_when_all_probes_unreachable() {
        // Deliberately point at a closed port on loopback — all three probes
        // fail fast with connection refused.
        let closed = "http://127.0.0.1:1"; // port 1 is reserved & unbound locally
        let client = test_client();
        let r = detect_with_urls(&client, closed, closed, closed).await;
        assert_eq!(r, NetworkState::Unknown);
    }
}
