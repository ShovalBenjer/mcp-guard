//! URL and Server-Sent-Events helpers.
//!
//! Shared by the networked transport and the CLI's authorization gate. These are pure functions,
//! always compiled and unit-tested, independent of whether the `http` feature is enabled.

use serde_json::Value;

/// Extract the host from a URL, without a full URL-parsing dependency.
///
/// Handles `scheme://[user@]host[:port][/path]` and bracketed IPv6 literals.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    // Drop any userinfo before '@'.
    let authority = authority.rsplit('@').next()?;

    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:8080
        let host = rest.split(']').next()?;
        return (!host.is_empty()).then(|| host.to_owned());
    }
    let host = authority.split(':').next()?;
    (!host.is_empty()).then(|| host.to_owned())
}

/// Whether `host` refers to the local loopback interface (`localhost`, `127.0.0.0/8`, `::1`).
///
/// Private-LAN and link-local addresses are deliberately **not** treated as loopback: a host on
/// your network may still be a system you do not own, so it requires explicit authorization.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host == "localhost" {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Parse every JSON message carried in an SSE stream body (`data:` lines).
#[must_use]
pub fn parse_sse_messages(body: &str) -> Vec<Value> {
    body.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim_start)
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_parses_common_forms() {
        assert_eq!(
            host_of("http://localhost:8080/mcp").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            host_of("https://example.com/path").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host_of("http://user@10.0.0.5:3000").as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(host_of("http://[::1]:9000/mcp").as_deref(), Some("::1"));
        assert_eq!(host_of("not-a-url"), None);
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.9.9.9"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("10.0.0.5"));
        assert!(!is_loopback_host("169.254.169.254"));
        assert!(!is_loopback_host("example.com"));
    }

    #[test]
    fn parses_sse_data_lines() {
        let body =
            "event: message\ndata: {\"id\":1,\"result\":{}}\n\ndata: {\"jsonrpc\":\"2.0\"}\n";
        let msgs = parse_sse_messages(body);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["id"], 1);
    }
}
