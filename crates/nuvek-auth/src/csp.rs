//! Content-Security-Policy values for adopting apps.

/// CSP for user-visible files (build logs, repository files): no script, no plugins, sandboxed.
pub const FILE_SANDBOX: &str = "sandbox; default-src 'none'";

/// Builds the strict SPA-shell CSP: `script-src 'self'` with no `unsafe-eval`, and the issuer
/// origin allowed only in `connect-src` (token endpoint) and `frame-src` (silent auth).
///
/// `issuer` is reduced to its `https://host[:port]` origin. `None`, or a value that is not a
/// plain `https://` URL, leaves the issuer out (`frame-src 'none'`).
pub fn spa_policy(issuer: Option<&str>) -> String {
    let origin = issuer.and_then(issuer_origin);
    let (connect, frame) = match &origin {
        Some(o) => (format!("'self' {o}"), o.clone()),
        None => ("'self'".to_string(), "'none'".to_string()),
    };
    format!(
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; connect-src {connect}; frame-src {frame}; \
         object-src 'none'; base-uri 'none'; frame-ancestors 'self'"
    )
}

fn issuer_origin(issuer: &str) -> Option<String> {
    // Same strict parser as the issuer config check and `OidcConfig::domain`.
    crate::config::parse_https_url(issuer)
        .map(|u| format!("https://{}", u.authority.to_ascii_lowercase()))
}
