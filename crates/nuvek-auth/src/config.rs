//! Environment-driven configuration: [`AuthConfig`], [`AuthMode`] and the redacting
//! [`SecretString`].

use std::fmt;
use std::str::FromStr;

use crate::error::AuthConfigError;

/// A secret string (the static API token). Its `Debug` output is always redacted, it has no
/// `Display` and no `Serialize`, so it cannot leak through logs or JSON by accident. It has no
/// `PartialEq` either: compare with the crate's constant-time check, never `==`.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the secret. Call this only at the point of comparison.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(****)")
    }
}

/// Which credentials the service accepts, from `{P}AUTH_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMode {
    /// `off`: no authentication; every caller is `anonymous` with every permission. Development
    /// and tests only; logs a warning at start-up.
    Off,
    /// `token`: the static machine token only.
    Token,
    /// `oidc`: Auth0 RS256 access tokens only.
    Oidc,
    /// `oidc+token`: Auth0 access tokens and the static machine token.
    OidcAndToken,
}

impl AuthMode {
    /// The canonical env value (`off`, `token`, `oidc`, `oidc+token`).
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Off => "off",
            AuthMode::Token => "token",
            AuthMode::Oidc => "oidc",
            AuthMode::OidcAndToken => "oidc+token",
        }
    }

    /// True when Auth0 access tokens are accepted.
    pub fn accepts_oidc(self) -> bool {
        matches!(self, AuthMode::Oidc | AuthMode::OidcAndToken)
    }

    /// True when the static machine token is accepted.
    pub fn accepts_token(self) -> bool {
        matches!(self, AuthMode::Token | AuthMode::OidcAndToken)
    }
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when parsing an unknown [`AuthMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown auth mode (expected off, token, oidc or oidc+token)")]
pub struct UnknownAuthMode;

impl FromStr for AuthMode {
    type Err = UnknownAuthMode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(AuthMode::Off),
            "token" => Ok(AuthMode::Token),
            "oidc" => Ok(AuthMode::Oidc),
            "oidc+token" => Ok(AuthMode::OidcAndToken),
            _ => Err(UnknownAuthMode),
        }
    }
}

/// OIDC (Auth0) settings. All values are public: they are served to the SPA. Only
/// [`AuthConfig::from_env`] builds one, so the issuer is always a validated `https://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    issuer: String,
    audience: String,
    client_id: String,
    allowed_subs: Vec<String>,
    required_permission: Option<String>,
    require_mfa: bool,
    require_passkey: bool,
}

impl OidcConfig {
    /// Issuer, always `https://host[:port]/[path/]` with exactly one trailing slash.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// API identifier that must appear in the token `aud`.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Public SPA client ID.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Subjects allowed in; empty means any subject.
    pub fn allowed_subs(&self) -> &[String] {
        &self.allowed_subs
    }

    /// Permission every user token must carry, if set.
    pub fn required_permission(&self) -> Option<&str> {
        self.required_permission.as_deref()
    }

    /// Whether `{P}REQUIRE_MFA` is on. It applies only to
    /// [`crate::Authenticator::require_permission`] and only to Auth0 principals
    /// ([`crate::Via::Oidc`]); the static machine token is exempt.
    pub fn require_mfa(&self) -> bool {
        self.require_mfa
    }

    /// Whether `{P}REQUIRE_PASSKEY` is on. Every OIDC token must then carry `passkey`
    /// in the signed `https://nuvek.ca/amr` claim before a principal is established.
    /// Static machine tokens are exempt; this does not satisfy or change MFA policy.
    pub fn require_passkey(&self) -> bool {
        self.require_passkey
    }

    /// The issuer host and optional port (e.g. `tenant.eu.auth0.com`), as the SPA SDK wants it.
    pub fn domain(&self) -> &str {
        parse_https_url(&self.issuer).map_or("", |u| u.authority)
    }

    /// The issuer origin (`https://host[:port]`), used in the CSP.
    pub fn issuer_origin(&self) -> String {
        format!("https://{}", self.domain())
    }

    /// The only URL the JWKS is ever fetched from: `{issuer}.well-known/jwks.json`.
    pub fn jwks_url(&self) -> String {
        format!("{}.well-known/jwks.json", self.issuer)
    }
}

/// A strictly parsed `https://` URL: lowercase-insensitive scheme, host of `[A-Za-z0-9.-]` with an
/// optional numeric port, no userinfo, query or fragment, and a path of `[A-Za-z0-9._~-]`
/// segments without `.`/`..`.
pub(crate) struct HttpsUrl<'a> {
    /// `host[:port]`, as written.
    pub(crate) authority: &'a str,
    /// The path, `""` or starting with `/`.
    pub(crate) path: &'a str,
}

/// Parses `value` as a strict `https://` URL. Shared by the issuer check, [`OidcConfig::domain`]
/// and the CSP builder so they can never disagree.
pub(crate) fn parse_https_url(value: &str) -> Option<HttpsUrl<'_>> {
    let scheme = value.get(..8)?;
    if !scheme.eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &value[8..];
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with('-')
        && !host.contains("..");
    let port_ok = port.is_none_or(|p| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n > 0)
    });
    let path_ok = path.split('/').skip(1).all(|seg| {
        seg != "."
            && seg != ".."
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
    });
    (host_ok && port_ok && path_ok).then_some(HttpsUrl { authority, path })
}

/// Validated authentication configuration. Build it with [`AuthConfig::from_env`]; it is
/// fail-closed: an unset or unknown mode, or a missing required key, is an error.
///
/// `Debug` is safe to log: the static tokens are [`SecretString`]s.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    prefix: String,
    mode: AuthMode,
    oidc: Option<OidcConfig>,
    api_token: Option<SecretString>,
    api_token_next: Option<SecretString>,
    auth_reads: bool,
    public_origin: Option<String>,
}

impl AuthConfig {
    /// Reads `{prefix}AUTH_MODE` and the related keys from the process environment. The prefix
    /// includes its trailing underscore (`"DEB_"`).
    ///
    /// The presence of the static token in the token modes is checked later, by
    /// [`AuthConfig::validate`] (called from [`crate::Authenticator::new`]), so that
    /// [`AuthConfig::with_api_token`] can still supply a legacy source.
    pub fn from_env(prefix: &str) -> Result<AuthConfig, AuthConfigError> {
        Self::from_lookup(prefix, |key| std::env::var(key).ok())
    }

    /// Like [`AuthConfig::from_env`], but reads keys through `lookup` instead of the process
    /// environment. Useful in tests, where mutating the environment races.
    pub fn from_lookup<F>(prefix: &str, lookup: F) -> Result<AuthConfig, AuthConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let key = |name: &str| format!("{prefix}{name}");
        // An empty or whitespace-only value counts as unset everywhere.
        let get = |name: &str| -> Option<String> {
            lookup(&key(name))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let mode_key = key("AUTH_MODE");
        let mode = match get("AUTH_MODE") {
            None => return Err(AuthConfigError::Missing { key: mode_key }),
            Some(v) => v
                .parse::<AuthMode>()
                .map_err(|_| AuthConfigError::Invalid {
                    key: mode_key,
                    reason: "expected off, token, oidc or oidc+token",
                })?,
        };

        let auth_reads = parse_bool(&key("AUTH_READS"), get("AUTH_READS"), true)?;
        let require_mfa = parse_bool(&key("REQUIRE_MFA"), get("REQUIRE_MFA"), false)?;
        let require_passkey = parse_bool(&key("REQUIRE_PASSKEY"), get("REQUIRE_PASSKEY"), false)?;

        let public_origin = match get("PUBLIC_ORIGIN") {
            Some(v) => Some(normalise_origin(&key("PUBLIC_ORIGIN"), &v)?),
            None if mode == AuthMode::Off => None,
            None => {
                return Err(AuthConfigError::Missing {
                    key: key("PUBLIC_ORIGIN"),
                })
            }
        };

        let oidc = if mode.accepts_oidc() {
            let require =
                |name: &str| get(name).ok_or_else(|| AuthConfigError::Missing { key: key(name) });
            let issuer = normalise_issuer(&key("OIDC_ISSUER"), &require("OIDC_ISSUER")?)?;
            let audience = require("OIDC_AUDIENCE")?;
            let client_id = require("OIDC_CLIENT_ID")?;
            let allowed_subs: Vec<String> = get("ALLOWED_SUBS")
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let required_permission = get("REQUIRED_PERMISSION");
            if allowed_subs.is_empty() && required_permission.is_none() {
                return Err(AuthConfigError::MissingOneOf {
                    first: key("ALLOWED_SUBS"),
                    second: key("REQUIRED_PERMISSION"),
                });
            }
            Some(OidcConfig {
                issuer,
                audience,
                client_id,
                allowed_subs,
                required_permission,
                require_mfa,
                require_passkey,
            })
        } else {
            None
        };

        let (api_token, api_token_next) = if mode.accepts_token() {
            let token = |name: &str| -> Result<Option<SecretString>, AuthConfigError> {
                get(name)
                    .map(|v| check_token_len(&key(name), v))
                    .transpose()
            };
            (token("API_TOKEN")?, token("API_TOKEN_NEXT")?)
        } else {
            (None, None)
        };

        Ok(AuthConfig {
            prefix: prefix.to_string(),
            mode,
            oidc,
            api_token,
            api_token_next,
            auth_reads,
            public_origin,
        })
    }

    /// Supplies a legacy static-token source (e.g. a config-file `api_token` or a bare
    /// `API_TOKEN`). It is used only when `{P}API_TOKEN` is unset, and only in the token modes.
    /// `None` or an empty value changes nothing. Its length is checked by
    /// [`AuthConfig::validate`].
    pub fn with_api_token(mut self, token: Option<String>) -> Self {
        if self.mode.accepts_token() && self.api_token.is_none() {
            self.api_token = token
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .map(SecretString::new);
        }
        self
    }

    /// Final fail-closed check: in the token modes a static token of at least
    /// [`MIN_TOKEN_LEN`] characters must be present (from `{P}API_TOKEN` or
    /// [`AuthConfig::with_api_token`]).
    pub fn validate(&self) -> Result<(), AuthConfigError> {
        if !self.mode.accepts_token() {
            return Ok(());
        }
        let key = format!("{}API_TOKEN", self.prefix);
        match &self.api_token {
            None => Err(AuthConfigError::Missing { key }),
            Some(t) if t.expose_secret().chars().count() < MIN_TOKEN_LEN => {
                Err(AuthConfigError::Invalid {
                    key,
                    reason: "must be at least 32 characters",
                })
            }
            Some(_) => Ok(()),
        }
    }

    /// The env prefix this config was read with.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The configured mode.
    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    /// OIDC settings, present in the oidc modes only.
    pub fn oidc(&self) -> Option<&OidcConfig> {
        self.oidc.as_ref()
    }

    /// Whether read routes are gated (`{P}AUTH_READS`, default true).
    pub fn auth_reads(&self) -> bool {
        self.auth_reads
    }

    /// The exact origin accepted by [`crate::Authenticator::check_origin`].
    pub fn public_origin(&self) -> Option<&str> {
        self.public_origin.as_deref()
    }

    /// The current and next static tokens, in that order, when set.
    pub(crate) fn api_tokens(&self) -> impl Iterator<Item = &SecretString> {
        self.api_token.iter().chain(self.api_token_next.iter())
    }
}

fn parse_bool(key: &str, value: Option<String>, default: bool) -> Result<bool, AuthConfigError> {
    match value {
        None => Ok(default),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(AuthConfigError::Invalid {
                key: key.to_string(),
                reason: "expected true or false",
            }),
        },
    }
}

/// Minimum length of a static API token, in characters.
pub const MIN_TOKEN_LEN: usize = 32;

fn check_token_len(key: &str, value: String) -> Result<SecretString, AuthConfigError> {
    if value.chars().count() < MIN_TOKEN_LEN {
        return Err(AuthConfigError::Invalid {
            key: key.to_string(),
            reason: "must be at least 32 characters",
        });
    }
    Ok(SecretString::new(value))
}

/// Validates the issuer strictly (see [`parse_https_url`]) and normalises it to
/// `https://<lowercase host[:port]><path>/`.
fn normalise_issuer(key: &str, value: &str) -> Result<String, AuthConfigError> {
    let url = parse_https_url(value).ok_or_else(|| AuthConfigError::Invalid {
        key: key.to_string(),
        reason: "must be https://host[:port]/[path/] with no userinfo, query or fragment",
    })?;
    let path = url.path.trim_end_matches('/');
    Ok(format!(
        "https://{}{path}/",
        url.authority.to_ascii_lowercase()
    ))
}

/// Validates a bare origin (`http(s)://host[:port]`) and lowercases its scheme and host, as
/// browsers serialise the `Origin` header.
fn normalise_origin(key: &str, value: &str) -> Result<String, AuthConfigError> {
    let invalid = || AuthConfigError::Invalid {
        key: key.to_string(),
        reason: "must be a bare origin such as https://app.example",
    };
    let trimmed = value.trim_end_matches('/');
    let lower = trimmed.to_ascii_lowercase();
    // Reuse the strict https parser; accept http:// by parsing it as https.
    let (scheme, as_https) = if let Some(rest) = lower.strip_prefix("http://") {
        ("http", format!("https://{rest}"))
    } else if lower.starts_with("https://") {
        ("https", lower.clone())
    } else {
        return Err(invalid());
    };
    let url = parse_https_url(&as_https).ok_or_else(invalid)?;
    if !url.path.is_empty() {
        return Err(invalid());
    }
    Ok(format!("{scheme}://{}", url.authority))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_gets_one_trailing_slash() {
        assert_eq!(
            normalise_issuer("K", "https://t.example").ok().as_deref(),
            Some("https://t.example/")
        );
        assert_eq!(
            normalise_issuer("K", "https://t.example//").ok().as_deref(),
            Some("https://t.example/")
        );
    }

    #[test]
    fn domain_and_jwks_url() {
        let o = OidcConfig {
            issuer: "https://t.example/".into(),
            audience: "a".into(),
            client_id: "c".into(),
            allowed_subs: vec![],
            required_permission: Some("p".into()),
            require_mfa: false,
            require_passkey: false,
        };
        assert_eq!(o.domain(), "t.example");
        assert_eq!(o.issuer_origin(), "https://t.example");
        assert_eq!(o.jwks_url(), "https://t.example/.well-known/jwks.json");
    }

    #[test]
    fn issuer_rejects_userinfo_query_fragment_and_bad_hosts() {
        for bad in [
            "https://x#@tenant/",
            "https://u@tenant/",
            "https://tenant/?q",
            "https://tenant/#f",
            "https://tenant/a?b",
            "https://tenant:0/",
            "https://tenant:99999/",
            "https://tenant:/",
            "https://ten ant/",
            "https://tenant/../x/",
            "https://tenant/%2e/",
            "https://.tenant/",
            "https:///",
            "http://tenant/",
            "tenant/",
        ] {
            assert!(normalise_issuer("K", bad).is_err(), "{bad}");
            assert!(parse_https_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn issuer_accepts_port_and_path_and_lowercases_host() {
        assert_eq!(
            normalise_issuer("K", "HTTPS://Tenant.Example:8443/sub/path")
                .ok()
                .as_deref(),
            Some("https://tenant.example:8443/sub/path/")
        );
    }

    #[test]
    fn origin_is_lowercased() {
        assert_eq!(
            normalise_origin("K", "HTTPS://App.Example/")
                .ok()
                .as_deref(),
            Some("https://app.example")
        );
        assert_eq!(
            normalise_origin("K", "http://LocalHost:5173")
                .ok()
                .as_deref(),
            Some("http://localhost:5173")
        );
        assert!(normalise_origin("K", "https://u@app.example").is_err());
        assert!(normalise_origin("K", "https://app.example/x").is_err());
    }
}
