//! Shared authentication for nuvek axum services.
//!
//! - **Auth0 access tokens:** RS256, validated against the tenant JWKS, which is fetched lazily
//!   and cached by `kid`.
//! - **A static machine token:** constant-time compare, never needs Auth0, so it doubles as the
//!   break-glass path.
//! - **Single-use 30 s tickets** for WebSocket, EventSource and plain links.
//! - **A strict SPA CSP** builder ([`csp`]).
//!
//! The crate is secret-free by construction: the only secret it ever holds is the static token,
//! wrapped in [`SecretString`] so it never reaches `Debug` output, and configuration errors name
//! environment keys, never values.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use axum::{routing::get, Router};
//! use nuvek_auth::{AuthConfig, Authenticator, Principal};
//!
//! let auth = Authenticator::new(AuthConfig::from_env("APP_")?)?;
//! let reads = Router::new().route("/api/status", get(|p: Principal| async move { p.sub }));
//! let writes = Router::new().route("/api/force", axum::routing::post(|| async { "ok" }));
//! let app: Router = Router::new()
//!     .merge(nuvek_auth::routes(auth.clone()))
//!     .merge(reads.layer(auth.require_user()))
//!     .merge(writes.layer(auth.require_permission("app:write")));
//! # let _ = app; Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod csp;
pub mod error;
pub mod jwks;
pub mod jwt;
pub mod layer;
pub mod routes;
pub mod ticket;

use std::fmt;
use std::sync::Arc;

use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use axum::http::{header, request::Parts, HeaderMap};
use subtle::ConstantTimeEq;

pub use config::{AuthConfig, AuthMode, OidcConfig, SecretString, UnknownAuthMode};
pub use error::{AuthConfigError, AuthError, JwksError};
pub use jwks::{HttpJwksSource, JwksSource};
pub use layer::{AuthLayer, AuthService};
pub use routes::routes;

/// Wildcard permission held by the static token and by the off-mode principal. Never granted from
/// a JWT: a `*` in token claims is discarded.
pub const ALL_PERMISSIONS: &str = "*";

/// Subject of the static machine token.
pub const STATIC_SUB: &str = "machine:static";

/// Subject used when authentication is disabled or bypassed.
pub const ANONYMOUS_SUB: &str = "anonymous";

/// How a [`Principal`] was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    /// An Auth0 access token.
    Oidc,
    /// The static machine token.
    StaticToken,
    /// No check was made: mode `off`, or a read route with `{P}AUTH_READS=false`.
    Disabled,
}

/// The authenticated caller. Handlers extract it directly; the auth layers place it in the
/// request extensions. Extraction without a layer is a 401.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Subject: the Auth0 user ID, [`STATIC_SUB`] or [`ANONYMOUS_SUB`].
    pub sub: String,
    /// Granted permissions; [`ALL_PERMISSIONS`] means every permission.
    pub permissions: Vec<String>,
    /// Whether the token shows MFA (`mfa` in `amr` or `https://nuvek.ca/amr`).
    pub mfa: bool,
    /// How the principal was established.
    pub via: Via,
}

impl Principal {
    /// True when the principal holds `permission` (or the wildcard).
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|p| p == permission || p == ALL_PERMISSIONS)
    }

    fn machine() -> Self {
        Self {
            sub: STATIC_SUB.to_string(),
            permissions: vec![ALL_PERMISSIONS.to_string()],
            mfa: false,
            via: Via::StaticToken,
        }
    }

    fn off() -> Self {
        Self {
            sub: ANONYMOUS_SUB.to_string(),
            permissions: vec![ALL_PERMISSIONS.to_string()],
            mfa: false,
            via: Via::Disabled,
        }
    }

    fn pass_through() -> Self {
        Self {
            sub: ANONYMOUS_SUB.to_string(),
            permissions: Vec::new(),
            mfa: false,
            via: Via::Disabled,
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Principal {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or(AuthError::Unauthorized("authentication required"))
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for Principal {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Principal>().cloned())
    }
}

struct Inner {
    config: AuthConfig,
    oidc: Option<(jwt::JwtValidator, jwks::JwksCache)>,
    tickets: ticket::TicketStore,
}

/// The request authenticator. Cheap to clone (an `Arc` inside); build one at start-up and hand
/// clones to the layers and [`routes()`].
#[derive(Clone)]
pub struct Authenticator {
    inner: Arc<Inner>,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticator")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    /// Validates `config` ([`AuthConfig::validate`]) and builds the authenticator, with the JWKS
    /// fetched over HTTPS from `{issuer}.well-known/jwks.json` on first use. Logs a warning when
    /// the mode is `off`.
    pub fn new(config: AuthConfig) -> Result<Self, AuthConfigError> {
        let source: Option<Arc<dyn JwksSource>> = match config.oidc() {
            Some(oidc) => Some(Arc::new(HttpJwksSource::new(oidc.jwks_url())?)),
            None => None,
        };
        Self::build(config, source)
    }

    /// Like [`Authenticator::new`] but with an injected JWKS source (tests, or a custom fetcher).
    /// The source is ignored outside the oidc modes.
    pub fn with_jwks_source(
        config: AuthConfig,
        source: Arc<dyn JwksSource>,
    ) -> Result<Self, AuthConfigError> {
        Self::build(config, Some(source))
    }

    fn build(
        config: AuthConfig,
        source: Option<Arc<dyn JwksSource>>,
    ) -> Result<Self, AuthConfigError> {
        config.validate()?;
        if config.mode() == AuthMode::Off {
            tracing::warn!(
                key = %format!("{}AUTH_MODE", config.prefix()),
                "authentication is OFF: every caller is anonymous with every permission"
            );
        }
        let oidc = match (config.oidc(), source) {
            (Some(oidc), Some(source)) => {
                Some((jwt::JwtValidator::new(oidc), jwks::JwksCache::new(source)))
            }
            _ => None,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                oidc,
                tickets: ticket::TicketStore::default(),
            }),
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &AuthConfig {
        &self.inner.config
    }

    /// The configured mode.
    pub fn mode(&self) -> AuthMode {
        self.inner.config.mode()
    }

    /// The OIDC issuer, when an oidc mode is on; feed it to [`csp::spa_policy`].
    pub fn issuer(&self) -> Option<&str> {
        self.inner.config.oidc().map(|o| o.issuer())
    }

    /// True unless the mode is `off`; export it as an `auth_enforced` gauge.
    pub fn enforced(&self) -> bool {
        self.mode() != AuthMode::Off
    }

    /// Authenticates a request from its `Authorization: Bearer …` header.
    ///
    /// - Mode `off`: always [`ANONYMOUS_SUB`] with every permission, `via = Disabled`.
    /// - The static token (token modes) is checked first, in constant time, and yields
    ///   [`STATIC_SUB`] with every permission. It never contacts Auth0.
    /// - Otherwise, in the oidc modes, the bearer is validated as an RS256 access token.
    ///
    /// Errors: 401 for a missing or invalid credential, 403 for a disallowed subject or a missing
    /// `{P}REQUIRED_PERMISSION` or `{P}REQUIRE_PASSKEY` assurance, 503 when the JWKS is unavailable.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, AuthError> {
        let config = &self.inner.config;
        if config.mode() == AuthMode::Off {
            return Ok(Principal::off());
        }
        let token = bearer(headers).ok_or(AuthError::Unauthorized("missing bearer token"))?;

        if config.mode().accepts_token() {
            // Compare SHA-256 digests in constant time, so neither the content nor the length of
            // the configured token leaks, and evaluate every token so timing does not reveal
            // which one matched.
            let presented = sha256(token.as_bytes());
            let matched = config
                .api_tokens()
                .fold(subtle::Choice::from(0u8), |acc, t| {
                    acc | sha256(t.expose_secret().as_bytes())[..].ct_eq(&presented[..])
                });
            if bool::from(matched) {
                return Ok(Principal::machine());
            }
        }

        match (config.oidc(), &self.inner.oidc) {
            (Some(oidc), Some((validator, jwks))) => validator.validate(token, oidc, jwks).await,
            _ => Err(AuthError::Unauthorized("invalid token")),
        }
    }

    /// Checks the request `Origin` header against `{P}PUBLIC_ORIGIN`, exactly. Use it on
    /// WebSocket upgrades. Passes in mode `off` when no origin is configured. A missing or
    /// different origin is a 403.
    pub fn check_origin(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        let Some(expected) = self.inner.config.public_origin() else {
            return if self.enforced() {
                Err(AuthError::Forbidden("origin not allowed"))
            } else {
                Ok(())
            };
        };
        match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            Some(origin) if origin == expected => Ok(()),
            _ => Err(AuthError::Forbidden("origin not allowed")),
        }
    }

    /// Issues a single-use ticket bound to `principal`, valid for [`ticket::TICKET_TTL`].
    pub async fn issue_ticket(&self, principal: Principal) -> Result<String, AuthError> {
        self.inner.tickets.issue(principal).await
    }

    /// Consumes a ticket and returns the principal it was issued to, if it is still valid.
    pub async fn redeem_ticket(&self, ticket: &str) -> Option<Principal> {
        self.inner.tickets.redeem(ticket).await
    }

    /// Layer for read routes: any valid principal. With `{P}AUTH_READS=false` it lets every
    /// request through as an anonymous principal with no permissions (`via = Disabled`).
    pub fn require_user(&self) -> AuthLayer {
        AuthLayer::new(self.clone(), layer::Policy::User)
    }

    /// Like [`Authenticator::require_user`], but a request without an `Authorization` header may
    /// instead present `?ticket=` (WebSocket, EventSource, plain links).
    pub fn require_user_or_ticket(&self) -> AuthLayer {
        AuthLayer::new(self.clone(), layer::Policy::UserOrTicket)
    }

    /// Layer for mutations: a valid principal holding `permission`. 403 when authenticated but
    /// lacking. Every success emits an audit event on the `nuvek_auth::audit` target.
    ///
    /// `{P}REQUIRE_MFA` is enforced here and only here, and only for Auth0 principals
    /// ([`Via::Oidc`]): such a principal also needs `mfa` in `amr` or `https://nuvek.ca/amr`.
    /// The static machine token is exempt (it has no interactive login), and read routes behind
    /// [`Authenticator::require_user`] never check MFA.
    pub fn require_permission(&self, permission: impl Into<String>) -> AuthLayer {
        AuthLayer::new(
            self.clone(),
            layer::Policy::Permission(Arc::from(permission.into())),
        )
    }

    pub(crate) fn pass_through_reads(&self) -> Option<Principal> {
        match self.mode() {
            AuthMode::Off => Some(Principal::off()),
            _ if !self.inner.config.auth_reads() => Some(Principal::pass_through()),
            _ => None,
        }
    }

    pub(crate) fn require_mfa(&self) -> bool {
        self.inner.config.oidc().is_some_and(|o| o.require_mfa())
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Extracts a bearer token; the scheme is matched case-insensitively.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}
