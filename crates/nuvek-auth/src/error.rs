//! Error types: start-up configuration errors, request authentication errors and JWKS fetch errors.
//!
//! None of these ever carries a secret. Configuration errors name the environment KEY only, never
//! its value.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// A configuration error raised at start-up. The process should exit non-zero and print it; the
/// message names the offending environment key, never its value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthConfigError {
    /// A required key is unset (or empty).
    #[error("{key} is required but not set")]
    Missing {
        /// Full environment key, prefix included (e.g. `DEB_AUTH_MODE`).
        key: String,
    },

    /// A key is set but its value is not acceptable. The value itself is never included.
    #[error("{key} is invalid: {reason}")]
    Invalid {
        /// Full environment key, prefix included.
        key: String,
        /// Why the value was rejected, in terms that never echo the value.
        reason: &'static str,
    },

    /// The OIDC modes need at least one of two authorisation keys, and neither is set.
    #[error("{first} or {second} is required in the oidc modes; neither is set")]
    MissingOneOf {
        /// First acceptable key (e.g. `DEB_ALLOWED_SUBS`).
        first: String,
        /// Second acceptable key (e.g. `DEB_REQUIRED_PERMISSION`).
        second: String,
    },

    /// The HTTP client used to fetch the JWKS could not be built.
    #[error("cannot build the JWKS HTTP client: {0}")]
    HttpClient(String),
}

/// A per-request authentication or authorisation failure. Renders as
/// `{"error": "UNAUTHORIZED"|"FORBIDDEN"|"TOO_MANY"|"AUTH_UNAVAILABLE", "message": "…"}` with
/// status 401, 403, 429 or 503, matching the debian-maintainer `ApiError` shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// No valid credential was presented (401).
    #[error("{0}")]
    Unauthorized(&'static str),

    /// A valid credential was presented but it lacks a permission, MFA, an allowlisted subject or
    /// a matching `Origin` (403).
    #[error("{0}")]
    Forbidden(&'static str),

    /// The caller holds too many outstanding tickets (429).
    #[error("{0}")]
    TooManyRequests(&'static str),

    /// The token could not be checked because the JWKS is unreachable and no static token matched
    /// (503).
    #[error("{0}")]
    Unavailable(&'static str),
}

impl AuthError {
    /// The HTTP status this error renders with.
    pub fn status(&self) -> StatusCode {
        match self {
            AuthError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
            AuthError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            AuthError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The stable machine-readable code placed in the `error` field of the JSON body.
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::Unauthorized(_) => "UNAUTHORIZED",
            AuthError::Forbidden(_) => "FORBIDDEN",
            AuthError::TooManyRequests(_) => "TOO_MANY",
            AuthError::Unavailable(_) => "AUTH_UNAVAILABLE",
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = Json(json!({ "error": self.code(), "message": self.to_string() }));
        let mut resp = (self.status(), body).into_response();
        if matches!(self, AuthError::Unauthorized(_)) {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

/// A failure to obtain or parse the JWKS document. Carries no secret: the JWKS URL is public.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwksError {
    /// The request could not be sent or the body could not be read.
    #[error("JWKS request failed: {0}")]
    Request(String),

    /// The server answered with a non-success status.
    #[error("JWKS request returned HTTP {0}")]
    Status(u16),

    /// The body exceeded the size cap.
    #[error("JWKS response is too large")]
    TooLarge,

    /// The body is not a JWKS document.
    #[error("JWKS document is malformed: {0}")]
    Parse(String),

    /// The document parsed but contains no usable RS256 signing key.
    #[error("JWKS document contains no usable RS256 key")]
    NoUsableKeys,
}
