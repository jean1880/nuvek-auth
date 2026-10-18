//! The auth endpoints every adopting app mounts: `GET /api/auth/config` and
//! `POST /api/auth/ticket`.

use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

use crate::error::AuthError;
use crate::ticket::TICKET_TTL;
use crate::{Authenticator, Principal};

/// Body of `GET /api/auth/config`. Every value is public. The OIDC fields are `null` in the
/// `token` and `off` modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicAuthConfig {
    /// `off`, `token`, `oidc` or `oidc+token`.
    pub mode: &'static str,
    /// Issuer URL (`https://tenant/`).
    pub issuer: Option<String>,
    /// Issuer host, as the Auth0 SPA SDK wants it.
    pub domain: Option<String>,
    /// Public SPA client ID.
    pub client_id: Option<String>,
    /// API audience to request.
    pub audience: Option<String>,
    /// `{P}REQUIRED_PERMISSION`, if set.
    pub permission: Option<String>,
}

impl PublicAuthConfig {
    /// Builds the public view of an authenticator's configuration.
    pub fn from_authenticator(auth: &Authenticator) -> Self {
        let oidc = auth.config().oidc();
        Self {
            mode: auth.mode().as_str(),
            issuer: oidc.map(|o| o.issuer().to_string()),
            domain: oidc.map(|o| o.domain().to_string()),
            client_id: oidc.map(|o| o.client_id().to_string()),
            audience: oidc.map(|o| o.audience().to_string()),
            permission: oidc.and_then(|o| o.required_permission().map(str::to_string)),
        }
    }
}

/// Body of `POST /api/auth/ticket`. Its `Debug` redacts the ticket.
#[derive(Clone, Serialize)]
pub struct TicketResponse {
    /// The single-use ticket, to pass as `?ticket=`.
    pub ticket: String,
    /// Seconds until it expires (30).
    pub expires_in: u64,
}

impl std::fmt::Debug for TicketResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketResponse")
            .field("ticket", &"****")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// The auth router:
/// - `GET /api/auth/config` (public): [`PublicAuthConfig`].
/// - `POST /api/auth/ticket` (behind [`Authenticator::require_user`]): [`TicketResponse`].
///
/// Both responses carry `Cache-Control: no-store`. Merge it into the app router; it works with any
/// app state type.
pub fn routes<S>(auth: Authenticator) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let ticket_layer = auth.require_user();
    Router::new()
        .route("/api/auth/config", get(config_handler))
        .route(
            "/api/auth/ticket",
            post(ticket_handler).route_layer(ticket_layer),
        )
        .with_state(auth)
}

async fn config_handler(State(auth): State<Authenticator>) -> Response {
    no_store(Json(PublicAuthConfig::from_authenticator(&auth)).into_response())
}

async fn ticket_handler(
    State(auth): State<Authenticator>,
    principal: Principal,
) -> Result<Response, AuthError> {
    let ticket = auth.issue_ticket(principal).await?;
    let body = TicketResponse {
        ticket,
        expires_in: TICKET_TTL.as_secs(),
    };
    Ok(no_store(Json(body).into_response()))
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
