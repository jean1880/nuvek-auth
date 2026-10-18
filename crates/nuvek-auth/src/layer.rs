//! Tower layers that enforce a route class: [`AuthLayer`] and its [`AuthService`].
//!
//! Build them with [`Authenticator::require_user`], [`Authenticator::require_user_or_ticket`] and
//! [`Authenticator::require_permission`], then apply with `Router::layer` or `route_layer`. On
//! success the [`Principal`] is inserted into the request extensions; on failure the
//! [`AuthError`] JSON response is returned and the inner service is never called.

use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::{header, request::Parts};
use axum::response::{IntoResponse, Response};
use tower::{Layer, Service};

use crate::error::AuthError;
use crate::jwks::BoxFuture;
use crate::ticket::ticket_from_query;
use crate::{Authenticator, Principal, Via};

/// Which route class a layer enforces.
#[derive(Debug, Clone)]
pub(crate) enum Policy {
    User,
    UserOrTicket,
    Permission(Arc<str>),
}

/// A layer enforcing one route class. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AuthLayer {
    auth: Authenticator,
    policy: Policy,
}

impl AuthLayer {
    pub(crate) fn new(auth: Authenticator, policy: Policy) -> Self {
        Self { auth, policy }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            auth: self.auth.clone(),
            policy: self.policy.clone(),
        }
    }
}

/// The service produced by [`AuthLayer`].
#[derive(Debug, Clone)]
pub struct AuthService<S> {
    inner: S,
    auth: Authenticator,
    policy: Policy,
}

impl<S> Service<Request> for AuthService<S>
where
    S: Service<Request, Error = Infallible> + Clone + Send + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // Take the service that was driven to readiness; leave a fresh clone in its place.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let auth = self.auth.clone();
        let policy = self.policy.clone();
        Box::pin(async move {
            // The body is not `Sync`; hold only the head across the await.
            let (mut parts, body) = req.into_parts();
            match authorise(&auth, &policy, &parts).await {
                Ok(principal) => {
                    parts.extensions.insert(principal);
                    let req = Request::from_parts(parts, body);
                    inner.call(req).await.map(IntoResponse::into_response)
                }
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}

async fn authorise(
    auth: &Authenticator,
    policy: &Policy,
    req: &Parts,
) -> Result<Principal, AuthError> {
    match policy {
        Policy::User => match auth.pass_through_reads() {
            Some(p) => Ok(p),
            None => auth.authenticate(&req.headers).await,
        },
        Policy::UserOrTicket => {
            if let Some(p) = auth.pass_through_reads() {
                return Ok(p);
            }
            if req.headers.contains_key(header::AUTHORIZATION) {
                return auth.authenticate(&req.headers).await;
            }
            match ticket_from_query(req.uri.query()) {
                Some(t) => auth
                    .redeem_ticket(t)
                    .await
                    .ok_or(AuthError::Unauthorized("invalid or expired ticket")),
                None => Err(AuthError::Unauthorized("missing bearer token or ticket")),
            }
        }
        Policy::Permission(permission) => {
            let principal = auth.authenticate(&req.headers).await?;
            if !principal.has_permission(permission) {
                return Err(AuthError::Forbidden("missing permission"));
            }
            if auth.require_mfa() && principal.via == Via::Oidc && !principal.mfa {
                return Err(AuthError::Forbidden("multi-factor authentication required"));
            }
            tracing::info!(
                target: "nuvek_auth::audit",
                actor = %principal.sub,
                via = ?principal.via,
                method = %req.method,
                path = %req.uri.path(),
                permission = %permission,
                "authorised"
            );
            Ok(principal)
        }
    }
}
