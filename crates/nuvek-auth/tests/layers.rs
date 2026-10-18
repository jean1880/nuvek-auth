//! Route layers, tickets, origin check and the auth router. Static-token and off mode only, so no
//! keypair is needed here.

mod common;

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::{
    routing::{get, post},
    Router,
};
use common::*;
use nuvek_auth::{AuthError, Authenticator, Principal, Via, ANONYMOUS_SUB};
use tower::ServiceExt;

fn token_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("AUTH_MODE", "token"),
        ("API_TOKEN", STATIC_TOKEN),
        ("PUBLIC_ORIGIN", ORIGIN),
    ]
}

fn auth_from(env: &[(&str, &str)]) -> Authenticator {
    Authenticator::new(config(env).expect("config")).expect("authenticator")
}

fn who(p: Principal) -> String {
    format!("{}|{:?}|{}", p.sub, p.via, p.permissions.join(","))
}

fn app(auth: &Authenticator) -> Router {
    let reads = Router::new()
        .route("/api/status", get(|p: Principal| async move { who(p) }))
        .layer(auth.require_user());
    let streams = Router::new()
        .route("/api/ws", get(|p: Principal| async move { who(p) }))
        .layer(auth.require_user_or_ticket());
    let writes = Router::new()
        .route("/api/force", post(|p: Principal| async move { who(p) }))
        .layer(auth.require_permission("deb:write"));
    Router::new()
        .merge(nuvek_auth::routes(auth.clone()))
        .merge(reads)
        .merge(streams)
        .merge(writes)
        .route("/unguarded", get(|p: Principal| async move { who(p) }))
}

async fn text(resp: axum::http::Response<axum::body::Body>) -> String {
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn issue_ticket(app: &Router, token: &str) -> String {
    let resp = app
        .clone()
        .oneshot(request("POST", "/api/auth/ticket", Some(token)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("cache-control"),
        Some(&HeaderValue::from_static("no-store"))
    );
    let body = body_json(resp).await;
    assert_eq!(body["expires_in"], 30);
    let ticket = body["ticket"].as_str().expect("ticket").to_string();
    assert_eq!(ticket.len(), 43, "32 bytes, base64url without padding");
    ticket
}

#[tokio::test]
async fn static_token_and_next_token_are_accepted() {
    let auth = auth_from(&with(token_env(), "API_TOKEN_NEXT", NEXT_TOKEN));
    for t in [STATIC_TOKEN, NEXT_TOKEN] {
        let p = auth.authenticate(&bearer_headers(t)).await.expect("token");
        assert_eq!(p.via, Via::StaticToken);
    }
    assert!(matches!(
        auth.authenticate(&bearer_headers("wrong")).await,
        Err(AuthError::Unauthorized(_))
    ));
    assert!(matches!(
        auth.authenticate(&HeaderMap::new()).await,
        Err(AuthError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn legacy_fallback_token_authenticates() {
    let env = [("AUTH_MODE", "token"), ("PUBLIC_ORIGIN", ORIGIN)];
    let cfg = config(&env)
        .expect("config")
        .with_api_token(Some(STATIC_TOKEN.into()));
    let auth = Authenticator::new(cfg).expect("authenticator");
    assert!(auth
        .authenticate(&bearer_headers(STATIC_TOKEN))
        .await
        .is_ok());

    // The prefixed env var wins over the legacy source.
    let cfg = config(&token_env())
        .expect("config")
        .with_api_token(Some(NEXT_TOKEN.into()));
    let auth = Authenticator::new(cfg).expect("authenticator");
    assert!(auth
        .authenticate(&bearer_headers(NEXT_TOKEN))
        .await
        .is_err());
}

#[tokio::test]
async fn route_classes() {
    let app = app(&auth_from(&token_env()));
    for (method, path) in [
        ("GET", "/api/status"),
        ("GET", "/api/ws"),
        ("POST", "/api/force"),
    ] {
        let resp = app
            .clone()
            .oneshot(request(method, path, None))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        let resp = app
            .clone()
            .oneshot(request(method, path, Some(STATIC_TOKEN)))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        assert_eq!(text(resp).await, "machine:static|StaticToken|*");
    }
    // A handler extracting Principal without any layer is a 401, never an open door.
    let resp = app
        .oneshot(request("GET", "/unguarded", Some(STATIC_TOKEN)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ticket_is_single_use() {
    let app = app(&auth_from(&token_env()));
    let ticket = issue_ticket(&app, STATIC_TOKEN).await;
    let uri = format!("/api/ws?x=1&ticket={ticket}");

    let resp = app
        .clone()
        .oneshot(request("GET", &uri, None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        text(resp).await,
        "machine:static|StaticToken|*",
        "bound to the issuing principal"
    );

    let resp = app
        .clone()
        .oneshot(request("GET", &uri, None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "second use fails");

    // Tickets are not accepted on header-only routes.
    let ticket = issue_ticket(&app, STATIC_TOKEN).await;
    let resp = app
        .oneshot(request(
            "GET",
            &format!("/api/status?ticket={ticket}"),
            None,
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(start_paused = true)]
async fn ticket_expires_after_30s() {
    let app = app(&auth_from(&token_env()));
    let ticket = issue_ticket(&app, STATIC_TOKEN).await;
    tokio::time::advance(Duration::from_secs(31)).await;
    let resp = app
        .clone()
        .oneshot(request("GET", &format!("/api/ws?ticket={ticket}"), None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let ticket = issue_ticket(&app, STATIC_TOKEN).await;
    tokio::time::advance(Duration::from_secs(29)).await;
    let resp = app
        .oneshot(request("GET", &format!("/api/ws?ticket={ticket}"), None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn ticket_cap_per_sub_is_429() {
    let auth = auth_from(&token_env());
    let app = app(&auth);
    for _ in 0..nuvek_auth::ticket::MAX_PER_SUB {
        issue_ticket(&app, STATIC_TOKEN).await;
    }
    let resp = app
        .clone()
        .oneshot(request("POST", "/api/auth/ticket", Some(STATIC_TOKEN)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "TOO_MANY");
    assert!(body["message"].is_string());

    // Another subject is unaffected.
    let other = Principal {
        sub: "auth0|bob".into(),
        permissions: vec![],
        mfa: false,
        via: Via::Oidc,
    };
    assert!(auth.issue_ticket(other).await.is_ok());

    // Once the tickets expire, the subject can get new ones.
    tokio::time::advance(Duration::from_secs(31)).await;
    issue_ticket(&app, STATIC_TOKEN).await;
}

#[test]
fn test_tokens_meet_the_minimum_length() {
    assert!(STATIC_TOKEN.len() >= nuvek_auth::config::MIN_TOKEN_LEN);
    assert!(NEXT_TOKEN.len() >= nuvek_auth::config::MIN_TOKEN_LEN);
}

#[tokio::test]
async fn ticket_endpoint_requires_a_user() {
    let app = app(&auth_from(&token_env()));
    let resp = app
        .oneshot(request("POST", "/api/auth/ticket", None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forged_ticket_is_rejected() {
    let app = app(&auth_from(&token_env()));
    for q in ["ticket=", "ticket=AAAA", "ticket=%27%3B"] {
        let resp = app
            .clone()
            .oneshot(request("GET", &format!("/api/ws?{q}"), None))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{q}");
    }
}

#[test]
fn origin_check_is_exact() {
    let auth = auth_from(&token_env());
    let mut h = HeaderMap::new();
    assert!(
        matches!(auth.check_origin(&h), Err(AuthError::Forbidden(_))),
        "missing origin"
    );
    for bad in [
        "https://evil.example",
        "https://app.test.example/",
        "http://app.test.example",
        "https://app.test.example.evil.example",
        "null",
    ] {
        h.insert("origin", HeaderValue::from_static(bad));
        assert!(
            matches!(auth.check_origin(&h), Err(AuthError::Forbidden(_))),
            "{bad}"
        );
    }
    h.insert("origin", HeaderValue::from_static(ORIGIN));
    assert!(auth.check_origin(&h).is_ok());
}

#[tokio::test]
async fn reads_pass_through_when_not_gated() {
    let auth = auth_from(&with(token_env(), "AUTH_READS", "false"));
    let app = app(&auth);
    let resp = app
        .clone()
        .oneshot(request("GET", "/api/status", None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(text(resp).await, format!("{ANONYMOUS_SUB}|Disabled|"));
    // Writes stay protected.
    let resp = app
        .oneshot(request("POST", "/api/force", None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn off_mode_is_anonymous_with_every_permission() {
    let auth = auth_from(&[("AUTH_MODE", "off")]);
    assert!(!auth.enforced());
    assert!(auth.check_origin(&HeaderMap::new()).is_ok());
    let resp = app(&auth)
        .oneshot(request("POST", "/api/force", None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(text(resp).await, format!("{ANONYMOUS_SUB}|Disabled|*"));
}

#[tokio::test]
async fn config_endpoint_is_public() {
    let resp = app(&auth_from(&token_env()))
        .oneshot(request("GET", "/api/auth/config", None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["mode"], "token");
    for k in ["issuer", "domain", "client_id", "audience", "permission"] {
        assert!(body[k].is_null(), "{k}");
    }

    let auth = Authenticator::with_jwks_source(
        config(&oidc_token_env()).expect("config"),
        TestSource::down(),
    )
    .expect("authenticator");
    let resp = app(&auth)
        .oneshot(request("GET", "/api/auth/config", None))
        .await
        .expect("response");
    let body = body_json(resp).await;
    assert_eq!(body["mode"], "oidc+token");
    assert_eq!(body["issuer"], ISSUER);
    assert_eq!(body["domain"], "tenant.test.example");
    assert_eq!(body["client_id"], CLIENT_ID);
    assert_eq!(body["audience"], AUDIENCE);
    assert_eq!(body["permission"], "deb:write");
    assert!(!body.to_string().contains(STATIC_TOKEN));
}
