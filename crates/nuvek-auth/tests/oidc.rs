//! RS256 access-token validation, JWKS caching and outage behaviour, permission/MFA layers.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::{routing::post, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use nuvek_auth::{AuthError, Principal, Via, STATIC_SUB};
use serde_json::json;
use tower::ServiceExt;

fn oidc_auth() -> (nuvek_auth::Authenticator, Arc<TestSource>) {
    let source = TestSource::ok(&["k1"]);
    (authenticator(&oidc_token_env(), source.clone()), source)
}

#[tokio::test]
async fn valid_token_yields_principal() {
    let (auth, _) = oidc_auth();
    let token = mint(
        &claims(json!({"amr": ["pwd", "mfa"], "scope": "openid read:x"})),
        "k1",
    );
    let p = auth
        .authenticate(&bearer_headers(&token))
        .await
        .expect("valid token");
    assert_eq!(p.sub, "auth0|alice");
    assert_eq!(p.via, Via::Oidc);
    assert!(p.mfa);
    assert!(p.has_permission("deb:write"));
    assert!(!p.has_permission("read:x"), "scope is never a permission");
    assert!(!p.has_permission("other"));
}

#[tokio::test]
async fn scope_never_grants_permissions() {
    // A required-permission gate would reject this token outright, so use a subject allowlist
    // and check the permission layer instead.
    let env = with(
        without(oidc_token_env(), "REQUIRED_PERMISSION"),
        "ALLOWED_SUBS",
        "auth0|alice",
    );
    let auth = authenticator(&env, TestSource::ok(&["k1"]));
    let mut c = claims(json!({"scope": "openid deb:write"}));
    if let Some(o) = c.as_object_mut() {
        o.remove("permissions");
    }
    let token = mint(&c, "k1");
    let p = auth
        .authenticate(&bearer_headers(&token))
        .await
        .expect("valid token");
    assert!(p.permissions.is_empty());
    assert!(!p.has_permission("deb:write"));
    let resp = write_app(&auth)
        .oneshot(request("POST", "/api/force", Some(&token)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // With REQUIRED_PERMISSION set, a scope-only token is refused at authentication.
    let (auth, _) = oidc_auth();
    assert!(matches!(
        auth.authenticate(&bearer_headers(&token)).await,
        Err(AuthError::Forbidden(_))
    ));
}

#[tokio::test]
async fn future_nbf_is_401() {
    let (auth, _) = oidc_auth();
    let token = mint(&claims(json!({"nbf": now() + 3600})), "k1");
    assert_eq!(
        auth.authenticate(&bearer_headers(&token)).await,
        Err(AuthError::Unauthorized("access token not yet valid"))
    );
}

#[tokio::test]
async fn token_without_kid_is_401() {
    let (auth, source) = oidc_auth();
    let header = Header::new(Algorithm::RS256);
    let token = jsonwebtoken::encode(&header, &claims(json!({})), &keys().encoding).expect("sign");
    assert_eq!(
        auth.authenticate(&bearer_headers(&token)).await,
        Err(AuthError::Unauthorized("access token has no key id"))
    );
    assert_eq!(source.count(), 0, "no JWKS fetch for a kid-less token");
}

#[tokio::test(start_paused = true)]
async fn key_set_older_than_10_min_is_refreshed_so_revoked_keys_stop_working() {
    let (auth, source) = oidc_auth();
    let k1 = mint(&claims(json!({})), "k1");
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_ok());

    // Upstream revokes k1 (rotates to k2 only).
    source.set(Ok(jwks_doc(&["k2"])));
    tokio::time::advance(Duration::from_secs(9 * 60)).await;
    assert!(
        auth.authenticate(&bearer_headers(&k1)).await.is_ok(),
        "still fresh"
    );
    assert_eq!(source.count(), 1);

    tokio::time::advance(Duration::from_secs(61)).await;
    assert_eq!(
        auth.authenticate(&bearer_headers(&k1)).await,
        Err(AuthError::Unauthorized("unknown signing key"))
    );
    assert_eq!(source.count(), 2, "one refresh once the set is 10 min old");
    let k2 = mint(&claims(json!({})), "k2");
    assert!(auth.authenticate(&bearer_headers(&k2)).await.is_ok());
    assert_eq!(source.count(), 2);
}

#[tokio::test(start_paused = true)]
async fn stale_key_set_is_used_for_at_most_24h_during_an_outage() {
    let (auth, source) = oidc_auth();
    let k1 = mint(&claims(json!({})), "k1");
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_ok());

    source.set(Err(nuvek_auth::JwksError::Status(502)));
    tokio::time::advance(Duration::from_secs(11 * 60)).await;
    assert!(
        auth.authenticate(&bearer_headers(&k1)).await.is_ok(),
        "refresh failed, last good set kept"
    );
    assert_eq!(source.count(), 2);

    // Only tokio's clock is paused; token `exp` uses wall time, so the token itself stays valid.
    tokio::time::advance(Duration::from_secs(24 * 60 * 60)).await;
    let k1 = mint(&claims(json!({})), "k1");
    let err = auth
        .authenticate(&bearer_headers(&k1))
        .await
        .expect_err("past the stale cap");
    assert_eq!(err.code(), "AUTH_UNAVAILABLE");

    // Recovery: the next successful fetch restores OIDC.
    source.set(Ok(jwks_doc(&["k1"])));
    tokio::time::advance(Duration::from_secs(61)).await;
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn cold_start_failure_retries_after_5s() {
    let source = TestSource::down();
    let auth = authenticator(&oidc_token_env(), source.clone());
    let k1 = mint(&claims(json!({})), "k1");
    assert_eq!(
        auth.authenticate(&bearer_headers(&k1))
            .await
            .map_err(|e| e.code()),
        Err("AUTH_UNAVAILABLE")
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_err());
    assert_eq!(source.count(), 1, "rate-limited inside the cold window");

    source.set(Ok(jwks_doc(&["k1"])));
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_ok());
    assert_eq!(source.count(), 2, "retried after 5 s, not 60 s");
}

#[tokio::test]
async fn namespaced_amr_counts_as_mfa() {
    let (auth, _) = oidc_auth();
    let token = mint(&claims(json!({"https://nuvek.ca/amr": "mfa"})), "k1");
    let p = auth
        .authenticate(&bearer_headers(&token))
        .await
        .expect("valid token");
    assert!(p.mfa);
}

#[tokio::test]
async fn wildcard_permission_from_jwt_is_discarded() {
    let (auth, _) = oidc_auth();
    let token = mint(&claims(json!({"permissions": ["deb:write", "*"]})), "k1");
    let p = auth
        .authenticate(&bearer_headers(&token))
        .await
        .expect("valid token");
    assert!(!p.has_permission("anything-else"));
}

#[tokio::test]
async fn alg_none_is_rejected() {
    let (auth, _) = oidc_auth();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT","kid":"k1"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims(json!({}))).expect("json"));
    let token = format!("{header}.{payload}.");
    let err = auth.authenticate(&bearer_headers(&token)).await;
    assert!(matches!(err, Err(AuthError::Unauthorized(_))), "{err:?}");
}

#[tokio::test]
async fn hs256_is_rejected_even_keyed_with_the_public_key() {
    let (auth, _) = oidc_auth();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k1".into());
    // Classic key-confusion attempt: HMAC keyed with the public modulus.
    let key = EncodingKey::from_secret(keys().n.as_bytes());
    let token = jsonwebtoken::encode(&header, &claims(json!({})), &key).expect("sign");
    let err = auth.authenticate(&bearer_headers(&token)).await;
    assert!(matches!(err, Err(AuthError::Unauthorized(_))), "{err:?}");
}

#[tokio::test]
async fn wrong_issuer_and_audience_are_rejected() {
    let (auth, _) = oidc_auth();
    for extra in [
        json!({"iss": "https://evil.example/"}),
        json!({"iss": "https://tenant.test.example"}),
        json!({"aud": "https://other.example/api"}),
    ] {
        let token = mint(&claims(extra.clone()), "k1");
        let err = auth.authenticate(&bearer_headers(&token)).await;
        assert!(
            matches!(err, Err(AuthError::Unauthorized(_))),
            "{extra}: {err:?}"
        );
    }
}

#[tokio::test]
async fn expired_is_rejected_but_leeway_is_honoured() {
    let (auth, _) = oidc_auth();
    let expired = mint(&claims(json!({"exp": now() - 3600})), "k1");
    assert_eq!(
        auth.authenticate(&bearer_headers(&expired)).await,
        Err(AuthError::Unauthorized("access token expired"))
    );
    let in_leeway = mint(&claims(json!({"exp": now() - 30})), "k1");
    assert!(auth.authenticate(&bearer_headers(&in_leeway)).await.is_ok());
    let future_nbf = mint(&claims(json!({"nbf": now() + 3600})), "k1");
    assert!(matches!(
        auth.authenticate(&bearer_headers(&future_nbf)).await,
        Err(AuthError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn missing_sub_or_exp_is_rejected() {
    let (auth, _) = oidc_auth();
    let mut c = claims(json!({}));
    if let Some(o) = c.as_object_mut() {
        o.remove("sub");
    }
    assert!(matches!(
        auth.authenticate(&bearer_headers(&mint(&c, "k1"))).await,
        Err(AuthError::Unauthorized(_))
    ));
    let mut c = claims(json!({}));
    if let Some(o) = c.as_object_mut() {
        o.remove("exp");
    }
    assert!(matches!(
        auth.authenticate(&bearer_headers(&mint(&c, "k1"))).await,
        Err(AuthError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn required_permission_and_allowed_subs_are_403() {
    let (auth, _) = oidc_auth();
    let token = mint(&claims(json!({"permissions": []})), "k1");
    assert!(matches!(
        auth.authenticate(&bearer_headers(&token)).await,
        Err(AuthError::Forbidden(_))
    ));

    let env = with(
        without(oidc_token_env(), "REQUIRED_PERMISSION"),
        "ALLOWED_SUBS",
        "auth0|bob",
    );
    let auth = authenticator(&env, TestSource::ok(&["k1"]));
    let alice = mint(&claims(json!({})), "k1");
    assert_eq!(
        auth.authenticate(&bearer_headers(&alice)).await,
        Err(AuthError::Forbidden("subject is not allowed"))
    );
    let bob = mint(&claims(json!({"sub": "auth0|bob"})), "k1");
    assert!(auth.authenticate(&bearer_headers(&bob)).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn jwks_is_lazy_and_unknown_kid_refetch_is_rate_limited() {
    let (auth, source) = oidc_auth();
    assert_eq!(source.count(), 0, "start-up does not fetch");

    let k1 = mint(&claims(json!({})), "k1");
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_ok());
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_ok());
    assert_eq!(source.count(), 1, "known kid is served from cache");

    // The tenant rotates to k2, but the cache was filled less than 60 s ago.
    source.set(Ok(jwks_doc(&["k1", "k2"])));
    let k2 = mint(&claims(json!({})), "k2");
    tokio::time::advance(Duration::from_secs(10)).await;
    for _ in 0..5 {
        assert_eq!(
            auth.authenticate(&bearer_headers(&k2)).await,
            Err(AuthError::Unauthorized("unknown signing key"))
        );
    }
    assert_eq!(source.count(), 1, "no refetch inside the 60 s window");

    tokio::time::advance(Duration::from_secs(51)).await;
    assert!(auth.authenticate(&bearer_headers(&k2)).await.is_ok());
    assert_eq!(source.count(), 2, "exactly one refetch after the window");

    let k3 = mint(&claims(json!({})), "k3");
    assert!(auth.authenticate(&bearer_headers(&k3)).await.is_err());
    assert_eq!(source.count(), 2);
}

#[tokio::test]
async fn jwks_outage_is_503_but_static_token_still_works() {
    let source = TestSource::down();
    let auth = authenticator(&oidc_token_env(), source.clone());
    let token = mint(&claims(json!({})), "k1");
    let err = auth
        .authenticate(&bearer_headers(&token))
        .await
        .expect_err("JWKS down");
    assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(err.code(), "AUTH_UNAVAILABLE");

    let p = auth
        .authenticate(&bearer_headers(STATIC_TOKEN))
        .await
        .expect("static token works without Auth0");
    assert_eq!(p.sub, STATIC_SUB);
    assert_eq!(p.via, Via::StaticToken);
    assert!(p.has_permission("deb:write"));
    assert_eq!(source.count(), 1, "the static token never touches the JWKS");
}

#[tokio::test(start_paused = true)]
async fn last_good_key_set_survives_an_outage() {
    let (auth, source) = oidc_auth();
    let k1 = mint(&claims(json!({})), "k1");
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_ok());

    source.set(Err(nuvek_auth::JwksError::Status(500)));
    tokio::time::advance(Duration::from_secs(61)).await;
    let k2 = mint(&claims(json!({})), "k2");
    let err = auth
        .authenticate(&bearer_headers(&k2))
        .await
        .expect_err("unknown kid during outage");
    assert_eq!(err.code(), "AUTH_UNAVAILABLE");
    assert_eq!(source.count(), 2);
    assert!(
        auth.authenticate(&bearer_headers(&k1)).await.is_ok(),
        "cached key keeps working"
    );
}

#[tokio::test]
async fn token_only_mode_rejects_jwts() {
    let env = [
        ("AUTH_MODE", "token"),
        ("API_TOKEN", STATIC_TOKEN),
        ("PUBLIC_ORIGIN", ORIGIN),
    ];
    let source = TestSource::ok(&["k1"]);
    let auth = authenticator(&env, source.clone());
    let token = mint(&claims(json!({})), "k1");
    assert!(matches!(
        auth.authenticate(&bearer_headers(&token)).await,
        Err(AuthError::Unauthorized(_))
    ));
    assert_eq!(source.count(), 0);
}

#[tokio::test]
async fn oidc_only_mode_ignores_static_token() {
    let env = with(oidc_token_env(), "AUTH_MODE", "oidc");
    let auth = authenticator(&env, TestSource::ok(&["k1"]));
    assert!(matches!(
        auth.authenticate(&bearer_headers(STATIC_TOKEN)).await,
        Err(AuthError::Unauthorized(_))
    ));
}

fn write_app(auth: &nuvek_auth::Authenticator) -> Router {
    Router::new()
        .route(
            "/api/force",
            post(|p: Principal| async move { format!("{}:{:?}", p.sub, p.via) }),
        )
        .layer(auth.require_permission("deb:write"))
}

#[tokio::test]
async fn require_permission_enforces_permission_and_mfa() {
    let env = with(oidc_token_env(), "REQUIRE_MFA", "true");
    let env = with(
        without(env, "REQUIRED_PERMISSION"),
        "ALLOWED_SUBS",
        "auth0|alice",
    );
    let auth = authenticator(&env, TestSource::ok(&["k1"]));
    let app = write_app(&auth);

    let no_perm = mint(&claims(json!({"permissions": [], "amr": ["mfa"]})), "k1");
    let resp = app
        .clone()
        .oneshot(request("POST", "/api/force", Some(&no_perm)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["error"], "FORBIDDEN");

    let no_mfa = mint(&claims(json!({})), "k1");
    let resp = app
        .clone()
        .oneshot(request("POST", "/api/force", Some(&no_mfa)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await["message"],
        "multi-factor authentication required"
    );

    let good = mint(&claims(json!({"amr": ["mfa"]})), "k1");
    let resp = app
        .clone()
        .oneshot(request("POST", "/api/force", Some(&good)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);

    // The static machine token is exempt from MFA.
    let resp = app
        .clone()
        .oneshot(request("POST", "/api/force", Some(STATIC_TOKEN)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(request("POST", "/api/force", None))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key("www-authenticate"));
    let body = body_json(resp).await;
    assert_eq!(body["error"], "UNAUTHORIZED");
    assert!(body["message"].is_string());
}

#[tokio::test]
async fn jwks_outage_on_a_route_is_503_json() {
    let auth = authenticator(&oidc_token_env(), TestSource::down());
    let token = mint(&claims(json!({})), "k1");
    let resp = write_app(&auth)
        .oneshot(request("POST", "/api/force", Some(&token)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(resp).await["error"], "AUTH_UNAVAILABLE");
}

/// A source whose fetches after the first hang until released, standing in for a hung Auth0.
struct HangingSource {
    fetches: std::sync::atomic::AtomicUsize,
    release: tokio::sync::Notify,
}

impl nuvek_auth::JwksSource for HangingSource {
    fn fetch(&self) -> nuvek_auth::jwks::BoxFuture<'_, Result<Vec<u8>, nuvek_auth::JwksError>> {
        let n = self
            .fetches
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            if n > 0 {
                self.release.notified().await;
            }
            Ok(jwks_doc(&["k1"]))
        })
    }
}

#[tokio::test(start_paused = true)]
async fn stale_key_is_served_while_another_task_refreshes() {
    let source = Arc::new(HangingSource {
        fetches: std::sync::atomic::AtomicUsize::new(0),
        release: tokio::sync::Notify::new(),
    });
    let auth = authenticator(&oidc_token_env(), source.clone());
    let k1 = mint(&claims(json!({})), "k1");
    assert!(auth.authenticate(&bearer_headers(&k1)).await.is_ok());

    // Past MAX_KEY_AGE: the next lookup starts a refresh, which hangs.
    tokio::time::advance(Duration::from_secs(11 * 60)).await;
    let refresher = {
        let auth = auth.clone();
        let k1 = k1.clone();
        tokio::spawn(async move { auth.authenticate(&bearer_headers(&k1)).await })
    };
    while source.fetches.load(std::sync::atomic::Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }

    // Concurrent requests with a cached kid do not queue behind the hung fetch.
    for _ in 0..3 {
        let p = tokio::time::timeout(
            Duration::from_millis(1),
            auth.authenticate(&bearer_headers(&k1)),
        )
        .await
        .expect("served from the stale cache without waiting");
        assert!(p.is_ok());
    }
    assert!(!refresher.is_finished());
    assert_eq!(source.fetches.load(std::sync::atomic::Ordering::SeqCst), 2);

    source.release.notify_one();
    assert!(refresher.await.expect("join").is_ok());
}
