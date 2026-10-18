//! Shared test helpers. No network: the RSA keypair is generated at runtime and the JWKS is served
//! by an injected [`JwksSource`].

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use nuvek_auth::jwks::BoxFuture;
use nuvek_auth::{AuthConfig, Authenticator, JwksError, JwksSource};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};

pub const ISSUER: &str = "https://tenant.test.example/";
pub const AUDIENCE: &str = "https://app.test.example/api";
pub const CLIENT_ID: &str = "spa-client-id";
pub const ORIGIN: &str = "https://app.test.example";
// Deliberately zero-entropy placeholders, so secret scanners have nothing to flag.
pub const STATIC_TOKEN: &str = "ssssssssssssssssssssssssssssssss";
pub const NEXT_TOKEN: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";

pub struct Keys {
    pub encoding: EncodingKey,
    pub n: String,
    pub e: String,
}

/// One 2048-bit keypair per test binary (generation is slow in debug builds).
pub fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rsa::rand_core::OsRng;
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let der = private.to_pkcs1_der().expect("encode RSA key");
        Keys {
            encoding: EncodingKey::from_rsa_der(der.as_bytes()),
            n: URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
        }
    })
}

/// A JWKS document publishing the test key under each of `kids`.
pub fn jwks_doc(kids: &[&str]) -> Vec<u8> {
    let k = keys();
    let keys: Vec<Value> = kids
        .iter()
        .map(|kid| json!({"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": k.n, "e": k.e}))
        .collect();
    serde_json::to_vec(&json!({ "keys": keys })).expect("serialise JWKS")
}

/// An injectable JWKS source whose response can be swapped and whose fetches are counted.
pub struct TestSource {
    pub response: Mutex<Result<Vec<u8>, JwksError>>,
    pub fetches: AtomicUsize,
}

impl TestSource {
    pub fn ok(kids: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            response: Mutex::new(Ok(jwks_doc(kids))),
            fetches: AtomicUsize::new(0),
        })
    }

    pub fn down() -> Arc<Self> {
        Arc::new(Self {
            response: Mutex::new(Err(JwksError::Status(503))),
            fetches: AtomicUsize::new(0),
        })
    }

    pub fn set(&self, response: Result<Vec<u8>, JwksError>) {
        *self.response.lock().expect("lock") = response;
    }

    pub fn count(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

impl JwksSource for TestSource {
    fn fetch(&self) -> BoxFuture<'_, Result<Vec<u8>, JwksError>> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let resp = self.response.lock().expect("lock").clone();
        Box::pin(async move { resp })
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Standard valid claims; override fields by merging.
pub fn claims(extra: Value) -> Value {
    let mut base = json!({
        "iss": ISSUER,
        "aud": [AUDIENCE, "https://tenant.test.example/userinfo"],
        "sub": "auth0|alice",
        "iat": now(),
        "exp": now() + 600,
        "permissions": ["deb:write"],
        "scope": "openid profile",
    });
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

/// Signs `claims` with RS256 under `kid`.
pub fn mint(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(&header, claims, &keys().encoding).expect("sign")
}

/// Builds a config from an in-memory env map, using the `T_` prefix.
pub fn config(vars: &[(&str, &str)]) -> Result<AuthConfig, nuvek_auth::AuthConfigError> {
    let map: HashMap<String, String> = vars
        .iter()
        .map(|(k, v)| (format!("T_{k}"), v.to_string()))
        .collect();
    AuthConfig::from_lookup("T_", |k| map.get(k).cloned())
}

/// A full `oidc+token` env, optionally with overrides.
pub fn oidc_token_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("AUTH_MODE", "oidc+token"),
        ("OIDC_ISSUER", ISSUER),
        ("OIDC_AUDIENCE", AUDIENCE),
        ("OIDC_CLIENT_ID", CLIENT_ID),
        ("REQUIRED_PERMISSION", "deb:write"),
        ("API_TOKEN", STATIC_TOKEN),
        ("PUBLIC_ORIGIN", ORIGIN),
    ]
}

pub fn with(
    mut env: Vec<(&'static str, &'static str)>,
    key: &'static str,
    value: &'static str,
) -> Vec<(&'static str, &'static str)> {
    env.retain(|(k, _)| *k != key);
    env.push((key, value));
    env
}

pub fn without(
    mut env: Vec<(&'static str, &'static str)>,
    key: &str,
) -> Vec<(&'static str, &'static str)> {
    env.retain(|(k, _)| *k != key);
    env
}

pub fn authenticator(env: &[(&str, &str)], source: Arc<dyn JwksSource>) -> Authenticator {
    Authenticator::with_jwks_source(config(env).expect("config"), source).expect("authenticator")
}

pub fn bearer_headers(token: &str) -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("header"),
    );
    h
}

pub fn request(method: &str, uri: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::empty()).expect("request")
}

pub async fn body_json(resp: Response<Body>) -> Value {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}
