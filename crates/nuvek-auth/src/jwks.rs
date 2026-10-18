//! JWKS retrieval and caching.
//!
//! - Keys are fetched lazily (start-up never blocks on Auth0) and cached by `kid`.
//! - Fetches are rate-limited: at most one per [`REFETCH_INTERVAL`], or per
//!   [`COLD_RETRY_INTERVAL`] while no key set has ever been loaded.
//! - An unknown `kid`, or a key set older than [`MAX_KEY_AGE`], triggers a refetch (subject to the
//!   limiter), so a key revoked upstream stops validating.
//! - A failed fetch keeps the last good set, but for at most [`MAX_STALE_AGE`]; after that OIDC
//!   answers 503 until a fetch succeeds.
//! - Stale-while-revalidate: while one task refreshes, others holding a cached key for their
//!   `kid` (under [`MAX_STALE_AGE`]) use it instead of waiting on the fetch.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;

use crate::error::{AuthConfigError, JwksError};

/// Minimum time between two JWKS fetches once a key set is loaded.
pub const REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// Minimum time between two JWKS fetches while no key set has ever been loaded.
pub const COLD_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// A key set older than this is refreshed on the next lookup.
pub const MAX_KEY_AGE: Duration = Duration::from_secs(10 * 60);

/// A key set older than this is no longer used, even if every refresh has failed.
pub const MAX_STALE_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Largest JWKS body accepted.
const MAX_JWKS_BYTES: usize = 256 * 1024;

/// Timeout for one JWKS request.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// A boxed, `Send` future, as returned by [`JwksSource::fetch`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where the JWKS document comes from. The default is [`HttpJwksSource`]; tests inject their own.
pub trait JwksSource: Send + Sync + 'static {
    /// Returns the raw JWKS JSON document (`{"keys": [...]}`).
    fn fetch(&self) -> BoxFuture<'_, Result<Vec<u8>, JwksError>>;
}

/// Fetches the JWKS over HTTPS from `{issuer}.well-known/jwks.json`: HTTPS only, no redirects, a
/// 5 s timeout and a 256 KiB body cap. TLS is rustls on ring with the bundled Mozilla (webpki)
/// roots, so no system CA bundle is needed.
#[derive(Debug, Clone)]
pub struct HttpJwksSource {
    client: reqwest::Client,
    url: String,
}

impl HttpJwksSource {
    /// Builds a source for the given JWKS URL.
    pub fn new(url: impl Into<String>) -> Result<Self, AuthConfigError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| AuthConfigError::HttpClient(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .timeout(FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AuthConfigError::HttpClient(e.to_string()))?;
        Ok(Self {
            client,
            url: url.into(),
        })
    }
}

impl JwksSource for HttpJwksSource {
    fn fetch(&self) -> BoxFuture<'_, Result<Vec<u8>, JwksError>> {
        Box::pin(async move {
            let request_err = |e: reqwest::Error| JwksError::Request(e.without_url().to_string());
            let mut resp = self
                .client
                .get(&self.url)
                .send()
                .await
                .map_err(request_err)?;
            let status = resp.status();
            if !status.is_success() {
                return Err(JwksError::Status(status.as_u16()));
            }
            if resp
                .content_length()
                .is_some_and(|n| n > MAX_JWKS_BYTES as u64)
            {
                return Err(JwksError::TooLarge);
            }
            // Read in chunks and stop as soon as the cap is crossed.
            let mut body = Vec::new();
            while let Some(chunk) = resp.chunk().await.map_err(request_err)? {
                if body.len() + chunk.len() > MAX_JWKS_BYTES {
                    return Err(JwksError::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        })
    }
}

#[derive(Deserialize)]
struct JwkSetDoc {
    keys: Vec<JwkDoc>,
}

#[derive(Deserialize)]
struct JwkDoc {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

type KeyMap = HashMap<String, Arc<DecodingKey>>;

/// Parses a JWKS document into RS256 decoding keys by `kid`. Non-RSA, non-signing, non-RS256 and
/// kid-less keys are skipped.
pub(crate) fn parse_jwks(body: &[u8]) -> Result<KeyMap, JwksError> {
    let doc: JwkSetDoc =
        serde_json::from_slice(body).map_err(|e| JwksError::Parse(e.to_string()))?;
    let mut keys = HashMap::new();
    for jwk in doc.keys {
        if jwk.kty != "RSA" {
            continue;
        }
        if jwk.alg.as_deref().is_some_and(|a| a != "RS256") {
            continue;
        }
        if jwk.use_.as_deref().is_some_and(|u| u != "sig") {
            continue;
        }
        let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
            continue;
        };
        if let Ok(key) = DecodingKey::from_rsa_components(&n, &e) {
            keys.insert(kid, Arc::new(key));
        }
    }
    if keys.is_empty() {
        return Err(JwksError::NoUsableKeys);
    }
    Ok(keys)
}

/// Outcome of a key lookup.
pub(crate) enum KeyLookup {
    /// The key for this `kid`.
    Found(Arc<DecodingKey>),
    /// The JWKS is healthy but does not hold this `kid`.
    Unknown,
    /// No usable key set: none loaded yet, the last fetch failed, or the set is past
    /// [`MAX_STALE_AGE`].
    Unavailable,
}

#[derive(Default)]
struct KeySet {
    keys: KeyMap,
    fetched_at: Option<Instant>,
}

impl KeySet {
    fn age(&self) -> Option<Duration> {
        self.fetched_at.map(|at| at.elapsed())
    }
}

#[derive(Default)]
struct FetchState {
    last_attempt: Option<Instant>,
    last_failed: bool,
}

/// Cache in front of a [`JwksSource`].
pub(crate) struct JwksCache {
    source: Arc<dyn JwksSource>,
    set: RwLock<KeySet>,
    fetch: Mutex<FetchState>,
}

impl JwksCache {
    pub(crate) fn new(source: Arc<dyn JwksSource>) -> Self {
        Self {
            source,
            set: RwLock::new(KeySet::default()),
            fetch: Mutex::new(FetchState::default()),
        }
    }

    /// Looks up `kid`, refetching when it is unknown or the set is older than [`MAX_KEY_AGE`],
    /// as far as the rate limit allows.
    pub(crate) async fn key(&self, kid: &str) -> KeyLookup {
        let stale = {
            let set = self.set.read().await;
            let cached = set.keys.get(kid).cloned();
            match (set.age(), cached) {
                (Some(age), Some(key)) if age < MAX_KEY_AGE => return KeyLookup::Found(key),
                (Some(age), Some(key)) if age < MAX_STALE_AGE => Some(key),
                _ => None,
            }
        };

        // Serialise fetches. Stale-while-revalidate: if another task is already refreshing and we
        // hold a usable (under MAX_STALE_AGE) key for this kid, serve it rather than queue behind
        // a possibly hung fetch.
        let mut state = match self.fetch.try_lock() {
            Ok(guard) => guard,
            Err(_) => match stale {
                Some(key) => return KeyLookup::Found(key),
                None => self.fetch.lock().await,
            },
        };
        // Another request may have refreshed while we waited for the lock.
        let (loaded, fresh_hit) = {
            let set = self.set.read().await;
            let fresh = set.age().is_some_and(|a| a < MAX_KEY_AGE);
            (
                set.fetched_at.is_some(),
                fresh && set.keys.contains_key(kid),
            )
        };

        if !fresh_hit {
            let interval = if loaded {
                REFETCH_INTERVAL
            } else {
                COLD_RETRY_INTERVAL
            };
            let due = state.last_attempt.is_none_or(|at| at.elapsed() >= interval);
            if due {
                state.last_attempt = Some(Instant::now());
                match self.source.fetch().await.and_then(|b| parse_jwks(&b)) {
                    Ok(keys) => {
                        state.last_failed = false;
                        *self.set.write().await = KeySet {
                            keys,
                            fetched_at: Some(Instant::now()),
                        };
                    }
                    Err(err) => {
                        state.last_failed = true;
                        tracing::warn!(error = %err, "JWKS fetch failed; keeping the last good key set");
                    }
                }
            }
        }

        let set = self.set.read().await;
        match set.age() {
            None => return KeyLookup::Unavailable,
            Some(age) if age >= MAX_STALE_AGE => return KeyLookup::Unavailable,
            Some(_) => {}
        }
        match set.keys.get(kid) {
            Some(key) => KeyLookup::Found(key.clone()),
            None if state.last_failed => KeyLookup::Unavailable,
            None => KeyLookup::Unknown,
        }
    }
}
