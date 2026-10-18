//! Manual TLS smoke test for the ring + webpki-roots client. Ignored by default because it needs
//! the network: `cargo test --test live_tls -- --ignored`.

use nuvek_auth::{HttpJwksSource, JwksSource};

#[tokio::test]
#[ignore = "needs network"]
async fn fetches_a_public_auth0_jwks_over_tls() {
    let source =
        HttpJwksSource::new("https://samples.auth0.com/.well-known/jwks.json").expect("client");
    let body = source.fetch().await.expect("fetch");
    let doc: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert!(doc["keys"].as_array().is_some_and(|k| !k.is_empty()));
}
