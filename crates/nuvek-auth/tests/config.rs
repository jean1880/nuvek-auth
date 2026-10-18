//! Fail-closed configuration, secret redaction and CSP output.

mod common;

use common::*;
use nuvek_auth::{csp, AuthConfigError, AuthMode, Authenticator, SecretString};

fn missing(key: &str) -> AuthConfigError {
    AuthConfigError::Missing {
        key: key.to_string(),
    }
}

fn err_of(env: &[(&str, &str)]) -> AuthConfigError {
    match config(env) {
        Ok(cfg) => match Authenticator::new(cfg) {
            Ok(_) => panic!("expected a configuration error"),
            Err(e) => e,
        },
        Err(e) => e,
    }
}

#[test]
fn mode_unset_fails() {
    assert_eq!(err_of(&[]), missing("T_AUTH_MODE"));
    assert_eq!(err_of(&[("AUTH_MODE", "  ")]), missing("T_AUTH_MODE"));
}

#[test]
fn mode_unknown_fails_without_echoing_value() {
    let err = err_of(&[("AUTH_MODE", "sesame-open")]);
    assert!(matches!(&err, AuthConfigError::Invalid { key, .. } if key == "T_AUTH_MODE"));
    assert!(!err.to_string().contains("sesame-open"));
}

#[test]
fn off_mode_needs_nothing_else() {
    let cfg = config(&[("AUTH_MODE", "off")]).expect("off config");
    assert_eq!(cfg.mode(), AuthMode::Off);
    let auth = Authenticator::new(cfg).expect("off authenticator");
    assert!(!auth.enforced());
}

#[test]
fn token_mode_requires_token_and_origin() {
    assert_eq!(
        err_of(&[("AUTH_MODE", "token"), ("PUBLIC_ORIGIN", ORIGIN)]),
        missing("T_API_TOKEN")
    );
    assert_eq!(
        err_of(&[
            ("AUTH_MODE", "token"),
            ("PUBLIC_ORIGIN", ORIGIN),
            ("API_TOKEN", "")
        ]),
        missing("T_API_TOKEN"),
        "an empty token counts as unset"
    );
    assert_eq!(
        err_of(&[("AUTH_MODE", "token"), ("API_TOKEN", STATIC_TOKEN)]),
        missing("T_PUBLIC_ORIGIN")
    );
    let auth = Authenticator::new(
        config(&[
            ("AUTH_MODE", "token"),
            ("API_TOKEN", STATIC_TOKEN),
            ("PUBLIC_ORIGIN", ORIGIN),
        ])
        .expect("config"),
    )
    .expect("token authenticator");
    assert!(auth.enforced());
}

#[test]
fn oidc_mode_requires_issuer_audience_client_and_an_authorisation_key() {
    let base = without(without(oidc_token_env(), "API_TOKEN"), "AUTH_MODE");
    let oidc = with(base, "AUTH_MODE", "oidc");
    for key in [
        "OIDC_ISSUER",
        "OIDC_AUDIENCE",
        "OIDC_CLIENT_ID",
        "PUBLIC_ORIGIN",
    ] {
        assert_eq!(
            err_of(&without(oidc.clone(), key)),
            missing(&format!("T_{key}"))
        );
    }
    assert_eq!(
        err_of(&without(oidc.clone(), "REQUIRED_PERMISSION")),
        AuthConfigError::MissingOneOf {
            first: "T_ALLOWED_SUBS".into(),
            second: "T_REQUIRED_PERMISSION".into()
        }
    );
    // ALLOWED_SUBS alone satisfies the requirement.
    let subs_only = with(
        without(oidc.clone(), "REQUIRED_PERMISSION"),
        "ALLOWED_SUBS",
        "auth0|alice, auth0|bob",
    );
    let cfg = config(&subs_only).expect("subs-only config");
    assert_eq!(
        cfg.oidc().map(|o| o.allowed_subs().to_vec()),
        Some(vec!["auth0|alice".to_string(), "auth0|bob".to_string()])
    );
    // oidc mode does not need (and ignores) a static token.
    assert!(Authenticator::new(config(&oidc).expect("config")).is_ok());
}

#[test]
fn oidc_plus_token_requires_everything() {
    assert_eq!(
        err_of(&without(oidc_token_env(), "API_TOKEN")),
        missing("T_API_TOKEN")
    );
    assert_eq!(
        err_of(&without(oidc_token_env(), "OIDC_ISSUER")),
        missing("T_OIDC_ISSUER")
    );
    assert!(Authenticator::new(config(&oidc_token_env()).expect("config")).is_ok());
}

#[test]
fn issuer_must_be_https_and_is_normalised() {
    let err = err_of(&with(
        oidc_token_env(),
        "OIDC_ISSUER",
        "http://tenant.test.example/",
    ));
    assert!(matches!(err, AuthConfigError::Invalid { ref key, .. } if key == "T_OIDC_ISSUER"));
    let cfg = config(&with(
        oidc_token_env(),
        "OIDC_ISSUER",
        "https://tenant.test.example",
    ))
    .expect("config");
    assert_eq!(cfg.oidc().map(|o| o.issuer()), Some(ISSUER));
}

#[test]
fn bad_bool_and_bad_origin_fail() {
    let err = err_of(&with(oidc_token_env(), "AUTH_READS", "maybe"));
    assert!(matches!(err, AuthConfigError::Invalid { ref key, .. } if key == "T_AUTH_READS"));
    let err = err_of(&with(oidc_token_env(), "REQUIRE_MFA", "2"));
    assert!(matches!(err, AuthConfigError::Invalid { ref key, .. } if key == "T_REQUIRE_MFA"));
    let err = err_of(&with(
        oidc_token_env(),
        "PUBLIC_ORIGIN",
        "https://app.test.example/path",
    ));
    assert!(matches!(err, AuthConfigError::Invalid { ref key, .. } if key == "T_PUBLIC_ORIGIN"));
}

#[test]
fn legacy_token_fallback() {
    let env = [("AUTH_MODE", "token"), ("PUBLIC_ORIGIN", ORIGIN)];
    let cfg = config(&env)
        .expect("config")
        .with_api_token(Some(STATIC_TOKEN.into()));
    assert!(cfg.validate().is_ok());
    // An empty fallback is still unset.
    let cfg = config(&env)
        .expect("config")
        .with_api_token(Some(" ".into()));
    assert_eq!(cfg.validate(), Err(missing("T_API_TOKEN")));
}

#[test]
fn debug_never_prints_the_token() {
    let cfg = config(&with(oidc_token_env(), "API_TOKEN_NEXT", NEXT_TOKEN)).expect("config");
    let cfg_debug = format!("{cfg:?}");
    assert!(!cfg_debug.contains(STATIC_TOKEN));
    assert!(!cfg_debug.contains(NEXT_TOKEN));
    assert!(cfg_debug.contains("SecretString(****)"));

    let auth = Authenticator::new(cfg).expect("authenticator");
    let auth_debug = format!("{auth:?} {auth:#?}");
    assert!(!auth_debug.contains(STATIC_TOKEN));
    assert!(!auth_debug.contains(NEXT_TOKEN));

    let secret = SecretString::new(STATIC_TOKEN);
    assert_eq!(format!("{secret:?}"), "SecretString(****)");
    assert_eq!(secret.expose_secret(), STATIC_TOKEN);
}

#[test]
fn config_errors_never_contain_values() {
    let err = err_of(&with(oidc_token_env(), "PUBLIC_ORIGIN", "ftp://secret-ish"));
    assert!(!err.to_string().contains("secret-ish"));
}

#[test]
fn spa_policy_with_and_without_issuer() {
    assert_eq!(
        csp::spa_policy(Some("https://tenant.test.example/")),
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; connect-src 'self' https://tenant.test.example; \
         frame-src https://tenant.test.example; object-src 'none'; base-uri 'none'; \
         frame-ancestors 'self'"
    );
    let none = csp::spa_policy(None);
    assert!(none.contains("connect-src 'self';"));
    assert!(none.contains("frame-src 'none'"));
    assert!(!none.contains("unsafe-eval"));
    // Injection attempts are dropped, not passed through.
    let evil = csp::spa_policy(Some("https://x.example; script-src *"));
    assert!(evil.contains("frame-src 'none'"));
    for confused in [
        "https://x#@tenant/",
        "https://u@tenant/",
        "https://tenant/?q",
    ] {
        assert!(
            csp::spa_policy(Some(confused)).contains("frame-src 'none'"),
            "{confused}"
        );
    }
    assert_eq!(csp::FILE_SANDBOX, "sandbox; default-src 'none'");
}

#[test]
fn issuer_with_userinfo_query_or_fragment_fails() {
    for bad in [
        "https://x#@tenant/",
        "https://u@tenant/",
        "https://tenant/?q",
    ] {
        let env = with(oidc_token_env(), "OIDC_ISSUER", bad);
        let err = err_of(&env);
        assert!(
            matches!(err, AuthConfigError::Invalid { ref key, .. } if key == "T_OIDC_ISSUER"),
            "{bad}: {err:?}"
        );
    }
}

#[test]
fn public_origin_is_lowercased() {
    let cfg = config(&with(
        oidc_token_env(),
        "PUBLIC_ORIGIN",
        "HTTPS://App.Test.Example/",
    ))
    .expect("config");
    assert_eq!(cfg.public_origin(), Some(ORIGIN));
}

#[test]
fn short_static_token_is_rejected_without_echoing_it() {
    let short = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 31 chars, zero entropy
    assert_eq!(short.len(), 31);
    let env = [
        ("AUTH_MODE", "token"),
        ("PUBLIC_ORIGIN", ORIGIN),
        ("API_TOKEN", short),
    ];
    let err = err_of(&env);
    assert!(
        matches!(err, AuthConfigError::Invalid { ref key, .. } if key == "T_API_TOKEN"),
        "{err:?}"
    );
    assert!(!err.to_string().contains(short));

    let env = with(token_mode_env(), "API_TOKEN_NEXT", short);
    let err = err_of(&env);
    assert!(
        matches!(err, AuthConfigError::Invalid { ref key, .. } if key == "T_API_TOKEN_NEXT"),
        "{err:?}"
    );

    // The legacy fallback is held to the same minimum.
    let cfg = config(&[("AUTH_MODE", "token"), ("PUBLIC_ORIGIN", ORIGIN)])
        .expect("config")
        .with_api_token(Some(short.into()));
    let err = Authenticator::new(cfg).expect_err("short fallback");
    assert!(matches!(err, AuthConfigError::Invalid { ref key, .. } if key == "T_API_TOKEN"));
    assert!(!err.to_string().contains(short));
}

fn token_mode_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("AUTH_MODE", "token"),
        ("PUBLIC_ORIGIN", ORIGIN),
        ("API_TOKEN", STATIC_TOKEN),
    ]
}

#[test]
fn ticket_response_debug_redacts_the_ticket() {
    let resp = nuvek_auth::routes::TicketResponse {
        ticket: "ticket-value-that-must-not-print".into(),
        expires_in: 30,
    };
    let dbg = format!("{resp:?}");
    assert!(!dbg.contains("ticket-value-that-must-not-print"), "{dbg}");
    assert!(dbg.contains("expires_in: 30"));
}
