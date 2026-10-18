//! The audit line. Kept in its own test binary: tracing caches callsite interest process-wide, so
//! a scoped subscriber races with other tests hitting the same callsite in parallel.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::{routing::post, Router};
use common::*;
use nuvek_auth::{Authenticator, Principal};
use tower::ServiceExt;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn audit_line_on_successful_permission_check_only() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let env = [
        ("AUTH_MODE", "token"),
        ("API_TOKEN", STATIC_TOKEN),
        ("PUBLIC_ORIGIN", ORIGIN),
    ];
    let auth = Authenticator::new(config(&env).expect("config")).expect("authenticator");
    let app = Router::new()
        .route("/api/force", post(|p: Principal| async move { p.sub }))
        .layer(auth.require_permission("deb:write"));

    let resp = app
        .clone()
        .oneshot(request("POST", "/api/force?ticket=zzz", Some(STATIC_TOKEN)))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .oneshot(request("POST", "/api/force", Some("wrong")))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let log = String::from_utf8(capture.0.lock().expect("lock").clone()).expect("utf8");
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("nuvek_auth::audit"))
        .collect();
    assert_eq!(lines.len(), 1, "{log}");
    let line = lines[0];
    assert!(line.contains("actor=machine:static"), "{line}");
    assert!(line.contains("via=StaticToken"), "{line}");
    assert!(line.contains("method=POST"), "{line}");
    assert!(line.contains("path=/api/force"), "{line}");
    assert!(line.contains("permission=deb:write"), "{line}");
    assert!(!line.contains("zzz"), "query string is never logged");
    assert!(!log.contains(STATIC_TOKEN), "token never logged");
}
