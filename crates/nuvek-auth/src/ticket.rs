//! Single-use stream tickets for WebSocket, EventSource and plain links, which cannot carry an
//! `Authorization` header.
//!
//! A ticket is 32 random bytes, base64url without padding, bound to the [`Principal`] that asked
//! for it, valid for [`TICKET_TTL`] and consumed on first use. Tickets live in memory only;
//! expired ones are swept on issue, at most once a second. Each subject may hold at most
//! [`MAX_PER_SUB`] live tickets.

use std::collections::HashMap;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::AuthError;
use crate::Principal;

/// How long a ticket stays valid.
pub const TICKET_TTL: Duration = Duration::from_secs(30);

/// Upper bound on outstanding tickets, so a caller cannot grow memory without limit.
const MAX_OUTSTANDING: usize = 10_000;

/// Upper bound on outstanding tickets per subject (429 beyond it).
pub const MAX_PER_SUB: usize = 32;

/// Number of random bytes in a ticket.
const TICKET_BYTES: usize = 32;

/// Expired tickets are swept at most this often.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

// No Debug: an entry's key is a live ticket.
struct Entry {
    principal: Principal,
    expires: Instant,
}

#[derive(Default)]
struct Tickets {
    entries: HashMap<String, Entry>,
    /// Stored tickets per subject (live, or expired but not yet swept), kept in step with
    /// `entries` so the per-subject cap check is O(1).
    per_sub: HashMap<String, usize>,
    last_sweep: Option<Instant>,
}

impl Tickets {
    fn forget(&mut self, sub: &str) {
        if let Some(n) = self.per_sub.get_mut(sub) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_sub.remove(sub);
            }
        }
    }

    fn sweep(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            if let Some(e) = self.entries.remove(&key) {
                self.forget(&e.principal.sub);
            }
        }
        self.last_sweep = Some(now);
    }
}

/// In-memory ticket store. Deliberately has no `Debug`: it holds live tickets.
#[derive(Default)]
pub(crate) struct TicketStore {
    inner: Mutex<Tickets>,
}

impl TicketStore {
    /// Issues a fresh ticket for `principal`. 429 when the subject already holds
    /// [`MAX_PER_SUB`] live tickets, 503 when the store is full.
    pub(crate) async fn issue(&self, principal: Principal) -> Result<String, AuthError> {
        let mut bytes = [0u8; TICKET_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|_| AuthError::Unavailable("cannot generate a ticket"))?;
        let ticket = URL_SAFE_NO_PAD.encode(bytes);

        let now = Instant::now();
        let mut t = self.inner.lock().await;
        if t.last_sweep
            .is_none_or(|at| now.duration_since(at) >= SWEEP_INTERVAL)
        {
            t.sweep(now);
        }
        // O(1). Tickets that expired within the last sweep interval still count, so the cap can
        // bite up to one second late; it never lets a subject exceed MAX_PER_SUB.
        let held = t.per_sub.get(&principal.sub).copied().unwrap_or(0);
        if held >= MAX_PER_SUB {
            return Err(AuthError::TooManyRequests("too many outstanding tickets"));
        }
        if t.entries.len() >= MAX_OUTSTANDING {
            return Err(AuthError::Unavailable("ticket store is full"));
        }
        *t.per_sub.entry(principal.sub.clone()).or_insert(0) += 1;
        t.entries.insert(
            ticket.clone(),
            Entry {
                principal,
                expires: now + TICKET_TTL,
            },
        );
        Ok(ticket)
    }

    /// Consumes `ticket`, returning its principal if it exists and has not expired. The ticket is
    /// removed either way; no sweep happens here.
    pub(crate) async fn redeem(&self, ticket: &str) -> Option<Principal> {
        let now = Instant::now();
        let entry = {
            let mut t = self.inner.lock().await;
            let entry = t.entries.remove(ticket);
            if let Some(e) = &entry {
                t.forget(&e.principal.sub);
            }
            entry
        };
        entry.filter(|e| e.expires > now).map(|e| e.principal)
    }
}

/// Extracts the `ticket` query parameter from a URI query string. Tickets are base64url, so no
/// percent-decoding is needed; anything with other characters is ignored.
pub(crate) fn ticket_from_query(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .filter_map(|pair| pair.strip_prefix("ticket="))
        .find(|t| {
            !t.is_empty()
                && t.len() <= 64
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Via;

    fn principal(sub: &str) -> Principal {
        Principal {
            sub: sub.to_string(),
            permissions: Vec::new(),
            mfa: false,
            via: Via::Oidc,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn per_sub_count_tracks_issue_redeem_and_sweep() {
        let store = TicketStore::default();
        let mut issued = Vec::new();
        for _ in 0..MAX_PER_SUB {
            issued.push(store.issue(principal("a")).await.expect("issue"));
        }
        assert_eq!(
            store.issue(principal("a")).await,
            Err(AuthError::TooManyRequests("too many outstanding tickets"))
        );
        assert!(store.issue(principal("b")).await.is_ok());

        // Redeem frees a slot.
        assert!(store.redeem(&issued[0]).await.is_some());
        assert!(store.issue(principal("a")).await.is_ok());
        // Redeeming an unknown or already-used ticket does not underflow the count.
        assert!(store.redeem(&issued[0]).await.is_none());
        assert!(store.redeem("nope").await.is_none());
        assert_eq!(
            store.inner.lock().await.per_sub.get("a"),
            Some(&MAX_PER_SUB)
        );

        // Sweep clears the counts with the entries.
        tokio::time::advance(TICKET_TTL + Duration::from_secs(1)).await;
        assert!(store.issue(principal("c")).await.is_ok());
        let t = store.inner.lock().await;
        assert_eq!(t.per_sub.get("a"), None);
        assert_eq!(t.per_sub.get("b"), None);
        assert_eq!(t.per_sub.get("c"), Some(&1));
        assert_eq!(t.entries.len(), 1);
    }
}
