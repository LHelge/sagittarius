//! Broadcast channel for the real-time tail of DNS query events.
//!
//! [`LiveLog`] is the live-stream half of the query log: every new
//! [`QueryEvent`] is published to a `tokio::sync::broadcast` channel that the
//! admin UI's SSE endpoint subscribes to. There is **no history here** — durable
//! history lives in the `query_log` table (E10) and is read back through
//! [`SqliteQueryLogRepo`](crate::storage::query_log::SqliteQueryLogRepo).
//!
//! # Live / history seam
//!
//! The admin log page seeds its initial rows from the database (newest page),
//! then subscribes to this broadcast for everything from "now" forward. Because
//! the batch writer (E10.4) persists with a small lag, the very newest events
//! appear in the broadcast tail before they land in the DB — which is exactly
//! what the live stream is for. A later manual refresh shows them from the DB.
//!
//! # Thread-safety
//!
//! The broadcast sender is `Send + Sync`; share [`LiveLog`] via
//! [`std::sync::Arc`].

use tokio::sync::broadcast;

use super::event::QueryEvent;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Capacity of the broadcast channel — how many unconsumed events a slow
/// subscriber may fall behind before it starts skipping (drop-oldest).
const BROADCAST_CAPACITY: usize = 1000;

// ── LiveLog ───────────────────────────────────────────────────────────────────

/// Broadcast channel for live [`QueryEvent`]s.
///
/// Share via [`std::sync::Arc`]. Construct with [`LiveLog::new`] or
/// [`LiveLog::default`].
pub struct LiveLog {
    /// Sender half of the broadcast channel.
    tx: broadcast::Sender<QueryEvent>,
}

impl LiveLog {
    /// Create a new [`LiveLog`].
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self { tx }
    }

    /// Broadcast an event to all current subscribers.
    ///
    /// The send error from the broadcast channel (returned when there are no
    /// active subscribers) is intentionally silenced — callers should not have
    /// to care whether anyone is listening.
    pub fn publish(&self, event: QueryEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to the live event stream.
    ///
    /// Each call returns an independent [`broadcast::Receiver`]. Subscribers
    /// only receive events published *after* the call to `subscribe`; history is
    /// seeded separately from the database.
    pub fn subscribe(&self) -> broadcast::Receiver<QueryEvent> {
        self.tx.subscribe()
    }
}

impl Default for LiveLog {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{message::Qtype, name::Name},
        resolver::pipeline::Outcome,
        telemetry::event::QueryEvent,
    };
    use std::net::SocketAddr;

    fn make_event(label: &str, outcome: Outcome) -> QueryEvent {
        let client: SocketAddr = "203.0.113.5:1234".parse().unwrap();
        let qname: Name = format!("{label}.example.com").parse().unwrap();
        QueryEvent::new(client, qname, Qtype::A, outcome)
    }

    // ── publish → subscriber receives ─────────────────────────────────────────

    #[tokio::test]
    async fn publish_delivers_to_subscriber() {
        let log = LiveLog::new();
        let mut rx = log.subscribe();

        let event = make_event("a", Outcome::Forwarded);
        log.publish(event.clone());

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for broadcast")
            .expect("broadcast channel closed");

        assert_eq!(received.qname.to_string(), event.qname.to_string());
    }

    // ── late subscriber contract ──────────────────────────────────────────────

    /// A subscriber only receives events published *after* it subscribes; events
    /// published earlier are gone (history is seeded from the DB instead).
    #[tokio::test]
    async fn late_subscriber_only_sees_post_subscribe_events() {
        let log = LiveLog::new();

        // Published before any subscriber exists — not delivered to a late one.
        log.publish(make_event("pre0", Outcome::Cached));

        let mut rx = log.subscribe();

        let post_event = make_event("post0", Outcome::Forwarded);
        log.publish(post_event.clone());

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for broadcast")
            .expect("broadcast channel closed");
        assert_eq!(
            received.qname.to_string(),
            post_event.qname.to_string(),
            "subscriber should only get the post-subscribe event"
        );

        // Nothing else is queued.
        let nothing = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(
            nothing.is_err(),
            "broadcast channel should be empty after the one post-subscribe event"
        );
    }
}
