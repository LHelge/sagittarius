//! Bounded ring buffer and broadcast channel for live DNS query events.
//!
//! [`LiveLog`] serves two concurrent consumers:
//!
//! 1. **Admin UI live view** — a Server-Sent Events (SSE) stream that receives
//!    every new [`QueryEvent`] via the `tokio::sync::broadcast` channel.
//! 2. **Freshly-opened admin view** — when a browser connects it seeds the
//!    visible table by calling [`LiveLog::recent`] to get the last N events,
//!    then switches to the live SSE stream.  The ring buffer holds at most
//!    [`DEFAULT_CAPACITY`] events; oldest entries are evicted as new ones arrive.
//!
//! # Thread-safety
//!
//! The ring is protected by a [`std::sync::Mutex`].  The critical section is
//! small (a `push_back` / optional `pop_front`) and entirely synchronous — no
//! `await` points appear inside the lock.  [`LiveLog`] is `Send + Sync` and
//! intended to be shared via [`std::sync::Arc`].

use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::sync::broadcast;

use super::event::QueryEvent;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default ring-buffer capacity (and broadcast channel capacity).
pub const DEFAULT_CAPACITY: usize = 1000;

// ── LiveLog ───────────────────────────────────────────────────────────────────

/// Ring-buffer store and broadcast channel for [`QueryEvent`]s.
///
/// Share via [`std::sync::Arc`].  Construct with [`LiveLog::new`] or
/// [`LiveLog::default`] (which uses [`DEFAULT_CAPACITY`]).
pub struct LiveLog {
    /// Recent events, oldest-first.  Bounded to `capacity`.
    ring: Mutex<VecDeque<QueryEvent>>,
    /// Maximum number of events retained in the ring.
    capacity: usize,
    /// Sender half of the broadcast channel.
    tx: broadcast::Sender<QueryEvent>,
}

impl LiveLog {
    /// Create a new [`LiveLog`] with the given capacity.
    ///
    /// Both the ring buffer and the broadcast channel are bounded to `capacity`.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            ring: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            tx,
        }
    }

    /// Push a new event into the ring buffer and broadcast it to subscribers.
    ///
    /// If the ring is at capacity, the oldest event is evicted before the new
    /// one is appended.  The send error from the broadcast channel (returned
    /// when there are no active subscribers) is intentionally silenced — callers
    /// should not have to care whether anyone is listening.
    pub fn publish(&self, event: QueryEvent) {
        // Keep the lock scope tight — acquire, mutate, release, then broadcast.
        {
            let mut ring = self.ring.lock().expect("ring mutex poisoned");
            if ring.len() == self.capacity {
                ring.pop_front();
            }
            ring.push_back(event.clone());
        }
        // Ignore "no receivers" error.
        let _ = self.tx.send(event);
    }

    /// Subscribe to the live event stream.
    ///
    /// Each call returns an independent [`broadcast::Receiver`].  Subscribers
    /// only receive events published *after* the call to `subscribe`.  To seed
    /// history, call [`LiveLog::recent`] first, then `subscribe`.
    pub fn subscribe(&self) -> broadcast::Receiver<QueryEvent> {
        self.tx.subscribe()
    }

    /// Snapshot the ring buffer, returning events from oldest to newest.
    ///
    /// The returned `Vec` is a point-in-time copy; future publishes do not
    /// mutate it.  Useful for seeding a freshly-opened admin view with history
    /// before switching to the live broadcast stream.
    pub fn recent(&self) -> Vec<QueryEvent> {
        self.ring
            .lock()
            .expect("ring mutex poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

impl Default for LiveLog {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
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
        let log = LiveLog::new(10);
        let mut rx = log.subscribe();

        let event = make_event("a", Outcome::Forwarded);
        log.publish(event.clone());

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for broadcast")
            .expect("broadcast channel closed");

        assert_eq!(received.qname.to_string(), event.qname.to_string());
    }

    // ── ring bounded + eviction ───────────────────────────────────────────────

    #[test]
    fn ring_bounded_evicts_oldest() {
        let log = LiveLog::new(3);

        // Publish 5 events with distinct names.
        for i in 0..5u8 {
            log.publish(make_event(&format!("host{i}"), Outcome::Forwarded));
        }

        let recent = log.recent();

        // Ring holds exactly 3 events.
        assert_eq!(recent.len(), 3);

        // The three retained events are host2, host3, host4 (oldest-first).
        let names: Vec<String> = recent.iter().map(|e| e.qname.to_string()).collect();
        assert_eq!(names[0], "host2.example.com.");
        assert_eq!(names[1], "host3.example.com.");
        assert_eq!(names[2], "host4.example.com.");
    }

    // ── late subscriber seeding contract ─────────────────────────────────────

    /// Documents the "seed from recent(), then stream live" contract:
    ///
    /// - `recent()` returns events published *before* subscribing.
    /// - A subscriber created *after* those publishes does **not** receive them
    ///   via `recv()` — broadcast delivers only post-subscribe events.
    #[tokio::test]
    async fn late_subscriber_seeding_contract() {
        let log = LiveLog::new(10);

        // Publish 3 events before any subscriber exists.
        for i in 0..3u8 {
            log.publish(make_event(&format!("pre{i}"), Outcome::Cached));
        }

        // recent() sees them.
        let history = log.recent();
        assert_eq!(history.len(), 3, "recent() must return pre-publish events");

        // A late subscriber does NOT see the pre-subscribe events via recv.
        let mut rx = log.subscribe();

        // Publish one more event after subscribing.
        let post_event = make_event("post0", Outcome::Forwarded);
        log.publish(post_event.clone());

        // Subscriber receives only the post-subscribe event.
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for broadcast")
            .expect("broadcast channel closed");

        assert_eq!(
            received.qname.to_string(),
            post_event.qname.to_string(),
            "subscriber should only get the post-subscribe event"
        );

        // There are no more events in the broadcast channel.
        // Try a short receive; it should time out (nothing else queued).
        let nothing = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(
            nothing.is_err(),
            "broadcast channel should be empty after consuming the one post-subscribe event"
        );
    }
}
