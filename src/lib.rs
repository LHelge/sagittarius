//! Sagittarius — a self-hosted DNS sinkhole.
//!
//! Shipped as a single self-contained binary containing the DNS engine,
//! persistent storage, and the web administration UI.  See
//! [`SPEC.md`](../SPEC.md) for the full architecture and design rationale.
//!
//! # Module layout
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`app`] | Runtime that owns shared state and wires subsystems |
//! | [`blocklist`] | Blocklist ingestion subsystem (fetch → parse → aggregate → schedule) |
//! | [`cli`] | clap argument surface; parses args/env into a [`config::Config`] |
//! | [`codec`] | Custom lazy DNS wire-format parser/serializer |
//! | [`config`] | Operational configuration domain types |
//! | [`error`] | Crate-wide error types and `Result` alias |
//! | [`resolver`] | DNS query pipeline (tower service stack) |
//! | [`storage`] | SQLite persistence (config, lists, credentials) |
//! | [`telemetry`] | Logging initialisation (tracing subscriber setup) |
//! | [`web`] | axum-based admin HTTP server with askama/Datastar UI |

pub mod app;
pub mod blocklist;
pub mod cli;
pub mod codec;
pub mod config;
pub mod error;
pub mod resolver;
pub mod storage;
pub mod telemetry;
pub mod time;
pub mod web;
