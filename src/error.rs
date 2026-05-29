//! Crate-wide error strategy.
//!
//! # Convention
//!
//! Each module defines its own typed error enum (e.g. [`config::Error`],
//! [`codec::Error`]) using [`thiserror`]. The top-level [`Error`] enum
//! collects them all via `#[from]` conversions so module errors can be
//! propagated with `?` across module boundaries.
//!
//! [`anyhow`] is reserved exclusively for the `main` binary entry point —
//! never used inside the library.
//!
//! The [`Result`] alias defaults the error to [`Error`] so call sites can
//! write `crate::error::Result<T>` (or just `Result<T>` with a re-export).

use crate::{codec, config, resolver, storage, web};

/// Top-level crate error, wrapping per-module typed errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Errors originating from the [`config`] module.
    #[error(transparent)]
    Config(#[from] config::Error),

    /// Errors originating from the [`codec`] module.
    #[error(transparent)]
    Codec(#[from] codec::Error),

    /// Errors originating from the [`resolver`] module.
    #[error(transparent)]
    Resolver(#[from] resolver::Error),

    /// Errors originating from the [`storage`] module.
    #[error(transparent)]
    Storage(#[from] storage::Error),

    /// Errors originating from the [`web`] module.
    #[error(transparent)]
    Web(#[from] web::Error),
}

/// Crate-wide [`Result`](std::result::Result) alias that defaults the error
/// type to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
