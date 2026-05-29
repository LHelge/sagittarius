//! Blocklist ingestion subsystem (SPEC §6).
//!
//! Handles the full lifecycle of external blocklist sources:
//!
//! ```text
//! ┌─────────┐   HTTP(S)   ┌─────────┐   text   ┌───────────┐   merge   ┌────────────┐
//! │ fetch   │ ──────────► │ parse   │ ────────► │ aggregate │ ────────► │  matchset  │
//! └─────────┘             └─────────┘           └───────────┘           └────────────┘
//!      ▲
//!      │ scheduler (periodic refresh)
//! ```
//!
//! Each stage is a separate sub-module, added as the corresponding epic tasks
//! are implemented:
//!
//! | Sub-module | Epic task | Responsibility |
//! |---|---|---|
//! | [`fetch`] | E7.1 | HTTP GET with conditional-request support (ETag / Last-Modified) |
//! | `parse` | E7.2 | Parse `hosts` and `domain-list` formats into `Name` iterators |
//! | `aggregate` | E7.3 | Merge parsed entries into the in-memory [`crate::resolver::matchset`] |
//! | `scheduler` | E7.4 | Periodic refresh loop driven by the storage layer |

pub mod fetch;
