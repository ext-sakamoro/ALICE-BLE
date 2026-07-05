//! ALICE-BLE: Pure Rust BLE protocol stack.
//!
//! Covers GATT, ATT, L2CAP, advertising, pairing, connection management,
//! UUID handling, and notification/indication support.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::wildcard_imports,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::return_self_not_must_use
)]

pub mod advertising;
pub mod att;
pub mod connection;
pub mod gatt;
pub mod l2cap;
pub mod pairing;
pub mod prelude;
pub mod uuid;
pub mod well_known_uuids;

#[cfg(test)]
mod integration_tests;

// Backward-compat re-exports.
pub use crate::advertising::*;
pub use crate::att::*;
pub use crate::connection::*;
pub use crate::gatt::*;
pub use crate::l2cap::*;
pub use crate::pairing::*;
pub use crate::uuid::*;
pub use crate::well_known_uuids::*;
