//! Opaque resource identifiers.
//!
//! All public identifiers are UUIDv7 strings (time-ordered, opaque):
//! database sequences are never exposed through the API.

use uuid::Uuid;

/// Identifier type alias. UUIDv7 rendered canonically, opaque to clients.
pub type Id = Uuid;

/// Generate a new opaque identifier (UUIDv7).
#[must_use]
pub fn new_id() -> Id {
    Uuid::now_v7()
}
