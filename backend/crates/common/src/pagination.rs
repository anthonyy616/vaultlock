//! Pagination conventions shared by all list endpoints.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Query parameters for list endpoints.
#[derive(Debug, Clone, Copy)]
pub struct PageParams {
    /// Maximum number of items returned (1..=100). Defaults to 25.
    pub limit: u32,
    /// Opaque cursor: the page starts strictly after this identifier.
    pub after: Option<Uuid>,
}

impl Default for PageParams {
    fn default() -> Self {
        Self { limit: 25, after: None }
    }
}

impl PageParams {
    /// Clamp free-form limit input into the supported range.
    #[must_use]
    pub fn clamp_limit(input: Option<i64>) -> Self {
        let limit = match input {
            Some(v) if v < 1 => 1,
            Some(v) if v > 100 => 100,
            Some(v) => u32::try_from(v).unwrap_or(25),
            None => 25,
        };
        Self { limit, after: None }
    }
}

/// Query-string form of [`PageParams`], used by Axum extractors.
#[derive(Debug, Clone, Deserialize)]
pub struct PageQuery {
    /// Maximum number of items returned.
    pub limit: Option<i64>,
    /// Opaque cursor for the next page.
    pub after: Option<Uuid>,
}

/// A stable paginated envelope.
#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    /// Items in this page.
    pub items: Vec<T>,
    /// Cursor to pass as `after` for the next page, if more items may exist.
    pub next_cursor: Option<Uuid>,
    /// Whether more items exist beyond this page.
    pub has_more: bool,
}
