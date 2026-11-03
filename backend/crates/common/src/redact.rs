//! Log redaction helpers.
//!
//! Rule: no code path may ever log passwords, tokens, secret values, private
//! keys or recovery material. Helpers in this module emphasise confidentiality
//! at the logging boundary and are used by the API layer.

/// Marker for values that are safe to log (booleans/counts/metadata only).
pub const REDACTED: &str = "[REDACTED]";

/// Returns a safe display form for a credential: length only, never contents.
#[must_use]
pub fn describe_secret_len(value: impl AsRef<str>) -> String {
    format!("len({})", value.as_ref().chars().count())
}
