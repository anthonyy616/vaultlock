//! Request/resource validation helpers, including path-safety checks used by
//! file uploads, manifests and restore plans (path-traversal protection).

use crate::error::{AppError, AppResult};

/// Validate a relative path used inside vaults or manifests.
///
/// Rejects absolute paths, parent traversal (including encoded dot-dot when
/// shown as raw components), NUL bytes, empty segments, Windows drive letters
/// and reserved traversal characters, so a stored path can always be joined
/// safely on any supported operating system.
///
/// Returns the normalised path (`/`-separated, no leading or trailing slash).
///
/// # Errors
/// [`AppError::Validation`] when the path is unsafe.
pub fn validate_identifier_path(path: &str) -> AppResult<String> {
    if path.is_empty() {
        return Err(AppError::validation("path", "path must not be empty"));
    }
    if path.len() > 4096 {
        return Err(AppError::validation("path", "path is too long"));
    }
    if path.contains(['\0', ':']) {
        return Err(AppError::validation("path", "path contains forbidden characters"));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(AppError::validation("path", "absolute paths are not allowed"));
    }
    if path.contains('\\') {
        return Err(AppError::validation("path", "backslashes are not allowed; use `/`"));
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(AppError::validation("path", "empty path segment"));
        }
        if segment == "." || segment == ".." {
            return Err(AppError::validation("path", "`.` and `..` segments are not allowed"));
        }
        if segment.bytes().any(|b| b < 0x20) {
            return Err(AppError::validation("path", "control characters are not allowed"));
        }
        // Windows reserved device names cannot be treated as plain files later.
        if matches!(segment.split_once('.').map_or(segment, |(stem, _)| stem).to_ascii_uppercase().as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9")
        {
            return Err(AppError::validation("path", "reserved device names are not allowed"));
        }
    }
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_safe_relative_paths() {
        assert_eq!(validate_identifier_path("a/b/c.env").unwrap_or_default(), "a/b/c.env");
        assert_eq!(validate_identifier_path("notes-2026/τora.md").unwrap_or_default(), "notes-2026/τora.md");
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        for bad in ["../secret", "a/../../etc", "/etc/passwd", "C:/env", "a\\\\b", "\0env", "a//b", "a/", "./x", "", "CON"] {
            assert!(validate_identifier_path(bad).is_err(), "expected rejection of {bad:?}");
        }
    }
}
