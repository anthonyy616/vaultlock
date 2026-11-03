//! Cryptographic primitives for Vaultlock's hybrid-encryption architecture.
//!
//! This module implements **server-managed envelope encryption (Mode A)**:
//! - Content encryption keys: AES-256-GCM with random 96-bit nonces and AAD.
//! - Key-wrapping: AES-256-GCM used as an AEAD key wrap (KEK wraps DEKs).
//! - Content addressing: HMAC-SHA-256 keyed fingerprints (privacy-preserving
//!   replacement for plaintext content hashes).
//!
//! It does **not** implement hand-rolled cryptography: all primitives come from
//! the RustCrypto ecosystem (`aes-gcm`, `hmac`, `sha2`) which are established,
//! reviewed libraries. Server infrastructure can decrypt Mode A data by design;
//! it is never advertised as zero-knowledge or end-to-end encryption.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

use rand::RngCore;
use rand_core::OsRng;
use zeroize::Zeroize;

use vaultlock_common::error::{AppError, AppResult};

/// Size in bytes of a data-encryption key (256-bit AES key).
pub const DEK_LEN: usize = 32;
/// Size in bytes of a GCM nonce.
pub const NONCE_LEN: usize = 12;
/// Size in bytes of a keyed fingerprint digest (HMAC-SHA-256).
pub const FINGERPRINT_LEN: usize = 32;

/// Encrypt `plaintext` with `dek`, binding `aad` (additional authenticated
/// data used as context). Returns `octets(nonce) || ciphertext+tag`.
///
/// Nonces are always freshly sourced from the OS CSPRNG for every encryption,
/// so the (dek, nonce) pair is never repeated for the same key.
///
/// # Errors
/// [`AppError::Internal`] on internal failures (encryption failure must not
/// disclose details).
pub fn encrypt(dek: &[u8; DEK_LEN], aad: &[u8], plaintext: &[u8]) -> AppResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AppError::Internal)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a payload produced by [`encrypt`]. AAD must match the encryption AAD.
///
/// # Errors
/// Returns [`AppError::Internal`] on tamper detection or malformed payloads
/// (never indicates *which* part failed).
pub fn decrypt(dek: &[u8; DEK_LEN], aad: &[u8], payload: &[u8]) -> AppResult<Vec<u8>> {
    if payload.len() < NONCE_LEN + 16 {
        return Err(AppError::Internal);
    }
    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AppError::Internal)
}

/// Generate a fresh random 32-byte data-encryption key.
#[must_use]
pub fn generate_dek() -> [u8; DEK_LEN] {
    let mut dek = [0u8; DEK_LEN];
    OsRng.fill_bytes(&mut dek);
    dek
}

/// Wrap a DEK using a key-encryption key (AES-256-GCM as AEAD key wrap).
/// AAD binds `key_id` so wrapped material cannot be replayed to another key.
///
/// # Errors
/// [`AppError::Internal`] on failure.
pub fn wrap_key(kek: &[u8; DEK_LEN], key_id: &[u8], dek: &[u8; DEK_LEN]) -> AppResult<Vec<u8>> {
    encrypt(kek, key_id, dek.as_slice())
}

/// Unwrap a DEK previously wrapped by [`wrap_key`].
///
/// The returned key zeroes itself when dropped.
///
/// # Errors
/// [`AppError::Internal`] on authentication failure or malformed input.
pub fn unwrap_key(kek: &[u8; DEK_LEN], key_id: &[u8], wrapped: &[u8]) -> AppResult<ZeroizingDek> {
    let plaintext = decrypt(kek, key_id, wrapped)?;
    plaintext
        .try_into()
        .map_err(|_| AppError::Internal)
        .map(ZeroizingDek)
}

/// A 32-byte DEK that zero-ises on drop.
#[derive(Clone)]
pub struct ZeroizingDek([u8; DEK_LEN]);

impl ZeroizingDek {
    /// Borrow the key bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; DEK_LEN] {
        &self.0
    }

    /// Construct from raw key bytes (zeroises on drop). Callers own the
    /// zeroisation of their source buffers.
    #[must_use]
    pub fn from_inner(dek: [u8; DEK_LEN]) -> Self {
        Self(dek)
    }
}

impl Drop for ZeroizingDek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for ZeroizingDek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Debug must never reveal key material.
        write!(f, "ZeroizingDek(<{} bytes redacted>)", DEK_LEN)
    }
}

/// Compute a privacy-preserving HMAC-SHA-256 fingerprint of content.
///
/// Keyed fingerprints prevent unauthorised parties from confirming the
/// presence of known content (NEQ-vs-EQ probe attacks possible with plain
/// content hashes of secret values).
#[must_use]
pub fn fingerprint(key: &[u8; DEK_LEN], data: &[u8]) -> [u8; FINGERPRINT_LEN] {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Derive a per-vault fingerprint key from the vault DEK (domain separation:
/// `"vaultlock/fingerprint/v1"`), so two vaults with different DEKs cannot
/// correlate content by fingerprint equality.
#[must_use]
pub fn fingerprint_key(dek: &[u8; DEK_LEN]) -> [u8; DEK_LEN] {
    fingerprint(dek, b"vaultlock/fingerprint/v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn roundtrip_and_tamper_detection() {
        let dek = generate_dek();
        let aad = b"context/vault/42";
        let payload = encrypt(&dek, aad, b"DATABASE_URL=postgres://example").unwrap_or_default();
        let decrypt_yes = decrypt(&dek, aad, &payload);
        assert!(decrypt_yes.is_ok());
        assert_eq!(
            decrypt_yes.unwrap_or_default(),
            b"DATABASE_URL=postgres://example"
        );

        let mut tampered = payload.clone();
        tampered[NONCE_LEN + 1] ^= 0x01;
        assert!(decrypt(&dek, aad, &tampered).is_err());

        // AAD mismatch is also an authentication failure.
        assert!(decrypt(&dek, b"context/vault/43", &payload).is_err());
    }

    #[test]
    fn key_wrap_roundtrip_and_error_paths() {
        let kek = generate_dek();
        let dek = generate_dek();
        let wrapped = wrap_key(&kek, b"key-id-1", &dek).unwrap_or_default();
        let unwrapped = unwrap_key(&kek, b"key-id-1", &wrapped);
        assert!(unwrapped.is_ok());
        assert_eq!(unwrapped.unwrap_or_else(|_| panic_dek()).expose(), &dek);

        // Wrong key id → replay protection.
        assert!(unwrap_key(&kek, b"key-id-2", &wrapped).is_err());
        assert!(unwrap_key(&kek, b"key-id-1", &wrapped[..wrapped.len() - 1]).is_err());
    }

    #[allow(clippy::panic)]
    fn panic_dek() -> ZeroizingDek {
        panic!("test contract breached");
    }

    #[test]
    fn fingerprints_are_keyed_and_stable() {
        let dek = generate_dek();
        let fp = fingerprint(&dek, b"secret chunk");
        assert_eq!(hex(&fp).len(), 64);
        let fp2 = fingerprint(&dek, b"secret chunk");
        assert_eq!(fp, fp2);

        // Different key → different fingerprint (cannot correlate vaults).
        let other = generate_dek();
        assert_ne!(fingerprint(&other, b"secret chunk"), fp);

        // A different vault DEK-derived key differs.
        assert_ne!(fingerprint_key(&other), fingerprint_key(&dek));
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let dek = ZeroizingDek(generate_dek());
        let formatted = format!("{dek:?}");
        assert!(!formatted.contains(hex(dek.expose()).as_str()));
        assert!(formatted.contains("redacted"));
    }
}
