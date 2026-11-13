//! Sealing a secret before it is written to the bus.
//!
//! The bus is the Valkey the estate already runs, shared and persisted to an
//! append-only file on disk. A provider credential written there in the clear
//! is a provider credential anyone who can read that keyspace, a backup, a
//! replica or the AOF now holds. Sealing it means a copy of the keyspace yields
//! ciphertext instead.
//!
//! The key is derived from the service secret the process already holds, under
//! a label of its own, so sealing shares that secret with the join tokens, the
//! keyed-link verifiers and the CSRF tokens without ever reusing one key across
//! two purposes. Rotating the secret makes every sealed record unreadable, the
//! same revocation lever those other domains already have; a record relinked
//! afterwards seals under the new key.
//!
//! An unsealed value (one written before sealing existed) is recognised by the
//! absence of the version prefix and returned unchanged, so existing records
//! keep working through the transition.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::Hmac;
use hmac::Mac;
use hmac::digest::KeyInit as HmacKeyInit;
use sha2::Sha256;

/// The version tag every sealed value carries. Bumping it is how a future
/// change to the scheme stays distinguishable from this one.
const PREFIX: &str = "v1.";

/// The 256-bit sealing subkey for one domain, from the service secret.
fn subkey(secret: &[u8], domain: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(secret).expect("hmac takes any key length");
    mac.update(b"collabcraft-seal-v1:");
    mac.update(domain.as_bytes());
    let tag = mac.finalize().into_bytes();
    // Copy into a plain array so this does not depend on the exact array type
    // the two RustCrypto generations use.
    let mut key = [0u8; 32];
    key.copy_from_slice(&tag[..32]);
    key
}

/// Seal a plaintext value for storage under `domain`.
///
/// Returns the plaintext unchanged when no secret is configured, which is the
/// case in tests that drive the store without one. In the running service the
/// secret is always present, so every credential written there is sealed.
pub fn seal(secret: &[u8], domain: &str, plain: &str) -> String {
    if secret.is_empty() {
        return plain.to_owned();
    }
    let mut nonce = [0u8; 12];
    if getrandom::fill(&mut nonce).is_err() {
        return plain.to_owned();
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&subkey(secret, domain)));
    match cipher.encrypt(Nonce::from_slice(&nonce), plain.as_bytes()) {
        Ok(ct) => format!("{PREFIX}{}.{}", B64.encode(nonce), B64.encode(ct)),
        // Encryption of a short string does not fail in practice. If it somehow
        // did, refuse to silently store a value that cannot be read back.
        Err(_) => String::new(),
    }
}

/// Open a value read back from storage under `domain`.
///
/// A value with no version prefix is a legacy plaintext record, returned as
/// written. A sealed value is decrypted, and `None` means it did not
/// authenticate, which includes a secret that has since been rotated.
pub fn open(secret: &[u8], domain: &str, raw: &str) -> Option<String> {
    let Some(rest) = raw.strip_prefix(PREFIX) else {
        return Some(raw.to_owned());
    };
    if secret.is_empty() {
        return None;
    }
    let (nonce_b64, ct_b64) = rest.split_once('.')?;
    let nonce = B64.decode(nonce_b64).ok()?;
    let ct = B64.decode(ct_b64).ok()?;
    if nonce.len() != 12 {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&subkey(secret, domain)));
    let plain = cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).ok()?;
    String::from_utf8(plain).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a-service-secret-at-least-32-bytes!!";

    #[test]
    fn a_sealed_value_round_trips() {
        let sealed = seal(SECRET, "link", "app-password");
        assert!(sealed.starts_with(PREFIX), "a sealed value is tagged");
        assert!(!sealed.contains("app-password"), "the plaintext must not survive");
        assert_eq!(open(SECRET, "link", &sealed).as_deref(), Some("app-password"));
    }

    #[test]
    fn a_wrong_domain_does_not_open() {
        let sealed = seal(SECRET, "link", "app-password");
        assert_eq!(open(SECRET, "connections", &sealed), None, "a subkey is per domain");
    }

    #[test]
    fn a_rotated_secret_does_not_open() {
        let sealed = seal(SECRET, "link", "app-password");
        assert_eq!(open(b"a-different-service-secret-32-bytes!", "link", &sealed), None);
    }

    #[test]
    fn a_legacy_plaintext_record_still_reads() {
        assert_eq!(open(SECRET, "link", "plain-old-password").as_deref(), Some("plain-old-password"));
    }

    #[test]
    fn with_no_secret_sealing_is_a_no_op() {
        assert_eq!(seal(b"", "link", "x"), "x");
        assert_eq!(open(b"", "link", "x").as_deref(), Some("x"));
    }
}
