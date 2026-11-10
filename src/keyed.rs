//! The keyed link: how somebody with no account at the provider receives a
//! document.
//!
//! A share aimed at an address nobody holds an account for cannot be opened by
//! signing in, because there is nothing to sign in to. So the service mints a
//! link carrying a one-time key, asks the provider to mail it, and admits
//! whoever presents the key to exactly one room at exactly one permission.
//!
//! The key in the URL is a lookup handle and a secret, never a signed blob
//! carrying the permission. A client holding a blob would hold the grant
//! itself, and withdrawing a share could then not take it back. Here the
//! authority stays in this process: the stored record names the room, and the
//! permission is re-decided against the provider on every request.
//!
//! Three properties are the whole of the security here.
//!
//! The stored record cannot produce a working key. What is stored is an HMAC
//! over the key material under the service secret, so a copy of the datastore
//! yields nothing that opens a document.
//!
//! The comparison is constant time, because [`Mac::verify_slice`] is. A byte
//! comparison would leak the verifier a byte at a time to anybody able to
//! retry, and a landing page is certainly able to retry.
//!
//! Every decision below is a pure function over a record and a clock. That is
//! deliberate: expiry, spending and withdrawal are the cases that matter and
//! none of them should need a datastore or a wall clock to test.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use craft_cloud::{Permission, Share};
// new_from_slice lives on digest::KeyInit in hmac 0.13, not on Mac.
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// How long a key is good for when the deployment does not say.
///
/// A week. Long enough that somebody who reads mail on Monday can open the
/// document on Friday. Short enough that a link forwarded onwards stops
/// working well before anybody has forgotten it exists.
pub const DEFAULT_TTL_HOURS: u64 = 168;

/// The longest a deployment may make a key good for.
///
/// Capped rather than trusted. A key that never expires is a permanent grant
/// nobody remembers issuing.
pub const MAX_TTL_HOURS: u64 = 720;

/// How many times a key may be spent when the deployment does not say.
///
/// Once. A keyed link is addressed to one person, and the second use of it is
/// somebody that person forwarded it to.
pub const DEFAULT_USES: u32 = 1;

/// The most uses a deployment may allow on one key.
pub const MAX_USES: u32 = 50;

/// Bytes of key material. 32, so guessing is not a strategy.
const SECRET_BYTES: usize = 32;

/// Bytes of lookup handle. 16, which is enough to never collide and short
/// enough to keep the link readable.
const HANDLE_BYTES: usize = 16;

/// Why a key was not honoured.
///
/// The variants are for the log, not for the recipient. Which check failed
/// says something about the record, and anybody can present a key.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Refusal {
    #[error("this deployment does not mint keyed links")]
    Disabled,
    #[error("that is not a key")]
    Shape,
    #[error("no such key")]
    Unknown,
    #[error("the key does not match")]
    Mismatch,
    #[error("the key expired at {exp}, now {now}")]
    Expired { exp: i64, now: i64 },
    #[error("the key has been spent {spent} times of {allowed}")]
    Spent { spent: u32, allowed: u32 },
    #[error("the share no longer grants that document")]
    Withdrawn,
    #[error("the document moved out from under the key")]
    Moved,
}

impl Refusal {
    /// What the recipient is told.
    ///
    /// One sentence for every refusal above. A recipient learns that the link
    /// does not work, which is all they can act on, and learns nothing about
    /// whether the key was wrong or the share was withdrawn.
    pub fn public(&self) -> &'static str {
        match self {
            Refusal::Disabled => "this service does not open shared links",
            _ => "this link no longer works. Ask whoever sent it to share the document again",
        }
    }
}

/// What this deployment will do with keyed links.
///
/// Read from the environment, because an organisation that forbids them has to
/// be able to say so without a rebuild. With it off nothing is minted and the
/// capability is reported absent, so a share dialog offers no button rather
/// than offering one that fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    allowed: bool,
    /// Where this service is reached, which is what a link has to point at.
    base: String,
    pub ttl_secs: u64,
    pub max_uses: u32,
}

impl Policy {
    /// Read `COLLABCRAFT_KEYED_LINKS` and its companions.
    pub fn from_env() -> Policy {
        let base = var("COLLABCRAFT_PUBLIC_URL").or_else(|| var("COLLABCRAFT_PUBLIC_RELAY")).unwrap_or_default();
        Policy::decide(
            var("COLLABCRAFT_KEYED_LINKS").as_deref(),
            &base,
            var("COLLABCRAFT_KEYED_LINK_TTL_HOURS").as_deref(),
            var("COLLABCRAFT_KEYED_LINK_USES").as_deref(),
        )
    }

    /// The same decision, over values rather than the environment.
    ///
    /// Separated so the off switch is testable. Reading the environment inside
    /// a test would race every other test in the binary.
    pub fn decide(switch: Option<&str>, base: &str, ttl_hours: Option<&str>, uses: Option<&str>) -> Policy {
        let off = switch.map(str::trim).map(str::to_ascii_lowercase);
        let allowed = !matches!(off.as_deref(), Some("off" | "0" | "false" | "no"));
        let hours = ttl_hours.and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(DEFAULT_TTL_HOURS).clamp(1, MAX_TTL_HOURS);
        let max_uses = uses.and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(DEFAULT_USES).clamp(1, MAX_USES);
        Policy { allowed, base: base.trim().trim_end_matches('/').to_owned(), ttl_secs: hours * 3600, max_uses }
    }

    /// Whether a key may be minted at all.
    ///
    /// A deployment that does not know its own public address cannot write a
    /// link anybody could follow, so that counts as off. Reporting the
    /// capability absent is the honest answer, and the alternative is a button
    /// that produces a link to nowhere.
    pub fn enabled(&self) -> bool {
        self.allowed && !self.base.is_empty()
    }

    /// The link to hand out for one key.
    pub fn url(&self, key: &Key) -> String {
        format!("{}/invite/{}", self.base, key.wire())
    }

    /// Where this service is reached, for a desktop handoff that has to come
    /// back here.
    pub fn base(&self) -> &str {
        &self.base
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// One key, as it travels in a URL.
///
/// Two halves doing two jobs. `handle` finds the record and may safely appear
/// in a key name or a log line. `secret` proves the holder was given the link
/// and is never written down anywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub handle: String,
    secret: String,
}

impl Key {
    /// A fresh key, from the operating system.
    ///
    /// Never a seeded generator. A predictable key is the same defect as no
    /// key at all.
    pub fn mint() -> Key {
        let mut handle = [0u8; HANDLE_BYTES];
        let mut secret = [0u8; SECRET_BYTES];
        getrandom::fill(&mut handle).ok();
        getrandom::fill(&mut secret).ok();
        Key { handle: URL_SAFE_NO_PAD.encode(handle), secret: URL_SAFE_NO_PAD.encode(secret) }
    }

    /// The form that goes in a URL, `handle.secret`.
    pub fn wire(&self) -> String {
        format!("{}.{}", self.handle, self.secret)
    }

    /// Read a key back off a URL.
    ///
    /// Both halves are checked for length before anything is looked up, so a
    /// malformed path never reaches the datastore.
    pub fn parse(raw: &str) -> Result<Key, Refusal> {
        let (handle, secret) = raw.split_once('.').ok_or(Refusal::Shape)?;
        let handle_bytes = URL_SAFE_NO_PAD.decode(handle).map_err(|_| Refusal::Shape)?;
        let secret_bytes = URL_SAFE_NO_PAD.decode(secret).map_err(|_| Refusal::Shape)?;
        if handle_bytes.len() != HANDLE_BYTES || secret_bytes.len() != SECRET_BYTES {
            return Err(Refusal::Shape);
        }
        Ok(Key { handle: handle.to_owned(), secret: secret.to_owned() })
    }

    /// The value stored against this key.
    ///
    /// An HMAC under the service secret rather than the key itself, so the
    /// stored record is useless without this process. Rotating the secret
    /// invalidates every outstanding key, which is the same revocation lever
    /// the join tokens already have.
    pub fn verifier(&self, secret: &[u8]) -> Result<String, Refusal> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).map_err(|_| Refusal::Mismatch)?;
        mac.update(self.material().as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    /// Check this key against a stored verifier, in constant time.
    fn check(&self, secret: &[u8], stored: &str) -> Result<(), Refusal> {
        let expected = URL_SAFE_NO_PAD.decode(stored).map_err(|_| Refusal::Mismatch)?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).map_err(|_| Refusal::Mismatch)?;
        mac.update(self.material().as_bytes());
        mac.verify_slice(&expected).map_err(|_| Refusal::Mismatch)
    }

    /// What the HMAC covers.
    ///
    /// The handle is included so a verifier cannot be replayed under another
    /// handle. The prefix keeps this domain apart from the join tokens, which
    /// are signed with the same secret.
    fn material(&self) -> String {
        format!("keyed-link:{}:{}", self.handle, self.secret)
    }
}

/// What the service remembers about one keyed link.
///
/// No key material and no provider credential. The recipient's address is here
/// because the mail went to it and a sharer reviewing their shares should see
/// who was invited.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Link {
    /// HMAC over the key material. See [`Key::verifier`].
    pub verifier: String,
    /// The collaboration room this key opens, and the only one.
    pub room: String,
    /// The provider's handle for the document. Used by this service on the
    /// recipient's behalf and never sent to them.
    pub doc: String,
    /// Which Craft app opens it. Chosen when the key was minted, so a request
    /// presenting the key cannot ask for a different build.
    pub app: String,
    /// What the sharer asked for. A ceiling rather than an authority: the
    /// grant is re-read from the provider on every request.
    pub permission: Permission,
    /// The address this was minted for.
    pub recipient: String,
    /// Who minted it. Their linked account is what reads the document, which
    /// is why a recipient needs none.
    pub owner: String,
    /// The provider's share. Withdrawing that withdraws this.
    pub share: String,
    /// Unix, after which the key stops working.
    pub exp: i64,
    /// How many times the key may be spent.
    pub max_uses: u32,
}

/// Whether a key may be spent, and for what at most.
///
/// Pure. `spent` is the count already consumed and `now` the clock, both
/// passed in, so expiry and exhaustion are testable without a datastore.
///
/// The order of the checks is the same as the join token's and for the same
/// reason. The verifier comes first, so somebody presenting a key they were
/// never given learns nothing about whether such a record exists, when it
/// expires or how often it has been opened.
pub fn redeem(secret: &[u8], link: &Link, key: &Key, spent: u32, now: i64) -> Result<Permission, Refusal> {
    key.check(secret, &link.verifier)?;
    if link.exp <= now {
        return Err(Refusal::Expired { exp: link.exp, now });
    }
    if spent >= link.max_uses {
        return Err(Refusal::Spent { spent, allowed: link.max_uses });
    }
    Ok(link.permission)
}

/// What the provider still grants, which is the only authority on the matter.
///
/// Called on every request a recipient makes, not once at the landing. A share
/// withdrawn or downgraded five minutes into a session has to take effect in
/// that session, and the only way to know is to ask.
///
/// `room_now` is the room the provider reports for the document today. A
/// document that has become a different room is a different document, so the
/// key does not reach it.
pub fn regrant(link: &Link, room_now: &str, shares: &[Share]) -> Result<Permission, Refusal> {
    if room_now != link.room {
        return Err(Refusal::Moved);
    }
    let still = shares.iter().find(|s| s.id == link.share).ok_or(Refusal::Withdrawn)?;
    // The narrower of the two. A sharer who downgraded the share to read-only
    // downgraded the recipient, and a key minted for editing must not outrank
    // the share it came from.
    Ok(match (link.permission, still.permission) {
        (Permission::Edit, Permission::Edit) => Permission::Edit,
        _ => Permission::View,
    })
}

/// The mail a recipient gets.
///
/// Carries this service's own link and nothing about the provider. A recipient
/// learns that a document was shared and where to open it. They learn no
/// provider name, no provider address and no credential.
pub fn invitation(recipient: &str, sharer: &str, document: &str, url: &str) -> craft_cloud::MailMessage {
    let subject = format!("{sharer} shared {document} with you");
    let body = format!(
        "{sharer} shared a document with you.\n\n{document}\n\nOpen it here:\n{url}\n\n\
         The link is for you alone. It stops working once it has been used, and it expires on its own.\n"
    );
    craft_cloud::MailMessage { to: vec![recipient.to_owned()], subject, body, html: false }
}
