//! Landing on a keyed link.
//!
//! Somebody with no account followed a link in their mail. The service
//! redeemed the key, spent one use and set a guest session cookie, then sent
//! the browser to one of the twelve app builds. This module is what that build
//! asks on startup, and it answers one of three things: this is an ordinary
//! visit, this is a keyed link that opened, or this is a keyed link the
//! service refused and here is the sentence to show.
//!
//! # Why it lives here and not in the interface crate
//!
//! The flow is three calls to this service and one socket. Nothing in it
//! draws. [`crate::Client`] already has the three calls and [`craft_collab`]
//! already has the socket, so putting the flow beside them leaves an
//! application with nothing to restate: no route, no cookie, no status code,
//! no version tracking and no ordering.
//!
//! A refusal also has to be readable before any canvas exists. An application
//! that never started has drawn nothing, so the one page a recipient must
//! never miss cannot be drawn by the application's own interface layer.
//! [`refuse`] writes it into the document instead.
//!
//! # What an application still owns
//!
//! Turning bytes into one of its own documents, and pumping its own relay
//! session. Both need the application's document model, and no library can
//! hold that.
//!
//! # What is here on every target
//!
//! [`verdict`] alone, which is the one piece of judgement in the flow: which
//! failures mean a dead link and which mean somebody who is not a recipient.
//! It is a pure function over an error so that it can be tested where there is
//! no browser. Everything else needs one, and lives in `browser`.

use crate::Error;

/// The code the service refuses a key with. See its `recipient::refuse_json`.
///
/// The one answer that means "this browser followed a keyed link and the link
/// is no good". Every other failure means something else, which is why the
/// code is matched rather than the status.
pub const LINK_INVALID: &str = "link_invalid";

/// What the service answers somebody who is signed in. See its
/// `recipient::not_a_recipient`.
///
/// Not a refusal of anything. An account holder has the ordinary routes, which
/// do more, so there is nothing on these ones for them to be refused.
pub const NOT_A_RECIPIENT: &str = "not_a_recipient";

/// What the landing page puts on the query when it hands a browser to an app
/// build. See the service's `recipient::handoff`.
///
/// It proves nothing and grants nothing. The cookie is the whole of the
/// authority. This only says that a keyed link is why this page was loaded, so
/// a service that cannot be reached is reported to the recipient instead of
/// being mistaken for an ordinary visit. Without it a network blip would show
/// somebody an empty document and no reason, which is the one outcome worse
/// than a plain refusal.
pub const MARKER: &str = "invite";

/// What a recipient is told when the service gave no sentence of its own.
const UNEXPLAINED: &str = "this link no longer works. Ask whoever sent it to share the document again";

/// What a failed `invite_token` call means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not a keyed link. The application carries on exactly as it does
    /// otherwise and says nothing about this.
    Ordinary,
    /// A keyed link that is no good, with the sentence the recipient reads.
    Refused(String),
}

/// Which of the two a failure is.
///
/// The service answers a dead key with its own code, and that is a refusal
/// whoever followed the link has to read.
///
/// Somebody signed in gets [`NOT_A_RECIPIENT`], and that is never a refusal.
/// They followed an invitation of their own, they hold more than it grants,
/// and they have the ordinary routes. Telling them the link is broken would be
/// a lie about a link that works.
///
/// `followed` is whether the landing page is what sent this browser here. It
/// decides the cases nothing else explains. A browser known to have followed a
/// link is known to be a recipient, so a service that cannot be reached is
/// reported. A browser that merely reloaded has no such claim on it, and most
/// loads of every app build are ordinary visits.
pub fn verdict(error: &Error, followed: bool) -> Verdict {
    match error {
        Error::Refused { code, detail } if code == LINK_INVALID => Verdict::Refused(public(detail)),
        Error::Refused { code, .. } if code == NOT_A_RECIPIENT => Verdict::Ordinary,
        _ if followed => Verdict::Refused(sentence(error)),
        _ => Verdict::Ordinary,
    }
}

/// The service's own sentence, or one of ours when it gave none.
fn public(detail: &str) -> String {
    let trimmed = detail.trim();
    if trimmed.is_empty() { UNEXPLAINED.to_owned() } else { trimmed.to_owned() }
}

/// One failure as a sentence for a person to read.
///
/// A recipient can act on one thing, which is asking whoever sent the link to
/// send another. An unreachable service is worth telling apart, because that
/// one is worth trying again.
pub fn sentence(error: &Error) -> String {
    match error {
        Error::Refused { code, detail } if code == LINK_INVALID => public(detail),
        Error::Unreachable(detail) => format!("This service could not be reached. {detail}"),
        Error::Refused { detail, .. } => public(detail),
        _ => UNEXPLAINED.to_owned(),
    }
}

/// Whether a query string carries [`MARKER`].
///
/// Here rather than beside the browser's `location`, so a test on any target
/// can show that a parameter merely containing the word does not count.
pub fn followed_a_link(search: &str) -> bool {
    search.trim_start_matches('?').split('&').any(|pair| pair.split('=').next().unwrap_or_default() == MARKER)
}

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
pub use browser::{Arrival, Invitation, Relay, Saver, arrive, arrive_through, refuse};

#[cfg(test)]
mod tests;
