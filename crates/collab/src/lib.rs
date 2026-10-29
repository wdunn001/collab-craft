//! Shared editing for the Craft apps.
//!
//! The relay assigns a strictly increasing sequence to every edit, and each client applies edits
//! in that order. Concurrent work in different regions proceeds freely. Concurrent work in the
//! same region is serialised by a scope lock, unless the command is `crdt.*`. Those carry
//! [`craft_crdt`](https://github.com/storytold/craft-libs) operations (RGA text, fractional
//! keys) and skip the lock: two people can type in the same paragraph and both insertions
//! survive. CAD booleans and renders still take a lock, because they do not commute.
//!
//! Sequence numbers are a delivery order for catch-up. Merge correctness for `crdt.*` comes
//! from character identities and frac keys, not from seq.
//!
//! Four pieces:
//!
//! * [`proto`] is the wire protocol, two enums and nothing else.
//! * [`Session`] orders, deduplicates and tracks locks. It performs no IO and returns [`Effect`]
//!   values describing what the app should do.
//! * [`Hub`] is the transport seam a caller implements, intended for Socket.IO at both ends.
//! * [`crdt`] is the per-scope RGA text replica, and [`Live`] pumps a hub plus those replicas.
//!   That is the shared solution. It does not live in `craft-cloud` (files) and it does not
//!   live in one app's desktop binary.
//!
//! A command is a name plus opaque JSON, matching the `CommandSpec` shape every Craft app already
//! has, and a lock scope is an opaque string each app reads its own way. So nothing here is tied
//! to one app. WordCraft maps a paragraph path. GridCraft maps a cell address. CAD booleans still
//! take a lock.
//!
//! ```
//! use craft_collab::{Effect, Session};
//! use serde_json::json;
//!
//! let mut s = Session::new("doc-42");
//! let _join = s.join("Alice");
//! // …the relay answers, the app feeds messages in, and acts on the effects it gets back.
//! let _ = s.submit("cell.set", json!({"cell": "B2", "input": "7"}), Some("B2".into()));
//! assert_eq!(s.inflight(), 1);
//! # let _ = Effect::Notice { detail: String::new() };
//! ```
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

pub mod crdt;
mod error;
mod hub;
mod live;
pub mod proto;
mod session;
mod token;

/// A [`Hub`] over `rust_socketio`, for native apps.
///
/// Behind a feature, because `rust_socketio` depends on `native-tls` and cannot
/// build for `wasm32`. A browser build leaves it off.
#[cfg(feature = "native-hub")]
pub mod native;

/// A [`Hub`] over the JS `socket.io-client`, for a browser.
///
/// Behind a feature, because it reaches a global the page is expected to have
/// put there and binds nothing at link time. A native build leaves it off.
#[cfg(feature = "web-hub")]
pub mod web;

#[cfg(test)]
mod tests;

pub use crdt::{TextError, TextPayload, Texts, char_pos};
pub use error::{Error, Result};
pub use hub::{EVENTS, Hub, decode, emit, encode, receive};
pub use live::{Live, Work};
pub use proto::{CRDT_POS, CRDT_TEXT, ClientMsg, DocId, LockState, PeerId, Presence, Scope, ServerMsg, is_crdt_command};
pub use session::{Effect, Session};
pub use token::doc_from_token;
