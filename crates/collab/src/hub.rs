//! The transport seam.
//!
//! A [`Hub`] is whatever carries the protocol. The crate never opens a connection, exactly as
//! `craft-nextcloud` never opens a socket, so one session implementation serves every target.
//!
//! The intended implementations are Socket.IO on both sides, which is where the Hub and
//! subscriber shape comes from. A native app drives `rust_socketio`. A browser build drives the
//! official `socket.io-client` through `wasm-bindgen`, because `rust_socketio` depends on
//! `native-tls` with no target-gated alternative and therefore cannot build for `wasm32`.
//!
//! Rooms do the subscribing. One room per document, which is how a relay fans an edit out to
//! exactly the peers holding that document open.
//!
//! [`emit`] and [`receive`] are the whole of the encoding, and both hubs use them. A host writing
//! a hub of its own uses them too, rather than working out which event name carries which message
//! a second time.

use crate::error::Result;
use crate::proto::{ClientMsg, ServerMsg};

/// A connection to the relay.
///
/// `send` is fire and forget. Ordering is the relay's job, and the session tolerates arrival out
/// of order, so an implementation needs no queue of its own.
///
/// `poll` is non-blocking and returns what has arrived since the last call. That suits an egui
/// app, which wants to drain messages once per frame rather than be called back on another
/// thread.
pub trait Hub {
    fn send(&mut self, msg: ClientMsg) -> Result<()>;

    /// Messages received since the previous call, oldest first.
    fn poll(&mut self) -> Vec<ServerMsg>;

    /// Whether the transport believes it is connected. A session stays usable across a brief
    /// disconnect, because the relay re-sends on rejoin.
    fn connected(&self) -> bool;
}

/// Every event the relay can send.
///
/// Listed explicitly because a Socket.IO client registers one callback per event name, so a hub
/// has to know the whole set before anything arrives. An event missing from here is an event
/// nobody is listening for, which looks like a relay that connects and then says nothing.
pub const EVENTS: [&str; 11] =
    ["joined", "op", "lock_granted", "lock_denied", "lock_released", "presence", "snapshot", "text_ops", "frame", "ephemeral", "error"];

/// Encode a client message as the JSON a Socket.IO event carries.
pub fn encode(msg: &ClientMsg) -> Result<String> {
    serde_json::to_string(msg).map_err(|e| crate::error::Error::malformed("client", e.to_string()))
}

/// Decode one relay payload.
pub fn decode(payload: &str) -> Result<ServerMsg> {
    serde_json::from_str(payload).map_err(|e| crate::error::Error::malformed("server", e.to_string()))
}

/// The event name and body for one client message.
///
/// The relay keys handlers on the event name and reads the document from the peer's token, so the
/// body carries only what the event needs.
pub fn emit(msg: &ClientMsg) -> (&'static str, serde_json::Value) {
    match msg {
        ClientMsg::Join { display, .. } => ("join", serde_json::json!({ "display": display })),
        ClientMsg::Leave { .. } => ("leave", serde_json::Value::Null),
        ClientMsg::Submit { local, command, params, scope, .. } => {
            ("submit", serde_json::json!({ "local": local, "command": command, "params": params, "scope": scope }))
        }
        ClientMsg::Lock { scope, .. } => ("lock", serde_json::json!({ "scope": scope })),
        ClientMsg::Unlock { scope, .. } => ("unlock", serde_json::json!({ "scope": scope })),
        ClientMsg::Resync { have, .. } => ("resync", serde_json::json!({ "have": have })),
        ClientMsg::Frame { payload, .. } => ("frame", serde_json::json!({ "payload": payload })),
        ClientMsg::Ephemeral { kind, payload, .. } => ("ephemeral", serde_json::json!({ "kind": kind, "payload": payload })),
    }
}

/// One relay payload, read as the message its event name says it is.
///
/// **The event name is the discriminator.** [`ServerMsg`] is a serde-tagged enum on `t`, and the
/// relay emits a bare body under an event name rather than repeating the tag inside it. Socket.IO
/// exists to carry that name, so duplicating it in the payload would be redundant on every
/// message. The tag is injected here before deserialising, which works because every event name
/// is exactly the snake_case name of its variant.
///
/// `None` for anything unreadable. Dropping a message we cannot read beats tearing down a live
/// session over it, and a caller logs it.
pub fn receive(event: &str, mut value: serde_json::Value) -> Option<ServerMsg> {
    match value.as_object_mut() {
        Some(map) => {
            map.insert("t".to_owned(), serde_json::Value::String(event.to_owned()));
        }
        None => {
            log::warn!("{event} payload was not an object");
            return None;
        }
    }
    match serde_json::from_value::<ServerMsg>(value) {
        Ok(msg) => Some(msg),
        Err(e) => {
            log::warn!("unreadable {event} message: {e}");
            None
        }
    }
}
