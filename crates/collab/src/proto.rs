//! The relay wire protocol.
//!
//! Two enums, one per direction, both tagged so they survive a JSON round trip. The transport
//! carries them as Socket.IO event payloads, and nothing here knows that.
//!
//! The protocol is deliberately app-agnostic. A command is a name plus opaque JSON, which is the
//! shape every Craft app's `CommandSpec` already has, and a lock [`Scope`] is an opaque string
//! that each app reads its own way. GridCraft puts a cell reference there. WordCraft puts a block
//! path. The relay never interprets either.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A peer, unique for the lifetime of one connection.
pub type PeerId = String;

/// A document, used as the relay room key.
pub type DocId = String;

/// The region a lock covers, as the owning app spells it.
///
/// Opaque on purpose. The relay compares scopes for equality and nothing else, so an app chooses
/// its own granularity: `"B2"` or `"B2:D9"` in GridCraft, `"/body/3"` in WordCraft, a layer id in
/// PhotoCraft. Two scopes that should not collide must not compare equal.
///
/// Commands named `crdt.*` must omit a scope. Their payload is a CRDT operation (RGA text,
/// fractional position) and concurrent edits in the same region are meant to merge. The
/// relay strips a scope if a buggy client sends one. GridCraft cells and SolidCraft
/// feature ops keep using a scope.
pub type Scope = String;

/// A command whose payload is a CRDT operation (`crdt.text`, `crdt.pos`, ...).
#[must_use]
pub fn is_crdt_command(command: &str) -> bool {
    command.starts_with("crdt.")
}

/// Insert or delete characters in one text unit. Payload is `craft_crdt::TextOp`.
pub const CRDT_TEXT: &str = "crdt.text";

/// Insert or move a sibling by fractional key. Payload is a position change.
pub const CRDT_POS: &str = "crdt.pos";

/// Who is in a document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    pub peer: PeerId,
    /// Shown in the UI. A display name, not an identity.
    pub display: String,
}

/// A held lock, as the relay sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockState {
    pub scope: Scope,
    pub holder: PeerId,
}

/// Client to relay.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Enter a document. The relay answers [`ServerMsg::Joined`].
    Join { doc: DocId, display: String },
    /// Leave it. No answer.
    Leave { doc: DocId },
    /// Offer a local edit for ordering.
    ///
    /// `local` is the client's own counter, echoed back in [`ServerMsg::Op`] so the sender can
    /// recognise its own command and confirm it rather than apply it twice.
    Submit {
        doc: DocId,
        local: u64,
        command: String,
        params: Value,
        /// The region this edit touches, when the app can name one. The relay refuses the edit
        /// when another peer holds that scope. Must be `None` for [`CRDT_TEXT`] and other
        /// `crdt.*` commands; the relay strips it if present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<Scope>,
    },
    /// Ask for a scope. Answered by [`ServerMsg::LockGranted`] or [`ServerMsg::LockDenied`].
    Lock { doc: DocId, scope: Scope },
    /// Give a scope back.
    Unlock { doc: DocId, scope: Scope },
    /// Ask for everything after `have`. The relay answers with ops, or with
    /// [`ServerMsg::Snapshot`] when it can no longer reach that far back.
    Resync { doc: DocId, have: u64 },
    /// Offer an opaque frame for pass-through. See [`ServerMsg::Frame`].
    ///
    /// Requires edit permission, because a frame carries changes the relay cannot inspect.
    Frame { doc: DocId, payload: String },
    /// Offer latest-wins state about this peer. See [`ServerMsg::Ephemeral`].
    ///
    /// Allowed without edit permission: somebody watching a design should still be able to
    /// say where they are looking.
    Ephemeral { doc: DocId, kind: String, payload: Value },
}

/// Relay to client.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Accepted into a document. `seq` is the relay's current sequence, so the client knows where
    /// it is starting from.
    Joined {
        doc: DocId,
        peer: PeerId,
        seq: u64,
        /// The id space this connection may mint CRDT character ids in. Never 0: space 0 is
        /// the file's own, so every replica that loads the same string agrees on it.
        ///
        /// Granted by the relay, because a client that derived its own could collide with
        /// another peer's and the two would then drop each other's characters. `0` means a
        /// relay too old to grant one, and a client treats that as "no space yet".
        #[serde(default)]
        space: u32,
        roster: Vec<Presence>,
        locks: Vec<LockState>,
    },
    /// CRDT operations a joining peer missed, outside the sequence.
    ///
    /// A joining peer loads the file, which is behind every edit made since it was written.
    /// These are the retained `crdt.*` operations for one scope, replayed so the peer can
    /// reach the text the room is actually editing. They carry no sequence, because the
    /// sequence is already past them and [`Session`](crate::Session) would drop them as
    /// replays.
    ///
    /// `complete` is false when the relay had to drop operations for this scope. The text
    /// cannot be reconstructed then, and the peer has to be told rather than left to believe
    /// it is current.
    TextOps {
        doc: DocId,
        scope: Scope,
        ops: Value,
        complete: bool,
    },
    /// An opaque frame, passed through unread and unordered.
    ///
    /// For a caller that does its own ordering, signing and encryption. The relay assigns no
    /// sequence, keeps no history and never decodes the payload, so a signed hash chain
    /// survives the trip. Never echoed to the sender.
    Frame {
        doc: DocId,
        origin: PeerId,
        /// Base64 of the caller's bytes. The transport is JSON.
        payload: String,
    },
    /// Latest-wins state about one peer, with no place in the document's history.
    ///
    /// A camera, a selection, a caret. `kind` is the caller's own label and the relay keeps
    /// only the newest value per peer and kind, which is what a joining peer is sent. Never
    /// echoed to the sender, never ordered, never journaled.
    Ephemeral {
        doc: DocId,
        origin: PeerId,
        kind: String,
        payload: Value,
    },
    /// An ordered edit. Every peer receives every op, including the one that sent it.
    Op {
        doc: DocId,
        /// The relay's order. Strictly increasing by one.
        seq: u64,
        origin: PeerId,
        /// The sender's own counter, echoed. Meaningless to other peers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local: Option<u64>,
        command: String,
        params: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<Scope>,
    },
    LockGranted {
        doc: DocId,
        scope: Scope,
    },
    /// Refused, with whoever holds it so the UI can say who.
    LockDenied {
        doc: DocId,
        scope: Scope,
        holder: PeerId,
    },
    LockReleased {
        doc: DocId,
        scope: Scope,
    },
    /// The roster changed.
    Presence {
        doc: DocId,
        roster: Vec<Presence>,
    },
    /// Start again from this document state at this sequence.
    ///
    /// Sent when a resync asks for ops the relay has dropped, which is also the recovery path for
    /// a client that fell too far behind.
    Snapshot {
        doc: DocId,
        seq: u64,
        document: Value,
    },
    /// Something was refused. Advisory, and never fatal on its own.
    Error {
        doc: DocId,
        detail: String,
    },
}

impl ServerMsg {
    /// The document every message belongs to.
    pub fn doc(&self) -> &str {
        match self {
            ServerMsg::Joined { doc, .. }
            | ServerMsg::Op { doc, .. }
            | ServerMsg::LockGranted { doc, .. }
            | ServerMsg::LockDenied { doc, .. }
            | ServerMsg::LockReleased { doc, .. }
            | ServerMsg::Presence { doc, .. }
            | ServerMsg::Snapshot { doc, .. }
            | ServerMsg::TextOps { doc, .. }
            | ServerMsg::Frame { doc, .. }
            | ServerMsg::Ephemeral { doc, .. }
            | ServerMsg::Error { doc, .. } => doc,
        }
    }
}
