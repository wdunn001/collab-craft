//! A connected relay session with CRDT text, for native and browser hubs.
//!
//! Apps still map their own document onto scopes (a paragraph path, a cell address, a
//! text-frame id). This type owns the socket, the ordering session, and the text replicas,
//! so WordCraft and GridCraft do not each carry a copy, and a wasm build uses the same
//! code path as a desktop one.
//!
//! # The join sequence an app has to respect
//!
//! 1. The relay grants an id space in its join payload. [`Live`] records it. Nothing may be
//!    typed before that, and [`insert_text`](Live::insert_text) refuses until it arrives.
//! 2. The relay replays the CRDT operations this peer missed, per scope. They are held.
//! 3. The app seeds each scope from the file through [`seed`](Live::seed). The held
//!    operations land on top, and [`seed`] answers with the text to show.
//!
//! The order of 2 and 3 does not matter, which is the point of holding. An app that seeds
//! on first paint and a relay that replays immediately both work.

use serde_json::Value;

use crate::crdt::{TextError, TextPayload, Texts};
use crate::error::{Error, Result};
use crate::hub::Hub;
use crate::proto::{CRDT_TEXT, ClientMsg, ServerMsg};
use crate::session::{Effect, Session};

/// Work the app must do after one [`Live::pump`].
///
/// CRDT text is already merged here. [`Work::Text`] is the rendered string to write into
/// the document. Other commands still go through the app's `apply_remote`.
#[derive(Debug)]
pub enum Work {
    /// A lock-scoped command that is not CRDT text.
    Command { command: String, params: Value },
    /// A text unit after remote ops were applied.
    Text { scope: String, rendered: String },
    /// Load this scope from the file, through [`Live::seed`].
    ///
    /// Raised when operations arrive for a scope this replica has not loaded. The operations
    /// are held until it does, so the app can answer at its own pace.
    SeedWanted { scope: String },
    /// This scope cannot be rebuilt from the file plus what the relay kept.
    ///
    /// The relay dropped operations, so the text has to come from somewhere else. The honest
    /// answers are to leave the collaboration or to reopen the file.
    TextIncomplete { scope: String },
    /// An opaque frame from another peer. The relay did not read it and neither did this crate.
    Frame { origin: String, payload: String },
    /// Latest-wins state about another peer: a camera, a selection, a caret.
    Ephemeral { origin: String, kind: String, payload: Value },
}

/// One live shared-editing link, over any [`Hub`].
pub struct Live<H> {
    hub: H,
    wire: Session,
    texts: Texts,
    /// Lines for the user, drained by the app each frame.
    pub notices: Vec<String>,
    /// Who else is in the document. The identifier comes with the name because a badge's
    /// colour is derived from it.
    pub roster: Vec<(String, String)>,
    was_connected: bool,
}

impl<H: Hub> Live<H> {
    /// Takes an already-connected hub. The relay admits a peer from the token in the
    /// handshake; nothing is sent here on purpose.
    pub fn new(hub: H, doc: impl Into<String>) -> Live<H> {
        Live {
            hub,
            wire: Session::new(doc.into()),
            // No id space until the relay grants one. A default would be a space another peer
            // is also minting in, and the two would drop each other's characters.
            texts: Texts::new(),
            notices: Vec::new(),
            roster: Vec::new(),
            was_connected: true,
        }
    }

    /// The text replicas, for reading a rendered scope.
    pub fn texts(&mut self) -> &mut Texts {
        &mut self.texts
    }

    /// Load one scope from the file and get the text to show.
    ///
    /// The answer already includes any operations that arrived before this call, so a scope
    /// seeded late still shows the room's current text.
    pub fn seed(&mut self, scope: &str, text: &str) -> String {
        self.texts.seed(scope, text)
    }

    /// Whether the relay has granted an id space yet. Typing is refused until it has.
    pub fn ready_to_type(&self) -> bool {
        self.texts.space().is_some()
    }

    /// Whether the transport believes it is connected.
    pub fn connected(&self) -> bool {
        self.hub.connected()
    }

    /// Send a lock-free text insert.
    pub fn insert_text(&mut self, scope: &str, char_pos: usize, text: &str) -> Result<()> {
        let ops = self.texts.local_insert(scope, char_pos, text).map_err(refusal)?;
        self.send_ops(scope, ops)
    }

    /// Send a lock-free text delete.
    pub fn delete_text(&mut self, scope: &str, char_pos: usize, len: usize) -> Result<()> {
        let ops = self.texts.local_delete(scope, char_pos, len).map_err(refusal)?;
        self.send_ops(scope, ops)
    }

    /// Send a lock-free whole-string replacement (a cell, a formula bar).
    pub fn replace_text(&mut self, scope: &str, text: &str) -> Result<()> {
        let ops = self.texts.replace(scope, text).map_err(refusal)?;
        self.send_ops(scope, ops)
    }

    /// Send a lock-scoped command. Typing should use [`insert_text`] or [`replace_text`].
    pub fn submit(&mut self, command: impl Into<String>, params: Value, scope: Option<String>) -> Result<()> {
        let msg = self.wire.submit(command, params, scope);
        self.hub.send(msg)
    }

    /// Pass an opaque frame to the room, unread by the relay.
    ///
    /// For a caller holding its own ordering, signing and encryption. Nothing here inspects
    /// the payload, and the relay keeps no copy.
    pub fn send_frame(&mut self, payload: impl Into<String>) -> Result<()> {
        let msg = self.wire.frame(payload);
        self.hub.send(msg)
    }

    /// Tell the room where this peer is: a camera, a selection, a caret.
    ///
    /// Latest-wins and never journaled. The relay keeps only the newest value per kind and
    /// hands it to a joining peer, so somebody arriving late sees where everyone is without
    /// waiting for them to move.
    pub fn send_ephemeral(&mut self, kind: impl Into<String>, payload: Value) -> Result<()> {
        let msg = self.wire.ephemeral(kind, payload);
        self.hub.send(msg)
    }

    /// One frame of inbound work. Outbound is the app's: it calls insert/replace/submit
    /// first, then this.
    pub fn pump(&mut self) -> Vec<Work> {
        let now = self.hub.connected();
        if now != self.was_connected {
            self.notices.push(if now {
                "reconnected to the other editors".to_owned()
            } else {
                "not connected to the other editors; your edits are waiting".to_owned()
            });
            self.was_connected = now;
        }

        let mut work = Vec::new();
        for msg in self.hub.poll() {
            if matches!(msg, ServerMsg::Joined { .. }) {
                let named = msg.doc().to_owned();
                if named != self.wire.doc() {
                    log::info!("collab: the relay named the room {named}");
                    self.wire = Session::new(named);
                }
            }
            let effects = self.wire.handle(msg);
            for effect in effects {
                self.act(effect, &mut work);
            }
        }
        work
    }

    fn send_ops(&mut self, scope: &str, ops: Vec<craft_crdt::text::TextOp>) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        let params = serde_json::to_value(TextPayload { scope: scope.to_owned(), ops }).map_err(|e| Error::malformed("client", e.to_string()))?;
        let msg: ClientMsg = self.wire.submit_crdt(CRDT_TEXT, params);
        self.hub.send(msg)
    }

    /// Merge one batch of text operations, or note that the scope is not loaded.
    fn merge_text(&mut self, scope: String, ops: &[craft_crdt::text::TextOp], work: &mut Vec<Work>) {
        match self.texts.apply(&scope, ops) {
            Some(rendered) => work.push(Work::Text { scope, rendered }),
            None => work.push(Work::SeedWanted { scope }),
        }
    }

    fn act(&mut self, effect: Effect, work: &mut Vec<Work>) {
        match effect {
            Effect::Space { space } => {
                self.texts.set_space(space);
                log::debug!("collab: the relay granted id space {space}");
            }
            Effect::Apply { command, params } if command == CRDT_TEXT => match serde_json::from_value::<TextPayload>(params) {
                Ok(payload) => self.merge_text(payload.scope, &payload.ops, work),
                Err(e) => {
                    log::warn!("collab: a crdt.text payload did not decode: {e}");
                    self.notices.push("could not apply a change from another editor".to_owned());
                }
            },
            Effect::Apply { command, params } => work.push(Work::Command { command, params }),
            Effect::TextOps { scope, ops, complete } => {
                if !complete {
                    log::warn!("collab: the relay could not keep every change to {scope}");
                    self.notices.push(format!("{scope} has changes this session cannot rebuild; reopen the file"));
                    work.push(Work::TextIncomplete { scope });
                    return;
                }
                match serde_json::from_value::<Vec<craft_crdt::text::TextOp>>(ops) {
                    Ok(ops) => self.merge_text(scope, &ops, work),
                    Err(e) => {
                        log::warn!("collab: replayed operations for {scope} did not decode: {e}");
                        self.notices.push(format!("{scope} could not be caught up; reopen the file"));
                        work.push(Work::TextIncomplete { scope });
                    }
                }
            }
            Effect::Frame { origin, payload } => work.push(Work::Frame { origin, payload }),
            Effect::Ephemeral { origin, kind, payload } => work.push(Work::Ephemeral { origin, kind, payload }),
            Effect::Confirmed { .. } => {}
            Effect::Replace { document, seq } => {
                if document.is_null() {
                    // The relay keeps no document, so this is not a recovery. Saying nothing
                    // and carrying on would leave the peer believing it is current when it has
                    // permanently missed edits.
                    log::warn!("collab: fell too far behind at seq {seq} and the relay holds no document");
                    self.notices.push("this window fell too far behind the other editors; reopen the file to catch up".to_owned());
                } else {
                    log::warn!("collab: a snapshot arrived at seq {seq} and this app cannot install one yet");
                    self.notices.push("the other editors sent a document this window cannot install; reopen the file".to_owned());
                }
            }
            Effect::LockHeld { .. } | Effect::LockDropped { .. } | Effect::RemoteLocks { .. } => {}
            Effect::LockRefused { scope, holder } => {
                self.notices.push(format!("{holder} is editing {scope}"));
            }
            Effect::Roster { roster } => {
                let me = self.wire.me().cloned();
                self.roster = roster.into_iter().filter(|p| Some(&p.peer) != me.as_ref()).map(|p| (p.peer.to_string(), p.display)).collect();
            }
            Effect::Notice { detail } => {
                log::info!("collab: {detail}");
                self.notices.push(detail);
            }
            Effect::Send { msg } => {
                if let Err(e) = self.hub.send(msg) {
                    log::warn!("collab: a resync request never left: {e}");
                }
            }
        }
    }
}

/// A refused text edit, as a transport-level error with the reason kept.
fn refusal(e: TextError) -> Error {
    Error::malformed("client", e.to_string())
}
