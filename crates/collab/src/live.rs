//! A connected relay session with CRDT text, for native and browser hubs.
//!
//! Apps still map their own document onto scopes (a paragraph path, a cell address, a
//! text-frame id). This type owns the socket, the ordering session, and the text replicas,
//! so WordCraft and GridCraft do not each carry a copy, and a wasm build uses the same
//! code path as a desktop one.

use serde_json::Value;

use crate::crdt::{TextPayload, Texts, space_for};
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
            texts: Texts::new(1),
            notices: Vec::new(),
            roster: Vec::new(),
            was_connected: true,
        }
    }

    /// The text replicas, for seeding from the file and for insert/replace before send.
    pub fn texts(&mut self) -> &mut Texts {
        &mut self.texts
    }

    /// Whether the transport believes it is connected.
    pub fn connected(&self) -> bool {
        self.hub.connected()
    }

    /// Send a lock-free text insert.
    pub fn insert_text(&mut self, scope: &str, char_pos: usize, text: &str) -> Result<()> {
        let ops = self.texts.local_insert(scope, char_pos, text);
        self.send_ops(scope, ops)
    }

    /// Send a lock-free whole-string replacement (a cell, a formula bar).
    pub fn replace_text(&mut self, scope: &str, text: &str) -> Result<()> {
        let ops = self.texts.replace(scope, text);
        self.send_ops(scope, ops)
    }

    /// Send a lock-scoped command. Typing should use [`insert_text`] or [`replace_text`].
    pub fn submit(&mut self, command: impl Into<String>, params: Value, scope: Option<String>) -> Result<()> {
        let msg = self.wire.submit(command, params, scope);
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
            if let Some(peer) = self.wire.me() {
                self.texts.set_space(space_for(peer));
            }
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
        let params = serde_json::to_value(TextPayload { scope: scope.to_owned(), ops })
            .map_err(|e| Error::malformed("client", e.to_string()))?;
        let msg: ClientMsg = self.wire.submit_crdt(CRDT_TEXT, params);
        self.hub.send(msg)
    }

    fn act(&mut self, effect: Effect, work: &mut Vec<Work>) {
        match effect {
            Effect::Apply { command, params } if command == CRDT_TEXT => match serde_json::from_value::<TextPayload>(params) {
                Ok(payload) => {
                    let rendered = self.texts.apply(&payload.scope, &payload.ops);
                    work.push(Work::Text { scope: payload.scope, rendered });
                }
                Err(e) => {
                    log::warn!("collab: a crdt.text payload did not decode: {e}");
                    self.notices.push("could not apply a change from another editor".to_owned());
                }
            },
            Effect::Apply { command, params } => work.push(Work::Command { command, params }),
            Effect::Confirmed { .. } => {}
            Effect::Replace { document, seq } => {
                if document.is_null() {
                    log::debug!("collab: resynced to seq {seq} with no snapshot");
                } else {
                    log::warn!("collab: a snapshot arrived at seq {seq} and this app cannot install one yet");
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
