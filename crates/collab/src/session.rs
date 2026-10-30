//! The client session: ordering, deduplication and lock bookkeeping.
//!
//! A [`Session`] holds no transport and performs no IO. Feed it [`ServerMsg`] values and it
//! returns [`Effect`] values telling the app what to do. That keeps the hard part, which is
//! ordering, pure and testable, and it means the same logic runs behind a native Socket.IO client
//! and behind the browser's.
//!
//! The ordering rule is the whole design. The relay assigns a strictly increasing `seq` to every
//! edit, and a client applies them in that order and no other. An op that arrives early is held
//! until its predecessors land. An op the client itself sent is confirmed instead of applied,
//! because the app already applied it locally when the user typed.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use crate::proto::{ClientMsg, DocId, LockState, PeerId, Presence, Scope, ServerMsg};

/// Ops held past this many waiting for a gap to fill. Beyond it the session asks for a resync,
/// because a gap that wide means something was lost rather than reordered.
const MAX_PENDING: usize = 512;

/// What the app should do in response to relay traffic.
#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    /// Run this command against the document. It came from another peer and is next in order.
    Apply { command: String, params: Value },
    /// A command this client sent has been ordered. Nothing to apply, the local copy is already
    /// correct, but any optimistic marker on it can be cleared.
    Confirmed { local: u64, seq: u64 },
    /// Replace the whole document, then continue from `seq`.
    Replace { document: Value, seq: u64 },
    /// A lock request succeeded. The app may now edit that scope.
    LockHeld { scope: Scope },
    /// A lock request failed. `holder` is who has it.
    LockRefused { scope: Scope, holder: PeerId },
    /// A scope this client held is no longer held.
    LockDropped { scope: Scope },
    /// Somebody else's lock changed. Useful for showing a region as busy.
    RemoteLocks { locks: Vec<LockState> },
    /// The roster changed.
    Roster { roster: Vec<Presence> },
    /// Tell the user something was refused.
    Notice { detail: String },
    /// Send this back to the relay. The session asks for its own resyncs this way.
    Send { msg: ClientMsg },
    /// The relay granted this connection its CRDT id space.
    ///
    /// Nothing may mint a character id before this arrives, so it is an effect rather than a
    /// field a caller has to remember to read.
    Space { space: u32 },
    /// CRDT operations this peer missed before it joined, for one scope.
    ///
    /// Outside the sequence, so no ordering applies. `complete` false means the relay could
    /// not keep them all and the text cannot be rebuilt from the file plus these.
    TextOps { scope: Scope, ops: Value, complete: bool },
    /// An opaque frame from another peer, unread by the relay and by this session.
    Frame { origin: PeerId, payload: String },
    /// Latest-wins state about another peer.
    Ephemeral { origin: PeerId, kind: String, payload: Value },
}

/// One document's shared-editing state.
pub struct Session {
    doc: DocId,
    me: Option<PeerId>,
    /// Highest sequence applied in order.
    applied: u64,
    /// Ops that arrived before their turn, keyed by sequence.
    pending: BTreeMap<u64, ServerMsg>,
    /// This client's own counter for optimistic edits.
    local: u64,
    /// Local counters submitted and not yet confirmed.
    inflight: HashSet<u64>,
    /// Scopes this client holds.
    held: HashSet<Scope>,
    /// Scopes other peers hold.
    remote_locks: HashMap<Scope, PeerId>,
    roster: Vec<Presence>,
    /// The CRDT id space the relay granted, once it has.
    space: Option<u32>,
}

impl Session {
    /// This session's own peer, once the relay has said who it is.
    ///
    /// A roster arrives with everybody in it, including the reader. A
    /// control showing who else is here has to drop itself from that list,
    /// and it cannot do so without knowing which one it is.
    pub fn me(&self) -> Option<&PeerId> {
        self.me.as_ref()
    }
    pub fn new(doc: impl Into<DocId>) -> Session {
        Session {
            doc: doc.into(),
            me: None,
            applied: 0,
            pending: BTreeMap::new(),
            local: 0,
            inflight: HashSet::new(),
            held: HashSet::new(),
            remote_locks: HashMap::new(),
            roster: Vec::new(),
            space: None,
        }
    }

    /// The CRDT id space the relay granted this connection.
    ///
    /// `None` until the join payload arrives. Minting a character id before then would reuse
    /// another peer's identities.
    pub fn space(&self) -> Option<u32> {
        self.space
    }

    pub fn doc(&self) -> &str {
        &self.doc
    }

    /// This client's peer id, once the relay has assigned one.
    pub fn peer(&self) -> Option<&str> {
        self.me.as_deref()
    }

    /// Highest sequence applied in order.
    pub fn applied(&self) -> u64 {
        self.applied
    }

    pub fn roster(&self) -> &[Presence] {
        &self.roster
    }

    /// Whether this client holds `scope`.
    pub fn holds(&self, scope: &str) -> bool {
        self.held.contains(scope)
    }

    /// Who holds `scope`, when somebody else does.
    pub fn blocked_by(&self, scope: &str) -> Option<&str> {
        self.remote_locks.get(scope).map(String::as_str)
    }

    /// Whether this client may edit `scope` right now.
    ///
    /// An unlocked scope is editable. The optimistic case matters: a scope nobody has claimed is
    /// fair game, and the relay is the arbiter if two peers claim it at once.
    pub fn may_edit(&self, scope: &str) -> bool {
        !self.remote_locks.contains_key(scope)
    }

    /// The message to send when entering the document.
    pub fn join(&self, display: impl Into<String>) -> ClientMsg {
        ClientMsg::Join { doc: self.doc.clone(), display: display.into() }
    }

    /// Ask for a scope.
    pub fn request_lock(&self, scope: impl Into<Scope>) -> ClientMsg {
        ClientMsg::Lock { doc: self.doc.clone(), scope: scope.into() }
    }

    /// Give a scope back. Dropping it locally is immediate, because a release cannot be refused.
    pub fn release_lock(&mut self, scope: impl Into<Scope>) -> ClientMsg {
        let scope = scope.into();
        self.held.remove(&scope);
        ClientMsg::Unlock { doc: self.doc.clone(), scope }
    }

    /// Offer a local edit for ordering.
    ///
    /// The app applies the command locally first and calls this to broadcast it, which is what
    /// makes typing feel immediate. The returned message carries a local counter that comes back
    /// as [`Effect::Confirmed`].
    pub fn submit(&mut self, command: impl Into<String>, params: Value, scope: Option<Scope>) -> ClientMsg {
        self.local += 1;
        self.inflight.insert(self.local);
        ClientMsg::Submit { doc: self.doc.clone(), local: self.local, command: command.into(), params, scope }
    }

    /// Offer a CRDT operation. Always lock-free: `scope` is omitted even if the
    /// caller would have named a region. Use this for [`crate::CRDT_TEXT`] and
    /// other `crdt.*` commands.
    pub fn submit_crdt(&mut self, command: impl Into<String>, params: Value) -> ClientMsg {
        self.submit(command, params, None)
    }

    /// Offer an opaque frame for pass-through.
    ///
    /// Carries no sequence and no local counter. The relay never decodes it and never stores
    /// it, so a caller that signs and orders its own frames keeps both properties.
    pub fn frame(&self, payload: impl Into<String>) -> ClientMsg {
        ClientMsg::Frame { doc: self.doc.clone(), payload: payload.into() }
    }

    /// Offer latest-wins state about this peer, such as a camera or a selection.
    pub fn ephemeral(&self, kind: impl Into<String>, payload: Value) -> ClientMsg {
        ClientMsg::Ephemeral { doc: self.doc.clone(), kind: kind.into(), payload }
    }

    /// How many local edits are awaiting confirmation.
    pub fn inflight(&self) -> usize {
        self.inflight.len()
    }

    /// Feed one relay message in, get the app's work out.
    ///
    /// A message for another document is ignored, so one handler can serve several sessions.
    pub fn handle(&mut self, msg: ServerMsg) -> Vec<Effect> {
        if msg.doc() != self.doc {
            log::debug!("session {} ignoring a message for {}", self.doc, msg.doc());
            return Vec::new();
        }
        match msg {
            ServerMsg::Joined { peer, seq, space, roster, locks, .. } => {
                self.me = Some(peer);
                self.applied = seq;
                self.space = (space > 0).then_some(space);
                self.pending.clear();
                self.roster = roster.clone();
                self.remote_locks.clear();
                self.held.clear();
                let me = self.me.clone().unwrap_or_default();
                for l in &locks {
                    if l.holder == me {
                        self.held.insert(l.scope.clone());
                    } else {
                        self.remote_locks.insert(l.scope.clone(), l.holder.clone());
                    }
                }
                let mut out = vec![Effect::Roster { roster }, Effect::RemoteLocks { locks }];
                if let Some(space) = self.space {
                    out.push(Effect::Space { space });
                } else {
                    log::warn!("doc {}: the relay granted no id space, so shared typing stays off", self.doc);
                }
                out
            }

            op @ ServerMsg::Op { .. } => self.take_op(op),

            ServerMsg::Snapshot { document, seq, .. } => {
                self.applied = seq;
                self.pending.clear();
                // Local edits cannot be reconciled against a document we did not derive, so they
                // are dropped. The snapshot already reflects whatever the relay accepted.
                self.inflight.clear();
                vec![Effect::Replace { document, seq }]
            }

            ServerMsg::LockGranted { scope, .. } => {
                self.remote_locks.remove(&scope);
                self.held.insert(scope.clone());
                vec![Effect::LockHeld { scope }]
            }

            ServerMsg::LockDenied { scope, holder, .. } => {
                self.held.remove(&scope);
                self.remote_locks.insert(scope.clone(), holder.clone());
                vec![Effect::LockRefused { scope, holder }]
            }

            ServerMsg::LockReleased { scope, .. } => {
                self.held.remove(&scope);
                self.remote_locks.remove(&scope);
                vec![Effect::LockDropped { scope }]
            }

            ServerMsg::Presence { roster, .. } => {
                self.roster = roster.clone();
                vec![Effect::Roster { roster }]
            }

            ServerMsg::TextOps { scope, ops, complete, .. } => vec![Effect::TextOps { scope, ops, complete }],

            ServerMsg::Frame { origin, payload, .. } => vec![Effect::Frame { origin, payload }],

            ServerMsg::Ephemeral { origin, kind, payload, .. } => vec![Effect::Ephemeral { origin, kind, payload }],

            ServerMsg::Error { detail, .. } => vec![Effect::Notice { detail }],
        }
    }

    /// Order one op, draining anything it unblocks.
    fn take_op(&mut self, op: ServerMsg) -> Vec<Effect> {
        let Some(seq) = op_seq(&op) else { return Vec::new() };

        // Already seen. The relay re-sends after a reconnect, so this is normal.
        if seq <= self.applied {
            return Vec::new();
        }

        if seq > self.applied + 1 {
            // Out of order. Hold it and wait.
            self.pending.insert(seq, op);
            if self.pending.len() > MAX_PENDING {
                log::warn!("doc {}: {} ops held, asking for a resync", self.doc, self.pending.len());
                self.pending.clear();
                return vec![Effect::Send { msg: ClientMsg::Resync { doc: self.doc.clone(), have: self.applied } }];
            }
            return Vec::new();
        }

        let mut out = Vec::new();
        self.consume(op, &mut out);
        // Drain the run that is now contiguous.
        while let Some(next) = self.pending.remove(&(self.applied + 1)) {
            self.consume(next, &mut out);
        }
        out
    }

    /// Apply or confirm one in-order op.
    fn consume(&mut self, op: ServerMsg, out: &mut Vec<Effect>) {
        let ServerMsg::Op { seq, origin, local, command, params, .. } = op else { return };
        self.applied = seq;

        let mine = self.me.as_deref() == Some(origin.as_str());
        match (mine, local) {
            // Our own edit, coming back ordered. The document already has it.
            (true, Some(local)) => {
                self.inflight.remove(&local);
                out.push(Effect::Confirmed { local, seq });
            }
            // Ours but with no counter, which should not happen. Applying it would duplicate the
            // edit, so it is dropped with a note in the log.
            (true, None) => log::warn!("doc {}: own op at seq {seq} carried no local counter", self.doc),
            (false, _) => out.push(Effect::Apply { command, params }),
        }
    }
}

fn op_seq(op: &ServerMsg) -> Option<u64> {
    match op {
        ServerMsg::Op { seq, .. } => Some(*seq),
        _ => None,
    }
}
