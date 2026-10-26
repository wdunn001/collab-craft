//! Per-document state: the sequence, the locks and the roster.
//!
//! This is the arbitration the relay exists for. A message broker can fan
//! traffic out, and several are already running in this estate, but none can
//! assign a monotonic order or decide who holds a scope. That decision has to
//! live in one place with one lock around it, which is here.
//!
//! No IO. The socket layer calls these methods and emits whatever comes back,
//! so every rule below is testable without a connection.

use std::collections::HashMap;

use serde::Serialize;

/// Ops retained per document for replaying to a peer that fell behind.
///
/// Past this a resync is answered with a snapshot instead. The bound matters:
/// an unbounded log is a memory leak with a document-shaped trigger.
pub const HISTORY: usize = 2048;

/// One ordered edit, as the relay recorded it.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Op {
    pub seq: u64,
    pub origin: String,
    /// The sender's own counter, echoed so it can confirm rather than reapply.
    pub local: Option<u64>,
    pub command: String,
    pub params: serde_json::Value,
    pub scope: Option<String>,
}

/// A peer in a document.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Peer {
    pub peer: String,
    pub display: String,
    /// Whether this peer may submit. A reader joins and watches.
    #[serde(skip)]
    pub may_edit: bool,
}

/// One peer's offered edit, before the relay has ordered it.
///
/// Grouped rather than passed as loose arguments, which also stops a caller
/// transposing the two `Option`s or the two strings.
pub struct Submission {
    pub peer_id: String,
    pub may_edit: bool,
    pub command: String,
    pub params: serde_json::Value,
    pub scope: Option<String>,
    pub local: Option<u64>,
}

/// Why a submit or a lock was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The peer holds read only.
    ReadOnly,
    /// Another peer holds the scope.
    Locked { holder: String },
}

impl Refusal {
    pub fn detail(&self) -> String {
        match self {
            Refusal::ReadOnly => "read-only access to this file".to_owned(),
            Refusal::Locked { holder } => format!("{holder} is editing that region"),
        }
    }
}

/// Commands whose payload is a CRDT operation. They never take a region lock.
#[must_use]
pub fn is_crdt_command(command: &str) -> bool {
    command.starts_with("crdt.")
}

/// One document.
///
/// The sequence is NOT assigned here. It comes from an `INCR` against the
/// shared Valkey, so it survives a relay restart and stays unique across
/// instances. A counter living in this struct would reset to 1 on restart, and
/// every connected client would then read the next op as a replay and silently
/// drop it.
#[derive(Default)]
pub struct Room {
    /// Highest sequence this relay has recorded.
    seq: u64,
    /// Recent ops, oldest first, capped at [`HISTORY`].
    history: Vec<Op>,
    /// Sequence of `history[0]`, so a resync knows how far back it can reach.
    first_in_history: u64,
    peers: Vec<Peer>,
    /// scope -> holder.
    locks: HashMap<String, String>,
}

impl Room {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Who holds a scope, as this relay last saw it.
    ///
    /// The authority is the bus, since another instance can grant a lock this
    /// relay never saw. This mirror exists only so [`Room::submit`] can refuse
    /// an edit without a round trip per keystroke.
    pub fn holder_of(&self, scope: &str) -> Option<&str> {
        self.locks.get(scope).map(String::as_str)
    }

    /// Add a peer, replacing any earlier connection with the same id.
    ///
    /// Replacing rather than rejecting matters on a reconnect: the old socket
    /// may not have been reaped yet, and refusing the new one would lock the
    /// user out of their own document until a timeout.
    pub fn join(&mut self, peer: Peer) {
        self.peers.retain(|p| p.peer != peer.peer);
        self.peers.push(peer);
    }

    /// Remove a peer and drop every scope it held.
    ///
    /// Releasing on disconnect is the whole reason a lock is safe to take. A
    /// lock that outlived its holder would wedge the region until a restart.
    pub fn leave(&mut self, peer_id: &str) -> Vec<String> {
        self.peers.retain(|p| p.peer != peer_id);
        let dropped: Vec<String> = self.locks.iter().filter(|(_, holder)| holder.as_str() == peer_id).map(|(scope, _)| scope.clone()).collect();
        for scope in &dropped {
            self.locks.remove(scope);
        }
        dropped
    }

    /// Order an edit, or refuse it.
    ///
    /// A scope held by another peer refuses. A scope held by this peer, or held
    /// by nobody, proceeds. The optimistic case is deliberate: requiring a lock
    /// before every edit would make typing wait for a round trip.
    ///
    /// Commands named `crdt.*` never take a lock. Their payload merges, so a
    /// region lock would only serialize what the CRDT is meant to combine. A
    /// scope on those commands is stripped so a buggy client cannot lock a
    /// paragraph by accident.
    pub fn submit(&mut self, seq: u64, s: Submission) -> Result<Op, Refusal> {
        if !s.may_edit {
            return Err(Refusal::ReadOnly);
        }
        let scope = if is_crdt_command(&s.command) { None } else { s.scope };
        if let Some(scope) = &scope
            && let Some(holder) = self.locks.get(scope)
            && holder != &s.peer_id
        {
            return Err(Refusal::Locked { holder: holder.clone() });
        }

        self.seq = self.seq.max(seq);
        let op = Op { seq, origin: s.peer_id, local: s.local, command: s.command, params: s.params, scope };

        self.history.push(op.clone());
        if self.first_in_history == 0 {
            self.first_in_history = op.seq;
        }
        if self.history.len() > HISTORY {
            self.history.remove(0);
            self.first_in_history += 1;
        }

        Ok(op)
    }

    /// Record a grant the bus already made.
    ///
    /// Arbitration happens in Valkey with `SET NX`, because two relay instances
    /// deciding locally would both say yes to the same scope. This table is the
    /// local mirror, kept so a join payload can list current holders without a
    /// round trip per scope.
    pub fn record_lock(&mut self, peer_id: &str, scope: String) {
        self.locks.insert(scope, peer_id.to_owned());
    }

    /// Note that somebody else holds a scope, learned from a refusal.
    pub fn record_holder(&mut self, scope: String, holder: String) {
        self.locks.insert(scope, holder);
    }

    /// Release a scope, but only if this peer holds it.
    ///
    /// Returns whether anything changed, so the caller only broadcasts a real
    /// release. Silently ignoring somebody else's lock is the safe reading of
    /// an unlock for a scope you do not hold.
    pub fn unlock(&mut self, peer_id: &str, scope: &str) -> bool {
        match self.locks.get(scope) {
            Some(holder) if holder == peer_id => {
                self.locks.remove(scope);
                true
            }
            _ => false,
        }
    }

    /// Ops after `have`, or `None` when the log no longer reaches that far.
    ///
    /// `None` is the caller's cue to send a snapshot. Replaying from a gap we
    /// cannot fill would leave the peer permanently out of order, which is
    /// worse than making it start again.
    pub fn since(&self, have: u64) -> Option<Vec<Op>> {
        if have >= self.seq {
            return Some(Vec::new());
        }
        if self.first_in_history == 0 || have + 1 < self.first_in_history {
            return None;
        }
        Some(self.history.iter().filter(|op| op.seq > have).cloned().collect())
    }
}
