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

/// Bytes of op parameters one document may retain.
///
/// [`HISTORY`] bounds the op count and says nothing about size. A client can put as much JSON
/// in one `params` as the transport will carry, so counting ops alone let one authenticated
/// editor hold an arbitrary multiple of the intended memory per room.
pub const HISTORY_BYTES: usize = 8 * 1024 * 1024;

/// Peers one document may hold at once.
///
/// The value `craft_crdt::Limits` carries. A room is a fan-out set and a roster broadcast, so
/// an unbounded one is quadratic work per join.
pub const MAX_PEERS: usize = 256;

/// Bytes of retained CRDT operations per scope.
///
/// These are what a joining peer is replayed, so they are kept apart from the op history and
/// outlive eviction from it. Past this the scope is marked incomplete, and a joiner is told
/// rather than left believing the file plus the replay is the whole text.
pub const TEXT_BYTES: usize = 2 * 1024 * 1024;

/// Latest-wins values one peer may hold at once.
///
/// A camera and a selection are two kinds. An unbounded set would let one peer grow the room
/// by inventing kind names.
pub const MAX_EPHEMERAL_KINDS: usize = 16;

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

/// Why a submit, a lock or a join was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The peer holds read only.
    ReadOnly,
    /// Another peer holds the scope.
    Locked { holder: String },
    /// The document already holds [`MAX_PEERS`].
    Full,
    /// The message is larger than a document may retain.
    TooLarge { bytes: usize },
}

impl Refusal {
    pub fn detail(&self) -> String {
        match self {
            Refusal::ReadOnly => "read-only access to this file".to_owned(),
            Refusal::Locked { holder } => format!("{holder} is editing that region"),
            Refusal::Full => format!("this document already has {MAX_PEERS} editors"),
            Refusal::TooLarge { bytes } => format!("that change is {bytes} bytes, more than this relay will carry"),
        }
    }
}

/// Retained CRDT operations for one scope.
#[derive(Default)]
pub struct TextLog {
    /// The operations, oldest first, as the clients sent them.
    ops: Vec<serde_json::Value>,
    bytes: usize,
    /// Whether everything since the file was opened is still here.
    complete: bool,
}

impl TextLog {
    /// The operations to replay to a joining peer.
    pub fn ops(&self) -> &[serde_json::Value] {
        &self.ops
    }

    /// Whether the text can be rebuilt from the file plus [`TextLog::ops`].
    pub fn complete(&self) -> bool {
        self.complete
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
    /// Bytes of `params` currently held in [`Room::history`].
    history_bytes: usize,
    /// scope -> the CRDT operations a joining peer needs.
    texts: HashMap<String, TextLog>,
    /// peer -> kind -> the newest value that peer sent.
    ephemeral: HashMap<String, HashMap<String, serde_json::Value>>,
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
    pub fn join(&mut self, peer: Peer) -> Result<(), Refusal> {
        let replacing = self.peers.iter().any(|p| p.peer == peer.peer);
        if !replacing && self.peers.len() >= MAX_PEERS {
            return Err(Refusal::Full);
        }
        self.peers.retain(|p| p.peer != peer.peer);
        self.peers.push(peer);
        Ok(())
    }

    /// The CRDT operations a joining peer needs, per scope.
    pub fn texts(&self) -> &HashMap<String, TextLog> {
        &self.texts
    }

    /// Every peer's newest latest-wins values, for a joining peer.
    ///
    /// Flattened to `(peer, kind, value)` so a caller emits one message each without walking
    /// two maps.
    pub fn ephemeral(&self) -> Vec<(String, String, serde_json::Value)> {
        let mut out: Vec<(String, String, serde_json::Value)> = self
            .ephemeral
            .iter()
            .flat_map(|(peer, kinds)| kinds.iter().map(move |(kind, value)| (peer.clone(), kind.clone(), value.clone())))
            .collect();
        // Sorted so a join payload does not depend on hash order, which makes it testable.
        out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        out
    }

    /// Record one peer's newest value for one kind.
    ///
    /// Latest wins, so the previous value is simply replaced. A peer past
    /// [`MAX_EPHEMERAL_KINDS`] is refused, because kind names are the peer's own and an
    /// unbounded set is a way to grow the room.
    pub fn remember_ephemeral(&mut self, peer_id: &str, kind: &str, value: serde_json::Value) -> Result<(), Refusal> {
        let bytes = value_bytes(&value);
        if bytes > TEXT_BYTES {
            return Err(Refusal::TooLarge { bytes });
        }
        let kinds = self.ephemeral.entry(peer_id.to_owned()).or_default();
        if !kinds.contains_key(kind) && kinds.len() >= MAX_EPHEMERAL_KINDS {
            return Err(Refusal::TooLarge { bytes });
        }
        kinds.insert(kind.to_owned(), value);
        Ok(())
    }

    /// Remove a peer and drop every scope it held.
    ///
    /// Releasing on disconnect is the whole reason a lock is safe to take. A
    /// lock that outlived its holder would wedge the region until a restart.
    pub fn leave(&mut self, peer_id: &str) -> Vec<String> {
        self.peers.retain(|p| p.peer != peer_id);
        // Their camera and selection go with them. A marker left behind would show somebody
        // looking at a part they are no longer in.
        self.ephemeral.remove(peer_id);
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
        let bytes = value_bytes(&s.params);
        if bytes > HISTORY_BYTES {
            return Err(Refusal::TooLarge { bytes });
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

        self.retain_text(&op);

        self.history.push(op.clone());
        self.history_bytes += bytes;
        // Both bounds, because either alone leaves the other unbounded: many tiny ops fill the
        // count, and one large op fills the budget.
        while self.history.len() > HISTORY || (self.history_bytes > HISTORY_BYTES && self.history.len() > 1) {
            let gone = self.history.remove(0);
            self.history_bytes = self.history_bytes.saturating_sub(value_bytes(&gone.params));
        }
        // Read from the log itself. Incrementing a mirror assumed the local history was
        // contiguous, and two submits racing for the room lock push out of sequence order.
        self.first_in_history = self.history.first().map_or(0, |op| op.seq);

        Ok(op)
    }

    /// Keep a CRDT operation for a peer that has not joined yet.
    ///
    /// The op history exists to fill a gap in the sequence and is evicted by age. These are
    /// what a joining peer is replayed, so they are kept per scope and survive that eviction.
    /// A scope past [`TEXT_BYTES`] is marked incomplete, which is what lets a joiner be told
    /// the text cannot be rebuilt instead of being handed a partial replay.
    fn retain_text(&mut self, op: &Op) {
        if !is_crdt_command(&op.command) {
            return;
        }
        let Some(scope) = op.params.get("scope").and_then(serde_json::Value::as_str) else {
            return;
        };
        let Some(ops) = op.params.get("ops") else { return };
        let bytes = value_bytes(ops);
        let log = self.texts.entry(scope.to_owned()).or_insert_with(|| TextLog { ops: Vec::new(), bytes: 0, complete: true });
        if log.bytes + bytes > TEXT_BYTES {
            // Dropping the oldest would leave a replay that cannot be applied, because later
            // operations anchor on characters the dropped ones created. Saying so is the only
            // honest answer.
            log.complete = false;
            log.ops.clear();
            log.bytes = 0;
            return;
        }
        log.ops.push(ops.clone());
        log.bytes += bytes;
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

/// How many bytes a JSON value costs to hold.
///
/// Measured by encoding it. A structural estimate would be cheaper and would also be the
/// number an attacker optimises against, and a submit already pays one serialisation to reach
/// the socket.
fn value_bytes(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value).map_or(0, |v| v.len())
}
