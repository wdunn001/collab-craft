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

/// Scopes one document may retain CRDT operations for.
///
/// [`TEXT_BYTES`] bounds the bytes within one scope and says nothing about how
/// many scopes there are. A client naming a fresh scope on every edit would
/// otherwise grow a room without limit, one bounded log at a time. A real
/// document has a scope per editable unit, far below this.
pub const MAX_SCOPES: usize = 4096;

/// Bytes of retained CRDT operations a document may hold across every scope.
///
/// [`TEXT_BYTES`] bounds one scope, and [`MAX_SCOPES`] bounds how many scopes
/// exist, but their product is nowhere near a sane room budget: a client that
/// spreads its edits across many near-cap scopes instead of one would
/// otherwise retain gigabytes while every individual check still passes. This
/// is the guard that actually bounds total memory. Set to the same figure as
/// [`HISTORY_BYTES`] on purpose: it is the same per-room budget already
/// accepted for the op history, applied to the other unbounded-by-count pool.
pub const TOTAL_TEXT_BYTES: usize = HISTORY_BYTES;

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
    /// The ordered sequence each op in [`TextLog::ops`] was assigned, so a save
    /// can drop the ones it has baked into the file. Same length as `ops`.
    seqs: Vec<u64>,
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

    /// Drop the operations a save has baked into the file.
    ///
    /// Everything ordered at or before `seq` is now in the saved file, so
    /// replaying it to a joiner who loads that file would apply it a second
    /// time. Only the operations after the save are kept.
    fn drop_through(&mut self, seq: u64) {
        let mut kept_ops = Vec::new();
        let mut kept_seqs = Vec::new();
        let mut bytes = 0;
        for (op, op_seq) in self.ops.drain(..).zip(self.seqs.drain(..)) {
            if op_seq > seq {
                bytes += value_bytes(&op);
                kept_ops.push(op);
                kept_seqs.push(op_seq);
            }
        }
        self.ops = kept_ops;
        self.seqs = kept_seqs;
        self.bytes = bytes;
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
    /// The sequence the saved file reflects, learned from a client's save.
    ///
    /// A joiner loads the file at this version, so it is the baseline the relay
    /// catches a joiner up from: the file plus every op after this is the
    /// current document. Zero until the first save, which is correct, because
    /// before any save the file a joiner loads is the original.
    saved_seq: u64,
    peers: Vec<Peer>,
    /// peer id -> how many live connections hold it.
    ///
    /// A client that reconnects reuses its token, so the same peer id opens a
    /// second socket before the first is reaped. Keyed on the peer id rather
    /// than the socket, a peer stays in the room while any connection holds it,
    /// and the old socket's disconnect cannot evict the live one.
    conns: HashMap<String, usize>,
    /// scope -> holder.
    locks: HashMap<String, String>,
    /// Bytes of `params` currently held in [`Room::history`].
    history_bytes: usize,
    /// scope -> the CRDT operations a joining peer needs.
    texts: HashMap<String, TextLog>,
    /// Bytes of `ops` currently held across every [`Room::texts`] entry, kept so
    /// [`Room::retain_text`] can enforce [`TOTAL_TEXT_BYTES`] without summing every
    /// scope on each submit.
    text_bytes: usize,
    /// peer -> kind -> the newest value that peer sent.
    ephemeral: HashMap<String, HashMap<String, serde_json::Value>>,
}

impl Room {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Raise the recorded sequence to a high-water mark learned from the bus.
    ///
    /// An in-memory room starts at sequence zero. When a relay restarts, or the
    /// last peer left and the room was dropped, the Valkey counter still holds
    /// where the document actually was. Seeding from it on join stops a reopened
    /// document from handing out sequence numbers the clients have already seen,
    /// which is what made a reopen replay or stall edits.
    pub fn observe_seq(&mut self, seq: u64) {
        self.seq = self.seq.max(seq);
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

    /// Add a peer, or a second connection for one already here.
    ///
    /// A reconnect opens a new socket under the same peer id before the old one
    /// is reaped. That counts as a second connection rather than a replacement,
    /// so the peer survives the old socket's later disconnect. The roster entry
    /// is refreshed to the newest connection's display and edit right.
    pub fn join(&mut self, peer: Peer) -> Result<(), Refusal> {
        let already = self.peers.iter().any(|p| p.peer == peer.peer);
        if !already && self.peers.len() >= MAX_PEERS {
            return Err(Refusal::Full);
        }
        *self.conns.entry(peer.peer.clone()).or_insert(0) += 1;
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

    /// Drop one of a peer's connections, and everything it held once the last
    /// one goes.
    ///
    /// Releasing on disconnect is the whole reason a lock is safe to take. A
    /// lock that outlived its holder would wedge the region until a restart. But
    /// a peer with a live reconnect still holds its scope, so the roster entry,
    /// its ephemeral state and its locks are released only when the last
    /// connection leaves. An old socket's disconnect decrements the count and
    /// returns nothing.
    pub fn leave(&mut self, peer_id: &str) -> Vec<String> {
        match self.conns.get_mut(peer_id) {
            Some(count) if *count > 1 => {
                *count -= 1;
                return Vec::new();
            }
            Some(_) => {
                self.conns.remove(peer_id);
            }
            // No tracked connection. Fall through and clean up defensively.
            None => {}
        }
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
    /// A scope past [`TEXT_BYTES`], or a document past [`TOTAL_TEXT_BYTES`] across every scope,
    /// is marked incomplete, which is what lets a joiner be told the text cannot be rebuilt
    /// instead of being handed a partial replay.
    fn retain_text(&mut self, op: &Op) {
        if !is_crdt_command(&op.command) {
            return;
        }
        let Some(scope) = op.params.get("scope").and_then(serde_json::Value::as_str) else {
            return;
        };
        // Flattened, one entry per operation. A payload carries a batch, and keeping the
        // batches nested would hand a joining peer an array of arrays that cannot decode as
        // the operation list it expects.
        let Some(ops) = op.params.get("ops").and_then(serde_json::Value::as_array) else {
            return;
        };
        let bytes: usize = ops.iter().map(value_bytes).sum();
        // A fresh scope past the cap is dropped rather than retained. The edit
        // still orders and broadcasts through the op history; what is refused is
        // only the per-scope replay buffer, so a room cannot be grown without
        // limit by inventing scope names.
        if !self.texts.contains_key(scope) && self.texts.len() >= MAX_SCOPES {
            return;
        }
        let log = self.texts.entry(scope.to_owned()).or_insert_with(|| TextLog { ops: Vec::new(), seqs: Vec::new(), bytes: 0, complete: true });
        // Both bounds, because either alone leaves the other kind of growth unbounded: one
        // scope filled past its own cap, or many scopes each under it but summing past what
        // the room as a whole may hold. `self.text_bytes` still counts this scope's current
        // bytes, which is why the comparison is against the total after adding `bytes` rather
        // than before.
        if log.bytes + bytes > TEXT_BYTES || self.text_bytes + bytes > TOTAL_TEXT_BYTES {
            // Dropping the oldest would leave a replay that cannot be applied, because later
            // operations anchor on characters the dropped ones created. Saying so is the only
            // honest answer.
            log.complete = false;
            self.text_bytes = self.text_bytes.saturating_sub(log.bytes);
            log.ops.clear();
            log.seqs.clear();
            log.bytes = 0;
            return;
        }
        log.ops.extend(ops.iter().cloned());
        // Every op in one submit shares that submit's sequence, which is what a
        // save checkpoint later compares against.
        log.seqs.extend(std::iter::repeat_n(op.seq, ops.len()));
        log.bytes += bytes;
        self.text_bytes += bytes;
    }

    /// Note that the document has been saved up to `seq`.
    ///
    /// Every ordered edit through `seq` is now in the file, so the retained CRDT
    /// operations at or below it are dropped. A joiner that loads the saved file
    /// then receives only the operations after the save, rather than replaying
    /// text the file already contains and seeing it twice.
    ///
    /// `seq` is capped at [`Room::seq`]. It is a client's report of what its own save reflects,
    /// and a save can only reflect edits this room has actually ordered: a claim past that
    /// would move the join baseline ahead of live edits and strand a later joiner, who would
    /// then treat them as already seen and never receive them.
    pub fn checkpoint(&mut self, seq: u64) {
        let seq = seq.min(self.seq);
        self.saved_seq = self.saved_seq.max(seq);
        for log in self.texts.values_mut() {
            log.drop_through(seq);
        }
        // Recomputed rather than tracked through the drop, because `drop_through` already
        // walks every surviving op to rebuild `bytes`; summing here is the same cost repeated
        // once per save, not once per op, and cannot drift from what the scopes actually hold.
        self.text_bytes = self.texts.values().map(|log| log.bytes).sum();
    }

    /// The sequence the saved file reflects. See [`Room::saved_seq`] field.
    ///
    /// The relay joins a peer at this baseline and replays every op after it, so
    /// the peer's file load plus the replay is the current document.
    pub fn saved_seq(&self) -> u64 {
        self.saved_seq
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

    /// Drop a mirrored holder with no peer to match against.
    ///
    /// For when the bus has already confirmed the scope is actually free: a holder's lease
    /// lapsed in Valkey on its own (a crash with no clean unlock), and nothing told this
    /// mirror. Unlike [`Room::unlock`], there is no releasing peer here, because the one who
    /// held it is already gone; the caller already checked the bus itself before reaching for
    /// this.
    pub fn forget_lock(&mut self, scope: &str) {
        self.locks.remove(scope);
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
        let ops: Vec<Op> = self.history.iter().filter(|op| op.seq > have).cloned().collect();
        // The run has to be contiguous from `have + 1`. A hole means a sequence
        // number was burned: allocated from the bus, then the submit refused
        // when a lock landed in the race window. That number never arrives, so a
        // peer replaying across the hole waits for it forever. Report the gap as
        // unreplayable, which is the caller's cue to send a snapshot instead.
        for (expected, op) in (have + 1..).zip(ops.iter()) {
            if op.seq != expected {
                return None;
            }
        }
        Some(ops)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str) -> Peer {
        Peer { peer: id.to_owned(), display: id.to_owned(), may_edit: true }
    }

    #[test]
    fn an_old_socket_disconnect_keeps_a_live_reconnect() {
        // A client reconnects under the same peer id before its first socket is
        // reaped. The old socket's later disconnect must not evict the live peer
        // or hand its lock to somebody else.
        let mut r = Room::default();
        r.join(peer("alice")).unwrap(); // socket A
        r.join(peer("bob")).unwrap();
        r.join(peer("alice")).unwrap(); // socket B, same id, A not yet reaped
        r.record_lock("alice", "B2".to_owned()); // held by the live connection

        let dropped = r.leave("alice"); // socket A disconnects
        let roster: Vec<&str> = r.peers().iter().map(|p| p.peer.as_str()).collect();
        assert!(roster.contains(&"alice"), "the live reconnect must stay: roster={roster:?}");
        assert_eq!(r.holder_of("B2"), Some("alice"), "its lock must not be handed away");
        assert!(dropped.is_empty(), "an old socket's close releases nothing");

        // The live socket's own disconnect does release everything.
        let dropped = r.leave("alice");
        assert_eq!(dropped, vec!["B2".to_owned()]);
        assert!(!r.peers().iter().any(|p| p.peer == "alice"), "the last connection leaving removes the peer");
    }

    fn crdt_sub(peer: &str, scope: &str) -> Submission {
        Submission {
            peer_id: peer.to_owned(),
            may_edit: true,
            command: "crdt.text".to_owned(),
            params: serde_json::json!({ "scope": scope, "ops": [{ "op": "x" }] }),
            scope: None,
            local: None,
        }
    }

    #[test]
    fn a_save_checkpoint_drops_the_operations_the_file_now_holds() {
        // Three text edits are retained. A save reflecting the first two drops
        // them, because the file now carries that text. Only the edit after the
        // save is still replayed, so a joiner loading the file does not apply
        // the saved text a second time.
        let mut r = Room::default();
        r.join(peer("alice")).unwrap();
        r.submit(1, crdt_sub("alice", "/body/0")).unwrap();
        r.submit(2, crdt_sub("alice", "/body/0")).unwrap();
        r.submit(3, crdt_sub("alice", "/body/0")).unwrap();
        assert_eq!(r.texts().get("/body/0").unwrap().ops().len(), 3);

        r.checkpoint(2);
        assert_eq!(r.texts().get("/body/0").unwrap().ops().len(), 1, "only the edit after the save survives");

        // A save reflecting everything leaves nothing to replay.
        r.checkpoint(3);
        assert!(r.texts().get("/body/0").unwrap().ops().is_empty());
    }

    fn plain_sub(peer: &str) -> Submission {
        Submission {
            peer_id: peer.to_owned(),
            may_edit: true,
            command: "cell.set".to_owned(),
            params: serde_json::json!({}),
            scope: None,
            local: None,
        }
    }

    #[test]
    fn since_reports_a_burned_sequence_hole() {
        // Sequence 3 was burned: allocated, then its submit refused. The history
        // holds 1, 2, 4. A replay from 2 cannot be a clean run, so `since`
        // reports the gap rather than handing back [4] that strands a client
        // waiting for 3.
        let mut r = Room::default();
        r.join(peer("alice")).unwrap();
        r.submit(1, plain_sub("alice")).unwrap();
        r.submit(2, plain_sub("alice")).unwrap();
        r.submit(4, plain_sub("alice")).unwrap();
        assert_eq!(r.since(4), Some(Vec::new()), "nothing after the latest");
        let contiguous = r.since(3).map(|ops| ops.iter().map(|o| o.seq).collect::<Vec<_>>());
        assert_eq!(contiguous, Some(vec![4]), "a run with no hole still replays");
        assert_eq!(r.since(2), None, "a hole at 3 is unreplayable");
    }

    #[test]
    fn the_join_baseline_follows_the_save() {
        // A save moves the baseline the relay catches a joiner up from. Before a
        // save it is zero, so a joiner replays from the top of the history. After
        // a save it is the saved sequence, so only the later ops replay.
        let mut r = Room::default();
        r.join(peer("alice")).unwrap();
        r.submit(1, plain_sub("alice")).unwrap();
        r.submit(2, plain_sub("alice")).unwrap();
        assert_eq!(r.saved_seq(), 0);
        let from_top = r.since(r.saved_seq()).map(|ops| ops.iter().map(|o| o.seq).collect::<Vec<_>>());
        assert_eq!(from_top, Some(vec![1, 2]), "with no save, a joiner replays every op");

        r.submit(3, plain_sub("alice")).unwrap();
        r.checkpoint(2);
        assert_eq!(r.saved_seq(), 2);
        let after_save = r.since(r.saved_seq()).map(|ops| ops.iter().map(|o| o.seq).collect::<Vec<_>>());
        assert_eq!(after_save, Some(vec![3]), "after a save, only the later ops replay");
    }

    #[test]
    fn a_checkpoint_past_the_room_s_own_sequence_is_capped() {
        // A client's report of what its save reflects is capped at the room's own sequence.
        // Otherwise a save claiming it covers edits the room never ordered would move the
        // join baseline past live edits and strand a later joiner behind them.
        let mut r = Room::default();
        r.join(peer("alice")).unwrap();
        r.submit(1, plain_sub("alice")).unwrap();
        r.checkpoint(u64::MAX);
        assert_eq!(r.saved_seq(), 1, "the claimed save cannot reach past the room's own sequence");
    }

    #[test]
    fn total_retained_text_bytes_are_bounded_across_scopes() {
        // TEXT_BYTES bounds one scope and MAX_SCOPES bounds how many exist, but their product
        // is far larger than a room should ever hold. Many scopes each under the per-scope cap
        // must still be bounded in total, or a client spreading its edits across scopes grows
        // the room without limit one bounded log at a time.
        let mut r = Room::default();
        r.join(peer("alice")).unwrap();
        let blob = "x".repeat(TEXT_BYTES - 64);
        let mut seq = 0u64;
        for i in 0.. {
            seq += 1;
            let sub = Submission {
                peer_id: "alice".to_owned(),
                may_edit: true,
                command: "crdt.text".to_owned(),
                params: serde_json::json!({ "scope": format!("/s/{i}"), "ops": [blob.clone()] }),
                scope: None,
                local: None,
            };
            r.submit(seq, sub).unwrap();
            if i >= 2 * (TOTAL_TEXT_BYTES / TEXT_BYTES) {
                break;
            }
        }
        let retained: usize = r.texts().values().map(|log| log.bytes).sum();
        assert!(
            retained <= TOTAL_TEXT_BYTES,
            "retained {retained} bytes across {} scopes, more than the room-wide budget of {TOTAL_TEXT_BYTES}",
            r.texts().len()
        );
    }

    #[test]
    fn retained_scopes_are_bounded() {
        // One editor naming a fresh scope on every edit cannot grow the room
        // without limit. Past the cap, a new scope's replay buffer is dropped.
        let mut r = Room::default();
        r.join(peer("alice")).unwrap();
        for i in 0..(MAX_SCOPES + 10) {
            let sub = Submission {
                peer_id: "alice".to_owned(),
                may_edit: true,
                command: "crdt.text".to_owned(),
                params: serde_json::json!({ "scope": format!("/s/{i}"), "ops": [{ "op": "x" }] }),
                scope: None,
                local: None,
            };
            r.submit((i + 1) as u64, sub).unwrap();
        }
        assert_eq!(r.texts().len(), MAX_SCOPES, "the scope count is capped");
    }

    #[test]
    fn a_reopened_room_seeds_its_sequence_from_the_bus() {
        // A fresh room starts at zero. On reopen the bus still holds where the
        // document was, and observe_seq raises the room to it so the next op is
        // in order rather than a replay the client silently drops.
        let mut r = Room::default();
        assert_eq!(r.seq(), 0);
        r.observe_seq(42);
        assert_eq!(r.seq(), 42, "the room must not hand out a sequence number already seen");
        r.observe_seq(10);
        assert_eq!(r.seq(), 42, "a stale read never pushes the counter backwards");
    }
}
