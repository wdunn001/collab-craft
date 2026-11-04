//! The shared Valkey, used as the bus and the arbiter.
//!
//! No new message queue. This estate already runs a shared Valkey that
//! Nextcloud itself uses for its distributed cache and file locking, so the
//! relay rides the same instance.
//!
//! These two make the relay safe to run beside another instance. Fan-out does not: an ordered
//! edit reaches the room through the in-process Socket.IO adapter, so a document is served by
//! exactly one relay. The README says so under "One relay per document".
//!
//! Two things live here that cannot live in relay memory:
//!
//! * **The sequence.** `INCR` is atomic, so two relay instances cannot hand out
//!   the same number, and the value survives a relay restart. A counter in
//!   process memory would reset to 1 on restart, and every connected client
//!   would then read the next op as a replay and silently drop it.
//! * **The lock table.** `SET NX` is atomic, so two instances cannot both grant
//!   the same scope. Deciding locally would let them.
//!
//! Everything else stays in relay memory on purpose. The shared instance runs
//! `maxmemory 2gb` with `maxmemory-policy noeviction`, which means a write at
//! the ceiling fails loudly for **every app on it**, Nextcloud included. So the
//! op history is bounded in process and never written here, and both key
//! families carry a TTL.

use std::time::Duration;

use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;

/// Key prefix. Namespaced because the instance is shared, and a bare `doc:1`
/// would be a fine key for somebody else too.
const PREFIX: &str = "collabcraft";

/// How long a sequence counter outlives its last edit.
///
/// Long, because losing it is worse than keeping it. See [`Bus::next_seq`] for
/// why, and for the reseed that makes expiry survivable anyway.
const SEQ_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How long a scope lock survives without a refresh.
///
/// Short, because a crashed relay must not wedge a region. A holder that is
/// still alive refreshes well inside this.
pub const LOCK_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum BusError {
    #[error("valkey: {0}")]
    Redis(#[from] redis::RedisError),

    /// The connection landed on a read-only replica.
    ///
    /// Called out separately because it must never pass quietly. The DNS name
    /// resolves to the primary today, and if a second answer is ever added a
    /// write could land on the replica. A sequence that silently fails to
    /// advance corrupts every client's ordering.
    #[error("valkey is a read-only replica; the relay needs the primary for INCR and SET NX")]
    ReadOnlyReplica,
}

/// Whether a scope was granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockOutcome {
    Granted,
    Held { holder: String },
}

/// A connection to the shared Valkey.
#[derive(Clone)]
pub struct Bus {
    conn: MultiplexedConnection,
}

impl Bus {
    /// Connect.
    ///
    /// `url` carries the database index, as in
    /// `redis://valkey:6379/6`. Index 6 is free: the stack README
    /// allocates 0 through 5 and 8, and the live keyspace also shows 10 and 13
    /// in use. Sharing an index with another app would mean one `FLUSHDB` away
    /// from losing their data or ours.
    pub async fn connect(url: &str) -> Result<Bus, BusError> {
        let client = redis::Client::open(url)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Bus { conn })
    }

    /// Fail now if this connection cannot write.
    ///
    /// Called at startup so a misrouted relay dies immediately with a clear
    /// message, rather than accepting peers and then refusing every edit.
    pub async fn check_writable(&mut self) -> Result<(), BusError> {
        let probe = format!("{PREFIX}:startup-probe");
        match redis::cmd("SET").arg(&probe).arg("1").arg("EX").arg(10i64).query_async::<()>(&mut self.conn).await {
            Ok(()) => Ok(()),
            Err(e) if is_readonly(&e) => Err(BusError::ReadOnlyReplica),
            Err(e) => Err(e.into()),
        }
    }

    /// The next sequence for a document.
    ///
    /// `floor` is the relay's own high-water mark for this document. When the
    /// counter is absent, which happens on first use and after the TTL lapses,
    /// it is seeded to `floor` before the increment. Without that seed an
    /// expired key would hand out 1 again, and a client holding sequence 900
    /// would treat the next hundred ops as replays and drop them all.
    pub async fn next_seq(&mut self, room: &str, floor: u64) -> Result<u64, BusError> {
        let key = format!("{PREFIX}:doc:{}:seq", encode_key(room));

        // NX, so a live counter is never pushed backwards by a late seed.
        let seeded: Result<(), _> = redis::cmd("SET").arg(&key).arg(floor).arg("NX").query_async(&mut self.conn).await;
        if let Err(e) = seeded {
            if is_readonly(&e) {
                return Err(BusError::ReadOnlyReplica);
            }
            return Err(e.into());
        }

        let next: u64 = match self.conn.incr(&key, 1i64).await {
            Ok(v) => v,
            Err(e) if is_readonly(&e) => return Err(BusError::ReadOnlyReplica),
            Err(e) => return Err(e.into()),
        };

        // Refreshed on every edit, so an active document never loses its
        // counter and an abandoned one eventually stops costing memory.
        let _: Result<bool, _> = self.conn.expire(&key, SEQ_TTL.as_secs() as i64).await;

        Ok(next)
    }

    /// The next CRDT id space for a document.
    ///
    /// One `INCR` per connection, from the same instance that hands out sequences, so two
    /// relays cannot grant the same space and a restart cannot hand out one twice. A client
    /// deriving its own space from its peer id could collide with another peer's, and the two
    /// would then mint the same character ids and drop each other's text.
    ///
    /// Space 0 is never granted. That space belongs to the text already in the file, which is
    /// how two peers loading the same string reach the same identities.
    pub async fn next_space(&mut self, room: &str) -> Result<u32, BusError> {
        let key = format!("{PREFIX}:doc:{}:space", encode_key(room));
        let next: u64 = match self.conn.incr(&key, 1i64).await {
            Ok(v) => v,
            Err(e) if is_readonly(&e) => return Err(BusError::ReadOnlyReplica),
            Err(e) => return Err(e.into()),
        };
        let _: Result<bool, _> = self.conn.expire(&key, SEQ_TTL.as_secs() as i64).await;
        // Wrapped rather than refused. The counter would have to pass four billion
        // connections to one document, and a wrapped space collides only with a peer from
        // that many connections ago.
        Ok(((next - 1) % u64::from(u32::MAX)) as u32 + 1)
    }

    /// Claim a scope, or report who holds it.
    ///
    /// `SET NX EX` in one round trip, which is what makes this safe with more
    /// than one relay. Re-granting to the current holder keeps it idempotent,
    /// which a client retrying after a reconnect relies on.
    pub async fn try_lock(&mut self, room: &str, scope: &str, peer: &str) -> Result<LockOutcome, BusError> {
        let key = self.lock_key(room, scope);

        let claimed: Option<String> =
            match redis::cmd("SET").arg(&key).arg(peer).arg("NX").arg("EX").arg(LOCK_TTL.as_secs() as i64).query_async(&mut self.conn).await {
                Ok(v) => v,
                Err(e) if is_readonly(&e) => return Err(BusError::ReadOnlyReplica),
                Err(e) => return Err(e.into()),
            };

        if claimed.is_some() {
            return Ok(LockOutcome::Granted);
        }

        let holder: Option<String> = self.conn.get(&key).await?;
        match holder {
            Some(h) if h == peer => {
                // Ours already. Refresh so holding it does not expire under us.
                let _: Result<bool, _> = self.conn.expire(&key, LOCK_TTL.as_secs() as i64).await;
                Ok(LockOutcome::Granted)
            }
            Some(h) => Ok(LockOutcome::Held { holder: h }),
            // It expired between the SET and the GET. Treat as free and let the
            // caller retry rather than inventing a holder.
            None => Ok(LockOutcome::Granted),
        }
    }

    /// Extend a lock this peer holds. Returns whether it still held it.
    pub async fn refresh_lock(&mut self, room: &str, scope: &str, peer: &str) -> Result<bool, BusError> {
        let key = self.lock_key(room, scope);
        let holder: Option<String> = self.conn.get(&key).await?;
        if holder.as_deref() != Some(peer) {
            return Ok(false);
        }
        let _: Result<bool, _> = self.conn.expire(&key, LOCK_TTL.as_secs() as i64).await;
        Ok(true)
    }

    /// Release a scope, but only when this peer holds it.
    ///
    /// Compare and delete in one script. A plain `GET` then `DEL` could delete
    /// a lock another peer acquired in the gap, which is the classic way to
    /// hand the same region to two editors at once.
    pub async fn release(&mut self, room: &str, scope: &str, peer: &str) -> Result<bool, BusError> {
        const SCRIPT: &str = r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('DEL', KEYS[1])
            else
                return 0
            end
        "#;
        let key = self.lock_key(room, scope);
        let deleted: i64 = match redis::Script::new(SCRIPT).key(&key).arg(peer).invoke_async(&mut self.conn).await {
            Ok(v) => v,
            Err(e) if is_readonly(&e) => return Err(BusError::ReadOnlyReplica),
            Err(e) => return Err(e.into()),
        };
        Ok(deleted > 0)
    }

    /// Every held scope for a document, for a join payload.
    ///
    /// `SCAN` rather than `KEYS`, because this is a shared instance and `KEYS`
    /// blocks the server for every other app on it.
    pub async fn holders(&mut self, room: &str) -> Result<Vec<(String, String)>, BusError> {
        let prefix = format!("{PREFIX}:doc:{}:lock:", encode_key(room));
        let pattern = format!("{prefix}*");
        let mut out = Vec::new();
        let mut cursor: u64 = 0;

        loop {
            let (next, keys): (u64, Vec<String>) =
                redis::cmd("SCAN").arg(cursor).arg("MATCH").arg(&pattern).arg("COUNT").arg(200i64).query_async(&mut self.conn).await?;

            for key in keys {
                // Strip the prefix rather than splitting on the separator. An encoded scope
                // can no longer contain one, and trusting a split cost a mis-reported holder
                // when it could.
                if let Some(encoded) = key.strip_prefix(&prefix)
                    && let Ok(Some(holder)) = self.conn.get::<_, Option<String>>(&key).await
                {
                    out.push((decode_key(encoded), holder));
                }
            }

            cursor = next;
            if cursor == 0 {
                break;
            }
        }

        out.sort();
        Ok(out)
    }

    fn lock_key(&self, room: &str, scope: &str) -> String {
        format!("{PREFIX}:doc:{}:lock:{}", encode_key(room), encode_key(scope))
    }
}

/// Make a room or a scope safe to put in a key.
///
/// A scope is whatever the owning app calls a region, and a room is whatever the provider calls
/// a document. Neither is this module's to constrain. Dropped into a key raw, a scope containing
/// the separator came back out of [`Bus::holders`] as a different scope, and the join payload
/// then marked the wrong region busy. A room containing one could reach into another document's
/// keys altogether.
///
/// Everything outside the unreserved set is escaped, so the result holds no `:` and no glob
/// character and the round trip is exact.
fn encode_key(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Read back what [`encode_key`] wrote.
fn decode_key(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether an error is Valkey refusing a write on a replica.
fn is_readonly(err: &redis::RedisError) -> bool {
    err.code() == Some("READONLY") || err.to_string().contains("READONLY")
}
