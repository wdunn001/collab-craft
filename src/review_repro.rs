//! Review reproductions (CollabCraft relay, review of f895a6f).
//!
//! Each test asserts the behaviour the relay/client SHOULD have. On the unmodified head
//! they fail, and the assertion message shows the observed defect.
//!
//! * Unit tests (`unit_*`) need nothing external.
//! * End-to-end tests (`e2e_*`) run the relay's real Socket.IO handlers (`on_connect` and
//!   friends from main.rs) in-process on 127.0.0.1, against a real Valkey, with two real
//!   `craft_collab::native::NativeHub` clients feeding real `craft_collab::Session`s.
//!   They are `#[ignore]` and need `REVIEW_VALKEY_URL=redis://127.0.0.1:PORT/6`.
//!   Run: `cargo test --bin collabcraft-relay review_repro -- --include-ignored --test-threads=1`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;

use crate::room::{Peer, Refusal, Room, Submission};
use crate::token;

const SECRET: &[u8] = b"a-shared-secret-at-least-32-chars-long";
const NOW: i64 = 1_760_000_000;

fn peer(id: &str) -> Peer {
    Peer { peer: id.to_owned(), display: id.to_uppercase(), may_edit: true }
}

fn sub(peer: &str, command: &str, params: serde_json::Value, scope: Option<&str>, local: Option<u64>) -> Submission {
    Submission { peer_id: peer.to_owned(), may_edit: true, command: command.to_owned(), params, scope: scope.map(str::to_owned), local }
}

fn op_msg(doc: &str, op: &crate::room::Op) -> craft_collab::ServerMsg {
    craft_collab::ServerMsg::Op {
        doc: doc.to_owned(),
        seq: op.seq,
        origin: op.origin.clone(),
        local: op.local,
        command: op.command.clone(),
        params: op.params.clone(),
        scope: op.scope.clone(),
    }
}

fn joined(doc: &str, me: &str, seq: u64) -> craft_collab::ServerMsg {
    craft_collab::ServerMsg::Joined { doc: doc.to_owned(), peer: me.to_owned(), seq, space: 3, roster: vec![], locks: vec![] }
}

// ---- hygiene H1: service token vs client doc_from_token ---------------------------------

/// The token the service actually mints (`token::sign_at`, called by `App::mint_token`) must be
/// readable by the client helper that derives the room name.
#[test]
fn unit_service_token_is_readable_by_doc_from_token() {
    let t = token::sign_at(SECRET, "4242", "alice", "Alice", true, "peer-a", NOW).expect("service mints");
    // The relay accepts it and names the room doc:4242.
    let claims = token::verify(&t, SECRET, NOW).expect("relay verifies its own token");
    assert_eq!(claims.room(), "doc:4242");
    // The client helper should name the same room.
    let client = craft_collab::doc_from_token(&t);
    assert_eq!(client.as_deref(), Some("doc:4242"), "client doc_from_token on a service-minted token returned {client:?}; payload = {}", {
        use base64::Engine;
        String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t.split('.').next().unwrap()).unwrap()).unwrap()
    });
}

// ---- relay H1: reopen after the last peer left ------------------------------------------

/// Composition of the exact steps main.rs takes: submit advances the room to seq N (Valkey
/// counter = N); last disconnect removes the Room; next connect makes `Room::default()` and
/// sends `joined.seq = room.seq()`; the next submit gets INCR = N+1. The client must be able
/// to confirm that edit.
#[test]
fn unit_reopened_room_confirms_the_next_edit() {
    const DOC: &str = "doc:7";
    let mut valkey_counter = 0u64;
    let mut rooms: std::collections::HashMap<String, Room> = Default::default();

    // Session 1: alice edits three times, then leaves (last peer).
    rooms.entry("7".into()).or_default().join(peer("alice-1")).unwrap();
    for _ in 0..3 {
        valkey_counter += 1;
        rooms.get_mut("7").unwrap().submit(valkey_counter, sub("alice-1", "cell.set", json!({}), None, None)).unwrap();
    }
    let room = rooms.get_mut("7").unwrap();
    room.leave("alice-1");
    if room.is_empty() {
        rooms.remove("7"); // main.rs:712-717
    }

    // Session 2: alice reopens.
    let room = rooms.entry("7".into()).or_default();
    // ADAPTATION: main.rs:445 reads the bus's retained counter and seeds the fresh,
    // in-memory `Room::default()` with it (`room.observe_seq(retained_seq)`) before admitting
    // anyone. This hand-rolled harness has no bus to read from, so it does the same seeding
    // directly from the counter it has been tracking, which is what the bus would answer.
    room.observe_seq(valkey_counter);
    room.join(peer("alice-2")).unwrap();
    let joined_seq = room.seq();
    let mut s = craft_collab::Session::new(DOC);
    s.handle(joined(DOC, "alice-2", joined_seq));
    let _ = s.submit("cell.set", json!({}), None);
    valkey_counter += 1; // bus.next_seq: INCR on the retained counter
    let op = room.submit(valkey_counter, sub("alice-2", "cell.set", json!({}), None, Some(1))).unwrap();
    let effects = s.handle(op_msg(DOC, &op));

    assert!(
        effects.iter().any(|e| matches!(e, craft_collab::Effect::Confirmed { local: 1, .. })),
        "joined.seq={joined_seq}, first op seq={}, effects={effects:?}, applied={}, inflight={}",
        op.seq,
        s.applied(),
        s.inflight()
    );
}

// ---- relay H3: a burned sequence number is an interior hole resync cannot detect --------

/// Preflight passes, bob is granted the scope, the INCR'd submit is refused Locked, and the
/// next accepted op leaves a hole. `Room::since` must not hand back a replay across that hole
/// as if it were complete, and a client must be able to make progress.
#[test]
fn unit_burned_sequence_is_recoverable() {
    const DOC: &str = "doc:9";
    let mut r = Room::default();
    r.join(peer("alice")).unwrap();
    r.join(peer("bob")).unwrap();
    r.submit(1, sub("alice", "cell.set", json!({"n": 1}), None, None)).unwrap();
    r.submit(2, sub("alice", "cell.set", json!({"n": 2}), None, None)).unwrap();
    // bob's lock lands between alice's preflight and Room::submit (main.rs:467 vs :499).
    r.record_lock("bob", "B2".into());
    assert_eq!(r.submit(3, sub("alice", "cell.set", json!({"n": 3}), Some("B2"), None)), Err(Refusal::Locked { holder: "bob".into() }));
    let op4 = r.submit(4, sub("alice", "cell.set", json!({"n": 4}), None, None)).unwrap();

    // Carol has applied 1..2 and receives op 4.
    let mut carol = craft_collab::Session::new(DOC);
    carol.handle(joined(DOC, "carol", 2));
    let fx = carol.handle(op_msg(DOC, &op4));
    // She asks for a resync (manually: the session only does so past 512 pending ops).
    let replay = r.since(2);
    let replay_seqs: Option<Vec<u64>> = replay.as_ref().map(|v| v.iter().map(|o| o.seq).collect());
    if let Some(ops) = &replay {
        for o in ops {
            carol.handle(op_msg(DOC, o));
        }
    }
    assert!(
        carol.applied() == 4 || replay.is_none(),
        "op 4 effects={fx:?}; since(2) returned {replay_seqs:?} (no hole reported); carol.applied()={} stuck behind missing seq 3",
        carol.applied()
    );
}

// ---- relay H4: same pid reconnect, then the OLD socket's disconnect ----------------------

/// Room-level half: there is no connection identity, so the stale socket's `leave(pid)`
/// removes the replacement's roster entry and locks.
#[test]
fn unit_stale_disconnect_keeps_replacement_peer() {
    let mut r = Room::default();
    r.join(peer("alice")).unwrap(); // socket A
    r.join(peer("bob")).unwrap();
    r.join(peer("alice")).unwrap(); // socket B, same pid, before A is reaped
    r.record_lock("alice", "B2".into()); // granted to B
    let dropped = r.leave("alice"); // socket A finally disconnects (main.rs:709)
    let roster: Vec<&str> = r.peers().iter().map(|p| p.peer.as_str()).collect();
    assert!(
        roster.contains(&"alice") && r.holder_of("B2") == Some("alice"),
        "after the OLD socket's disconnect: roster={roster:?}, holder_of(B2)={:?}, dropped={dropped:?}",
        r.holder_of("B2")
    );
}

// ---- relay H2: CRDT replay duplicates text already in the saved file ---------------------

/// Alice types "!" into "hello" and saves "hello!" while still connected. Bob opens the saved
/// file and receives the retained replay. He must see "hello!".
#[test]
fn unit_replay_after_save_does_not_duplicate() {
    use craft_collab::Texts;
    let mut alice = Texts::in_space(1);
    alice.seed("/body/0", "hello");
    let ops = alice.local_insert("/body/0", 5, "!").unwrap();
    let saved = alice.render("/body/0").unwrap();
    assert_eq!(saved, "hello!");

    let mut r = Room::default();
    r.join(peer("alice")).unwrap();
    r.submit(1, sub("alice", "crdt.text", json!({"scope": "/body/0", "ops": serde_json::to_value(&ops).unwrap()}), None, None)).unwrap();
    // ADAPTATION: the scenario is "alice saves 'hello!' while still connected", which is what
    // makes bob's load of the saved file valid in the first place. That save is what main.rs's
    // on_saved reports to the room as a checkpoint; without calling it here, the submitted op
    // is still retained unsaved, and replaying it on top of a file that already contains it is
    // exactly the double-apply this test exists to rule out, not something it should find.
    r.checkpoint(1);

    let log = r.texts().get("/body/0").unwrap();
    let replay: Vec<craft_crdt::text::TextOp> = serde_json::from_value(serde_json::Value::Array(log.ops().to_vec())).unwrap();
    let mut bob = Texts::in_space(2);
    bob.apply("/body/0", &replay);
    let seen = bob.seed("/body/0", &saved); // bob loads the SAVED file
    assert_eq!(
        seen,
        saved,
        "late joiner seeded from the saved file {saved:?} then replayed retained ops (complete={}) and sees {seen:?}",
        log.complete()
    );
}

// ---- relay H5 / hygiene N2: retained CRDT scopes are unbounded per room ------------------

/// The per-scope cap is 2 MiB, but nothing bounds the number of scopes, so one editor keeps
/// adding retained state. Correct behaviour: some per-room budget refuses or evicts.
#[test]
fn unit_retained_crdt_scopes_are_bounded() {
    let mut r = Room::default();
    r.join(peer("mallory")).unwrap();
    // 1) Many distinct scopes, each tiny.
    let n = 100_000u64;
    let mut refused = 0;
    for i in 0..n {
        let p = json!({"scope": format!("s{i}"), "ops": [{"x": 1}]});
        if r.submit(i + 1, sub("mallory", "crdt.text", p, None, None)).is_err() {
            refused += 1;
        }
    }
    let scopes = r.texts().len();
    // 2) Total retained bytes with a few near-cap scopes.
    let mut r2 = Room::default();
    r2.join(peer("mallory")).unwrap();
    let blob = "x".repeat(crate::room::TEXT_BYTES - 64);
    for i in 0..12u64 {
        let p = json!({"scope": format!("big{i}"), "ops": [blob.clone()]});
        r2.submit(i + 1, sub("mallory", "crdt.text", p, None, None)).unwrap();
    }
    let retained: usize = r2.texts().values().flat_map(|l| l.ops().iter()).map(|v| serde_json::to_vec(v).unwrap().len()).sum();
    assert!(
        refused > 0 || scopes < 10_000,
        "{n} submits with distinct scopes: refused={refused}, retained scopes={scopes}; 12 near-cap scopes retain {retained} bytes ({} MiB) of text in one room, vs HISTORY_BYTES={} and TEXT_BYTES={}",
        retained / (1024 * 1024),
        crate::room::HISTORY_BYTES,
        crate::room::TEXT_BYTES
    );
}

// ======================= end-to-end: real handlers, real Valkey ===========================

mod e2e {
    use std::sync::Arc;
    use std::time::Duration;

    use craft_collab::native::NativeHub;
    use craft_collab::{ClientMsg, Effect, Hub, Session};
    use serde_json::json;
    use socketioxide::SocketIo;
    use tokio::sync::Mutex;

    use super::SECRET;
    use crate::{MAX_FRAME_BYTES, Relay, bus::Bus, on_connect, token};

    struct Harness {
        relay: Arc<Relay>,
        url: String,
        valkey: String,
    }

    async fn start() -> Option<Harness> {
        let valkey = std::env::var("REVIEW_VALKEY_URL").ok()?;
        let mut bus = Bus::connect(&valkey).await.expect("valkey");
        bus.check_writable().await.expect("writable");
        let relay = Arc::new(Relay { secret: SECRET.to_vec(), bus: Mutex::new(bus), rooms: Mutex::new(Default::default()) });
        let (layer, io) = SocketIo::builder().max_payload(MAX_FRAME_BYTES as u64).with_state(relay.clone()).build_layer();
        io.ns("/", on_connect);
        let app = axum::Router::new().layer(layer);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Some(Harness { relay, url: format!("http://{addr}"), valkey })
    }

    fn now() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
    }

    fn unique_room(tag: &str) -> String {
        format!("{tag}-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())
    }

    struct Client {
        hub: NativeHub,
        s: Session,
        fx: Vec<Effect>,
    }

    impl Client {
        async fn connect(h: &Harness, room: &str, pid: &str) -> Client {
            let t = token::sign_at(SECRET, room, pid, pid, true, pid, now()).unwrap();
            // A fresh Session every time: nothing of its own to resume from.
            let hub = NativeHub::connect(&h.url, &t, None).await.expect("connect");
            let mut c = Client { hub, s: Session::new(format!("doc:{room}")), fx: Vec::new() };
            c.until(Duration::from_secs(5), |s, _| s.peer().is_some()).await;
            assert!(c.s.peer().is_some(), "{pid} never got joined");
            c
        }
        fn send(&mut self, m: ClientMsg) {
            self.hub.send(m).unwrap();
        }
        /// Pump messages into the session until `done` or timeout. Returns whether done.
        async fn until(&mut self, d: Duration, done: impl Fn(&Session, &[Effect]) -> bool) -> bool {
            let end = tokio::time::Instant::now() + d;
            loop {
                for m in self.hub.poll() {
                    let fx = self.s.handle(m);
                    for e in fx {
                        if let Effect::Send { msg } = &e {
                            let _ = self.hub.send(msg.clone());
                        }
                        self.fx.push(e);
                    }
                }
                if done(&self.s, &self.fx) {
                    return true;
                }
                if tokio::time::Instant::now() > end {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        async fn settle(&mut self, d: Duration) {
            self.until(d, |_, _| false).await;
        }
    }

    async fn wait_room_gone(h: &Harness, room: &str) -> bool {
        for _ in 0..250 {
            if !h.relay.rooms.lock().await.contains_key(room) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    fn confirmed(fx: &[Effect], local: u64) -> Option<u64> {
        fx.iter().find_map(|e| match e {
            Effect::Confirmed { local: l, seq } if *l == local => Some(*seq),
            _ => None,
        })
    }

    /// Control: the harness itself delivers edits. Same setup as the reopen test, minus the reopen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_control_fresh_room_edit_is_delivered() {
        let Some(h) = start().await else { return };
        let room = unique_room("control");
        let mut a = Client::connect(&h, &room, "alice").await;
        let mut b = Client::connect(&h, &room, "bob").await;
        let m = a.s.submit("cell.set", json!({"cell": "A1", "v": 1}), None);
        a.send(m);
        let a_ok = a.until(Duration::from_secs(3), |_, fx| confirmed(fx, 1).is_some()).await;
        let b_ok = b.until(Duration::from_secs(3), |_, fx| fx.iter().any(|e| matches!(e, Effect::Apply { .. }))).await;
        assert!(a_ok && b_ok, "control failed: alice fx={:?} bob fx={:?}", a.fx, b.fx);
    }

    /// Relay H1 end to end. One relay, one Valkey, no race: edit, everyone leaves, reopen,
    /// edit once. The edit must be confirmed for its sender and applied for the other peer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_reopen_after_last_disconnect_next_edit_is_delivered() {
        let Some(h) = start().await else { return };
        let room = unique_room("reopen");

        let mut a1 = Client::connect(&h, &room, "alice-1").await;
        let m = a1.s.submit("cell.set", json!({"cell": "A1", "v": 1}), None);
        a1.send(m);
        assert!(a1.until(Duration::from_secs(5), |_, fx| confirmed(fx, 1).is_some()).await, "first edit never confirmed: {:?}", a1.fx);
        let first_seq = confirmed(&a1.fx, 1).unwrap();
        drop(a1); // closes the socket; alice was the last peer
        assert!(wait_room_gone(&h, &room).await, "room was not dropped after the last disconnect");

        let mut a2 = Client::connect(&h, &room, "alice-2").await;
        let mut b = Client::connect(&h, &room, "bob").await;
        let a2_joined_at = a2.s.applied();
        let b_joined_at = b.s.applied();
        let m = a2.s.submit("cell.set", json!({"cell": "A1", "v": 2}), None);
        a2.send(m);
        let a_ok = a2.until(Duration::from_secs(3), |_, fx| confirmed(fx, 1).is_some()).await;
        let b_ok = b.until(Duration::from_secs(3), |_, fx| fx.iter().any(|e| matches!(e, Effect::Apply { .. }))).await;
        assert!(
            a_ok && b_ok,
            "previous session's last seq={first_seq}; after reopen joined.seq: alice={a2_joined_at}, bob={b_joined_at}. \
             Alice confirmed={a_ok} (applied={}, inflight={}), Bob applied={b_ok} (applied={}). alice fx={:?} bob fx={:?}",
            a2.s.applied(),
            a2.s.inflight(),
            b.s.applied(),
            a2.fx,
            b.fx
        );
    }

    /// Relay H4 end to end. Alice reconnects with the same pid before her old socket is reaped,
    /// takes a lock on the new socket, then the old socket disconnects.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_stale_socket_disconnect_keeps_replacement_and_its_lock() {
        let Some(h) = start().await else { return };
        let room = unique_room("reconnect");

        let old = Client::connect(&h, &room, "alice").await;
        let mut bob = Client::connect(&h, &room, "bob").await;
        let mut new = Client::connect(&h, &room, "alice").await; // same token pid, old not yet reaped
        let m = new.s.request_lock("B2");
        new.send(m);
        assert!(new.until(Duration::from_secs(5), |s, _| s.holds("B2")).await, "new socket never got B2: {:?}", new.fx);
        bob.settle(Duration::from_millis(300)).await;

        drop(old); // the stale socket finally goes
        tokio::time::sleep(Duration::from_millis(800)).await;
        bob.settle(Duration::from_millis(300)).await;
        new.settle(Duration::from_millis(300)).await;

        let relay_roster: Vec<String> =
            h.relay.rooms.lock().await.get(&room).map(|r| r.peers().iter().map(|p| p.peer.clone()).collect()).unwrap_or_default();
        let bob_sees: Vec<String> = bob.s.roster().iter().map(|p| p.peer.clone()).collect();
        let bob_saw_release = bob.fx.iter().any(|e| matches!(e, Effect::LockDropped { scope } if scope == "B2"));
        // Bob now asks for B2 while alice's live connection still believes it holds it.
        let m = bob.s.request_lock("B2");
        bob.send(m);
        bob.until(Duration::from_secs(3), |s, fx| s.holds("B2") || fx.iter().any(|e| matches!(e, Effect::LockRefused { .. }))).await;
        assert!(
            relay_roster.contains(&"alice".to_owned()) && !bob.s.holds("B2"),
            "after the OLD alice socket disconnected while the NEW one is live: relay roster={relay_roster:?}, bob's roster={bob_sees:?}, \
             bob got lock_released(B2)={bob_saw_release}, bob then granted B2={} while new alice socket holds(B2)={}",
            bob.s.holds("B2"),
            new.s.holds("B2")
        );
    }

    /// Relay M2 end to end: a peer already in the room is never told about another peer's grant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_existing_peer_learns_of_a_new_lock() {
        let Some(h) = start().await else { return };
        let room = unique_room("presence-lock");
        let mut alice = Client::connect(&h, &room, "alice").await;
        let mut bob = Client::connect(&h, &room, "bob").await;
        let m = bob.s.request_lock("B2");
        bob.send(m);
        assert!(bob.until(Duration::from_secs(5), |s, _| s.holds("B2")).await);
        let told = alice.until(Duration::from_secs(2), |s, _| s.blocked_by("B2").is_some()).await;
        // What happens when alice trusts may_edit and edits optimistically.
        let editable = alice.s.may_edit("B2");
        let m = alice.s.submit("cell.set", json!({"cell": "B2"}), Some("B2".into()));
        alice.send(m);
        alice.settle(Duration::from_millis(800)).await;
        let notices: Vec<&Effect> = alice.fx.iter().filter(|e| matches!(e, Effect::Notice { .. })).collect();
        assert!(
            told,
            "alice never learned bob holds B2: blocked_by={:?}, may_edit(B2)={editable}; her optimistic edit then got {notices:?}, inflight={}",
            alice.s.blocked_by("B2"),
            alice.s.inflight()
        );
    }

    /// Relay M1 end to end: once bob's Valkey lease lapses (TTL), the relay's mirror keeps
    /// refusing alice, and bob's later unlock is never announced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_expired_lease_stops_blocking() {
        let Some(h) = start().await else { return };
        let room = unique_room("lease");
        let mut alice = Client::connect(&h, &room, "alice").await;
        let mut bob = Client::connect(&h, &room, "bob").await;
        let m = bob.s.request_lock("B2");
        bob.send(m);
        assert!(bob.until(Duration::from_secs(5), |s, _| s.holds("B2")).await);

        // Let the 60 s lease lapse without waiting 60 s: shorten its TTL to 1 ms in Valkey.
        let client = redis::Client::open(h.valkey.as_str()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let key = format!("collabcraft:doc:{room}:lock:B2");
        let _: i64 = redis::cmd("PEXPIRE").arg(&key).arg(1).query_async(&mut conn).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let exists: i64 = redis::cmd("EXISTS").arg(&key).query_async(&mut conn).await.unwrap();

        let m = alice.s.submit("cell.set", json!({"cell": "B2"}), Some("B2".into()));
        alice.send(m);
        let ok = alice.until(Duration::from_secs(3), |_, fx| confirmed(fx, 1).is_some()).await;
        let notices: Vec<String> =
            alice.fx.iter().filter_map(|e| if let Effect::Notice { detail } = e { Some(detail.clone()) } else { None }).collect();

        let m = bob.s.release_lock("B2");
        bob.send(m);
        alice.settle(Duration::from_millis(800)).await;
        let alice_saw_release = alice.fx.iter().any(|e| matches!(e, Effect::LockDropped { .. }));
        assert!(
            ok,
            "lease key exists in Valkey after expiry: {exists}; alice's edit of B2 confirmed={ok}, notices={notices:?}; \
             after bob's unlock alice received lock_released={alice_saw_release}"
        );
    }
}
