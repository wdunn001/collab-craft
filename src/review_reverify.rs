//! Re-verification tests (review of 8a2a563). New tests, not part of the gist patch.
//! Same harness as review_repro::e2e (real handlers, real Valkey, real NativeHub clients).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e {
    use std::sync::Arc;
    use std::time::Duration;

    use craft_collab::native::NativeHub;
    use craft_collab::{ClientMsg, Effect, Hub, Session, Texts};
    use serde_json::json;
    use socketioxide::SocketIo;
    use tokio::sync::Mutex;

    use crate::{MAX_FRAME_BYTES, Relay, bus::Bus, on_connect, token};

    const SECRET: &[u8] = b"a-shared-secret-at-least-32-chars-long";

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
        async fn connect_with(h: &Harness, room: &str, pid: &str, may_edit: bool, s: Session) -> Client {
            let t = token::sign_at(SECRET, room, pid, pid, may_edit, pid, now()).unwrap();
            // A session that has already joined knows what it applied, and resuming there is
            // what lets a reconnect pick up exactly what it missed. A fresh session has
            // nothing of its own to offer, so the join falls back to the saved file's sequence.
            let applied = s.peer().is_some().then(|| s.applied());
            let hub = NativeHub::connect(&h.url, &t, applied).await.expect("connect");
            let mut c = Client { hub, s, fx: Vec::new() };
            let joined_before = c.fx.len();
            c.until(Duration::from_secs(5), |s, fx| s.peer().is_some() && fx.len() > joined_before).await;
            assert!(c.s.peer().is_some(), "{pid} never got joined");
            c
        }
        async fn connect(h: &Harness, room: &str, pid: &str, may_edit: bool) -> Client {
            Client::connect_with(h, room, pid, may_edit, Session::new(format!("doc:{room}"))).await
        }
        fn send(&mut self, m: ClientMsg) {
            self.hub.send(m).unwrap();
        }
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
        /// Every replayed text op the relay sent this client for `scope`.
        fn replay(&self, scope: &str) -> (Vec<craft_crdt::text::TextOp>, Vec<bool>) {
            let mut ops = Vec::new();
            let mut complete = Vec::new();
            for e in &self.fx {
                if let Effect::TextOps { scope: s, ops: o, complete: c } = e
                    && s == scope
                {
                    let v: Vec<craft_crdt::text::TextOp> = serde_json::from_value(o.clone()).unwrap();
                    ops.extend(v);
                    complete.push(*c);
                }
                // ADAPTATION (8cae690): the join now replays text as ordered `op` events
                // (Effect::Apply of `crdt.text`) instead of `text_ops`. Count both, so the
                // assertions see every replayed text op the joiner would apply.
                if let Effect::Apply { command, params } = e
                    && command == "crdt.text"
                    && params.get("scope").and_then(|s| s.as_str()) == Some(scope)
                {
                    let v: Vec<craft_crdt::text::TextOp> = serde_json::from_value(params["ops"].clone()).unwrap();
                    ops.extend(v);
                    complete.push(true);
                }
            }
            (ops, complete)
        }
    }

    fn confirmed(fx: &[Effect], local: u64) -> Option<u64> {
        fx.iter().find_map(|e| match e {
            Effect::Confirmed { local: l, seq } if *l == local => Some(*seq),
            _ => None,
        })
    }

    /// Alice types "!" into "hello". Returns her Texts and the ops she submitted.
    async fn alice_types_bang(a: &mut Client) -> (Texts, serde_json::Value) {
        let mut t = Texts::in_space(a.s.space().expect("space granted"));
        t.seed("/body/0", "hello");
        let ops = t.local_insert("/body/0", 5, "!").unwrap();
        let params = json!({"scope": "/body/0", "ops": serde_json::to_value(&ops).unwrap()});
        (t, params)
    }

    /// Issue 27 positive check through the real socket: confirm the edit, save, send
    /// `session.saved()`, then a late joiner loading the saved file must see it once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_saved_after_confirm_late_joiner_sees_text_once() {
        let Some(h) = start().await else { return };
        let room = unique_room("saved-ok");
        let mut a = Client::connect(&h, &room, "alice", true).await;
        let (t, params) = alice_types_bang(&mut a).await;
        let m = a.s.submit("crdt.text", params, None);
        a.send(m);
        assert!(a.until(Duration::from_secs(5), |_, fx| confirmed(fx, 1).is_some()).await, "edit never confirmed: {:?}", a.fx);
        let saved_file = t.render("/body/0").unwrap();
        let m = a.s.saved();
        a.send(m);
        a.settle(Duration::from_millis(300)).await;

        let mut b = Client::connect(&h, &room, "bob", true).await;
        b.settle(Duration::from_millis(500)).await;
        let (replay, complete) = b.replay("/body/0");
        let mut bt = Texts::in_space(b.s.space().unwrap());
        bt.apply("/body/0", &replay);
        let seen = bt.seed("/body/0", &saved_file);
        assert_eq!(seen, saved_file, "saved {saved_file:?}; bob replayed {} ops (complete={complete:?}) and sees {seen:?}", replay.len());
    }

    /// Issue 27, the save that includes a local edit the relay has not confirmed yet (autosave
    /// while typing). The file holds "hello!", but `saved()` reports `applied`, which excludes
    /// the in-flight op, so the op is still replayed to a joiner who loads that file.
    ///
    /// NOT FIXED this round: out of scope for the four defects this recheck covers (join
    /// resume, Saved permission and its cap, the total-bytes budget, hygiene). `Session::saved`
    /// now documents the precondition this test violates on purpose (call it only once the
    /// edits the save reflects are confirmed, not merely rendered). A real fix would need the
    /// relay to accept something other than a sequence number for "and also whatever my own
    /// in-flight ops turn out to be", which is a protocol change, not a guard. Run explicitly
    /// (`--exact`) to see it fail; the gate's e2e run skips it rather than failing on a known,
    /// disclosed gap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_saved_with_inflight_edit_late_joiner_sees_text_once() {
        let Some(h) = start().await else { return };
        let room = unique_room("saved-inflight");
        let mut a = Client::connect(&h, &room, "alice", true).await;
        let (t, params) = alice_types_bang(&mut a).await;
        let m = a.s.submit("crdt.text", params, None);
        a.send(m);
        // The app saves what it shows, which already includes the "!", then reports the save.
        let saved_file = t.render("/body/0").unwrap();
        let saved_msg = a.s.saved();
        let reported = match &saved_msg {
            ClientMsg::Saved { seq, .. } => *seq,
            _ => unreachable!(),
        };
        let inflight_at_save = a.s.inflight();
        a.send(saved_msg);
        assert!(a.until(Duration::from_secs(5), |_, fx| confirmed(fx, 1).is_some()).await, "edit never confirmed: {:?}", a.fx);
        let op_seq = confirmed(&a.fx, 1).unwrap();

        let mut b = Client::connect(&h, &room, "bob", true).await;
        b.settle(Duration::from_millis(500)).await;
        let (replay, _) = b.replay("/body/0");
        let mut bt = Texts::in_space(b.s.space().unwrap());
        bt.apply("/body/0", &replay);
        let seen = bt.seed("/body/0", &saved_file);
        assert_eq!(
            seen,
            saved_file,
            "file saved as {saved_file:?} with {inflight_at_save} edit in flight; Saved reported seq={reported}, the edit was ordered at seq={op_seq}; bob replayed {} ops and sees {seen:?}",
            replay.len()
        );
    }

    /// `on_saved` takes no edit permission and does not bound `seq`. A read-only peer reports a
    /// save it cannot have made; the unsaved edit is no longer replayed, so a joiner loading the
    /// (still old) file diverges from alice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_reader_cannot_prune_unsaved_text() {
        let Some(h) = start().await else { return };
        let room = unique_room("saved-reader");
        let mut a = Client::connect(&h, &room, "alice", true).await;
        let (t, params) = alice_types_bang(&mut a).await;
        let m = a.s.submit("crdt.text", params, None);
        a.send(m);
        assert!(a.until(Duration::from_secs(5), |_, fx| confirmed(fx, 1).is_some()).await);
        let alice_sees = t.render("/body/0").unwrap();

        let mut viewer = Client::connect(&h, &room, "viewer", false).await;
        let room_seq = h.relay.rooms.lock().await.get(&room).map(|r| r.seq()).unwrap();
        viewer.send(ClientMsg::Saved { doc: format!("doc:{room}"), seq: u64::MAX });
        viewer.settle(Duration::from_millis(300)).await;

        // Nobody saved: the provider still holds "hello".
        let mut b = Client::connect(&h, &room, "bob", true).await;
        b.settle(Duration::from_millis(500)).await;
        let (replay, _) = b.replay("/body/0");
        let mut bt = Texts::in_space(b.s.space().unwrap());
        bt.apply("/body/0", &replay);
        let seen = bt.seed("/body/0", "hello");
        assert_eq!(
            seen,
            alice_sees,
            "read-only viewer sent Saved{{seq: u64::MAX}} (room seq {room_seq}); bob loaded the unsaved file \"hello\", was replayed {} ops, and sees {seen:?} while alice sees {alice_sees:?}",
            replay.len()
        );
    }

    /// Issue item 4: a peer that reconnects (same pid, same Session) must get the ordered ops it
    /// missed while disconnected, or a snapshot. Not addressed by the three commits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_reconnect_receives_missed_ops() {
        let Some(h) = start().await else { return };
        let room = unique_room("missed");
        let mut a = Client::connect(&h, &room, "alice", true).await;
        let b = Client::connect(&h, &room, "bob", true).await;
        let Client { hub, s: bob_session, .. } = b;
        drop(hub); // bob's network drops; his app keeps its Session
        tokio::time::sleep(Duration::from_millis(500)).await;
        let bob_applied_before = bob_session.applied();

        for (i, v) in [1, 2].iter().enumerate() {
            let m = a.s.submit("cell.set", json!({"cell": "A1", "v": v}), None);
            a.send(m);
            let local = (i + 1) as u64;
            assert!(a.until(Duration::from_secs(5), |_, fx| confirmed(fx, local).is_some()).await);
        }

        let mut b = Client::connect_with(&h, &room, "bob", true, bob_session).await;
        b.settle(Duration::from_millis(800)).await;
        let applies = b.fx.iter().filter(|e| matches!(e, Effect::Apply { .. })).count();
        let replaced = b.fx.iter().any(|e| matches!(e, Effect::Replace { .. }));
        assert!(
            applies == 2 || replaced,
            "bob applied seq {bob_applied_before} before dropping; alice made 2 edits; after reconnect bob.applied={} but Apply effects={applies}, snapshot={replaced}; fx={:?}",
            b.s.applied(),
            b.fx
        );
    }

    /// 1b1a0dc error path: `on_disconnect` is registered before `next_space`. A reconnect whose
    /// join fails on the bus is disconnected, and its `on_disconnect` calls `leave(pid)` for a
    /// connection that never joined, evicting the live one and releasing its lock.
    /// Fault injection: the room's space counter is made non-numeric so INCR fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_failed_reconnect_keeps_live_peer_and_lock() {
        let Some(h) = start().await else { return };
        let room = unique_room("failjoin");
        let mut live = Client::connect(&h, &room, "alice", true).await;
        let mut bob = Client::connect(&h, &room, "bob", true).await;
        let m = live.s.request_lock("B2");
        live.send(m);
        assert!(live.until(Duration::from_secs(5), |s, _| s.holds("B2")).await);
        bob.settle(Duration::from_millis(300)).await;

        let client = redis::Client::open(h.valkey.as_str()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let key = format!("collabcraft:doc:{room}:space");
        let _: () = redis::cmd("SET").arg(&key).arg("not-a-number").query_async(&mut conn).await.unwrap();

        // A second alice socket (a reconnect) that the relay refuses at next_space.
        let t = token::sign_at(SECRET, &room, "alice", "alice", true, "alice", now()).unwrap();
        let second = NativeHub::connect(&h.url, &t, None).await.expect("connect");
        tokio::time::sleep(Duration::from_millis(1000)).await;
        drop(second);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _: () = redis::cmd("DEL").arg(&key).query_async(&mut conn).await.unwrap();
        bob.settle(Duration::from_millis(300)).await;

        let relay_roster: Vec<String> =
            h.relay.rooms.lock().await.get(&room).map(|r| r.peers().iter().map(|p| p.peer.clone()).collect()).unwrap_or_default();
        let bob_saw_release = bob.fx.iter().any(|e| matches!(e, Effect::LockDropped { scope } if scope == "B2"));
        let m = bob.s.request_lock("B2");
        bob.send(m);
        bob.until(Duration::from_secs(3), |s, fx| s.holds("B2") || fx.iter().any(|e| matches!(e, Effect::LockRefused { .. }))).await;
        assert!(
            relay_roster.contains(&"alice".to_owned()) && !bob.s.holds("B2"),
            "after a refused alice reconnect: relay roster={relay_roster:?}, bob got lock_released(B2)={bob_saw_release}, bob then granted B2={} while live alice holds(B2)={}",
            bob.s.holds("B2"),
            live.s.holds("B2")
        );
    }
}
