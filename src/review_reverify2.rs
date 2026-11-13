//! Re-verification tests for 8cae690 (new, not in the gist). Same harness as review_reverify.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod unit {
    use craft_collab::{ClientMsg, Effect, ServerMsg, Session};
    use serde_json::json;

    fn op(doc: &str, seq: u64) -> ServerMsg {
        ServerMsg::Op {
            doc: doc.to_owned(),
            seq,
            origin: "alice".to_owned(),
            local: None,
            command: "cell.set".to_owned(),
            params: json!({"n": seq}),
            scope: None,
        }
    }

    /// Item 5, the client half. `since()` reports a burned-sequence hole, but a client only
    /// asked for it past the old MAX_PENDING (512) held ops, so a long-lived connected session
    /// that fell behind a hole sat frozen for far longer than normal reordering ever needs.
    /// Distinct from the sequence-hole *reporting* the reviewer already confirmed passes
    /// (`Room::since` itself, covered by `review_repro::unit_burned_sequence_is_recoverable`
    /// and `room::tests::since_reports_a_burned_sequence_hole`): this is the client noticing.
    /// Fixed by lowering `craft_collab::session::MAX_PENDING` to 64; this test's 97 held ops
    /// (seq 4 through 100, behind the hole at 3) comfortably cross that.
    #[test]
    fn unit_client_behind_hole_recovers_promptly() {
        const DOC: &str = "doc:hole";
        let mut carol = Session::new(DOC);
        carol.handle(ServerMsg::Joined { doc: DOC.to_owned(), peer: "carol".to_owned(), seq: 2, space: 3, roster: vec![], locks: vec![] });
        let mut fx = Vec::new();
        for seq in 4..=100u64 {
            fx.extend(carol.handle(op(DOC, seq)));
        }
        let resync = fx.iter().any(|e| matches!(e, Effect::Send { msg: ClientMsg::Resync { .. } }));
        let applies = fx.iter().filter(|e| matches!(e, Effect::Apply { .. })).count();
        assert!(
            carol.applied() == 100 || resync,
            "seq 3 burned; carol got ops 4..=100: applied()={}, Apply effects={applies}, resync requested={resync}",
            carol.applied()
        );
    }

    /// Item 7, bytes. MAX_SCOPES bounds the count, but each scope may hold TEXT_BYTES, so the
    /// per-room retained text is bounded only by MAX_SCOPES * TEXT_BYTES without a room-wide
    /// budget.
    ///
    /// ADAPTATION: checked against `room::TOTAL_TEXT_BYTES`, the dedicated room-wide budget the
    /// fix introduces, rather than `HISTORY_BYTES`. The two happen to share a value by design
    /// (see `TOTAL_TEXT_BYTES`'s own doc comment), but `HISTORY_BYTES` names a different pool
    /// (the op history) and asserting against it here would pass by coincidence rather than by
    /// naming the guard that is actually doing the work.
    #[test]
    fn unit_retained_text_bytes_are_bounded_per_room() {
        use crate::room::{MAX_SCOPES, Room, Submission, TEXT_BYTES, TOTAL_TEXT_BYTES};
        let mut r = Room::default();
        r.join(crate::room::Peer { peer: "mallory".into(), display: "mallory".into(), may_edit: true }).unwrap();
        let blob = "x".repeat(TEXT_BYTES - 64);
        for i in 0..16u64 {
            let sub = Submission {
                peer_id: "mallory".into(),
                may_edit: true,
                command: "crdt.text".into(),
                params: json!({"scope": format!("big{i}"), "ops": [blob.clone()]}),
                scope: None,
                local: None,
            };
            r.submit(i + 1, sub).unwrap();
        }
        let retained: usize = r.texts().values().flat_map(|l| l.ops().iter()).map(|v| serde_json::to_vec(v).unwrap().len()).sum();
        assert!(
            retained <= TOTAL_TEXT_BYTES,
            "16 near-cap scopes retain {retained} bytes ({} MiB) in one room; TOTAL_TEXT_BYTES={TOTAL_TEXT_BYTES}, TEXT_BYTES={TEXT_BYTES}, MAX_SCOPES={MAX_SCOPES} => worst case {} MiB",
            retained / (1024 * 1024),
            (MAX_SCOPES * TEXT_BYTES) / (1024 * 1024)
        );
    }
}

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
    }

    async fn start() -> Option<Harness> {
        // Unlike review_reverify.rs's harness, nothing in this file reaches Valkey directly
        // (no lease-expiry fault injection here), so the URL is read only to gate on its
        // presence and is not kept.
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
        Some(Harness { relay, url: format!("http://{addr}") })
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

    fn applies(fx: &[Effect]) -> usize {
        fx.iter().filter(|e| matches!(e, Effect::Apply { .. })).count()
    }

    async fn cell_edits(a: &mut Client, vals: &[i64]) {
        for v in vals {
            let before = a.s.inflight();
            let m = a.s.submit("cell.set", json!({"cell": "A1", "v": v}), None);
            a.send(m);
            let _ = before;
            assert!(a.until(Duration::from_secs(5), |s, _| s.inflight() == 0).await, "edit {v} never confirmed");
        }
    }

    /// Item 4 after a save. Bob drops at seq 0; alice makes 2 edits, saves (Saved{2}), makes a
    /// third. Bob's app keeps its Session (it did not reload the file). He must receive all 3
    /// missed ops, or a snapshot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_reconnect_after_save_receives_missed_ops() {
        let Some(h) = start().await else { return };
        let room = unique_room("missed-save");
        let mut a = Client::connect(&h, &room, "alice", true).await;
        let b = Client::connect(&h, &room, "bob", true).await;
        let Client { hub, s: bob_session, .. } = b;
        drop(hub);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let before = bob_session.applied();
        cell_edits(&mut a, &[1, 2]).await;
        let m = a.s.saved();
        a.send(m);
        a.settle(Duration::from_millis(200)).await;
        cell_edits(&mut a, &[3]).await;

        let mut b = Client::connect_with(&h, &room, "bob", true, bob_session).await;
        b.settle(Duration::from_millis(800)).await;
        let n = applies(&b.fx);
        let replaced = b.fx.iter().any(|e| matches!(e, Effect::Replace { .. }));
        assert!(
            n == 3 || replaced,
            "bob applied seq {before} before dropping; alice made 3 edits and saved at 2; after reconnect bob.applied={} but Apply effects={n}, snapshot={replaced}",
            b.s.applied()
        );
    }

    /// Regression check for the new join. Bob is online and applies alice's 2 edits, then
    /// reconnects with the same Session. He must not be handed them again as new Applies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_reconnect_does_not_reapply_seen_ops() {
        let Some(h) = start().await else { return };
        let room = unique_room("reapply");
        let mut a = Client::connect(&h, &room, "alice", true).await;
        let mut b = Client::connect(&h, &room, "bob", true).await;
        cell_edits(&mut a, &[1, 2]).await;
        assert!(b.until(Duration::from_secs(5), |s, _| s.applied() == 2).await);
        let first = applies(&b.fx);
        let Client { hub, s: bob_session, .. } = b;
        drop(hub);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut b = Client::connect_with(&h, &room, "bob", true, bob_session).await;
        b.settle(Duration::from_millis(800)).await;
        let again = applies(&b.fx);
        assert_eq!(
            again, 0,
            "bob applied {first} ops while online (applied=2); after reconnecting with the same Session he got {again} more Apply effects for ops he already had"
        );
    }

    /// The same, with a text edit and real Texts: does the re-delivery change what bob sees?
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_reconnect_text_is_not_doubled() {
        let Some(h) = start().await else { return };
        let room = unique_room("reapply-text");
        let mut a = Client::connect(&h, &room, "alice", true).await;
        let mut b = Client::connect(&h, &room, "bob", true).await;
        let (t, params) = alice_types_bang(&mut a).await;
        let m = a.s.submit("crdt.text", params, None);
        a.send(m);
        assert!(a.until(Duration::from_secs(5), |_, fx| confirmed(fx, 1).is_some()).await);
        assert!(b.until(Duration::from_secs(5), |s, _| s.applied() == 1).await);
        let mut bt = Texts::in_space(b.s.space().unwrap());
        bt.seed("/body/0", "hello");
        let (r1, _) = b.replay("/body/0");
        bt.apply("/body/0", &r1);
        let online = bt.render("/body/0").unwrap();
        let Client { hub, s: bob_session, .. } = b;
        drop(hub);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut b = Client::connect_with(&h, &room, "bob", true, bob_session).await;
        b.settle(Duration::from_millis(800)).await;
        let (r2, _) = b.replay("/body/0");
        bt.apply("/body/0", &r2);
        let after = bt.render("/body/0").unwrap();
        assert_eq!(
            after,
            t.render("/body/0").unwrap(),
            "bob saw {online:?} online; after reconnect he was re-sent {} text ops and sees {after:?}",
            r2.len()
        );
    }

    /// A read-only viewer reports a save slightly ahead of the room. `saved_seq` is now the
    /// join baseline (monotonic max), so a later joiner is told it has applied past the room
    /// and drops the next live edits as already seen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs REVIEW_VALKEY_URL"]
    async fn e2e_viewer_saved_ahead_does_not_strand_joiner() {
        let Some(h) = start().await else { return };
        let room = unique_room("viewer-ahead");
        let mut a = Client::connect(&h, &room, "alice", true).await;
        cell_edits(&mut a, &[1]).await;
        let mut viewer = Client::connect(&h, &room, "viewer", false).await;
        let room_seq = h.relay.rooms.lock().await.get(&room).map(|r| r.seq()).unwrap();
        viewer.send(ClientMsg::Saved { doc: format!("doc:{room}"), seq: room_seq + 3 });
        viewer.settle(Duration::from_millis(300)).await;

        let mut b = Client::connect(&h, &room, "bob", true).await;
        let joined_at = b.s.applied();
        cell_edits(&mut a, &[2, 3]).await;
        b.settle(Duration::from_millis(800)).await;
        let n = applies(&b.fx);
        assert!(
            n >= 2,
            "viewer (may_edit=false) sent Saved{{seq: {}}} at room seq {room_seq}; bob joined with applied={joined_at}; alice then made 2 edits; bob Apply effects={n}, applied={}",
            room_seq + 3,
            b.s.applied()
        );
    }
}
