//! Tests for the parts that must be right: token verification, arbitration
//! and the keyed links a recipient with no account follows. None of them
//! needs a socket or a Valkey.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::room::{Peer, Refusal, Room, Submission, is_crdt_command};
use crate::token::{self, PERMISSION_READ, PERMISSION_UPDATE, TokenError};

const SECRET: &[u8] = b"a-shared-secret-at-least-32-chars-long";
const NOW: i64 = 1_760_000_000;

/// Mint a token the way the PHP side does, so the test exercises the real
/// format rather than a convenient one.
fn mint(payload: serde_json::Value, secret: &[u8]) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(payload.to_string());
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("key");
    mac.update(encoded.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{encoded}.{sig}")
}

fn claims_json(perm: u32, exp: i64) -> serde_json::Value {
    json!({ "rm": "1234", "uid": "alice", "dsp": "Alice", "perm": perm, "exp": exp, "pid": "peer-a" })
}

// ---- token ----------------------------------------------------------------

#[test]
fn a_well_formed_token_verifies() {
    let t = mint(claims_json(PERMISSION_READ | PERMISSION_UPDATE, NOW + 300), SECRET);
    let c = token::verify(&t, SECRET, NOW).expect("verifies");
    assert_eq!(c.rm, "1234");
    assert_eq!(c.uid, "alice");
    assert_eq!(c.dsp, "Alice");
    assert_eq!(c.pid, "peer-a");
    assert!(c.may_edit());
    assert_eq!(c.room(), "doc:1234");
}

#[test]
fn a_read_only_token_verifies_but_cannot_edit() {
    let t = mint(claims_json(PERMISSION_READ, NOW + 300), SECRET);
    let c = token::verify(&t, SECRET, NOW).expect("a reader may still join");
    assert!(!c.may_edit());
}

#[test]
fn a_token_with_no_read_is_refused() {
    let t = mint(claims_json(0, NOW + 300), SECRET);
    assert_eq!(token::verify(&t, SECRET, NOW), Err(TokenError::NoRead));
}

#[test]
fn a_tampered_payload_fails_the_signature() {
    let t = mint(claims_json(PERMISSION_READ, NOW + 300), SECRET);
    let (payload, sig) = t.split_once('.').expect("shape");
    // Re-encode the payload with elevated permissions, keeping the old signature.
    let forged = URL_SAFE_NO_PAD.encode(claims_json(PERMISSION_READ | PERMISSION_UPDATE, NOW + 300).to_string());
    assert_ne!(forged, payload);
    assert_eq!(token::verify(&format!("{forged}.{sig}"), SECRET, NOW), Err(TokenError::Signature));
}

#[test]
fn another_secret_fails() {
    let t = mint(claims_json(PERMISSION_READ, NOW + 300), b"a-different-secret-also-long-enough-x");
    assert_eq!(token::verify(&t, SECRET, NOW), Err(TokenError::Signature));
}

#[test]
fn an_expired_token_is_refused() {
    let t = mint(claims_json(PERMISSION_READ, NOW - 1), SECRET);
    match token::verify(&t, SECRET, NOW) {
        Err(TokenError::Expired { exp, now }) => {
            assert_eq!(exp, NOW - 1);
            assert_eq!(now, NOW);
        }
        other => panic!("expected Expired, got {other:?}"),
    }
}

#[test]
fn expiry_is_checked_after_the_signature() {
    // An expired token signed with the wrong key reports Signature, not
    // Expired. A caller must not learn anything about a token it did not sign.
    let t = mint(claims_json(PERMISSION_READ, NOW - 1), b"wrong-secret-but-long-enough-to-use-x");
    assert_eq!(token::verify(&t, SECRET, NOW), Err(TokenError::Signature));
}

#[test]
fn malformed_tokens_are_refused_without_panicking() {
    for bad in ["", ".", "a.", ".b", "no-dot", "!!!.!!!", "a.b.c"] {
        assert!(token::verify(bad, SECRET, NOW).is_err(), "{bad:?} must be refused");
    }
}

// ---- arbitration ----------------------------------------------------------

fn peer(id: &str, may_edit: bool) -> Peer {
    Peer { peer: id.to_owned(), display: id.to_uppercase(), may_edit }
}

/// A submission from `peer`, editing `scope` with `command`.
fn sub(peer: &str, may_edit: bool, command: &str, params: serde_json::Value, scope: Option<&str>) -> Submission {
    Submission { peer_id: peer.to_owned(), may_edit, command: command.to_owned(), params, scope: scope.map(str::to_owned), local: None }
}

fn room_with(ids: &[(&str, bool)]) -> Room {
    let mut r = Room::default();
    for (id, may_edit) in ids {
        r.join(peer(id, *may_edit));
    }
    r
}

#[test]
fn a_reader_cannot_submit() {
    let mut r = room_with(&[("bob", false)]);
    assert_eq!(r.submit(1, sub("bob", false, "cell.set", json!({}), None)), Err(Refusal::ReadOnly));
}

#[test]
fn an_unlocked_scope_accepts_an_edit() {
    let mut r = room_with(&[("alice", true)]);
    let op = r.submit(1, Submission { local: Some(7), ..sub("alice", true, "cell.set", json!({"cell": "B2"}), Some("B2")) }).expect("ok");
    assert_eq!(op.seq, 1);
    assert_eq!(op.origin, "alice");
    assert_eq!(op.local, Some(7));
}

#[test]
fn a_scope_another_peer_holds_refuses() {
    let mut r = room_with(&[("alice", true), ("bob", true)]);
    r.record_lock("bob", "B2".into());
    let out = r.submit(1, sub("alice", true, "cell.set", json!({}), Some("B2")));
    assert_eq!(out, Err(Refusal::Locked { holder: "bob".into() }));
}

#[test]
fn a_scope_this_peer_holds_proceeds() {
    let mut r = room_with(&[("alice", true)]);
    r.record_lock("alice", "B2".into());
    assert!(r.submit(1, sub("alice", true, "cell.set", json!({}), Some("B2"))).is_ok());
}

#[test]
fn an_edit_with_no_scope_is_never_blocked() {
    let mut r = room_with(&[("alice", true), ("bob", true)]);
    r.record_lock("bob", "B2".into());
    assert!(r.submit(1, sub("alice", true, "doc.title", json!({}), None)).is_ok());
}

#[test]
fn a_crdt_text_edit_ignores_a_held_lock() {
    assert!(is_crdt_command("crdt.text"));
    assert!(!is_crdt_command("cell.set"));
    let mut r = room_with(&[("alice", true), ("bob", true)]);
    r.record_lock("bob", "B2".into());
    let op = r.submit(1, sub("alice", true, "crdt.text", json!({"op": "ins"}), Some("B2"))).expect("crdt.text skips the lock");
    assert!(op.scope.is_none(), "a crdt.* command must not keep the client's scope");
}

#[test]
fn a_crdt_command_still_requires_edit_access() {
    let mut r = room_with(&[("bob", false)]);
    assert_eq!(r.submit(1, sub("bob", false, "crdt.text", json!({}), None)), Err(Refusal::ReadOnly));
}

#[test]
fn leaving_drops_every_scope_the_peer_held() {
    let mut r = room_with(&[("alice", true), ("bob", true)]);
    r.record_lock("bob", "B2".into());
    r.record_lock("bob", "C3".into());
    r.record_lock("alice", "A1".into());

    let dropped = r.leave("bob");
    let mut dropped = dropped;
    dropped.sort();
    assert_eq!(dropped, vec!["B2".to_owned(), "C3".to_owned()]);
    assert_eq!(r.holder_of("A1"), Some("alice"), "alice keeps hers");
    assert_eq!(r.holder_of("B2"), None, "bob's went with him");
    assert_eq!(r.peers().len(), 1);
}

#[test]
fn unlock_only_releases_your_own() {
    let mut r = room_with(&[("alice", true), ("bob", true)]);
    r.record_lock("bob", "B2".into());
    assert!(!r.unlock("alice", "B2"), "alice must not release bob's lock");
    assert!(r.unlock("bob", "B2"));
    assert!(!r.unlock("bob", "B2"), "a second release changes nothing");
}

#[test]
fn rejoining_replaces_the_earlier_connection() {
    let mut r = room_with(&[("alice", true)]);
    r.join(peer("alice", true));
    assert_eq!(r.peers().len(), 1, "a reconnect must not duplicate the peer");
}

#[test]
fn the_room_tracks_the_highest_sequence_it_has_seen() {
    let mut r = room_with(&[("alice", true)]);
    r.submit(5, sub("alice", true, "a", json!({}), None)).expect("ok");
    assert_eq!(r.seq(), 5, "the sequence comes from the bus, so it may not start at 1");
    r.submit(6, sub("alice", true, "b", json!({}), None)).expect("ok");
    assert_eq!(r.seq(), 6);
}

#[test]
fn a_resync_within_history_replays() {
    let mut r = room_with(&[("alice", true)]);
    for seq in 1..=5 {
        r.submit(seq, sub("alice", true, &format!("c{seq}"), json!({}), None)).expect("ok");
    }
    let ops = r.since(2).expect("history reaches back");
    assert_eq!(ops.len(), 3);
    assert_eq!(ops.iter().map(|o| o.seq).collect::<Vec<_>>(), vec![3, 4, 5]);
}

#[test]
fn a_resync_already_current_replays_nothing() {
    let mut r = room_with(&[("alice", true)]);
    r.submit(1, sub("alice", true, "a", json!({}), None)).expect("ok");
    assert_eq!(r.since(1).expect("current"), Vec::new());
    assert_eq!(r.since(99).expect("ahead of us"), Vec::new());
}

#[test]
fn a_resync_past_the_history_asks_for_a_snapshot() {
    let mut r = room_with(&[("alice", true)]);
    // Fill past the cap so the oldest ops are evicted.
    for seq in 1..=(crate::room::HISTORY as u64 + 10) {
        r.submit(seq, sub("alice", true, "c", json!({}), None)).expect("ok");
    }
    assert!(r.since(0).is_none(), "a gap the log cannot fill must answer None");
    assert!(r.since(crate::room::HISTORY as u64 + 5).is_some(), "a recent gap still replays");
}

#[test]
fn an_empty_room_is_reported_empty() {
    let mut r = room_with(&[("alice", true)]);
    assert!(!r.is_empty());
    r.leave("alice");
    assert!(r.is_empty());
}

#[test]
fn the_mirror_reports_who_holds_a_scope() {
    let mut r = room_with(&[("alice", true), ("bob", true)]);
    assert_eq!(r.holder_of("B2"), None, "an unclaimed scope has no holder");
    r.record_lock("bob", "B2".into());
    assert_eq!(r.holder_of("B2"), Some("bob"));
    r.record_holder("C3".into(), "carol".into());
    assert_eq!(r.holder_of("C3"), Some("carol"), "a holder learned from a refusal is recorded too");
}

/// Keyed links, for a recipient who holds no account anywhere.
///
/// Its own module because `Refusal` means one thing in arbitration and
/// another here, and importing both into one namespace would need an alias at
/// every call site.
///
/// Every decision under test is a pure function over a record and a clock.
/// Expiry, spending, withdrawal and the off switch are the cases that matter,
/// and none of them needs a datastore or a wall clock to exercise.
mod keyed_links {

    use serde_json::json;

    use craft_cloud::{Permission, Share, ShareTarget};

    use crate::keyed::{self, Key, Link, Policy, Refusal};
    use crate::session::{Guest, Session};
    use crate::state::{App, Permissions, ServiceCapability};

    use super::{NOW, SECRET};

    /// A policy with keyed links on, as a deployment that allows them has.
    fn policy_on() -> Policy {
        Policy::decide(None, "https://craft.example.com", None, None)
    }

    /// A service, as far as anything below needs one.
    ///
    /// Nothing here opens a socket. The store holds a client rather than a
    /// connection, and every assertion is about what this deployment reports or
    /// permits rather than about what it stores.
    fn service(keyed: Policy) -> App {
        App {
            secret: SECRET.to_vec(),
            relay_url: "https://craft.example.com".to_owned(),
            settings: crate::settings::Settings::decide(Some("https://cloud.example.com"), None, None),
            permissions: Permissions::from_env(),
            store: crate::store::Store::new("redis://127.0.0.1:6379/15", "collabcraft:test").expect("a client, not a connection"),
            oidc: None,
            http: reqwest::Client::new(),
            web: tower_http::services::ServeDir::new("."),
            hosted: vec!["gridcraft".to_owned(), "wordcraft".to_owned()],
            keyed,
            esign: None,
        }
    }

    fn link_for(key: &Key, exp: i64, max_uses: u32, permission: Permission) -> Link {
        Link {
            verifier: key.verifier(SECRET).expect("a verifier"),
            room: "room-7".to_owned(),
            doc: "/Documents/Budget.xlsx".to_owned(),
            app: "gridcraft".to_owned(),
            permission,
            recipient: "outsider@example.org".to_owned(),
            owner: "alice".to_owned(),
            share: "share-99".to_owned(),
            exp,
            max_uses,
            invite_url: None,
        }
    }

    /// The share the provider still reports for that document.
    fn standing_share(permission: Permission) -> Share {
        Share {
            id: "share-99".to_owned(),
            target: ShareTarget::Email("outsider@example.org".to_owned()),
            display: None,
            permission,
            url: None,
            note: None,
            created: None,
        }
    }

    #[test]
    fn a_minted_key_round_trips_through_a_url() {
        let key = Key::mint();
        let wire = key.wire();
        assert!(!wire.contains('/'), "a key has to survive a path segment");
        let read_back = Key::parse(&wire).expect("parses");
        assert_eq!(read_back, key);
        assert_eq!(policy_on().url(&key), format!("https://craft.example.com/invite/{wire}"));
    }

    #[test]
    fn two_minted_keys_differ() {
        let a = Key::mint();
        let b = Key::mint();
        assert_ne!(a.handle, b.handle);
        assert_ne!(a.wire(), b.wire());
    }

    #[test]
    fn a_key_works_once_and_then_does_not() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);

        // Nothing spent yet, so the key opens the document.
        assert_eq!(keyed::redeem(SECRET, &link, &key, 0, NOW), Ok(Permission::Edit));

        // One use taken is the whole allowance.
        assert_eq!(
            keyed::redeem(SECRET, &link, &key, 1, NOW),
            Err(Refusal::Spent { spent: 1, allowed: 1 }),
            "a single-use key must not open the document twice"
        );
    }

    #[test]
    fn a_key_allowed_more_uses_spends_each_one() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 3, Permission::View);
        for spent in 0..3 {
            assert_eq!(keyed::redeem(SECRET, &link, &key, spent, NOW), Ok(Permission::View));
        }
        assert_eq!(keyed::redeem(SECRET, &link, &key, 3, NOW), Err(Refusal::Spent { spent: 3, allowed: 3 }));
    }

    #[test]
    fn a_key_past_its_expiry_is_refused() {
        let key = Key::mint();
        let link = link_for(&key, NOW - 1, 1, Permission::Edit);
        assert_eq!(keyed::redeem(SECRET, &link, &key, 0, NOW), Err(Refusal::Expired { exp: NOW - 1, now: NOW }));
    }

    #[test]
    fn expiry_lands_exactly_on_the_second_it_names() {
        let key = Key::mint();
        let link = link_for(&key, NOW, 1, Permission::Edit);
        assert!(keyed::redeem(SECRET, &link, &key, 0, NOW).is_err(), "the expiry second is already past");
        assert!(keyed::redeem(SECRET, &link, &key, 0, NOW - 1).is_ok(), "the second before it is not");
    }

    #[test]
    fn another_key_does_not_open_the_link() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        let other = Key::mint();
        assert_eq!(keyed::redeem(SECRET, &link, &other, 0, NOW), Err(Refusal::Mismatch));
    }

    #[test]
    fn the_verifier_is_checked_before_anything_else() {
        // An expired, exhausted record presented with the wrong key reports a
        // mismatch. Somebody holding no key must not learn that such a record
        // exists, when it expired or how often it has been opened.
        let key = Key::mint();
        let link = link_for(&key, NOW - 10_000, 1, Permission::Edit);
        let other = Key::mint();
        assert_eq!(keyed::redeem(SECRET, &link, &other, 99, NOW), Err(Refusal::Mismatch));
    }

    #[test]
    fn a_verifier_made_under_another_secret_does_not_open_the_link() {
        let key = Key::mint();
        let mut link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        link.verifier = key.verifier(b"a-different-secret-also-long-enough-x").expect("a verifier");
        assert_eq!(keyed::redeem(SECRET, &link, &key, 0, NOW), Err(Refusal::Mismatch));
    }

    #[test]
    fn malformed_keys_are_refused_without_a_lookup() {
        for bad in ["", ".", "no-dot", "a.b", "!!!.!!!", "a.b.c", "AAAAAAAAAAAAAAAAAAAAAA"] {
            assert_eq!(Key::parse(bad), Err(Refusal::Shape), "{bad:?} must be refused");
        }
        // The right shape with the wrong lengths is still not a key.
        let key = Key::mint();
        assert_eq!(Key::parse(&format!("{}.{}", key.handle, "c2hvcnQ")), Err(Refusal::Shape));
    }

    #[test]
    fn the_stored_record_carries_no_key_material() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        let stored = serde_json::to_string(&link).expect("serialises");
        assert!(!stored.contains(&key.wire()), "the record must not hold the key");
        // What it holds instead is an HMAC under the service secret. A copy of the
        // keyspace therefore opens no document without this process.
        let verifier = key.verifier(SECRET).expect("a verifier");
        assert!(stored.contains(&verifier));
        assert_ne!(verifier, key.wire());
    }

    #[test]
    fn a_withdrawn_share_withdraws_the_key() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        // The provider reports no share for that document any more.
        assert_eq!(keyed::regrant(&link, "room-7", &[]), Err(Refusal::Withdrawn));
    }

    #[test]
    fn another_share_on_the_same_document_does_not_stand_in() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        let someone_else = Share { id: "share-100".to_owned(), ..standing_share(Permission::Edit) };
        assert_eq!(
            keyed::regrant(&link, "room-7", &[someone_else]),
            Err(Refusal::Withdrawn),
            "the key names one share and only that one may keep it alive"
        );
    }

    #[test]
    fn a_key_for_a_room_the_share_no_longer_grants_is_refused() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        // The share stands, but the document the provider reports is a different
        // room now. A key must not follow a document it was never minted for.
        assert_eq!(keyed::regrant(&link, "room-8", &[standing_share(Permission::Edit)]), Err(Refusal::Moved));
    }

    #[test]
    fn the_grant_follows_the_share_down() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        assert_eq!(
            keyed::regrant(&link, "room-7", &[standing_share(Permission::View)]),
            Ok(Permission::View),
            "a share downgraded to reading downgrades the recipient"
        );
    }

    #[test]
    fn the_grant_never_rises_above_what_was_minted() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::View);
        assert_eq!(
            keyed::regrant(&link, "room-7", &[standing_share(Permission::Edit)]),
            Ok(Permission::View),
            "a key minted for reading stays a key for reading"
        );
    }

    #[test]
    fn a_standing_share_keeps_the_key_working() {
        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        assert_eq!(keyed::regrant(&link, "room-7", &[standing_share(Permission::Edit)]), Ok(Permission::Edit));
    }

    #[test]
    fn every_refusal_tells_a_recipient_the_same_thing() {
        // Which check failed says something about the record, and anybody can
        // follow a link. Only the deployment-wide refusal reads differently,
        // because that one is not about any particular link.
        let refusals = [
            Refusal::Shape,
            Refusal::Unknown,
            Refusal::Mismatch,
            Refusal::Expired { exp: NOW, now: NOW },
            Refusal::Spent { spent: 1, allowed: 1 },
            Refusal::Withdrawn,
            Refusal::Moved,
        ];
        let first = refusals[0].public();
        for refusal in &refusals {
            assert_eq!(refusal.public(), first, "{refusal} must not be distinguishable");
        }
        assert_ne!(Refusal::Disabled.public(), first);
    }

    // ---- the off switch -------------------------------------------------------

    #[test]
    fn a_deployment_can_switch_keyed_links_off() {
        for off in ["off", "OFF", "0", "false", "no", " off "] {
            let policy = Policy::decide(Some(off), "https://craft.example.com", None, None);
            assert!(!policy.enabled(), "{off:?} must turn keyed links off");
            assert_eq!(service(policy).service_capabilities(), Vec::new(), "with them off the capability is reported absent, so no button appears");
        }
    }

    #[test]
    fn keyed_links_are_on_unless_a_deployment_says_otherwise() {
        for on in [None, Some("on"), Some("true"), Some("1"), Some("")] {
            let policy = Policy::decide(on, "https://craft.example.com", None, None);
            assert!(policy.enabled(), "{on:?} leaves keyed links on");
            assert_eq!(service(policy).service_capabilities(), vec![ServiceCapability::KeyedLinks]);
        }
    }

    #[test]
    fn a_deployment_that_does_not_know_its_own_address_mints_nothing() {
        // A link has to point somewhere. Reporting the capability absent is the
        // honest answer, and the alternative is a button that produces a link to
        // nowhere.
        assert!(!Policy::decide(None, "", None, None).enabled());
        assert!(!Policy::decide(None, "   ", None, None).enabled());
        assert_eq!(service(Policy::decide(None, "", None, None)).service_capabilities(), Vec::new());
    }

    #[test]
    fn a_trailing_slash_on_the_public_address_does_not_double_up() {
        let policy = Policy::decide(None, "https://craft.example.com/", None, None);
        let key = Key::mint();
        assert_eq!(policy.url(&key), format!("https://craft.example.com/invite/{}", key.wire()));
    }

    #[test]
    fn the_lifetime_and_the_use_count_are_clamped() {
        let huge = Policy::decide(None, "https://craft.example.com", Some("99999"), Some("9999"));
        assert_eq!(huge.ttl_secs, keyed::MAX_TTL_HOURS * 3600);
        assert_eq!(huge.max_uses, keyed::MAX_USES);

        let zero = Policy::decide(None, "https://craft.example.com", Some("0"), Some("0"));
        assert_eq!(zero.ttl_secs, 3600, "an hour is the shortest a key may last");
        assert_eq!(zero.max_uses, 1, "a key nobody may spend is not a key");

        let nonsense = Policy::decide(None, "https://craft.example.com", Some("soon"), Some("lots"));
        assert_eq!(nonsense.ttl_secs, keyed::DEFAULT_TTL_HOURS * 3600);
        assert_eq!(nonsense.max_uses, keyed::DEFAULT_USES);
    }

    // ---- what a recipient is entitled to --------------------------------------

    fn guest_session() -> Session {
        Session {
            user: Guest::user_id("handle-1"),
            display: "outsider@example.org".to_owned(),
            email: Some("outsider@example.org".to_owned()),
            groups: Vec::new(),
            guest: Some(Guest {
                link: "handle-1".to_owned(),
                room: "room-7".to_owned(),
                doc: "/Documents/Budget.xlsx".to_owned(),
                app: "gridcraft".to_owned(),
                permission: Permission::Edit,
            }),
        }
    }

    #[test]
    fn a_recipient_may_open_one_app_and_no_other() {
        let permissions = Permissions::from_env();
        let session = guest_session();
        assert_eq!(permissions.apps_for_session(&session), vec!["gridcraft".to_owned()]);
        assert!(permissions.may_open(&session, "gridcraft"));
        for other in ["wordcraft", "deckcraft", "pdfcraft", "cadcraft"] {
            assert!(!permissions.may_open(&session, other), "a recipient must not reach {other}");
        }
    }

    #[test]
    fn a_recipient_carries_no_group() {
        // Entitlement here is granted by group membership. A recipient holding a
        // group would inherit whatever that group may open.
        let session = guest_session();
        assert!(session.groups.is_empty());
        assert!(session.is_guest());
    }

    #[tokio::test]
    async fn a_recipient_is_never_given_a_provider() {
        // The sharer's credential reads the document. A recipient acting as an
        // account holder is the one thing none of this may allow, so the lookup
        // refuses before it reaches the store.
        let app = service(policy_on());
        assert!(app.provider_for(&guest_session()).await.is_none());
    }

    #[test]
    fn a_session_written_before_keyed_links_existed_still_loads() {
        let old = json!({ "user": "alice", "display": "Alice", "email": null, "groups": ["editors"] });
        let session: Session = serde_json::from_value(old).expect("an older record still reads");
        assert!(!session.is_guest());
        assert!(session.guest.is_none());
    }

    // ---- the invitation -------------------------------------------------------

    #[test]
    fn the_invitation_names_no_provider_and_carries_no_credential() {
        let message = keyed::invitation("outsider@example.org", "Alice", "Budget.xlsx", "https://craft.example.com/invite/handle.secret");
        assert_eq!(message.to, vec!["outsider@example.org".to_owned()]);
        assert!(!message.html, "plain text, so nothing in it can be dressed up as something else");
        assert!(message.subject.contains("Alice"));
        assert!(message.subject.contains("Budget.xlsx"));
        assert!(message.body.contains("https://craft.example.com/invite/handle.secret"));
        let haystack = format!("{} {}", message.subject.to_lowercase(), message.body.to_lowercase());
        for leak in ["nextcloud", "webdav", "ocs", "password", "valkey", "redis", "cloud.example.com"] {
            assert!(!haystack.contains(leak), "an invitation must not mention {leak}");
        }
    }

    // ---- what the app build is handed ----------------------------------------

    #[test]
    fn the_handoff_sends_a_browser_to_the_app_build_and_says_a_link_sent_it() {
        let page = crate::recipient::handoff("gridcraft", "session-abc", "https://craft.example.com");
        // The browser fallback and the link beside it go to the same place, so
        // somebody who presses the link rather than waiting gets the same
        // page. The marker says a keyed link is why, which is what lets the
        // build tell an unreachable service from an ordinary visit.
        assert!(page.contains("/gridcraft/?invite"), "the fallback carries the marker: {page}");
        assert_eq!(page.matches("/gridcraft/?invite").count(), 2, "the script target and the link agree");
        assert!(page.contains("craft+gridcraft://join"), "the installed app is tried first");
    }

    #[test]
    fn the_handoff_marker_carries_nothing_but_itself() {
        // It is one word on a query string. Anybody can type it, and the
        // service reads the cookie it set rather than anything in the URL. The
        // test exists so nobody later reads the marker as an authority, and so
        // the session id cannot be appended to it by a later edit.
        let page = crate::recipient::handoff("wordcraft", "session-abc", "https://craft.example.com");
        assert!(page.contains("/wordcraft/?invite\""), "the marker stands alone on the query");
        assert_eq!(page.matches("session-abc").count(), 1, "the session id appears once, in the scheme URL");
        let after_marker: Vec<&str> = page.split("/wordcraft/?invite").skip(1).collect();
        for tail in after_marker {
            assert!(!tail.starts_with('='), "nothing is appended to the marker");
            assert!(!tail.starts_with('&'), "and nothing follows it on the query");
        }
    }

    #[test]
    fn the_token_answer_carries_what_an_app_needs_before_it_draws() {
        // The shape `craft_cloud_client::InviteJoin` reads. A recipient has no
        // file list, so the name, the version and the address they were
        // written to can come from nowhere else.
        let answer = crate::recipient::Join {
            token: "relay-token".to_owned(),
            relay: "https://relay.example.com".to_owned(),
            room: "room-7".to_owned(),
            permission: Permission::View,
            name: "Budget.xlsx".to_owned(),
            etag: Some("v3".to_owned()),
            recipient: "outsider@example.org".to_owned(),
        };
        let wire = serde_json::to_value(&answer).expect("it serialises");
        assert_eq!(wire["name"], json!("Budget.xlsx"));
        assert_eq!(wire["etag"], json!("v3"));
        assert_eq!(wire["recipient"], json!("outsider@example.org"));
        assert_eq!(wire["permission"], json!("view"));
        assert!(wire.get("doc").is_none(), "the provider's handle is never sent to a recipient");
        assert!(wire.get("owner").is_none(), "nor is the sharer's account");
    }

    // ---- against a live bus -----------------------------------------------

    /// The store half, which no pure function can cover.
    ///
    /// Ignored by default because it needs a Valkey, and the gate that runs on
    /// every push has none. Run it with a bus in reach:
    ///
    /// ```text
    /// COLLABCRAFT_TEST_VALKEY=redis://127.0.0.1:6379/15 cargo test -- --ignored
    /// ```
    ///
    /// What it proves is the part the pure tests cannot. A record survives a
    /// round trip through the bus, the use counter is spent once and then
    /// refuses, and withdrawing the share deletes every key minted from it.
    #[tokio::test]
    #[ignore = "needs a Valkey; set COLLABCRAFT_TEST_VALKEY"]
    async fn the_bus_spends_a_key_once_and_withdrawal_removes_it() {
        let Ok(url) = std::env::var("COLLABCRAFT_TEST_VALKEY") else {
            panic!("set COLLABCRAFT_TEST_VALKEY to a Valkey this test may write to");
        };
        let store = crate::store::Store::new(&url, "collabcraft:selftest").expect("a client");

        let key = Key::mint();
        let link = link_for(&key, NOW + 3600, 1, Permission::Edit);
        assert!(store.put_keyed_link(&key.handle, &link, 300).await, "the record goes in");

        let read_back = store.keyed_link(&key.handle).await.expect("the record comes back");
        assert_eq!(read_back, link, "a round trip through the bus changes nothing");
        assert_eq!(store.keyed_uses(&key.handle).await, 0, "a fresh key is unspent");

        // Spending once is allowed. Spending again is not, which is the whole
        // of a single-use link.
        assert!(store.spend_keyed_link(&key.handle, link.max_uses, 300).await, "the first use is granted");
        assert_eq!(store.keyed_uses(&key.handle).await, 1);
        assert!(!store.spend_keyed_link(&key.handle, link.max_uses, 300).await, "the second use is refused");

        // A key that allows three uses grants three and then stops.
        let three = Key::mint();
        let generous = link_for(&three, NOW + 3600, 3, Permission::View);
        assert!(store.put_keyed_link(&three.handle, &generous, 300).await);
        for use_number in 1..=3 {
            assert!(store.spend_keyed_link(&three.handle, 3, 300).await, "use {use_number} is granted");
        }
        assert!(!store.spend_keyed_link(&three.handle, 3, 300).await, "the fourth is refused");

        // Withdrawing the share withdraws both of them, because both were
        // minted from the same one.
        let dropped = store.drop_keyed_links_for_share(&link.share).await;
        assert_eq!(dropped, 2, "both keys were minted from share {}", link.share);
        assert!(store.keyed_link(&key.handle).await.is_none(), "the record is gone");
        assert!(store.keyed_link(&three.handle).await.is_none(), "so is the other");
        assert_eq!(store.keyed_uses(&key.handle).await, 0, "and so is the counter");

        // Withdrawing a share nothing was minted from is not an error.
        assert_eq!(store.drop_keyed_links_for_share("share-nobody-used").await, 0);
    }

    /// Plant a key a live service can be asked to follow.
    ///
    /// Ignored for the same reason, and separate because it leaves the record
    /// in place on purpose. It writes the key to the path in
    /// `COLLABCRAFT_TEST_KEY_OUT` so a shell can follow the link against a
    /// running service and see the whole chain run.
    #[tokio::test]
    #[ignore = "needs a Valkey; set COLLABCRAFT_TEST_VALKEY and COLLABCRAFT_TEST_KEY_OUT"]
    async fn plant_a_key_for_a_live_service() {
        let Ok(url) = std::env::var("COLLABCRAFT_TEST_VALKEY") else {
            panic!("set COLLABCRAFT_TEST_VALKEY to a Valkey this test may write to");
        };
        let Ok(out) = std::env::var("COLLABCRAFT_TEST_KEY_OUT") else {
            panic!("set COLLABCRAFT_TEST_KEY_OUT to a path the key may be written to");
        };
        // The same prefix the service uses, so the service finds what this
        // writes. The secret has to match the running service's too.
        let secret = std::env::var("COLLABCRAFT_SECRET").expect("the service secret");
        let store = crate::store::Store::new(&url, "collabcraft:svc").expect("a client");

        let key = Key::mint();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let link = Link {
            verifier: key.verifier(secret.as_bytes()).expect("a verifier"),
            room: "room-planted".to_owned(),
            doc: "/Documents/Budget.xlsx".to_owned(),
            app: "gridcraft".to_owned(),
            permission: Permission::Edit,
            recipient: "outsider@example.org".to_owned(),
            owner: "alice".to_owned(),
            share: "share-planted".to_owned(),
            exp: now + 3600,
            max_uses: 1,
            invite_url: None,
        };
        assert!(store.put_keyed_link(&key.handle, &link, 3600).await);
        std::fs::write(&out, key.wire()).expect("the key is written where the shell can read it");
    }
}

/// The web face: who may open what, who may configure the provider, and which
/// provider wins.
///
/// Its own module for the same reason as the one above. Every decision under
/// test is a pure function over configuration and a session, or a handler that
/// refuses before it reaches the bus. None of them needs a datastore.
mod web {

    use std::sync::Arc;

    use axum::extract::{Form, Query, State};
    use axum::http::StatusCode;
    use craft_cloud::{Capability, Permission};

    use crate::keyed::Policy;
    use crate::pages::{self, Flash, ProviderForm};
    use crate::session::{Guest, Session};
    use crate::settings::{ProviderConfig, Settings, Source};
    use crate::state::{App, Permissions};

    use super::SECRET;

    /// A service, as far as anything below needs one.
    ///
    /// Nothing here opens a socket. The store holds a client and not a
    /// connection, and every assertion is about what this deployment permits
    /// or draws.
    fn service(permissions: Permissions, settings: Settings, hosted: &[&str]) -> App {
        App {
            secret: SECRET.to_vec(),
            relay_url: "https://craft.example.com".to_owned(),
            settings,
            permissions,
            store: crate::store::Store::new("redis://127.0.0.1:6379/15", "collabcraft:test").expect("a client, not a connection"),
            oidc: None,
            http: reqwest::Client::new(),
            web: tower_http::services::ServeDir::new("."),
            hosted: hosted.iter().map(|a| (*a).to_owned()).collect(),
            keyed: Policy::decide(None, "https://craft.example.com", None, None),
            esign: None,
        }
    }

    fn signed_in(groups: &[&str]) -> Session {
        Session {
            user: "sub-1".to_owned(),
            display: "Alice Example".to_owned(),
            email: Some("alice@example.com".to_owned()),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            guest: None,
        }
    }

    fn recipient(app: &str) -> Session {
        Session {
            user: Guest::user_id("handle-1"),
            display: "outsider@example.org".to_owned(),
            email: Some("outsider@example.org".to_owned()),
            groups: Vec::new(),
            guest: Some(Guest {
                link: "handle-1".to_owned(),
                room: "room-7".to_owned(),
                doc: "/Documents/Budget.xlsx".to_owned(),
                app: app.to_owned(),
                permission: Permission::Edit,
            }),
        }
    }

    fn env_provider(url: &str) -> Settings {
        Settings::decide(Some(url), None, None)
    }

    fn admin_settings() -> Settings {
        Settings::decide(Some("https://cloud.example.com"), None, Some("craft-admins"))
    }

    /// An identity provider, as far as a page needs one.
    ///
    /// Nothing here dials it. A page only asks whether this deployment has
    /// one, because that decides whether a sign-in can work at all.
    fn identity_provider() -> crate::session::Oidc {
        crate::session::Oidc {
            client_id: "collabcraft".to_owned(),
            client_secret: "not a real client secret".to_owned(),
            redirect_uri: "https://craft.example.com/auth/callback".to_owned(),
            discovery: crate::session::Discovery {
                authorization_endpoint: "https://id.example.com/authorize".to_owned(),
                token_endpoint: "https://id.example.com/token".to_owned(),
                userinfo_endpoint: "https://id.example.com/userinfo".to_owned(),
            },
        }
    }

    fn form(csrf: &str, kind: &str, base: &str, action: &str) -> ProviderForm {
        ProviderForm {
            csrf: csrf.to_owned(),
            kind: kind.to_owned(),
            base: base.to_owned(),
            contacts: String::new(),
            action: action.to_owned(),
            client_id: String::new(),
            client_secret: String::new(),
        }
    }

    // ---- entitlement a deployment can change without a redeploy -------------

    #[test]
    fn a_typed_entitlement_round_trips_through_the_form_and_back() {
        // What somebody types has to come back as what they typed. A page that
        // reformats an administrator's text on every save teaches them not to
        // trust it.
        let typed = Permissions::parse("gridcraft, wordcraft", "editors: deckcraft, pdfcraft\nreaders: pdfcraft\n");
        assert_eq!(typed.default_apps(), ["gridcraft".to_owned(), "wordcraft".to_owned()]);
        assert_eq!(typed.groups_text(), "editors: deckcraft, pdfcraft\nreaders: pdfcraft\n");

        let again = Permissions::parse(&typed.default_apps().join(", "), &typed.groups_text());
        assert_eq!(again, typed, "a save of what the page showed changes nothing");
    }

    #[test]
    fn a_checkbox_save_keeps_a_grant_for_an_application_that_is_not_hosted() {
        let mut saved = Permissions::from_checks(&["gridcraft".to_owned()], &["editors".to_owned()], &["0:wordcraft".to_owned()]);
        let previous = Permissions::parse("gridcraft, missingcraft", "editors: wordcraft, alsomissing");
        saved.keep_absent(&previous, &["gridcraft".to_owned(), "wordcraft".to_owned()]);
        assert!(saved.default_apps().contains(&"missingcraft".to_owned()));
        let editors = saved.group_apps().get("editors").expect("the group");
        assert!(editors.contains(&"wordcraft".to_owned()));
        assert!(editors.contains(&"alsomissing".to_owned()));
    }

    #[test]
    fn the_apps_page_offers_a_box_per_hosted_application() {
        let app = service(Permissions::decide("gridcraft", &[]), crate::settings::Settings::decide(None, None, None), &["gridcraft", "wordcraft"]);
        let entitled = Permissions::decide("gridcraft", &[("editors", "wordcraft")]);
        let body = pages::apps_body(&app, &signed_in(&["craft-admins"]), &entitled, Source::Stored, None, None);
        assert!(body.contains("type=\"checkbox\" name=\"default\" value=\"gridcraft\" checked"));
        assert!(body.contains("type=\"checkbox\" name=\"grant\" value=\"0:wordcraft\" checked"));
        assert!(body.contains("name=\"group_name\""));
        assert!(!body.contains("name=\"groups\""), "the comma textarea is gone");
        assert!(!body.contains("<textarea"));
    }

    #[test]
    fn a_group_line_without_a_colon_grants_that_group_nothing() {
        // Half a line is a line somebody is still typing. Granting the whole
        // catalogue to a group because its line was unfinished would be the
        // worst reading of it.
        let typed = Permissions::parse("", "editors\n  \n: wordcraft\n");
        assert_eq!(typed.group_apps().len(), 1, "the nameless line is dropped");
        assert_eq!(typed.group_apps().get("editors"), Some(&Vec::new()));
    }

    #[test]
    fn a_group_name_is_stored_in_one_case_whatever_was_typed() {
        let typed = Permissions::parse("", "Craft-Editors: wordcraft");
        assert_eq!(typed.group_apps().keys().collect::<Vec<_>>(), vec!["craft-editors"]);
        assert_eq!(typed.apps_for_session(&signed_in(&["CRAFT-EDITORS"])), vec!["wordcraft".to_owned()]);
    }

    #[test]
    fn the_page_names_what_is_granted_and_not_deployed() {
        // The one mistake whose only symptom is a card that never appears.
        // Both halves have to be right, and only this page sees both.
        let entitled = Permissions::parse("gridcraft, figcraft", "editors: wordcraft, soundcraft");
        let app = service(Permissions::decide("", &[]), env_provider("https://cloud.example.com"), &["gridcraft", "wordcraft"]);
        assert_eq!(pages::granted_but_absent(&app, &entitled), vec!["figcraft".to_owned(), "soundcraft".to_owned()]);

        let all_there = Permissions::parse("gridcraft", "editors: wordcraft");
        assert!(pages::granted_but_absent(&app, &all_there).is_empty(), "nothing to warn about");
    }

    #[test]
    fn an_entitlement_nobody_stored_is_the_one_the_environment_named() {
        // The store is unreachable in a test, which is the same answer as a
        // deployment that never visited the page. Both leave the environment
        // in charge, and neither is an error.
        let app = service(Permissions::decide("gridcraft", &[]), env_provider("https://cloud.example.com"), &["gridcraft"]);
        let (entitled, source) = futures_lite_block_on(app.entitlements());
        assert_eq!(entitled.default_apps(), ["gridcraft".to_owned()]);
        assert_eq!(source, crate::settings::Source::Environment);
    }

    /// Runs one future to completion on this thread.
    ///
    /// The entitlement read is async because it may reach the bus. Everything
    /// it is asserted about here is the fallback, which touches nothing.
    fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
        // Timers on, because the bus client arms one before it gives up on a
        // connection nobody is listening for.
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime").block_on(f)
    }

    // ---- what the launcher may draw -----------------------------------------

    #[test]
    fn the_launcher_draws_only_what_this_deployment_hosts() {
        // An entitlement to an application nobody deployed opens nothing. A
        // card for it would be a tile over a 404.
        let app = service(Permissions::decide("gridcraft,wordcraft", &[]), env_provider("https://cloud.example.com"), &["gridcraft"]);
        assert_eq!(app.launchable(&app.permissions, &signed_in(&[])), vec!["gridcraft".to_owned()]);
    }

    #[test]
    fn an_application_nobody_is_entitled_to_draws_no_card() {
        let app = service(Permissions::decide("gridcraft", &[]), env_provider("https://cloud.example.com"), &["gridcraft", "pdfcraft"]);
        let launchable = app.launchable(&app.permissions, &signed_in(&[]));
        assert_eq!(launchable, vec!["gridcraft".to_owned()]);
        assert!(!launchable.contains(&"pdfcraft".to_owned()), "hosting an application is not granting it");
    }

    #[test]
    fn a_group_adds_to_what_the_default_grants() {
        let permissions = Permissions::decide("gridcraft", &[("editors", "wordcraft,deckcraft")]);
        let app = service(permissions, env_provider("https://cloud.example.com"), &["gridcraft", "wordcraft", "deckcraft"]);
        assert_eq!(app.launchable(&app.permissions, &signed_in(&[])), vec!["gridcraft".to_owned()]);
        assert_eq!(
            app.launchable(&app.permissions, &signed_in(&["editors"])),
            vec!["deckcraft".to_owned(), "gridcraft".to_owned(), "wordcraft".to_owned()],
            "membership of one group is the whole of granting the rest"
        );
    }

    #[test]
    fn a_group_name_matches_whatever_case_the_identity_provider_reports() {
        let permissions = Permissions::decide("", &[("Craft-Editors", "wordcraft")]);
        let app = service(permissions, env_provider("https://cloud.example.com"), &["wordcraft"]);
        for reported in ["craft-editors", "Craft-Editors", "CRAFT-EDITORS"] {
            assert_eq!(app.launchable(&app.permissions, &signed_in(&[reported])), vec!["wordcraft".to_owned()], "{reported} is the same group");
        }
    }

    #[test]
    fn a_recipient_may_launch_only_the_application_their_link_names() {
        let hosted = ["gridcraft", "wordcraft"];
        let app = service(Permissions::decide("gridcraft,wordcraft", &[]), env_provider("https://cloud.example.com"), &hosted);
        assert_eq!(app.launchable(&app.permissions, &recipient("gridcraft")), vec!["gridcraft".to_owned()]);
        assert_eq!(app.launchable(&app.permissions, &recipient("wordcraft")), vec!["wordcraft".to_owned()]);
    }

    #[test]
    fn a_recipient_sent_into_an_application_nobody_hosts_may_launch_nothing() {
        let app = service(Permissions::decide("gridcraft", &[]), env_provider("https://cloud.example.com"), &["gridcraft"]);
        assert!(app.launchable(&app.permissions, &recipient("cadcraft")).is_empty());
    }

    // ---- who may configure the provider -------------------------------------

    #[test]
    fn only_a_member_of_a_named_group_may_change_the_provider() {
        let settings = admin_settings();
        assert!(settings.may_configure(&signed_in(&["craft-admins"])));
        assert!(!settings.may_configure(&signed_in(&["editors"])));
        assert!(!settings.may_configure(&signed_in(&[])));
    }

    #[test]
    fn the_configuring_group_matches_whatever_case_is_reported() {
        let settings = Settings::decide(None, None, Some(" Craft-Admins , platform "));
        for reported in ["craft-admins", "CRAFT-ADMINS", "Craft-Admins", "platform", "PLATFORM"] {
            assert!(settings.may_configure(&signed_in(&[reported])), "{reported} names a configuring group");
        }
        assert!(!settings.may_configure(&signed_in(&["craft-admins-readonly"])), "a longer name is a different group");
    }

    #[test]
    fn a_deployment_naming_no_group_lets_nobody_change_the_provider() {
        // The safe way round. A deployment that never said who may configure
        // it has nobody who may, so the page refuses everybody and the control
        // appears for nobody.
        for groups in [None, Some(""), Some("  "), Some(" , ")] {
            let settings = Settings::decide(Some("https://cloud.example.com"), None, groups);
            assert!(settings.admin_groups().is_empty(), "{groups:?} names no group");
            assert!(!settings.may_configure(&signed_in(&["craft-admins"])));
            let app = service(Permissions::decide("", &[]), settings, &[]);
            assert_eq!(pages::who_may(&app), "Nobody. This deployment names no group for it.");
        }
    }

    #[test]
    fn a_recipient_may_never_change_the_provider() {
        // A recipient carries no group, so the group check would refuse them
        // anyway. Refusing on the session as well means a deployment that
        // somehow granted a group to one still refuses.
        let settings = admin_settings();
        let mut holding_a_group = recipient("gridcraft");
        holding_a_group.groups = vec!["craft-admins".to_owned()];
        assert!(!settings.may_configure(&recipient("gridcraft")));
        assert!(!settings.may_configure(&holding_a_group));
    }

    #[test]
    fn the_page_names_the_group_that_may_change_the_provider() {
        let one = service(Permissions::decide("", &[]), Settings::decide(None, None, Some("craft-admins")), &[]);
        assert_eq!(pages::who_may(&one), "Members of the group craft-admins.");
        let two = service(Permissions::decide("", &[]), Settings::decide(None, None, Some("craft-admins,platform")), &[]);
        assert_eq!(pages::who_may(&two), "Members of these groups: craft-admins, platform.");
    }

    #[test]
    fn a_refusal_says_what_the_sign_in_actually_carried() {
        // The two reasons a person is refused are fixed in different places.
        // Being in none of the named groups is a membership to change. A
        // sign-in carrying no groups at all is usually a scope that was never
        // bound to this application, and no amount of group editing fixes it.
        assert_eq!(pages::carried(&signed_in(&[])), pages::NO_GROUPS);
        assert_eq!(pages::carried(&signed_in(&["dunn-home-users", "app-collabcraft"])), "Your sign-in carried: dunn-home-users, app-collabcraft.");
    }

    // ---- where the provider comes from --------------------------------------

    #[test]
    fn a_stored_provider_overrides_the_environment() {
        let settings = env_provider("https://env.example.com");
        let stored = ProviderConfig { kind: "nextcloud".to_owned(), base: "https://stored.example.com".to_owned(), contacts: None };
        let (config, source) = settings.resolve(Some(stored)).expect("a provider");
        assert_eq!(config.base, "https://stored.example.com");
        assert_eq!(source, Source::Stored);
    }

    #[test]
    fn a_deployment_that_stores_nothing_keeps_its_environment_provider() {
        // The whole of the compatibility promise. A deployment upgraded into
        // this stores nothing, so it stays on exactly the provider it had.
        let settings = env_provider("https://env.example.com/");
        let (config, source) = settings.resolve(None).expect("a provider");
        assert_eq!(config.base, "https://env.example.com", "a trailing slash is normalised away");
        assert_eq!(config.kind, "nextcloud");
        assert_eq!(source, Source::Environment);
    }

    #[test]
    fn a_stored_record_naming_no_address_is_ignored() {
        // A half-written record must not take a working deployment off its
        // provider.
        let settings = env_provider("https://env.example.com");
        for empty in ["", "   "] {
            let stored = ProviderConfig { kind: "nextcloud".to_owned(), base: empty.to_owned(), contacts: None };
            let (config, source) = settings.resolve(Some(stored)).expect("the environment still answers");
            assert_eq!(config.base, "https://env.example.com");
            assert_eq!(source, Source::Environment);
        }
    }

    #[test]
    fn a_deployment_with_neither_has_no_provider() {
        let settings = Settings::decide(None, None, None);
        assert!(settings.resolve(None).is_none());
        assert!(settings.env_default().is_none());
    }

    #[test]
    fn the_environment_default_is_still_reported_once_something_is_stored() {
        // The setup page says which of the two is in use. That needs both.
        let settings = env_provider("https://env.example.com");
        let stored = ProviderConfig { kind: "nextcloud".to_owned(), base: "https://stored.example.com".to_owned(), contacts: None };
        assert_eq!(settings.resolve(Some(stored)).map(|(c, _)| c.base), Some("https://stored.example.com".to_owned()));
        assert_eq!(settings.env_default().map(|c| c.base.clone()), Some("https://env.example.com".to_owned()));
    }

    #[test]
    fn an_address_that_is_not_a_server_address_is_refused() {
        for bad in ["", "   ", "cloud.example.com", "ftp://cloud.example.com", "https://", "https:///files", "javascript:alert(1)"] {
            assert!(ProviderConfig::parse("nextcloud", bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn an_address_carrying_a_credential_or_a_query_is_refused() {
        // Accepting one would put a credential into configuration every
        // administrator can read.
        for bad in [
            "https://user:secret@cloud.example.com",
            "https://cloud.example.com?token=abc",
            "https://cloud.example.com#/apps/files",
            "https://cloud example.com",
        ] {
            assert!(ProviderConfig::parse("nextcloud", bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn an_address_that_is_a_server_address_is_accepted_and_tidied() {
        let config = ProviderConfig::parse(" NextCloud ", "  https://cloud.example.com/  ").expect("accepted");
        assert_eq!(config.kind, "nextcloud");
        assert_eq!(config.base, "https://cloud.example.com");
        assert_eq!(ProviderConfig::parse("nextcloud", "http://cloud.internal:8080").expect("accepted").base, "http://cloud.internal:8080");
    }

    #[test]
    fn a_kind_this_binary_does_not_implement_is_refused() {
        // Offered nowhere in the form either. Storing one would leave a
        // deployment pointed at something nothing here can speak to.
        for bad in ["", "dropbox", "seafile", "nextcloud-ng"] {
            assert!(ProviderConfig::parse(bad, "https://cloud.example.com").is_err(), "{bad:?} must be refused");
        }
        assert!(ProviderConfig::parse("nextcloud", "https://cloud.example.com").is_ok());
        assert_eq!(
            ProviderConfig::parse("git", "https://github.com/fpoussin/solidcraft-designs/").expect("accepted").base,
            "https://github.com/fpoussin/solidcraft-designs"
        );
    }

    #[test]
    fn an_unusable_environment_address_leaves_the_deployment_with_no_provider() {
        // Reported as no provider at all. Half-believing a malformed address
        // would leave every route failing on use with nothing said at startup.
        let settings = Settings::decide(Some("cloud.example.com"), None, None);
        assert!(settings.env_default().is_none());
        assert!(settings.resolve(None).is_none());
    }

    // ---- the pages themselves -----------------------------------------------

    #[test]
    fn an_anonymous_visitor_is_offered_a_sign_in_and_never_a_refusal() {
        let mut app = service(Permissions::decide("gridcraft", &[]), env_provider("https://cloud.example.com"), &["gridcraft"]);
        app.oidc = Some(identity_provider());
        let page = pages::layout("Welcome", None, &pages::welcome(&app));
        assert!(page.contains("/auth/login"), "an anonymous visitor gets somewhere to go");
        for refusal in ["403", "Forbidden", "not permitted", "unauthenticated"] {
            assert!(!page.contains(refusal), "nobody has been refused anything yet, so {refusal} has no place here");
        }
    }

    #[test]
    fn a_deployment_with_no_identity_provider_offers_no_sign_in() {
        // The control cannot work, so it is not drawn.
        let app = service(Permissions::decide("", &[]), env_provider("https://cloud.example.com"), &[]);
        assert!(app.oidc.is_none());
        let page = pages::layout("Welcome", None, &pages::welcome(&app));
        assert!(!page.contains("/auth/login"), "a sign-in with nowhere to go is not offered");
        assert!(page.contains("no identity provider configured"), "the page says why instead");
    }

    #[test]
    fn the_launcher_names_no_provider_and_carries_no_credential() {
        // What a browser receives is bounded. The address of the provider is
        // for the group entitled to change it.
        let app = service(Permissions::decide("gridcraft", &[]), env_provider("https://cloud.example.com"), &["gridcraft"]);
        let page = pages::layout("Applications", Some(&signed_in(&[])), &pages::card("gridcraft"));
        let haystack = format!("{page}{}", pages::welcome(&app)).to_lowercase();
        for leak in ["cloud.example.com", "nextcloud", "webdav", "ocs", "password", "valkey", "redis", "secret"] {
            assert!(!haystack.contains(leak), "a page must not mention {leak}");
        }
    }

    #[test]
    fn the_setup_page_names_the_address_because_that_group_may_change_it() {
        let app = service(Permissions::decide("gridcraft", &[]), admin_settings(), &["gridcraft"]);
        let stored = ProviderConfig { kind: "nextcloud".to_owned(), base: "https://stored.example.com".to_owned(), contacts: None };
        let in_use = (stored, Source::Stored);
        let body = pages::provider_body(&app, &signed_in(&["craft-admins"]), Some(&in_use), None, None);
        assert!(body.contains("https://stored.example.com"), "the address in use is the point of the page");
        assert!(body.contains("https://cloud.example.com"), "so is the environment default it overrides");
        assert!(body.contains("set on this page"), "and which of the two is in use");
        assert!(body.contains("craft-admins"), "the page says who may change it");
    }

    #[test]
    fn the_setup_page_hands_back_what_somebody_typed() {
        // A refused form comes back with their own text in it, escaped.
        let app = service(Permissions::decide("gridcraft", &[]), admin_settings(), &["gridcraft"]);
        let typed = form("", "nextcloud", "https://typo.example.com\" onload=\"x", "save");
        let body = pages::provider_body(&app, &signed_in(&["craft-admins"]), None, None, Some(&typed));
        assert!(body.contains("https://typo.example.com&quot; onload=&quot;x"), "their text comes back as text");
        assert!(!body.contains("onload=\"x\""), "and never as markup");
    }

    #[test]
    fn a_page_escapes_what_a_person_called_themselves() {
        let mut session = signed_in(&[]);
        session.display = "<script>alert('x')</script>".to_owned();
        let page = pages::layout("Applications", Some(&session), "");
        assert!(!page.contains("<script>alert"), "a display name is text and never markup");
        assert!(page.contains("&lt;script&gt;"));
    }

    #[test]
    fn a_card_carries_the_application_name_and_a_stable_tile() {
        let one = pages::card("gridcraft");
        assert!(one.contains("href=\"/gridcraft/\""));
        assert!(one.contains("GridCraft"), "a slug reads as the application's name");
        assert!(one.contains("--app:#1f9d55"), "a known app uses the launcher's brand colour");
        assert_eq!(one, pages::card("gridcraft"), "the same application draws the same card every time");
        assert_ne!(pages::card("wordcraft"), one);
        // An application this binary has never heard of still gets a card.
        let unknown = pages::card("sheetworks");
        assert!(unknown.contains("Sheetworks"));
        assert!(unknown.contains("--app:hsl("), "an unknown app still gets a stable colour");
    }

    #[test]
    fn a_capability_with_nothing_to_say_draws_nothing() {
        // The account page lists what storage allows. A capability with no
        // sentence for a person is left out, because an internal name tells
        // them nothing they can act on.
        assert_eq!(pages::capability_label(Capability::Sharing), Some("Share a document"));
        assert_eq!(pages::capability_label(Capability::Etags), None);
    }

    // ---- forms prove where they came from -----------------------------------

    #[test]
    fn a_form_token_is_tied_to_one_person() {
        let mine = pages::csrf(SECRET, "sub-1");
        assert!(pages::csrf_ok(SECRET, "sub-1", &mine));
        assert!(!pages::csrf_ok(SECRET, "sub-2", &mine), "another account's form must not act on mine");
        assert_ne!(pages::csrf(SECRET, "sub-2"), mine);
    }

    #[test]
    fn a_form_token_from_another_secret_does_not_pass() {
        let elsewhere = pages::csrf(b"a-different-secret-also-long-enough-x", "sub-1");
        assert!(!pages::csrf_ok(SECRET, "sub-1", &elsewhere));
    }

    #[test]
    fn a_form_with_no_usable_token_is_refused() {
        for bad in ["", "   ", "not base64 at all", "AAAA", "!!!!"] {
            assert!(!pages::csrf_ok(SECRET, "sub-1", bad), "{bad:?} must not pass");
        }
    }

    // ---- the gate, through the handler --------------------------------------

    #[tokio::test]
    async fn the_setup_page_refuses_somebody_outside_the_group() {
        let app = Arc::new(service(Permissions::decide("gridcraft", &[]), admin_settings(), &["gridcraft"]));

        let outside = pages::provider(State(app.clone()), Some(signed_in(&["editors"])), Query(Flash::default())).await;
        assert_eq!(outside.status(), StatusCode::FORBIDDEN);

        let recipient_asking = pages::provider(State(app.clone()), Some(recipient("gridcraft")), Query(Flash::default())).await;
        assert_eq!(recipient_asking.status(), StatusCode::FORBIDDEN);

        // An anonymous visitor is sent to sign in. They have been refused
        // nothing yet.
        let anonymous = pages::provider(State(app), None, Query(Flash::default())).await;
        assert_eq!(anonymous.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn saving_the_provider_refuses_somebody_outside_the_group_before_anything_else() {
        let app = Arc::new(service(Permissions::decide("gridcraft", &[]), admin_settings(), &["gridcraft"]));
        // A token this service really did mint, from a session outside the
        // group. The gate is membership and nothing else.
        let submitted = form(&pages::csrf(SECRET, "sub-1"), "nextcloud", "https://elsewhere.example.com", "save");
        let refused = pages::provider_save(State(app), signed_in(&["editors"]), Form(submitted)).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn saving_the_provider_refuses_a_form_this_service_did_not_serve() {
        let app = Arc::new(service(Permissions::decide("gridcraft", &[]), admin_settings(), &["gridcraft"]));
        let submitted = form("borrowed-from-nowhere", "nextcloud", "https://elsewhere.example.com", "save");
        let refused = pages::provider_save(State(app), signed_in(&["craft-admins"]), Form(submitted)).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_address_the_form_refuses_never_reaches_the_network() {
        let app = Arc::new(service(Permissions::decide("gridcraft", &[]), admin_settings(), &["gridcraft"]));
        let submitted = form(&pages::csrf(SECRET, "sub-1"), "nextcloud", "cloud.example.com", "save");
        let refused = pages::provider_save(State(app), signed_in(&["craft-admins"]), Form(submitted)).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "a malformed address is refused before anything is dialled");
    }
}

mod provider_kinds {
    use crate::settings::{KINDS, ProviderConfig, kind_label};

    #[test]
    fn every_kind_the_binary_offers_is_accepted_and_builds_a_provider() {
        for kind in KINDS {
            let config = ProviderConfig::parse(kind, "https://cloud.example.com").expect("accepted");
            let provider = crate::state::provider_from(&config, "alice", "pw").expect("built");
            assert_eq!(provider.id(), kind, "the provider reports the kind it was configured as");
        }
        let unknown = ProviderConfig { kind: "dropbox".to_owned(), base: "https://x".to_owned(), contacts: None };
        assert!(crate::state::provider_from(&unknown, "alice", "pw").is_none());
    }

    #[test]
    fn only_nextcloud_links_through_a_browser_sign_in() {
        let link = |kind| ProviderConfig::parse(kind, "https://cloud.example.com").expect("accepted").uses_login_flow();
        assert!(link("nextcloud"));
        assert!(!link("owncloud"));
        assert!(!link("webdav"));
        assert!(!link("google"));
        assert!(!link("git"));
    }

    #[test]
    fn a_webdav_address_may_carry_a_path_and_a_user_placeholder() {
        let config = ProviderConfig::parse("webdav", "https://dav.example.com/files/{user}/").expect("accepted");
        assert_eq!(config.base, "https://dav.example.com/files/{user}");
        assert_eq!(config.layout().files_for("alice"), "https://dav.example.com/files/alice");
    }

    #[test]
    fn an_address_book_is_kept_for_webdav_and_dropped_elsewhere() {
        let dav = ProviderConfig::parse("webdav", "https://dav.example.com/files").expect("accepted");
        let with = dav.clone().with_contacts(" https://dav.example.com/card/{user}/ ").expect("accepted");
        assert_eq!(with.contacts.as_deref(), Some("https://dav.example.com/card/{user}"));
        assert!(dav.clone().with_contacts("not an address").is_err());
        assert_eq!(dav.with_contacts("").expect("empty is none").contacts, None);
        let nc = ProviderConfig::parse("nextcloud", "https://cloud.example.com").expect("accepted");
        assert_eq!(nc.with_contacts("https://elsewhere.example.com").expect("ignored").contacts, None);
    }

    #[test]
    fn a_record_stored_before_address_books_existed_still_reads() {
        let old: ProviderConfig = serde_json::from_str(r#"{"kind":"nextcloud","base":"https://cloud.example.com"}"#).expect("read");
        assert_eq!(old.contacts, None);
        let written = serde_json::to_string(&old).expect("written");
        assert!(!written.contains("contacts"), "an absent address book is not written out");
    }

    #[test]
    fn kinds_are_named_the_way_their_makers_spell_them() {
        assert_eq!(kind_label("owncloud"), "ownCloud");
        assert_eq!(kind_label("webdav"), "WebDAV");
        assert_eq!(kind_label("nextcloud"), "Nextcloud");
        assert_eq!(kind_label("google"), "Google Drive");
        assert_eq!(kind_label("git"), "Git");
    }

    #[test]
    fn a_connection_handle_round_trips_and_a_legacy_handle_does_not_split() {
        let id = "ab".repeat(32);
        let stamped = crate::route::stamp(&id, "file:with:colons");
        assert_eq!(crate::route::split(&stamped), Some((id.as_str(), "file:with:colons")));
        assert!(crate::route::split("/Documents/Budget.xlsx").is_none());
        assert!(crate::route::split("cx:short:file").is_none());
    }
}
