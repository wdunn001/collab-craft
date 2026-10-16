//! Tests. Every one runs against a canned transport, so none of them touch a
//! network and none of them need a browser.
//!
//! Two things are covered. The mappings in [`crate::answer`], which both
//! targets share, and the sequence in [`crate::run`], which the browser's twin
//! repeats with an `await` on each call. So a request's shape and the dialog's
//! answer are checked once and hold on both.

use std::sync::{Arc, Mutex};

use craft_cloud::{Capability, Permission, Share, ShareTarget};
use craft_cloud_client::{Client, Error, KeyedOutcome, Me, Request as Sent, Response, ShareFailure, ShareOutcome, Transport};
use craft_ui::share::{Answer, Grant, Request};

use crate::{answer, run};

/// A transport that answers from a script and records what it was asked.
struct Fake {
    replies: Mutex<Vec<Response>>,
    seen: Mutex<Vec<Sent>>,
}

impl Fake {
    fn one(status: u16, body: &str) -> Arc<Fake> {
        Arc::new(Fake { replies: Mutex::new(vec![Response::new(status, body.as_bytes().to_vec())]), seen: Mutex::new(Vec::new()) })
    }

    fn last(&self) -> Sent {
        self.seen.lock().unwrap().last().cloned().unwrap_or_else(|| Sent::new(craft_cloud_client::Method::Get, ""))
    }
}

impl Transport for Fake {
    fn send(&self, req: Sent) -> Result<Response, Error> {
        self.seen.lock().unwrap().push(req);
        let mut replies = self.replies.lock().unwrap();
        if replies.is_empty() {
            return Err(Error::Unreachable("no scripted reply left".to_owned()));
        }
        Ok(replies.remove(0))
    }
}

fn client(fake: &Arc<Fake>) -> Client {
    Client::with_transport("https://craft.example.com", fake.clone() as Arc<dyn Transport + Send + Sync>)
}

const WHO: &str = r#"{"id":"u1","display":"Alice","email":"alice@example.net","avatar":null,"apps":["gridcraft"],
    "capabilities":["files","sharing","link_shares"],"provider_linked":true}"#;

fn me(email: Option<&str>, linked: bool) -> Me {
    Me {
        id: "u1".to_owned(),
        display: "Alice".to_owned(),
        email: email.map(str::to_owned),
        avatar: None,
        apps: Vec::new(),
        capabilities: vec![Capability::Sharing],
        provider_linked: linked,
    }
}

// ---- the mappings both targets share ----------------------------------------

#[test]
fn a_grant_becomes_the_services_share_request() {
    let asked = answer::asked(
        Grant {
            password: Some("key".to_owned()),
            id: "docs/plan.ods".to_owned(),
            targets: vec![ShareTarget::Link],
            permission: Permission::View,
            note: Some("have a look".to_owned()),
            notify: true,
        },
        Some("gridcraft"),
    );
    assert_eq!(asked.id, "docs/plan.ods");
    assert_eq!(asked.targets, vec![ShareTarget::Link]);
    assert_eq!(asked.permission, Permission::View);
    assert_eq!(asked.note.as_deref(), Some("have a look"));
    assert!(asked.notify);
    assert_eq!(asked.app.as_deref(), Some("gridcraft"));
    assert_eq!(asked.password.as_deref(), Some("key"));
    assert_eq!(asked.expires, None, "the dialog has no field for an expiry, and inventing one would end a share nobody asked to end");
    assert_eq!(asked.app.as_deref(), Some("gridcraft"), "the sharing app names where a keyed invite lands");
}

#[test]
fn capabilities_carry_whether_an_account_is_linked() {
    match answer::capabilities(me(None, false)) {
        Answer::Capabilities { capabilities, linked } => {
            assert_eq!(capabilities, vec![Capability::Sharing]);
            assert!(!linked, "an unlinked account has nowhere to share to, and the dialog has to know before it offers");
        }
        other => panic!("expected the capabilities, got {other:?}"),
    }
}

#[test]
fn a_destination_names_the_account_behind_it() {
    match answer::destinations(me(Some("alice@example.net"), true)) {
        Answer::Destinations(places) => {
            assert_eq!(places.len(), 1);
            assert_eq!(places[0].id, answer::DESTINATION);
            assert_eq!(places[0].account.as_deref(), Some("alice@example.net"));
            assert!(places[0].linked);
        }
        other => panic!("expected the destinations, got {other:?}"),
    }
}

#[test]
fn a_destination_falls_back_to_the_display_name() {
    match answer::destinations(me(None, true)) {
        Answer::Destinations(places) => assert_eq!(places[0].account.as_deref(), Some("Alice")),
        other => panic!("expected the destinations, got {other:?}"),
    }
}

#[test]
fn a_share_reports_both_halves() {
    let outcome = ShareOutcome {
        shared: vec![Share {
            id: "ocs/1".to_owned(),
            target: ShareTarget::User("bob".to_owned()),
            display: Some("Bob Vickers".to_owned()),
            permission: Permission::Edit,
            url: None,
            note: None,
            created: None,
        }],
        failed: vec![ShareFailure {
            target: ShareTarget::Email("typo@".to_owned()),
            code: "invalid".to_owned(),
            detail: "not an address".to_owned(),
        }],
        keyed: Vec::new(),
    };
    match answer::granted(outcome) {
        Answer::Granted { shared, failed } => {
            assert_eq!(shared.len(), 1);
            assert_eq!(failed.len(), 1);
            assert_eq!(failed[0].code, "invalid");
            assert_eq!(failed[0].target, ShareTarget::Email("typo@".to_owned()));
        }
        other => panic!("expected a grant, got {other:?}"),
    }
}

// ---- the sequence each target repeats ---------------------------------------

#[test]
fn asking_what_the_provider_can_do_asks_the_service_who_this_is() {
    let fake = Fake::one(200, WHO);
    let answered = run(&client(&fake), Request::Capabilities).unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/me");
    assert!(matches!(answered, Answer::Capabilities { linked: true, .. }));
}

#[test]
fn a_lookup_carries_the_query_and_the_limit() {
    let fake = Fake::one(200, "[]");
    let answered = run(&client(&fake), Request::Lookup { query: "al ice".to_owned(), limit: 5 }).unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/contacts?q=al%20ice&limit=5");
    assert!(matches!(answered, Answer::Lookup(_)));
}

#[test]
fn asking_who_has_access_names_the_document() {
    let fake = Fake::one(200, "[]");
    let answered = run(&client(&fake), Request::Access { id: "docs/plan.ods".to_owned() }).unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/shares?id=docs%2Fplan.ods");
    assert!(matches!(answered, Answer::Access(_)));
}

#[test]
fn a_grant_is_posted_and_both_halves_come_back() {
    let fake = Fake::one(200, r#"{"shared":[],"failed":[],"keyed":[]}"#);
    let answered = run(
        &client(&fake),
        Request::Grant(Grant {
            password: None,
            id: "docs/plan.ods".to_owned(),
            targets: vec![ShareTarget::Email("someone@example.net".to_owned())],
            permission: Permission::Edit,
            note: None,
            notify: false,
        }),
    )
    .unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/shares");
    let body: serde_json::Value = serde_json::from_slice(&fake.last().body).unwrap();
    assert_eq!(body["targets"][0]["id"], "someone@example.net");
    assert!(matches!(answered, Answer::Granted { .. }));
}

#[test]
fn a_keyed_link_replaces_the_provider_url_for_the_same_share() {
    let outcome = ShareOutcome {
        shared: vec![Share {
            id: "ocs/1".to_owned(),
            target: ShareTarget::Link,
            display: None,
            permission: Permission::View,
            url: Some("https://cloud.example.net/s/provider".to_owned()),
            note: None,
            created: None,
        }],
        failed: Vec::new(),
        keyed: vec![KeyedOutcome {
            target: ShareTarget::Link,
            url: "https://craft.example.com/invite/handle.key".to_owned(),
            expires: 1_800_000_000,
            uses: 1,
            delivered: false,
            delivery: "copy".to_owned(),
        }],
    };
    match answer::granted(outcome) {
        Answer::Granted { shared, failed } => {
            assert!(failed.is_empty());
            assert_eq!(shared[0].id, "ocs/1", "the provider id stays available for revocation");
            assert_eq!(shared[0].url.as_deref(), Some("https://craft.example.com/invite/handle.key"));
        }
        other => panic!("expected a grant, got {other:?}"),
    }
}

#[test]
fn a_withdrawal_names_the_share_it_took_away() {
    let fake = Fake::one(204, "");
    let answered = run(&client(&fake), Request::Withdraw { share_id: "ocs/42".to_owned() }).unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/shares/ocs%2F42");
    match answered {
        // Handed back so the dialog can drop that row without asking again.
        Answer::Withdrawn { share_id } => assert_eq!(share_id, "ocs/42"),
        other => panic!("expected a withdrawal, got {other:?}"),
    }
}

#[test]
fn asking_where_a_document_could_go_describes_the_account() {
    let fake = Fake::one(200, WHO);
    match run(&client(&fake), Request::Destinations).unwrap() {
        Answer::Destinations(places) => assert_eq!(places[0].account.as_deref(), Some("alice@example.net")),
        other => panic!("expected the destinations, got {other:?}"),
    }
}

#[test]
fn asking_to_link_an_account_reports_where_to_go() {
    let fake = Fake::one(200, r#"{"login_url":"https://cloud.example.net/login/v2","handle":"h1"}"#);
    let refused = run(&client(&fake), Request::Link { destination: answer::DESTINATION.to_owned() }).unwrap_err();
    assert_eq!(fake.last().url, "https://craft.example.com/auth/link/start");
    assert!(refused.contains("https://cloud.example.net/login/v2"), "{refused}");
}

#[test]
fn asking_for_a_picture_is_refused_in_words() {
    let fake = Fake::one(200, "");
    let refused = run(&client(&fake), Request::Avatar { url: "https://cloud.example.net/avatar/bob".to_owned() }).unwrap_err();
    assert_eq!(refused, answer::no_pictures());
    assert_eq!(fake.last().url, "", "no call goes out for a picture, because that call would be to the provider");
}

#[test]
fn a_refusal_reaches_the_dialog_in_words_a_user_can_read() {
    let fake = Fake::one(401, r#"{"code":"unauthenticated","detail":"sign in first"}"#);
    let refused = run(&client(&fake), Request::Capabilities).unwrap_err();
    assert_eq!(refused, "sign in again");
}
