//! Tests. Every one runs against a canned transport, so none of them touch a
//! network and none of them need a browser.
//!
//! Both clients build their requests with [`crate::req`] and read their
//! answers with [`crate::wire`], so a test here covers the browser's URLs,
//! headers, bodies and refusals as well as the desktop's. What is left over in
//! the browser is the `fetch` call itself, and no test without a browser
//! reaches that.

use std::sync::{Arc, Mutex};

use craft_cloud::{Capability, Permission, ShareTarget};

use crate::wire::{Method, Request, Response, Target, enc, meta_selector, pending, status};
use crate::{Client, Error, Result, ShareRequest, Transport, req};

/// A transport that answers from a script and records what it was asked.
struct Fake {
    replies: Mutex<Vec<Response>>,
    seen: Mutex<Vec<Request>>,
}

impl Fake {
    fn new(replies: Vec<Response>) -> Arc<Fake> {
        Arc::new(Fake { replies: Mutex::new(replies), seen: Mutex::new(Vec::new()) })
    }

    fn one(status: u16, body: &str) -> Arc<Fake> {
        Fake::new(vec![Response::new(status, body.as_bytes().to_vec())])
    }

    fn last(&self) -> Request {
        self.seen.lock().unwrap().last().cloned().unwrap_or_else(|| Request::new(Method::Get, ""))
    }

    fn asked(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Transport for Fake {
    fn send(&self, req: Request) -> Result<Response> {
        self.seen.lock().unwrap().push(req);
        let mut replies = self.replies.lock().unwrap();
        if replies.is_empty() {
            return Err(Error::Unreachable("no scripted reply left".to_owned()));
        }
        Ok(replies.remove(0))
    }
}

const BASE: &str = "https://craft.example.com";

fn client(fake: &Arc<Fake>) -> Client {
    Client::with_transport(BASE, fake.clone() as Arc<dyn Transport + Send + Sync>)
}

/// One entry, as the service sends it.
const ENTRY: &str = r#"{"id":"docs/plan.ods","room":"fid-9","name":"plan.ods","path":"/docs","kind":"file",
    "size":12,"modified":null,"mime":null,"etag":"v2","writable":true,"shared_by":null}"#;

// ---- where a request goes ---------------------------------------------------

#[test]
fn the_service_root_loses_a_trailing_slash() {
    assert_eq!(Target::new("https://craft.example.com///").base(), BASE);
    assert_eq!(Target::new("").base(), "");
}

#[test]
fn an_address_is_the_root_and_the_route() {
    let addressed = Target::new(BASE).address(req::me().request().clone());
    assert_eq!(addressed.url, "https://craft.example.com/api/v1/me");
}

#[test]
fn an_empty_root_leaves_the_route_relative_to_the_page() {
    // What a browser build served by CollabCraft uses. The page resolves it.
    let addressed = Target::new("").address(req::me().request().clone());
    assert_eq!(addressed.url, "/api/v1/me");
}

#[test]
fn a_token_rides_as_a_bearer_header() {
    let addressed = Target::new(BASE).with_token("s3ss10n").address(req::me().request().clone());
    assert_eq!(addressed.get_header("authorization"), Some("Bearer s3ss10n"));
}

#[test]
fn no_token_sends_no_authorization_header() {
    // A recipient of a keyed link holds a cookie instead, and the browser
    // attaches that on its own.
    let addressed = Target::new(BASE).address(req::me().request().clone());
    assert_eq!(addressed.get_header("authorization"), None);
    assert!(!Target::new(BASE).is_signed_in());
}

#[test]
fn query_values_are_encoded() {
    assert_eq!(enc("plain-name_1.txt~"), "plain-name_1.txt~");
    assert_eq!(enc("a b"), "a%20b");
    assert_eq!(enc("a/b"), "a%2Fb");
    assert_eq!(enc("ä"), "%C3%A4");
    assert_eq!(enc("100%"), "100%25");
    assert_eq!(enc("q?x=1&y=2"), "q%3Fx%3D1%26y%3D2");
}

// ---- what each route asks for ----------------------------------------------

#[test]
fn listing_names_the_folder_in_the_query() {
    let fake = Fake::one(200, "[]");
    let _ = client(&fake).list("/my docs");
    assert_eq!(fake.last().method, Method::Get);
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/files?path=%2Fmy%20docs");
}

#[test]
fn an_empty_folder_path_is_the_root() {
    let fake = Fake::one(200, "[]");
    let _ = client(&fake).list("");
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/files?path=");
}

#[test]
fn shared_with_me_is_its_own_route() {
    let fake = Fake::one(200, "[]");
    let _ = client(&fake).shared_with_me();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/files/shared");
}

#[test]
fn reading_names_the_document() {
    let fake = Fake::one(200, "bytes");
    let _ = client(&fake).read("docs/plan.ods");
    assert_eq!(fake.last().method, Method::Get);
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/files/content?id=docs%2Fplan.ods");
    assert!(fake.last().body.is_empty(), "a read must carry no body: a browser refuses to send one on a GET");
}

#[test]
fn a_save_sends_the_bytes_and_the_version() {
    let fake = Fake::one(200, ENTRY);
    let _ = client(&fake).write("docs/plan.ods", b"new", Some("v2"));
    let sent = fake.last();
    assert_eq!(sent.method, Method::Put);
    assert_eq!(sent.url, "https://craft.example.com/api/v1/files/content?id=docs%2Fplan.ods&if_match=v2");
    assert_eq!(sent.body, b"new");
    assert_eq!(sent.get_header("content-type"), Some("application/octet-stream"));
}

#[test]
fn a_save_without_a_version_sends_no_if_match() {
    let fake = Fake::one(200, ENTRY);
    let _ = client(&fake).write("docs/plan.ods", b"new", None);
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/files/content?id=docs%2Fplan.ods");
}

#[test]
fn creating_names_the_folder_and_the_name() {
    let fake = Fake::one(200, ENTRY);
    let _ = client(&fake).create("/docs", "plan b.ods", b"xyz");
    let sent = fake.last();
    assert_eq!(sent.method, Method::Post);
    assert_eq!(sent.url, "https://craft.example.com/api/v1/files/new?folder=%2Fdocs&name=plan%20b.ods");
    assert_eq!(sent.body, b"xyz");
}

#[test]
fn a_contact_search_carries_the_query_and_the_limit() {
    let fake = Fake::one(200, "[]");
    let _ = client(&fake).contacts("al ice", 7);
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/contacts?q=al%20ice&limit=7");
}

#[test]
fn a_share_is_posted_as_json() {
    let fake = Fake::one(200, r#"{"shared":[],"failed":[]}"#);
    let asked = ShareRequest {
        id: "docs/plan.ods".to_owned(),
        targets: vec![ShareTarget::Email("someone@example.net".to_owned())],
        permission: Permission::Edit,
        note: None,
        notify: true,
        app: Some("gridcraft".to_owned()),
        password: None,
        expires: None,
    };
    let _ = client(&fake).share(&asked);
    let sent = fake.last();
    assert_eq!(sent.method, Method::Post);
    assert_eq!(sent.url, "https://craft.example.com/api/v1/shares");
    assert_eq!(sent.get_header("content-type"), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(body["id"], "docs/plan.ods");
    assert_eq!(body["permission"], "edit");
    assert_eq!(body["targets"][0]["kind"], "email");
    assert_eq!(body["targets"][0]["id"], "someone@example.net");
    assert_eq!(body["app"], "gridcraft");
    assert!(body.get("password").is_none(), "an absent key must not be sent as null: the server reads it as a key of its own");
}

#[test]
fn a_withdrawal_is_a_delete_on_the_share() {
    let fake = Fake::one(204, "");
    let outcome = client(&fake).unshare("ocs/42");
    assert_eq!(fake.last().method, Method::Delete);
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/shares/ocs%2F42");
    assert!(outcome.is_ok(), "204 is success with nothing to read");
}

#[test]
fn the_conversation_route_names_the_document() {
    let fake = Fake::one(200, r#"{"url":"https://cloud.example.net/call/x","name":"Talk"}"#);
    let answered = client(&fake).conversation("docs/plan.ods").unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/conversation?id=docs%2Fplan.ods");
    assert_eq!(answered.name, "Talk");
}

#[test]
fn a_join_asks_for_a_relay_token() {
    let fake = Fake::one(200, r#"{"token":"jwt","relay":"https://relay.example.com","room":"fid-9"}"#);
    let joined = client(&fake).join("docs/plan.ods").unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/token?id=docs%2Fplan.ods");
    assert_eq!(joined.token, "jwt");
    assert_eq!(joined.relay, "https://relay.example.com");
    assert_eq!(joined.room, "fid-9");
}

#[test]
fn the_app_list_is_the_services_answer() {
    let fake = Fake::one(200, r#"["gridcraft","wordcraft"]"#);
    let apps = client(&fake).apps().unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/apps");
    assert_eq!(apps, vec!["gridcraft".to_owned(), "wordcraft".to_owned()]);
}

// ---- a keyed link's recipient ----------------------------------------------

#[test]
fn a_recipient_asks_for_a_token_on_the_invite_route() {
    let fake = Fake::one(
        200,
        r#"{"token":"jwt","relay":"https://relay.example.com","room":"fid-9","permission":"view",
            "name":"Budget.xlsx","etag":"v3","recipient":"outsider@example.org"}"#,
    );
    let joined = client(&fake).invite_token().unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/invite/token");
    assert_eq!(joined.room, "fid-9");
    assert_eq!(joined.permission, Permission::View, "the service decides this per request, and a read-only document must open as one");
    // What a recipient has instead of a file list and an account. All three
    // come from the service on this request, so a renamed document opens
    // under the name it has now.
    assert_eq!(joined.name, "Budget.xlsx");
    assert_eq!(joined.etag.as_deref(), Some("v3"), "the first save is conditional on this");
    assert_eq!(joined.recipient, "outsider@example.org");
}

#[test]
fn a_provider_without_versions_still_admits_a_recipient() {
    // A provider with no etags leaves the field out. The document still opens;
    // only the condition on a save is missing.
    let fake = Fake::one(
        200,
        r#"{"token":"jwt","relay":"https://relay.example.com","room":"fid-9","permission":"edit",
            "name":"Notes.docx","recipient":"outsider@example.org"}"#,
    );
    let joined = client(&fake).invite_token().unwrap();
    assert_eq!(joined.etag, None);
    assert_eq!(joined.name, "Notes.docx");
}

#[test]
fn a_recipient_reads_the_document_on_the_invite_route() {
    let fake = Fake::one(200, "raw bytes");
    let bytes = client(&fake).invite_read().unwrap();
    assert_eq!(fake.last().method, Method::Get);
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/invite/content");
    assert_eq!(bytes, b"raw bytes");
}

#[test]
fn a_recipient_saves_with_the_version_as_the_only_parameter() {
    let fake = Fake::one(200, ENTRY);
    let saved = client(&fake).invite_write(b"edited", Some("v2")).unwrap();
    let sent = fake.last();
    assert_eq!(sent.method, Method::Put);
    assert_eq!(sent.url, "https://craft.example.com/api/v1/invite/content?if_match=v2");
    assert_eq!(sent.body, b"edited");
    assert_eq!(saved.etag.as_deref(), Some("v2"));
}

#[test]
fn a_recipient_saves_without_a_version() {
    let fake = Fake::one(200, ENTRY);
    let _ = client(&fake).invite_write(b"edited", None);
    assert_eq!(fake.last().url, "https://craft.example.com/api/v1/invite/content");
}

#[test]
fn a_recipient_whose_link_went_away_is_refused_by_code() {
    let fake = Fake::one(403, r#"{"code":"link_invalid","detail":"this link does not work any more"}"#);
    match client(&fake).invite_read() {
        Err(Error::Refused { code, detail }) => {
            assert_eq!(code, "link_invalid");
            assert_eq!(detail, "this link does not work any more");
        }
        other => panic!("expected a refusal naming the code, got {other:?}"),
    }
}

// ---- reading what came back -------------------------------------------------

#[test]
fn me_reads_the_capabilities_and_whether_an_account_is_linked() {
    let fake = Fake::one(
        200,
        r#"{"id":"u1","display":"Alice","email":"alice@example.net","avatar":null,
            "apps":["gridcraft"],"capabilities":["files","sharing","link_password"],
            "service":["keyed_links"],"provider_linked":true}"#,
    );
    let me = client(&fake).me().unwrap();
    assert_eq!(me.display, "Alice");
    assert!(me.provider_linked);
    assert!(me.capabilities.contains(&Capability::Sharing));
    assert!(me.capabilities.contains(&Capability::LinkPassword));
}

#[test]
fn a_field_this_client_does_not_know_is_ignored() {
    // The service reports what it can do itself as well. An older client has
    // to keep working when the service learns a new field.
    let fake = Fake::one(
        200,
        r#"{"id":"u1","display":"Alice","email":null,"avatar":null,"apps":[],
            "capabilities":[],"provider_linked":false,"something_new":42}"#,
    );
    assert!(client(&fake).me().is_ok());
}

#[test]
fn reading_a_document_hands_back_the_bytes_untouched() {
    let fake = Fake::new(vec![Response::new(200, vec![0u8, 159, 146, 150])]);
    assert_eq!(client(&fake).read("d").unwrap(), vec![0u8, 159, 146, 150], "a document is bytes, and must not be read as text");
}

#[test]
fn a_share_reports_what_failed_by_name() {
    let fake = Fake::one(
        200,
        r#"{"shared":[{"id":"ocs/1","target":{"kind":"user","id":"bob"},"permission":"edit","url":null,"note":null,"created":null}],
            "failed":[{"target":{"kind":"email","id":"typo@"},"code":"invalid","detail":"not an address"}]}"#,
    );
    let asked = ShareRequest {
        id: "d".to_owned(),
        targets: Vec::new(),
        permission: Permission::Edit,
        note: None,
        notify: false,
        app: None,
        password: None,
        expires: None,
    };
    let outcome = client(&fake).share(&asked).unwrap();
    assert_eq!(outcome.shared.len(), 1);
    assert_eq!(outcome.failed.len(), 1);
    assert_eq!(outcome.failed[0].code, "invalid");
    assert_eq!(outcome.failed[0].target, ShareTarget::Email("typo@".to_owned()));
}

// ---- refusals ---------------------------------------------------------------

#[test]
fn a_401_with_no_readable_body_is_a_sign_in_again() {
    assert!(matches!(status(401, b"<html>"), Error::Unauthenticated));
}

#[test]
fn a_428_with_no_readable_body_asks_for_an_account() {
    assert!(matches!(status(428, b""), Error::NotLinked));
}

#[test]
fn the_code_in_the_body_wins_over_the_status() {
    // The device poll answers 428 while waiting, which is not a missing
    // account. Reading the status alone would send the user to link one.
    let waiting = status(428, br#"{"code":"authorization_pending","detail":"waiting for the browser"}"#);
    assert!(matches!(&waiting, Error::Refused { code, .. } if code == "authorization_pending"), "got {waiting:?}");
}

#[test]
fn an_unauthenticated_code_is_a_sign_in_again_whatever_the_status() {
    assert!(matches!(status(500, br#"{"code":"unauthenticated","detail":"sign in first"}"#), Error::Unauthenticated));
}

#[test]
fn a_provider_not_linked_code_asks_for_an_account() {
    assert!(matches!(status(200, br#"{"code":"provider_not_linked","detail":"link one"}"#), Error::NotLinked));
}

#[test]
fn an_unreadable_body_still_gives_an_error_naming_the_status() {
    assert!(matches!(&status(503, b"upstream is down"), Error::Refused { code, .. } if code == "503"));
}

#[test]
fn an_answer_of_the_wrong_shape_is_malformed() {
    let fake = Fake::one(200, r#"{"display":"Alice"}"#);
    assert!(matches!(client(&fake).me(), Err(Error::Malformed(_))));
}

#[test]
fn a_transport_that_could_not_reach_the_service_says_so() {
    let fake = Fake::new(Vec::new());
    assert!(matches!(client(&fake).me(), Err(Error::Unreachable(_))));
}

// ---- the two polls ----------------------------------------------------------

#[test]
fn pending_turns_the_one_code_into_a_state() {
    let waiting: Result<u8> = Err(Error::Refused { code: "authorization_pending".to_owned(), detail: String::new() });
    assert_eq!(pending(waiting).unwrap(), None);
    assert_eq!(pending(Ok(7u8)).unwrap(), Some(7));
}

#[test]
fn pending_catches_no_other_refusal() {
    let expired: Result<u8> = Err(Error::Refused { code: "expired".to_owned(), detail: String::new() });
    assert!(pending(expired).is_err(), "an expired sign-in is over, and looping on it would never end");
}

#[test]
fn a_sign_in_poll_reads_a_token_as_the_session() {
    let fake = Fake::one(200, r#"{"token":"s3ss10n"}"#);
    let collected = client(&fake).sign_in_poll("dev-1").unwrap();
    assert_eq!(fake.last().url, "https://craft.example.com/auth/device/poll");
    assert_eq!(fake.last().get_header("content-type"), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(&fake.last().body).unwrap();
    assert_eq!(body["device_code"], "dev-1");
    assert_eq!(collected, Some("s3ss10n".to_owned()));
}

#[test]
fn a_sign_in_poll_reads_pending_as_not_finished() {
    let fake = Fake::one(428, r#"{"code":"authorization_pending","detail":"waiting for the browser"}"#);
    assert_eq!(client(&fake).sign_in_poll("dev-1").unwrap(), None);
}

#[test]
fn a_link_poll_reads_success_as_linked() {
    let fake = Fake::one(200, "{}");
    assert!(client(&fake).link_poll("h1").unwrap());
    assert_eq!(fake.last().url, "https://craft.example.com/auth/link/poll");
}

#[test]
fn a_link_poll_reads_pending_as_not_finished() {
    let fake = Fake::one(428, r#"{"code":"authorization_pending","detail":"waiting"}"#);
    assert!(!client(&fake).link_poll("h1").unwrap());
}

#[test]
fn a_sign_in_starts_where_the_service_says() {
    let fake = Fake::one(200, r#"{"device_code":"dev-1","verify_url":"https://id.example.net/x","expires_in":600,"interval":2}"#);
    let started = client(&fake).sign_in_start().unwrap();
    assert_eq!(fake.last().method, Method::Post);
    assert_eq!(fake.last().url, "https://craft.example.com/auth/device/start");
    assert_eq!(started.verify_url, "https://id.example.net/x");
    assert_eq!(fake.asked(), 1);
}

// ---- the seam itself --------------------------------------------------------

#[test]
fn a_call_carries_its_own_answer_type() {
    // A host driving these over an HTTP stack of its own gets the pairing as
    // well, which is the reason the two are separable at all.
    let call = req::join("d");
    assert_eq!(call.request().method, Method::Get);
    let joined = call.answer(Response::new(200, br#"{"token":"t","relay":"r","room":"m"}"#.to_vec())).unwrap();
    assert_eq!(joined.relay, "r");
}

#[test]
fn a_meta_name_cannot_end_the_attribute_and_start_something_else() {
    assert_eq!(meta_selector("craft-cloud-url"), "meta[name=\"craft-cloud-url\"]");
    assert_eq!(meta_selector("x\"],script"), "meta[name=\"x\\\"],script\"]");
}
