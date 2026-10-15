//! Tests. Every one runs against a canned transport, so none touches a network.

use std::cell::RefCell;

use craft_cloud::{Accounts, Capability, Contacts, Error, Files, Provider, Sharing};
use craft_nextcloud::{Http, Method, Request, Response};

use crate::{Layout, WebDav, origin, probe};

struct Fake {
    replies: RefCell<Vec<Response>>,
    seen: RefCell<Vec<Request>>,
}

impl Fake {
    fn new(replies: Vec<Response>) -> Fake {
        Fake { replies: RefCell::new(replies), seen: RefCell::new(Vec::new()) }
    }

    fn urls(&self) -> Vec<String> {
        self.seen.borrow().iter().map(|r| r.url.clone()).collect()
    }
}

impl Http for &Fake {
    type Error = String;

    fn send(&self, req: Request) -> Result<Response, String> {
        self.seen.borrow_mut().push(req);
        let mut replies = self.replies.borrow_mut();
        if replies.is_empty() {
            return Err("no scripted reply left".to_owned());
        }
        Ok(replies.remove(0))
    }
}

const LISTING: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/dav/alice/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
  <d:response><d:href>/dav/alice/Report%20Q3.docx</d:href><d:propstat><d:prop>
    <d:resourcetype/><d:getcontentlength>2048</d:getcontentlength><d:getetag>"abc"</d:getetag>
    <d:getcontenttype>application/vnd.openxmlformats-officedocument.wordprocessingml.document</d:getcontenttype>
  </d:prop></d:propstat></d:response>
  <d:response><d:href>/dav/alice/Drafts/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
</d:multistatus>"#;

fn layout() -> Layout {
    Layout::new("https://files.example.org/dav/{user}/", Some("https://files.example.org/card/{user}".to_owned()))
}

#[test]
fn the_user_goes_into_the_template_as_one_segment() {
    let l = layout();
    assert_eq!(l.files_for("alice"), "https://files.example.org/dav/alice");
    assert_eq!(l.files_for("a/b c"), "https://files.example.org/dav/a%2Fb%20c", "a name must not widen into a path");
    assert_eq!(l.contacts_for("alice").as_deref(), Some("https://files.example.org/card/alice"));
    assert_eq!(l.files_unpersonalised(), "https://files.example.org/dav/");
    let fixed = Layout::new("https://nas.local:5006/home", None);
    assert_eq!(fixed.files_for("alice"), "https://nas.local:5006/home");
    assert_eq!(fixed.contacts_for("alice"), None);
}

#[test]
fn an_origin_has_no_path() {
    assert_eq!(origin("https://files.example.org/dav/alice"), "https://files.example.org");
    assert_eq!(origin("http://nas.local:5006"), "http://nas.local:5006");
}

#[test]
fn a_listing_drops_the_folder_itself_and_keys_rooms_on_the_path() {
    let fake = Fake::new(vec![Response::new(207, LISTING)]);
    let dav = WebDav::new(&layout(), "alice", "pw", &fake);
    let got = dav.list("").expect("listed");
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].name, "Report Q3.docx");
    assert_eq!(got[0].id, "/Report Q3.docx");
    assert_eq!(got[0].room, "/Report Q3.docx");
    assert_eq!(got[0].etag.as_deref(), Some("abc"));
    assert_eq!(got[0].size, Some(2048));
    assert_eq!(got[1].kind, craft_cloud::EntryKind::Folder);
    assert_eq!(fake.urls(), vec!["https://files.example.org/dav/alice/".to_owned()], "the root is asked for with its slash");
}

#[test]
fn a_save_carries_the_etag_and_a_412_is_a_conflict() {
    let fake = Fake::new(vec![Response::new(412, "")]);
    let dav = WebDav::new(&layout(), "alice", "pw", &fake);
    let err = dav.write("/Report Q3.docx", b"new", Some("abc")).expect_err("refused");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    let seen = fake.seen.borrow();
    assert_eq!(seen[0].method, Method::Put);
    assert_eq!(seen[0].url, "https://files.example.org/dav/alice/Report%20Q3.docx");
    assert_eq!(seen[0].get_header("if-match"), Some("\"abc\""));
}

#[test]
fn a_wrong_password_is_unauthenticated() {
    let fake = Fake::new(vec![Response::new(401, "")]);
    let dav = WebDav::new(&layout(), "alice", "wrong", &fake);
    assert!(matches!(dav.me(), Err(Error::Unauthenticated)));
}

#[test]
fn what_plain_webdav_cannot_do_is_reported_absent() {
    let fake = Fake::new(vec![]);
    let dav = WebDav::new(&Layout::new("https://h/dav", None), "alice", "pw", &fake);
    assert_eq!(dav.id(), "webdav");
    let caps = dav.capabilities();
    assert!(caps.contains(&Capability::Files) && caps.contains(&Capability::Etags));
    assert!(!caps.contains(&Capability::Sharing) && !caps.contains(&Capability::Contacts));
    assert!(matches!(dav.shares("/x"), Err(Error::Unsupported(_))));
    assert!(dav.shared_with_me().expect("empty").is_empty());
    assert!(dav.search("bob", 5).expect("empty").is_empty(), "no address book, nothing to search");
    assert!(fake.urls().is_empty(), "nothing was asked of the server");
}

#[test]
fn contacts_come_from_carddav_as_addresses() {
    let books = r#"<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
      <d:response><d:href>/card/alice/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
      <d:response><d:href>/card/alice/default/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/><card:addressbook/></d:resourcetype></d:prop></d:propstat></d:response>
    </d:multistatus>"#;
    let cards = "<d:multistatus xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\">\
      <d:response><d:href>/card/alice/default/1.vcf</d:href><d:propstat><d:prop><card:address-data>BEGIN:VCARD\nUID:1\nFN:Bob Jones\nEMAIL:bob@example.org\nEND:VCARD</card:address-data></d:prop></d:propstat></d:response>\
      <d:response><d:href>/card/alice/default/2.vcf</d:href><d:propstat><d:prop><card:address-data>BEGIN:VCARD\nUID:2\nFN:Carol\nEND:VCARD</card:address-data></d:prop></d:propstat></d:response>\
    </d:multistatus>";
    let fake = Fake::new(vec![Response::new(207, books), Response::new(207, cards)]);
    let dav = WebDav::new(&layout(), "alice", "pw", &fake);
    let found = dav.search("bob", 10).expect("searched");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].target, craft_cloud::ShareTarget::Email("bob@example.org".to_owned()));
    assert_eq!(found[0].name, "Bob Jones");
    assert_eq!(fake.urls()[1], "https://files.example.org/card/alice/default/", "a rooted href resolves against the origin");
}

#[test]
fn a_probe_accepts_a_dav_header_or_a_challenge_and_nothing_else() {
    let l = layout();
    let ok = Fake::new(vec![Response::new(200, "").header("DAV", "1, 2")]);
    assert!(probe(&&ok, &l).is_ok());
    assert_eq!(ok.seen.borrow()[0].method, Method::Options);
    let guarded = Fake::new(vec![Response::new(401, "").header("WWW-Authenticate", "Basic realm=\"dav\"")]);
    assert!(probe(&&guarded, &l).is_ok());
    let web = Fake::new(vec![Response::new(200, "<html>")]);
    assert!(probe(&&web, &l).is_err(), "a web page is not a WebDAV server");
    let gone = Fake::new(vec![Response::new(404, "")]);
    assert!(probe(&&gone, &l).is_err());
}
