//! Review reproduction (craft-cloud contracts, narrowed): `Files::write` must return the version
//! the PUT wrote, not a version read by a follow-up PROPFIND. The fake below answers a PUT with one
//! etag and a PROPFIND with a different one, which is what a concurrent writer landing in between
//! looks like. The only thing deciding the returned etag is which of the two the adapter trusts.

use std::cell::RefCell;

use craft_cloud::Files as _;
use craft_nextcloud::{Account, Http, Method, Nextcloud, Request, Response};
use craft_webdav::{Layout, WebDav};

/// A server whose PUT and PROPFIND report different etags on purpose.
#[derive(Default)]
struct RacingServer {
    puts: RefCell<usize>,
}

impl Http for &RacingServer {
    type Error = String;
    fn send(&self, req: Request) -> Result<Response, String> {
        match req.method {
            // The bytes just written become "e-put". This is the version the
            // caller must keep as its next compare-and-set baseline.
            Method::Put => {
                *self.puts.borrow_mut() += 1;
                Ok(Response::new(204, "").header("etag", "\"e-put\""))
            }
            // A later reader sees "e-racer", standing in for somebody else's
            // save landing between the PUT and this PROPFIND.
            Method::Propfind => Ok(Response::new(
                207,
                r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/alice/Plan.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>7</d:getcontentlength><d:getetag>"e-racer"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#,
            )),
            other => Err(format!("{other} not scripted")),
        }
    }
}

#[test]
fn webdav_write_returns_the_put_version_not_a_later_one() {
    let server = RacingServer::default();
    let dav = WebDav::new(&Layout::new("https://files.example.org/dav/{user}/", None), "alice", "pw", &server);
    let saved = dav.write("/Plan.txt", b"Alice v2", None).expect("write");
    assert_eq!(saved.etag.as_deref(), Some("e-put"), "write() must return the etag the PUT produced, not the one a later stat read");
}

#[test]
fn nextcloud_write_returns_the_put_version_not_a_later_one() {
    let server = RacingServer::default();
    let nc = Nextcloud::new(Account::new("https://cloud.example.net/", "alice", "app-pw"), &server);
    let saved = nc.write("/Plan.txt", b"Alice v2", None).expect("write");
    assert_eq!(saved.etag.as_deref(), Some("e-put"), "write() must return the etag the PUT produced, not the one a later stat read");
}
