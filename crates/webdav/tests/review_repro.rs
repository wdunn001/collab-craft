//! Review reproduction (craft-cloud contracts H1, narrowed): `Files::create` on the WebDAV and
//! Nextcloud adapters replaces an existing file. The fake below is a small in-memory WebDAV
//! server that honours RFC 7232 preconditions (If-Match / If-None-Match: *) the way SabreDAV,
//! Nextcloud and Apache do, so the only thing deciding the outcome is what the adapter sends.

use std::cell::RefCell;
use std::collections::BTreeMap;

use craft_cloud::Files as _;
use craft_nextcloud::{Account, Http, Method, Nextcloud, Request, Response};
use craft_webdav::{Layout, WebDav};

#[derive(Default)]
struct DavServer {
    files: RefCell<BTreeMap<String, (Vec<u8>, u32)>>,
    puts: RefCell<Vec<BTreeMap<String, String>>>,
}

impl DavServer {
    fn with(path: &str, bytes: &[u8]) -> DavServer {
        let s = DavServer::default();
        s.files.borrow_mut().insert(path.to_owned(), (bytes.to_vec(), 1));
        s
    }
    fn content(&self, path: &str) -> String {
        self.files.borrow().get(path).map(|(b, _)| String::from_utf8_lossy(b).into_owned()).unwrap_or_default()
    }
}

fn url_path(url: &str) -> String {
    let after = url.splitn(4, '/').nth(3).unwrap_or("");
    format!("/{after}")
}

impl Http for &DavServer {
    type Error = String;
    fn send(&self, req: Request) -> Result<Response, String> {
        let path = url_path(&req.url);
        match req.method {
            Method::Put => {
                self.puts.borrow_mut().push(req.headers.clone());
                let mut files = self.files.borrow_mut();
                let existing = files.get(&path).map(|(_, v)| format!("\"v{v}\""));
                if req.get_header("if-none-match") == Some("*") && existing.is_some() {
                    return Ok(Response::new(412, ""));
                }
                if let Some(want) = req.get_header("if-match")
                    && existing.as_deref() != Some(want)
                {
                    return Ok(Response::new(412, ""));
                }
                let version = files.get(&path).map_or(1, |(_, v)| v + 1);
                let status = if existing.is_some() { 204 } else { 201 };
                files.insert(path, (req.body.clone(), version));
                Ok(Response::new(status, ""))
            }
            Method::Propfind => {
                let files = self.files.borrow();
                let Some((bytes, v)) = files.get(&path) else { return Ok(Response::new(404, "")) };
                Ok(Response::new(
                    207,
                    format!(
                        r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength><d:getetag>"v{v}"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#,
                        bytes.len()
                    ),
                ))
            }
            other => Err(format!("{other} not scripted")),
        }
    }
}

#[test]
fn review_h1_webdav_create_over_an_existing_name_replaces_it() {
    let server = DavServer::with("/dav/alice/Report.docx", b"their report");
    let dav = WebDav::new(&Layout::new("https://files.example.org/dav/{user}/", None), "alice", "pw", &server);
    let created = dav.create("", "Report.docx", b"my new document");
    assert!(
        created.is_err() && server.content("/dav/alice/Report.docx") == "their report",
        "create() of a name that exists returned {:?}; server file now holds {:?}; PUT headers {:?}",
        created.map(|e| e.etag),
        server.content("/dav/alice/Report.docx"),
        server.puts.borrow()
    );
}

#[test]
fn review_h1_nextcloud_create_over_an_existing_name_replaces_it() {
    let path = "/remote.php/dav/files/alice/Report.docx";
    let server = DavServer::with(path, b"their report");
    let nc = Nextcloud::new(Account::new("https://cloud.example.net/", "alice", "app-pw"), &server);
    let created = nc.create("", "Report.docx", b"my new document");
    assert!(
        created.is_err() && server.content(path) == "their report",
        "create() of a name that exists returned {:?}; server file now holds {:?}; PUT headers {:?}",
        created.map(|e| e.etag),
        server.content(path),
        server.puts.borrow()
    );
}
