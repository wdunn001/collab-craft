//! The HTTP client the providers use.
//!
//! `craft-cloud` and `craft-nextcloud` open no sockets, so something has to.
//! Keeping it here means a provider crate stays testable with no server and
//! the service decides timeouts, redirects and TLS in one place.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use craft_nextcloud::{Http, Request, Response};

/// The one blocking client the whole process shares.
///
/// Built once, on first use. That matters twice. Building a `reqwest::blocking`
/// client spins up its own runtime, and doing that on a Tokio worker panics
/// under debug assertions and is wasteful otherwise, so construction must not
/// happen while a provider is being assembled in async code. Every provider
/// call runs inside `spawn_blocking`, so the first `send` initialises this from
/// a blocking thread rather than a worker. Building it per request, as the old
/// `Default` did, also spun a fresh runtime up and down on every save.
static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();

fn client() -> &'static reqwest::blocking::Client {
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            // The contract is to hand back what came off the wire. Following a
            // redirect would turn a 302 into something the parsers never see,
            // and WebDAV's 207 is a real answer rather than a failure.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("CollabCraft")
            .build()
            .unwrap_or_default()
    })
}

/// A zero-sized handle to the shared client. Cheap to create in async code,
/// because it builds nothing: the client is made on first [`Http::send`].
#[derive(Default)]
pub struct ReqwestHttp;

impl Http for ReqwestHttp {
    type Error = String;

    fn send(&self, req: Request) -> Result<Response, String> {
        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes()).map_err(|e| e.to_string())?;
        let mut call = client().request(method, &req.url);
        for (name, value) in &req.headers {
            call = call.header(name, value);
        }
        if !req.body.is_empty() {
            call = call.body(req.body);
        }
        let raw = call.send().map_err(|e| e.to_string())?;
        let status = raw.status().as_u16();
        let mut headers = BTreeMap::new();
        for (name, value) in raw.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.as_str().to_ascii_lowercase(), v.to_owned());
            }
        }
        let body = raw.bytes().map_err(|e| e.to_string())?.to_vec();
        Ok(Response { status, headers, body })
    }
}
