//! Sending requests from a desktop app, with `ureq`.
//!
//! Every call blocks. An app's UI thread must therefore not call one directly,
//! and [`Client`] is cheap to move to a worker.
//!
//! The transport sits behind a trait rather than being reached directly. A
//! host with its own HTTP stack supplies one, and the tests supply a canned
//! one so every route can be checked with no network anywhere near it.

use std::sync::Arc;
use std::time::Duration;

use craft_cloud::{Contact, Conversation, Entry, Share};
use craft_esign::{CompletedDocument, Envelope, EnvelopeDraft};

use crate::wire::{Call, Method, Request, Response, Target, pending};
use crate::{DeviceStart, Error, InviteJoin, Join, LinkStart, Me, Result, ShareOutcome, ShareRequest, req};

/// Somewhere a request can be sent.
///
/// An implementation sends `req` as given, follows no redirects, and hands
/// back whatever came off the wire. It must not raise an error for a non-2xx
/// status: that is an answer carrying a reason, the decoders read it, and
/// losing it would leave every refusal looking identical.
pub trait Transport {
    fn send(&self, req: Request) -> Result<Response>;
}

/// A connection to one CollabCraft deployment.
#[derive(Clone)]
pub struct Client {
    target: Target,
    http: Arc<dyn Transport + Send + Sync>,
}

/// Copy the headers onto a `ureq` builder.
///
/// A macro rather than a function because `ureq` gives a request with a body
/// and one without different types, and the four arms below would otherwise
/// repeat this loop.
macro_rules! headed {
    ($builder:expr, $headers:expr) => {{
        let mut builder = $builder;
        for (name, value) in $headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        builder
    }};
}

/// The transport a desktop app gets by default.
struct Ureq {
    agent: ureq::Agent,
}

impl Ureq {
    fn new() -> Ureq {
        Ureq {
            agent: ureq::Agent::config_builder()
                .timeout_connect(Some(Duration::from_secs(10)))
                .timeout_global(Some(Duration::from_secs(60)))
                // Trust what the machine trusts. The default is Mozilla's root
                // list, which rejects any CollabCraft behind an internally
                // signed certificate, and says only "UnknownIssuer".
                .tls_config(ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build())
                // A non-2xx is an answer carrying a reason, not a transport
                // failure. Treating it as an error would throw the body away.
                .http_status_as_error(false)
                .build()
                .into(),
        }
    }
}

impl Transport for Ureq {
    fn send(&self, req: Request) -> Result<Response> {
        let answered = match req.method {
            Method::Get => headed!(self.agent.get(&req.url), &req.headers).call(),
            Method::Delete => headed!(self.agent.delete(&req.url), &req.headers).call(),
            Method::Post => headed!(self.agent.post(&req.url), &req.headers).send(&req.body[..]),
            Method::Put => headed!(self.agent.put(&req.url), &req.headers).send(&req.body[..]),
        };
        let mut response = answered.map_err(|e| Error::Unreachable(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response.body_mut().read_to_vec().map_err(|e| Error::Unreachable(e.to_string()))?;
        Ok(Response { status, body })
    }
}

impl Client {
    /// `base` is the service root, such as `https://craft.example.com`.
    pub fn new(base: impl Into<String>) -> Client {
        Client { target: Target::new(base), http: Arc::new(Ureq::new()) }
    }

    /// A client sending through a transport the caller owns.
    ///
    /// For a host that already has an HTTP stack it would rather use, and for
    /// the tests here, which drive a canned one and touch no network.
    pub fn with_transport(base: impl Into<String>, transport: Arc<dyn Transport + Send + Sync>) -> Client {
        Client { target: Target::new(base), http: transport }
    }

    /// Present a session token on later calls.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Client {
        self.target = self.target.with_token(token);
        self
    }

    pub fn token(&self) -> Option<&str> {
        self.target.token()
    }

    pub fn is_signed_in(&self) -> bool {
        self.target.is_signed_in()
    }

    pub fn base(&self) -> &str {
        self.target.base()
    }

    /// Send one call and read its answer.
    fn call<T>(&self, call: Call<T>) -> Result<T> {
        let Call { request, decode } = call;
        decode(self.http.send(self.target.address(request))?)
    }

    // ---- signing in -------------------------------------------------------

    /// Begin a sign-in. Open [`DeviceStart::verify_url`] in a browser, then
    /// poll.
    pub fn sign_in_start(&self) -> Result<DeviceStart> {
        self.call(req::sign_in_start()?)
    }

    /// Collect the session once the browser is done.
    ///
    /// `Ok(None)` means the user has not finished yet, which is a state rather
    /// than a failure, so a caller loops on it.
    pub fn sign_in_poll(&self, device_code: &str) -> Result<Option<String>> {
        pending(self.call(req::sign_in_poll(device_code)?))
    }

    /// Run a sign-in to completion, calling `show` with the URL to open.
    ///
    /// Blocks, so it belongs on a worker. The deadline is the server's, which
    /// is why it is not a parameter.
    pub fn sign_in(&mut self, show: impl FnOnce(&str)) -> Result<()> {
        let start = self.sign_in_start()?;
        show(&start.verify_url);
        let deadline = std::time::Instant::now() + Duration::from_secs(start.expires_in);
        while std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_secs(start.interval.clamp(1, 10)));
            if let Some(token) = self.sign_in_poll(&start.device_code)? {
                self.target = self.target.clone().with_token(token);
                return Ok(());
            }
        }
        Err(Error::Refused { code: "expired".into(), detail: "the sign-in timed out".into() })
    }

    // ---- linking a cloud account ------------------------------------------

    pub fn link_start(&self) -> Result<LinkStart> {
        self.call(req::link_start()?)
    }

    /// `Ok(false)` means the user has not finished in the browser yet.
    pub fn link_poll(&self, handle: &str) -> Result<bool> {
        Ok(pending(self.call(req::link_poll(handle)?))?.is_some())
    }

    // ---- the things an app actually does ----------------------------------

    pub fn me(&self) -> Result<Me> {
        self.call(req::me())
    }

    /// Which apps this user may open.
    pub fn apps(&self) -> Result<Vec<String>> {
        self.call(req::apps())
    }

    /// One folder. An empty path is the user's root.
    pub fn list(&self, path: &str) -> Result<Vec<Entry>> {
        self.call(req::list(path))
    }

    /// Everything other people have shared with this user.
    pub fn shared_with_me(&self) -> Result<Vec<Entry>> {
        self.call(req::shared_with_me())
    }

    pub fn read(&self, id: &str) -> Result<Vec<u8>> {
        self.call(req::read(id))
    }

    /// Save, refusing to overwrite a newer version when `if_match` is given.
    pub fn write(&self, id: &str, bytes: &[u8], if_match: Option<&str>) -> Result<Entry> {
        self.call(req::write(id, bytes, if_match))
    }

    pub fn create(&self, folder: &str, name: &str, bytes: &[u8]) -> Result<Entry> {
        self.call(req::create(folder, name, bytes))
    }

    /// People matching what has been typed, for a share dialog.
    pub fn contacts(&self, query: &str, limit: usize) -> Result<Vec<Contact>> {
        self.call(req::contacts(query, limit))
    }

    /// Share with several people at once.
    ///
    /// Partial success is reported rather than hidden, so a dialog can say
    /// which address failed instead of failing the lot.
    pub fn share(&self, request: &ShareRequest) -> Result<ShareOutcome> {
        self.call(req::share(request)?)
    }

    pub fn shares(&self, id: &str) -> Result<Vec<Share>> {
        self.call(req::shares(id))
    }

    /// Withdraw one share.
    pub fn unshare(&self, share_id: &str) -> Result<()> {
        self.call(req::unshare(share_id))
    }

    /// Where to go to work together on a document.
    pub fn conversation(&self, id: &str) -> Result<Conversation> {
        self.call(req::conversation(id))
    }

    /// A document conversation's messages, oldest first (`after`: the newest id
    /// already held).
    pub fn messages(&self, id: &str, after: Option<&str>) -> Result<Vec<craft_cloud::ChatMessage>> {
        self.call(req::messages(id, after))
    }

    /// Send a message to a document's conversation.
    pub fn post_message(&self, id: &str, text: &str) -> Result<craft_cloud::ChatMessage> {
        self.call(req::post_message(id, text))
    }

    /// A relay token for one document, plus where to take it.
    pub fn join(&self, id: &str) -> Result<Join> {
        self.call(req::join(id))
    }

    // ---- somebody who arrived on a keyed link -----------------------------

    /// A relay token for the one room a recipient's key names.
    pub fn invite_token(&self) -> Result<InviteJoin> {
        self.call(req::invite_token())
    }

    /// The document a recipient's key names.
    pub fn invite_read(&self) -> Result<Vec<u8>> {
        self.call(req::invite_read())
    }

    /// Save it back, where the share still allows an edit.
    pub fn invite_write(&self, bytes: &[u8], if_match: Option<&str>) -> Result<Entry> {
        self.call(req::invite_write(bytes, if_match))
    }

    // ---- e-sign -----------------------------------------------------------

    pub fn esign_capabilities(&self) -> Result<req::EsignCaps> {
        self.call(req::esign_capabilities())
    }

    pub fn esign_create(&self, draft: &EnvelopeDraft, document: &[u8], idempotency_key: &str, send: bool) -> Result<Envelope> {
        self.call(req::esign_create(draft, document, idempotency_key, send)?)
    }

    pub fn esign_send(&self, id: &str) -> Result<Envelope> {
        self.call(req::esign_send(id)?)
    }

    pub fn esign_status(&self, id: &str) -> Result<Envelope> {
        self.call(req::esign_status(id))
    }

    pub fn esign_completed(&self, id: &str) -> Result<CompletedDocument> {
        self.call(req::esign_completed(id))
    }

    pub fn esign_void(&self, id: &str, reason: &str) -> Result<()> {
        self.call(req::esign_void(id, reason)?)
    }

    pub fn esign_remind(&self, id: &str, recipient: &str) -> Result<()> {
        self.call(req::esign_remind(id, recipient)?)
    }
}
