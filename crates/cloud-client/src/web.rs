//! Sending requests from a browser, with the page's own `fetch`.
//!
//! A WebAssembly build has no socket and no thread to block, so `fetch` is the
//! only way out and every method here is `async`. Nothing else differs. The
//! method names, the parameters and the answer types are the ones the desktop
//! client has, built from the same [`crate::req`] functions.
//!
//! Nothing here holds a certificate store or a root list. The browser settled
//! which certificates it trusts before the page loaded, which is why the
//! desktop client's platform verifier has no counterpart.
//!
//! The session rides two ways and both reach the same record. Somebody who
//! followed a keyed link has a cookie this service set, so requests go out
//! with credentials and there is no token to hold. An app handed a bearer
//! token presents that instead. One client serves both.
//!
//! `fetch` is reached through the global object rather than through
//! [`web_sys::window`], so this works on a worker as well as on a page. The
//! twelve apps put real work on workers and a save must not be the one call
//! that cannot be made from one.

use craft_cloud::{Contact, Conversation, Entry, Share};
use js_sys::{Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortController, Headers, Request as WebRequest, RequestCredentials, RequestInit, Response as WebResponse};

use crate::wire::{Call, Request, Response, Target, meta_selector, pending};
use crate::{DeviceStart, Error, InviteJoin, Join, LinkStart, Me, Result, ShareOutcome, ShareRequest, req};

/// How long to wait for the service before giving up, in milliseconds.
///
/// The desktop client has the same ceiling for the same reason. A request that
/// never answers would leave a dialog waiting for the rest of the session, and
/// a browser's own limit is minutes away.
const TIMEOUT: i32 = 60_000;

/// Where a page names the service, when it is not the page's own origin.
const URL_META: &str = "craft-cloud-url";

/// A connection to one CollabCraft deployment.
///
/// Holds no browser object, so it is cheap to clone and can be kept in
/// application state beside everything else.
#[derive(Clone, Debug)]
pub struct Client {
    target: Target,
    timeout: i32,
}

impl Client {
    /// `base` is the service root, such as `https://craft.example.com`. An
    /// empty one means the service that served this page.
    pub fn new(base: impl Into<String>) -> Client {
        Client { target: Target::new(base), timeout: TIMEOUT }
    }

    /// A client for whatever served this page.
    ///
    /// CollabCraft serves the browser builds itself, so this is the ordinary
    /// case. It is also the only arrangement in which a recipient's cookie
    /// reaches the service, because a cookie does not cross an origin.
    pub fn same_origin() -> Client {
        Client::new("")
    }

    /// A client configured by the page.
    ///
    /// A build served by CollabCraft needs nothing. One served from somewhere
    /// else carries `<meta name="craft-cloud-url" content="…">`, and that is
    /// read here rather than compiled in, which is what lets one build talk to
    /// any deployment.
    pub fn from_page() -> Client {
        match meta(URL_META) {
            Some(base) => Client::new(base),
            None => Client::same_origin(),
        }
    }

    /// Present a session token on later calls.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Client {
        self.target = self.target.with_token(token);
        self
    }

    /// Give up after `millis` rather than after [`TIMEOUT`].
    #[must_use]
    pub fn with_timeout(mut self, millis: i32) -> Client {
        self.timeout = millis;
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
    async fn call<T>(&self, call: Call<T>) -> Result<T> {
        let Call { request, decode } = call;
        decode(self.send(self.target.address(request)).await?)
    }

    /// One request, through `fetch`.
    async fn send(&self, req: Request) -> Result<Response> {
        let global = js_sys::global();
        let fetch = function(&global, "fetch").ok_or_else(|| Error::Unreachable("this browser offers no fetch".to_owned()))?;

        let init = RequestInit::new();
        init.set_method(req.method.as_str());
        // Cookies are attached only when asked for, and the cookie is how a
        // recipient of a keyed link carries their session.
        init.set_credentials(RequestCredentials::Include);

        let headers = Headers::new().map_err(js)?;
        for (name, value) in &req.headers {
            headers.set(name, value).map_err(js)?;
        }
        init.set_headers(headers.as_ref());

        // Only where the method allows one. A browser refuses to send a GET
        // carrying a body, with an error naming neither the route nor the
        // method.
        if req.method.takes_a_body() {
            let body = Uint8Array::from(&req.body[..]);
            init.set_body(body.as_ref());
        }

        let controller = AbortController::new().map_err(js)?;
        init.set_signal(Some(&controller.signal()));
        let deadline = Deadline::start(&controller, self.timeout);

        let request = WebRequest::new_with_str_and_init(&req.url, &init).map_err(js)?;
        let promised = fetch.call1(global.as_ref(), request.as_ref()).map_err(js)?;
        let promised: Promise =
            promised.dyn_into().map_err(|_| Error::Unreachable("fetch answered with something that is not a promise".to_owned()))?;

        let answered = JsFuture::from(promised).await;
        // The answer is in, so stop the timer rather than leaving it to fire
        // against a request that is already finished.
        drop(deadline);

        let value = match answered {
            Ok(value) => value,
            Err(error) => {
                if controller.signal().aborted() {
                    return Err(Error::Unreachable(format!("collabcraft did not answer within {} seconds", self.timeout / 1000)));
                }
                return Err(Error::Unreachable(describe(&error)));
            }
        };

        let response: WebResponse =
            value.dyn_into().map_err(|_| Error::Unreachable("fetch answered with something that is not a response".to_owned()))?;
        let status = response.status();
        let buffer = JsFuture::from(response.array_buffer().map_err(js)?).await.map_err(js)?;
        Ok(Response { status, body: Uint8Array::new(&buffer).to_vec() })
    }

    // ---- signing in -------------------------------------------------------

    /// Begin a sign-in. Open [`DeviceStart::verify_url`], then poll.
    pub async fn sign_in_start(&self) -> Result<DeviceStart> {
        self.call(req::sign_in_start()?).await
    }

    /// Collect the session once the browser is done.
    ///
    /// `Ok(None)` means the user has not finished yet, which is a state rather
    /// than a failure, so a caller loops on it.
    pub async fn sign_in_poll(&self, device_code: &str) -> Result<Option<String>> {
        pending(self.call(req::sign_in_poll(device_code)?).await)
    }

    /// Run a sign-in to completion, calling `show` with the URL to open.
    ///
    /// For an app embedded in a page that cannot navigate away to the
    /// service's own sign-in. A build served by CollabCraft is sent there by
    /// the service and arrives holding a cookie, so it never needs this.
    ///
    /// Waits on the browser's own timer, so it holds up no frame. The deadline
    /// is the server's, which is why it is not a parameter.
    pub async fn sign_in(&mut self, show: impl FnOnce(&str)) -> Result<()> {
        let start = self.sign_in_start().await?;
        show(&start.verify_url);
        let gap = i32::try_from(start.interval.clamp(1, 10)).unwrap_or(2);
        let mut waited = 0u64;
        while waited < start.expires_in {
            sleep(gap * 1000).await;
            waited += u64::try_from(gap).unwrap_or(2);
            if let Some(token) = self.sign_in_poll(&start.device_code).await? {
                self.target = self.target.clone().with_token(token);
                return Ok(());
            }
        }
        Err(Error::Refused { code: "expired".into(), detail: "the sign-in timed out".into() })
    }

    // ---- linking a cloud account ------------------------------------------

    pub async fn link_start(&self) -> Result<LinkStart> {
        self.call(req::link_start()?).await
    }

    /// `Ok(false)` means the user has not finished in the browser yet.
    pub async fn link_poll(&self, handle: &str) -> Result<bool> {
        Ok(pending(self.call(req::link_poll(handle)?).await)?.is_some())
    }

    // ---- the things an app actually does ----------------------------------

    pub async fn me(&self) -> Result<Me> {
        self.call(req::me()).await
    }

    /// Which apps this user may open.
    pub async fn apps(&self) -> Result<Vec<String>> {
        self.call(req::apps()).await
    }

    /// One folder. An empty path is the user's root.
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        self.call(req::list(path)).await
    }

    /// Everything other people have shared with this user.
    pub async fn shared_with_me(&self) -> Result<Vec<Entry>> {
        self.call(req::shared_with_me()).await
    }

    pub async fn read(&self, id: &str) -> Result<Vec<u8>> {
        self.call(req::read(id)).await
    }

    pub async fn read_range(&self, id: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
        self.call(req::read_range(id, offset, length)).await
    }

    pub async fn stat(&self, id: &str) -> Result<Entry> {
        self.call(req::stat(id)).await
    }

    /// Save, refusing to overwrite a newer version when `if_match` is given.
    pub async fn write(&self, id: &str, bytes: &[u8], if_match: Option<&str>) -> Result<Entry> {
        self.call(req::write(id, bytes, if_match)).await
    }

    pub async fn create(&self, folder: &str, name: &str, bytes: &[u8]) -> Result<Entry> {
        self.call(req::create(folder, name, bytes)).await
    }

    /// People matching what has been typed, for a share dialog.
    pub async fn contacts(&self, query: &str, limit: usize) -> Result<Vec<Contact>> {
        self.call(req::contacts(query, limit)).await
    }

    /// Share with several people at once.
    ///
    /// Partial success is reported rather than hidden, so a dialog can say
    /// which address failed instead of failing the lot.
    pub async fn share(&self, request: &ShareRequest) -> Result<ShareOutcome> {
        self.call(req::share(request)?).await
    }

    pub async fn shares(&self, id: &str) -> Result<Vec<Share>> {
        self.call(req::shares(id)).await
    }

    /// Withdraw one share.
    pub async fn unshare(&self, share_id: &str) -> Result<()> {
        self.call(req::unshare(share_id)).await
    }

    /// Where to go to work together on a document.
    pub async fn conversation(&self, id: &str) -> Result<Conversation> {
        self.call(req::conversation(id)).await
    }

    /// A relay token for one document, plus where to take it.
    pub async fn join(&self, id: &str) -> Result<Join> {
        self.call(req::join(id)).await
    }

    // ---- somebody who arrived on a keyed link -----------------------------

    /// A relay token for the one room a recipient's key names.
    pub async fn invite_token(&self) -> Result<InviteJoin> {
        self.call(req::invite_token()).await
    }

    /// The document a recipient's key names.
    pub async fn invite_read(&self) -> Result<Vec<u8>> {
        self.call(req::invite_read()).await
    }

    /// Save it back, where the share still allows an edit.
    pub async fn invite_write(&self, bytes: &[u8], if_match: Option<&str>) -> Result<Entry> {
        self.call(req::invite_write(bytes, if_match)).await
    }
}

/// A timer that abandons one request.
///
/// Dropped the moment the answer arrives, which clears the timer. A browser
/// with no reachable `setTimeout` leaves no deadline rather than no request.
struct Deadline {
    handle: f64,
    /// The callback, kept alive while JavaScript can still reach it. Dropping
    /// a [`Closure`] invalidates the function the timer holds.
    _fired: Closure<dyn FnMut()>,
}

impl Deadline {
    fn start(controller: &AbortController, after: i32) -> Option<Deadline> {
        let abandoning = controller.clone();
        let fired = Closure::<dyn FnMut()>::new(move || abandoning.abort());
        let global = js_sys::global();
        let set = function(&global, "setTimeout")?;
        let handle = set.call2(global.as_ref(), fired.as_ref(), &JsValue::from_f64(f64::from(after))).ok()?.as_f64()?;
        Some(Deadline { handle, _fired: fired })
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        let global = js_sys::global();
        if let Some(clear) = function(&global, "clearTimeout") {
            let _ = clear.call1(global.as_ref(), &JsValue::from_f64(self.handle));
        }
    }
}

/// Wait, on the browser's own timer.
async fn sleep(millis: i32) {
    let promise = Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        if let Some(set) = function(&global, "setTimeout") {
            let _ = set.call2(global.as_ref(), &resolve, &JsValue::from_f64(f64::from(millis)));
        }
    });
    let _ = JsFuture::from(promise).await;
}

/// One function off an object, by name.
fn function(object: &JsValue, name: &str) -> Option<Function> {
    Reflect::get(object, &JsValue::from_str(name)).ok()?.dyn_into().ok()
}

/// One `meta` element's content, from the page.
///
/// `None` on a worker, which has no document. The caller falls back to the
/// origin it was served from, and that is the right answer there anyway.
fn meta(name: &str) -> Option<String> {
    let document = web_sys::window()?.document()?;
    let element = document.query_selector(&meta_selector(name)).ok()??;
    let content = element.get_attribute("content")?;
    let trimmed = content.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) }
}

fn js(error: JsValue) -> Error {
    Error::Unreachable(describe(&error))
}

/// A JavaScript error in words.
///
/// An `Error` object serialises to `{}`, so its message is read off it rather
/// than stringified. Without this every browser failure reads the same.
fn describe(value: &JsValue) -> String {
    if let Some(text) = value.as_string() {
        return text;
    }
    if let Ok(message) = Reflect::get(value, &JsValue::from_str("message"))
        && let Some(text) = message.as_string()
    {
        return text;
    }
    js_sys::JSON::stringify(value)
        .ok()
        .and_then(|text| text.as_string())
        .unwrap_or_else(|| "the browser gave an error it could not describe".to_owned())
}
