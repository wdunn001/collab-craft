//! Every call the service answers.
//!
//! One function per route, each handing back the request to send together
//! with the type of the answer. Neither transport writes a URL of its own and
//! neither picks an answer type, so adding a route is one function here and
//! one line on each client.
//!
//! The paths are the service's: `/api/v1` for an app, `/auth` for a sign-in,
//! and `/api/v1/invite` for somebody who arrived on a keyed link and has no
//! account to act as.

use craft_cloud::{Contact, Conversation, Entry, Share};
use craft_esign::{CompletedDocument, Envelope, EnvelopeDraft};
use serde::Serialize;

use crate::wire::{Call, Method, Request, enc};
use crate::{DeviceStart, Error, InviteJoin, Join, LinkStart, Me, Result, ShareOutcome, ShareRequest};

/// Where the app-facing routes live.
const API: &str = "/api/v1";

fn get(path: String) -> Request {
    Request::new(Method::Get, path)
}

/// A POST carrying a JSON message.
fn posting<T: Serialize>(path: String, body: &T) -> Result<Request> {
    let encoded = serde_json::to_vec(body).map_err(|e| Error::Unsendable(e.to_string()))?;
    Ok(Request::new(Method::Post, path).header("content-type", "application/json").body(encoded))
}

/// A request carrying a document rather than a message.
fn sending(method: Method, path: String, bytes: &[u8]) -> Request {
    Request::new(method, path).header("content-type", "application/octet-stream").body(bytes.to_vec())
}

// ---- signing in -----------------------------------------------------------

/// Begin a sign-in. Open [`DeviceStart::verify_url`] in a browser, then poll.
pub fn sign_in_start() -> Result<Call<DeviceStart>> {
    Ok(Call::json(posting("/auth/device/start".to_owned(), &())?))
}

/// Collect the session once the browser is done.
///
/// The answer is the token itself. A service still waiting answers
/// `authorization_pending`, which [`crate::wire::pending`] turns into a state
/// rather than a failure.
pub fn sign_in_poll(device_code: &str) -> Result<Call<String>> {
    #[derive(Serialize)]
    struct Body<'a> {
        device_code: &'a str,
    }
    Ok(Call::collected(posting("/auth/device/poll".to_owned(), &Body { device_code })?))
}

// ---- linking a cloud account ----------------------------------------------

pub fn link_start() -> Result<Call<LinkStart>> {
    Ok(Call::json(posting("/auth/link/start".to_owned(), &())?))
}

/// Finish linking. Answers nothing, so the outcome is the status.
pub fn link_poll(handle: &str) -> Result<Call<()>> {
    #[derive(Serialize)]
    struct Body<'a> {
        handle: &'a str,
    }
    Ok(Call::nothing(posting("/auth/link/poll".to_owned(), &Body { handle })?))
}

// ---- the things an app actually does --------------------------------------

pub fn me() -> Call<Me> {
    Call::json(get(format!("{API}/me")))
}

/// Which apps this user may open, as the service decides it.
pub fn apps() -> Call<Vec<String>> {
    Call::json(get(format!("{API}/apps")))
}

/// One folder. An empty path is the user's root.
pub fn list(path: &str) -> Call<Vec<Entry>> {
    Call::json(get(format!("{API}/files?path={}", enc(path))))
}

/// Everything other people have shared with this user.
pub fn shared_with_me() -> Call<Vec<Entry>> {
    Call::json(get(format!("{API}/files/shared")))
}

pub fn read(id: &str) -> Call<Vec<u8>> {
    Call::raw(get(format!("{API}/files/content?id={}", enc(id))))
}

/// Ranged read via `Range: bytes=…` on the content route.
pub fn read_range(id: &str, offset: u64, length: u64) -> Call<Vec<u8>> {
    let last = offset.saturating_add(length.saturating_sub(1));
    Call::raw(get(format!("{API}/files/content?id={}", enc(id))).header("range", format!("bytes={offset}-{last}")))
}

/// Metadata without downloading bytes (`GET /files/meta`).
pub fn stat(id: &str) -> Call<Entry> {
    Call::json(get(format!("{API}/files/meta?id={}", enc(id))))
}

/// Save, refusing to overwrite a newer version when `if_match` is given.
pub fn write(id: &str, bytes: &[u8], if_match: Option<&str>) -> Call<Entry> {
    Call::json(sending(Method::Put, format!("{API}/files/content?id={}{}", enc(id), tag(if_match)), bytes))
}

pub fn create(folder: &str, name: &str, bytes: &[u8]) -> Call<Entry> {
    Call::json(sending(Method::Post, format!("{API}/files/new?folder={}&name={}", enc(folder), enc(name)), bytes))
}

/// People matching what has been typed, for a share dialog.
pub fn contacts(query: &str, limit: usize) -> Call<Vec<Contact>> {
    Call::json(get(format!("{API}/contacts?q={}&limit={limit}", enc(query))))
}

/// Share with several people at once.
///
/// Partial success is reported rather than hidden, so a dialog can say which
/// address failed instead of failing the lot.
pub fn share(request: &ShareRequest) -> Result<Call<ShareOutcome>> {
    Ok(Call::json(posting(format!("{API}/shares"), request)?))
}

pub fn shares(id: &str) -> Call<Vec<Share>> {
    Call::json(get(format!("{API}/shares?id={}", enc(id))))
}

/// Withdraw one share.
///
/// `share_id` is the one [`Share::id`] carried, and means nothing to anybody
/// but the provider that issued it.
pub fn unshare(share_id: &str) -> Call<()> {
    Call::nothing(Request::new(Method::Delete, format!("{API}/shares/{}", enc(share_id))))
}

/// Where to go to work together on a document.
///
/// The service decides whether the caller may, and which provider answers. A
/// refusal here is a refusal to open that document, never a hint about how the
/// provider is configured.
pub fn conversation(id: &str) -> Call<Conversation> {
    Call::json(get(format!("{API}/conversation?id={}", enc(id))))
}

/// A relay token for one document, plus where to take it.
pub fn join(id: &str) -> Call<Join> {
    Call::json(get(format!("{API}/token?id={}", enc(id))))
}

// ---- somebody who arrived on a keyed link ---------------------------------

/// A relay token for the one room a recipient's key names.
///
/// Separate from [`join`] because that one acts as the signed-in user against
/// the provider, and a recipient is not one. The service reads the document as
/// the sharer, which is the whole reason a recipient needs no credential.
pub fn invite_token() -> Call<InviteJoin> {
    Call::json(get(format!("{API}/invite/token")))
}

/// The document a recipient's key names.
pub fn invite_read() -> Call<Vec<u8>> {
    Call::raw(get(format!("{API}/invite/content")))
}

/// Save it back, where the share still allows an edit.
pub fn invite_write(bytes: &[u8], if_match: Option<&str>) -> Call<Entry> {
    Call::json(sending(Method::Put, format!("{API}/invite/content{}", first(tag(if_match))), bytes))
}

// ---- e-sign -----------------------------------------------------------------

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct EsignCaps {
    pub capabilities: Vec<craft_esign::EsignCapability>,
    pub responsible_party: String,
    pub linked: bool,
    pub provider: String,
}

#[derive(Serialize)]
pub struct EsignCreate<'a> {
    pub draft: &'a EnvelopeDraft,
    pub document: &'a [u8],
    pub idempotency_key: &'a str,
    pub send: bool,
}

pub fn esign_capabilities() -> Call<EsignCaps> {
    Call::json(get(format!("{API}/esign/capabilities")))
}

pub fn esign_create(draft: &EnvelopeDraft, document: &[u8], idempotency_key: &str, send: bool) -> Result<Call<Envelope>> {
    Ok(Call::json(posting(
        format!("{API}/esign/envelopes"),
        &EsignCreate { draft, document, idempotency_key, send },
    )?))
}

pub fn esign_send(id: &str) -> Result<Call<Envelope>> {
    Ok(Call::json(posting(format!("{API}/esign/envelopes/{}/send", enc(id)), &())?))
}

pub fn esign_status(id: &str) -> Call<Envelope> {
    Call::json(get(format!("{API}/esign/envelopes/{}", enc(id))))
}

pub fn esign_completed(id: &str) -> Call<CompletedDocument> {
    Call::json(get(format!("{API}/esign/envelopes/{}/completed", enc(id))))
}

pub fn esign_void(id: &str, reason: &str) -> Result<Call<()>> {
    #[derive(Serialize)]
    struct Body<'a> {
        reason: &'a str,
    }
    Ok(Call::nothing(posting(format!("{API}/esign/envelopes/{}/void", enc(id)), &Body { reason })?))
}

pub fn esign_remind(id: &str, recipient: &str) -> Result<Call<()>> {
    Ok(Call::nothing(posting(
        format!("{API}/esign/envelopes/{}/remind/{}", enc(id), enc(recipient)),
        &(),
    )?))
}

/// `&if_match=…`, or nothing at all.
fn tag(if_match: Option<&str>) -> String {
    match if_match {
        Some(value) => format!("&if_match={}", enc(value)),
        None => String::new(),
    }
}

/// The same parameter where it is the first one on the query.
fn first(parameter: String) -> String {
    match parameter.strip_prefix('&') {
        Some(rest) => format!("?{rest}"),
        None => parameter,
    }
}
