//! The CollabCraft API.
//!
//! This is the only thing a Craft app talks to. Apps hold no provider
//! credential, know no provider URL and implement no provider protocol. They
//! ask here, and here decides which provider answers.
//!
//! That split is the whole design. A desktop binary carrying a cloud app
//! password leaks one the moment somebody copies the file, and every app would
//! reimplement WebDAV, OCS and CardDAV to use it. Both problems go away when
//! one service holds the credential and speaks the protocols.
//!
//! Every route is scoped to a signed-in session. Nothing here acts without
//! knowing who is asking.
//!
//! The contracts are synchronous, because a provider crate that opens no
//! socket has no reason to be async. Handlers therefore push provider work
//! onto a blocking thread with [`run`]. Calling it inline would stall the
//! runtime, and building a blocking HTTP client inside a runtime panics
//! outright.

use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{ACCEPT_RANGES, CONTENT_RANGE, CONTENT_TYPE, ETAG, RANGE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use craft_cloud::{Permission, Provider, ShareTarget};
use serde::{Deserialize, Serialize};

use crate::session::Session;
use crate::state::{App, Permissions};

type Shared = Arc<dyn Provider + Send + Sync>;

/// What a failed call looks like on the wire.
///
/// The shape is stable so a client acts on `code` without reading `detail`,
/// which is for a human.
#[derive(Serialize)]
pub struct ApiError {
    pub code: &'static str,
    pub detail: String,
}

/// Map a contract error onto a status and a stable code.
///
/// The distinctions matter to a UI. `unauthenticated` offers a sign-in,
/// `forbidden` must not, `conflict` offers to reload, `unsupported` hides the
/// feature rather than explaining it.
pub(crate) fn fail(e: craft_cloud::Error) -> Response {
    use craft_cloud::Error as E;
    let (status, code) = match &e {
        E::Unreachable(_) => (StatusCode::BAD_GATEWAY, "unreachable"),
        E::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
        E::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
        E::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found"),
        E::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        E::Unsupported(_) => (StatusCode::NOT_IMPLEMENTED, "unsupported"),
        E::Malformed { .. } => (StatusCode::BAD_GATEWAY, "malformed"),
        E::Invalid { .. } => (StatusCode::BAD_REQUEST, "invalid"),
    };
    (status, Json(ApiError { code, detail: e.to_string() })).into_response()
}

/// Run one blocking provider call and render whatever it returns as JSON.
async fn run<T, F>(f: F) -> Response
where
    T: Serialize + Send + 'static,
    F: FnOnce() -> craft_cloud::Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(e)) => fail(e),
        // The thread panicked. Reported rather than swallowed, because a
        // provider that panics is a defect somebody has to see.
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response(),
    }
}

/// No provider account linked yet.
///
/// Its own code, because the fix is specific: the user links an account. It is
/// neither a failed sign-in nor a permission problem, and offering either
/// would send them somewhere useless.
fn not_linked() -> Response {
    (
        StatusCode::PRECONDITION_REQUIRED,
        Json(ApiError { code: "provider_not_linked", detail: "link a cloud account before opening or saving documents".to_owned() }),
    )
        .into_response()
}

// ---- who am I -------------------------------------------------------------

/// Where to open the provider's conversation app when no document is in hand.
///
/// Document rooms still go through [`conversation`]. This is the empty lobby:
/// the launcher and the CollabCraft home page open it so somebody can chat
/// without first opening a Craft document.
#[derive(Serialize)]
pub struct ConversationHome {
    /// What the provider calls it (Talk, …).
    pub name: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct Me {
    pub id: String,
    pub display: String,
    pub email: Option<String>,
    pub avatar: Option<String>,
    /// Which Craft apps this user may open. Decided here, not by the client:
    /// a client asking itself would be no check at all.
    pub apps: Vec<String>,
    /// What the provider can actually do, so a UI hides what it cannot
    /// deliver rather than failing on use.
    pub capabilities: Vec<craft_cloud::Capability>,
    /// What this deployment does itself, on the same terms. An organisation
    /// that forbids keyed links reports none, and the share dialog then offers
    /// no button rather than one that fails.
    pub service: Vec<crate::state::ServiceCapability>,
    /// Until an account is linked, Open and Save have nowhere to go.
    pub provider_linked: bool,
    /// The provider's conversation lobby, when it has one. Absent where chat is
    /// unsupported, so a launcher draws no Talk button rather than a dead one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<ConversationHome>,
    /// Present when this deployment stores files in a git repository.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<crate::git::GitView>,
}

pub async fn me(State(app): State<Arc<App>>, session: Session) -> Response {
    let apps = app.entitlements().await.0.apps_for_session(&session);
    let service = app.service_capabilities();
    let Some(provider) = app.provider_for(&session).await else {
        return Json(Me {
            id: session.user,
            display: session.display,
            email: session.email,
            avatar: None,
            apps,
            capabilities: Vec::new(),
            service,
            provider_linked: false,
            conversation: None,
            git: None,
        })
        .into_response();
    };

    let capabilities = provider.capabilities();
    // Lobby URL for chat with nothing open. Document rooms still use
    // conversation(); this is only for the launcher / CollabCraft home.
    let conversation = if capabilities.contains(&craft_cloud::Capability::Conversation) {
        match craft_cloud::Conversations::conversation_name(provider.as_ref()) {
            Some(name) => {
                app.provider_config().await.map(|(cfg, _)| ConversationHome { name, url: format!("{}/apps/spreed", cfg.base.trim_end_matches('/')) })
            }
            None => None,
        }
    } else {
        None
    };
    let git = if provider.id() == "git" {
        app.provider_config().await.map(|(config, _)| crate::git::GitView { branch: "main".to_owned(), remote: config.base })
    } else {
        None
    };
    let p = provider.clone();
    let identity = tokio::task::spawn_blocking(move || craft_cloud::Accounts::me(p.as_ref())).await;
    match identity {
        Ok(Ok(id)) => Json(Me {
            id: session.user,
            display: id.display,
            email: id.email.or(session.email),
            avatar: id.avatar,
            apps,
            capabilities,
            service,
            provider_linked: true,
            conversation,
            git,
        })
        .into_response(),
        Ok(Err(e)) => fail(e),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response(),
    }
}

// ---- files ----------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListQuery {
    /// Folder to list. Absent means the user's root.
    #[serde(default)]
    pub path: String,
}

pub async fn list(State(app): State<Arc<App>>, session: Session, Query(q): Query<ListQuery>) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    run(move || p.list(&q.path)).await
}

/// Everything other people have shared with this user.
///
/// A separate route because it is a separate question. These entries have no
/// common parent folder, so no amount of listing would find them.
pub async fn shared_with_me(State(app): State<Arc<App>>, session: Session) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    run(move || p.shared_with_me()).await
}

#[derive(Deserialize)]
pub struct IdQuery {
    pub id: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub length: Option<u64>,
}

fn parse_http_range(value: Option<&HeaderValue>) -> Option<(u64, u64)> {
    let raw = value?.to_str().ok()?;
    let spec = raw.strip_prefix("bytes=")?;
    let (start, end_inclusive) = spec.split_once('-')?;
    let first: u64 = start.parse().ok()?;
    if end_inclusive.is_empty() {
        return None;
    }
    let last: u64 = end_inclusive.parse().ok()?;
    if last < first {
        return None;
    }
    Some((first, last.saturating_sub(first).saturating_add(1)))
}

/// Where to go to work together on a document.
///
/// Nextcloud calls it Talk. Another provider calls it something else, and the
/// answer carries that name so a control can say which. A provider without the
/// feature answers that it is unsupported, and the client then draws nothing.
pub async fn conversation(State(app): State<Arc<App>>, session: Session, Query(q): Query<IdQuery>) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    // The last segment, which is what a person would call the document. A
    // provider that names the room uses it. One that keys on a file id ignores
    // it.
    let title = q.id.rsplit('/').next().unwrap_or_default().to_owned();
    run(move || p.conversation(&q.id, &title)).await
}

pub async fn read(State(app): State<Arc<App>>, session: Session, Query(q): Query<IdQuery>, headers: HeaderMap) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    let range = parse_http_range(headers.get(RANGE)).or(match (q.offset, q.length) {
        (Some(offset), Some(length)) => Some((offset, length)),
        _ => None,
    });
    if let Some((offset, length)) = range {
        let id = q.id.clone();
        match tokio::task::spawn_blocking(move || {
            let entry = p.stat(&id)?;
            let total = entry.size.unwrap_or(0);
            if total > 0 && offset >= total {
                return Err(craft_cloud::Error::Invalid { what: "range", detail: "range not satisfiable".to_owned() });
            }
            let bytes = p.read_range(&id, offset, length)?;
            Ok((bytes, total, entry.etag))
        })
        .await
        {
            Ok(Ok((bytes, total, etag))) => {
                let last = offset.saturating_add(bytes.len() as u64).saturating_sub(1);
                let mut builder = Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header(ACCEPT_RANGES, "bytes")
                    .header(CONTENT_RANGE, format!("bytes {offset}-{last}/{total}"));
                if let Some(tag) = etag
                    && let Ok(v) = HeaderValue::from_str(&tag)
                {
                    builder = builder.header(ETAG, v);
                }
                builder.body(Body::from(bytes)).unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
            Ok(Err(craft_cloud::Error::Invalid { what: "range", detail })) => {
                (StatusCode::RANGE_NOT_SATISFIABLE, Json(ApiError { code: "range_not_satisfiable", detail })).into_response()
            }
            Ok(Err(e)) => fail(e),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response(),
        }
    } else {
        let id = q.id;
        match tokio::task::spawn_blocking(move || p.read(&id)).await {
            Ok(Ok(bytes)) => (
                StatusCode::OK,
                [(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream")), (ACCEPT_RANGES, HeaderValue::from_static("bytes"))],
                bytes,
            )
                .into_response(),
            Ok(Err(e)) => fail(e),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response(),
        }
    }
}

pub async fn file_meta(State(app): State<Arc<App>>, session: Session, Query(q): Query<IdQuery>) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    run(move || p.stat(&q.id)).await
}

#[derive(Deserialize)]
pub struct WriteQuery {
    pub id: String,
    /// The version the client last saw. Sent back so a save refuses to
    /// overwrite work somebody else saved in the meantime.
    #[serde(default)]
    pub if_match: Option<String>,
}

pub async fn write(State(app): State<Arc<App>>, session: Session, Query(q): Query<WriteQuery>, body: axum::body::Bytes) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    run(move || p.write(&q.id, &body, q.if_match.as_deref())).await
}

#[derive(Deserialize)]
pub struct CreateQuery {
    pub folder: String,
    pub name: String,
}

pub async fn create(State(app): State<Arc<App>>, session: Session, Query(q): Query<CreateQuery>, body: axum::body::Bytes) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    run(move || p.create(&q.folder, &q.name, &body)).await
}

// ---- contacts, for the share dialog ---------------------------------------

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

/// People matching what has been typed so far.
///
/// Called on each keystroke, so the limit is enforced here as well as asked of
/// the provider. A dialog that pulls a thousand contacts to show eight only
/// hurts on somebody else's address book.
pub async fn contacts(State(app): State<Arc<App>>, session: Session, Query(q): Query<SearchQuery>) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    let limit = q.limit.clamp(1, 50);
    run(move || p.search(&q.q, limit)).await
}

// ---- sharing --------------------------------------------------------------

#[derive(Deserialize)]
pub struct ShareRequest {
    /// The document's provider handle.
    pub id: String,
    /// Everyone to share with, in one call. The dialog is multi-select, so a
    /// request per recipient would be several round trips and a partial
    /// failure the user cannot see.
    pub targets: Vec<ShareTarget>,
    pub permission: Permission,
    #[serde(default)]
    pub note: Option<String>,
    /// Ask the provider to tell the recipient.
    #[serde(default)]
    pub notify: bool,
    /// A key the recipient must present. Only meaningful for a link, and
    /// refused by a server that does not allow one.
    #[serde(default)]
    pub password: Option<String>,
    /// `YYYY-MM-DD`, after which the share stops working.
    #[serde(default)]
    pub expires: Option<String>,
    /// Which Craft app opens this document, for a recipient with no account.
    ///
    /// Named by the app doing the sharing, because that app is already the
    /// right answer. Checked here against what this deployment hosts and what
    /// the sharer may open, so nobody can send a recipient into a build they
    /// could not open themselves. It is then pinned to the key and never read
    /// from the request that redeems it.
    #[serde(default)]
    pub app: Option<String>,
}

#[derive(Serialize)]
pub struct ShareOutcome {
    pub shared: Vec<craft_cloud::Share>,
    /// One entry per target that failed, so the dialog can say which.
    pub failed: Vec<ShareFailure>,
    /// One entry per recipient who has no account and got a keyed link.
    ///
    /// Empty where this deployment forbids them, where nothing was shared by
    /// address, or where every address turned out to hold an account after
    /// all.
    pub keyed: Vec<KeyedOutcome>,
}

#[derive(Serialize)]
pub struct ShareFailure {
    pub target: ShareTarget,
    pub code: &'static str,
    pub detail: String,
}

/// A keyed link that was minted, and what became of it.
#[derive(Serialize)]
pub struct KeyedOutcome {
    pub target: ShareTarget,
    /// The link to hand out. A lookup handle and a key, carrying no
    /// permission: the grant stays in this service and is re-read on every
    /// request.
    pub url: String,
    /// Unix, when the key stops working.
    pub expires: i64,
    /// How many times it may be opened.
    pub uses: u32,
    /// Whether the provider mailed it.
    pub delivered: bool,
    /// Why it was not mailed. `mail_unsupported` means this provider sends no
    /// mail of its own, so the sharer has to pass the link on themselves,
    /// which is why the link is returned here rather than only sent.
    pub delivery: &'static str,
}

/// Share with several people at once.
///
/// Partial success is reported rather than hidden. Sharing with five people
/// where one address is wrong should share with four and name the one that
/// failed, not fail the lot and not claim all five worked.
///
/// A target that turns out to be an address nobody holds an account for also
/// gets a keyed link, because such a person cannot be told to sign in. The
/// provider still records the share, so it stays the authority on who may open
/// what and withdrawing it withdraws the key.
pub async fn share(State(app): State<Arc<App>>, session: Session, headers: HeaderMap, Json(req): Json<ShareRequest>) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    if !p.supports(craft_cloud::Capability::Sharing) {
        return fail(craft_cloud::Error::Unsupported("sharing"));
    }

    // Where a recipient with no account would land. Settled before anything is
    // shared, because a key with nowhere to go is worse than no key, and a
    // sharer told now can do something about it.
    //
    // Prefer the app named in the body. Older browser builds omit it. Share
    // calls often come from a worker with no Referer, so the app cookie set
    // when the page was served is next, then Referer / Origin / X-Craft-App.
    let named = req
        .app
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| header_text(&headers, axum::http::HeaderName::from_static("x-craft-app")))
        .or_else(|| cookie_value(&headers, crate::session::APP_COOKIE))
        .or_else(|| app_from_browser(&headers));
    let landing = landing_app(&app, &app.entitlements().await.0, &session, named.as_deref());
    let mint = app.keyed.enabled() && landing.is_some();
    if app.keyed.enabled() && landing.is_none() {
        tracing::warn!(asked = ?req.app, "share has no landing app; keyed CollabCraft links were not minted");
    }

    let req = Arc::new(req);
    let placing = tokio::task::spawn_blocking({
        let p = p.clone();
        let req = req.clone();
        move || place(p.as_ref(), &req, mint)
    })
    .await;
    let mut placed = match placing {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response();
        }
    };

    // Mint and record each key, then ask the provider to send one mail per
    // invitation. Both halves are separate from the sharing above because one
    // needs the bus and the other needs the share ids the provider just
    // issued.
    let mut invitations = Vec::new();
    if let (Some(slug), Some(entry)) = (landing.as_deref(), placed.entry.clone()) {
        let exp = now_unix() + app.keyed.ttl_secs as i64;
        for (target, share) in &placed.keyed {
            let key = crate::keyed::Key::mint();
            let Ok(verifier) = key.verifier(&app.secret) else {
                placed.failed.push(ShareFailure {
                    target: target.clone(),
                    code: "mint_failed",
                    detail: "this service could not mint a key for that recipient".to_owned(),
                });
                continue;
            };
            let recipient = match target {
                ShareTarget::Email(address) => address.clone(),
                ShareTarget::Link => "Guest".to_owned(),
                _ => continue,
            };
            let invite_url = app.keyed.url(&key);
            let link = crate::keyed::Link {
                verifier,
                room: entry.room.clone(),
                doc: req.id.clone(),
                app: slug.to_owned(),
                permission: req.permission,
                recipient,
                owner: session.user.clone(),
                share: share.id.clone(),
                exp,
                max_uses: app.keyed.max_uses,
                invite_url: Some(invite_url.clone()),
            };
            if !app.store.put_keyed_link(&key.handle, &link, app.keyed.ttl_secs).await {
                placed.failed.push(ShareFailure {
                    target: target.clone(),
                    code: "store_failed",
                    detail: "this service could not record a key for that recipient".to_owned(),
                });
                continue;
            }
            // The handle identifies the link for diagnosis. The key itself
            // appears in the response and in the mail and in no log line
            // anywhere, because a log is read by people who were never given
            // the link.
            tracing::info!(link = %key.handle, room = %entry.room, app = %slug, "minted a keyed link");
            invitations.push((target.clone(), invite_url, exp));
        }

        let sharer = placed.sharer.clone().unwrap_or_else(|| session.display.clone());
        let email_invitations: Vec<(String, String, i64)> = invitations
            .iter()
            .filter_map(|(target, url, expires)| match target {
                ShareTarget::Email(address) => Some((address.clone(), url.clone(), *expires)),
                _ => None,
            })
            .collect();
        let mut delivery = deliver(&p, &email_invitations, &sharer, &entry.name).await.into_iter();
        for (target, url, expires) in invitations {
            let outcome = if matches!(target, ShareTarget::Email(_)) { delivery.next().unwrap_or("mail_failed") } else { "copy" };
            // Older share dialogs ignore `keyed` and copy `shared[].url`. Put
            // the CollabCraft invite there so they still hand out a link that
            // opens the app. The provider share id stays for revocation.
            if let Some(shared) = placed.shared.iter_mut().find(|share| share.target == target) {
                shared.url = Some(url.clone());
            }
            placed.keyed_out.push(KeyedOutcome {
                target,
                url,
                expires,
                uses: app.keyed.max_uses,
                delivered: outcome == DELIVERED,
                delivery: outcome,
            });
        }
    }

    Json(ShareOutcome { shared: placed.shared, failed: placed.failed, keyed: placed.keyed_out }).into_response()
}

/// Which app a recipient with no account would be sent into.
///
/// `None` means no key is minted for this share. Either the sharing app named
/// no app, or it named one this deployment does not host, or it named one the
/// sharer may not open. The last is the one that matters: nobody may hand a
/// recipient a build they could not open themselves.
fn landing_app(app: &App, entitled: &Permissions, session: &Session, named: Option<&str>) -> Option<String> {
    let name = named?.trim();
    if !app.is_app(name) || !entitled.may_open(session, name) {
        return None;
    }
    Some(name.to_owned())
}

/// The Craft app a browser request came from, when the body did not name one.
///
/// Apps are served as `/<slug>/…` under this deployment. The first path
/// segment of Referer (preferred) or Origin is that slug. Anything else is
/// ignored: landing_app still rejects names this deployment does not host.
fn app_from_browser(headers: &HeaderMap) -> Option<String> {
    header_text(headers, axum::http::header::REFERER)
        .and_then(|v| app_slug_from_url(&v))
        .or_else(|| header_text(headers, axum::http::header::ORIGIN).and_then(|v| app_slug_from_url(&v)))
}

fn header_text(headers: &HeaderMap, name: axum::http::HeaderName) -> Option<String> {
    headers.get(name)?.to_str().ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let (k, v) = part.split_once('=')?;
        if k.trim() == name {
            let value = v.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn app_slug_from_url(raw: &str) -> Option<String> {
    let uri: axum::http::Uri = raw.parse().ok()?;
    let slug = uri.path().trim_start_matches('/').split('/').next()?.trim();
    if slug.is_empty() {
        return None;
    }
    Some(slug.to_owned())
}

/// What one blocking pass over the provider produced.
struct Placed {
    shared: Vec<craft_cloud::Share>,
    failed: Vec<ShareFailure>,
    /// Target and provider share for every recipient who needs a keyed link.
    keyed: Vec<(ShareTarget, craft_cloud::Share)>,
    keyed_out: Vec<KeyedOutcome>,
    /// The document, for the room a key names and the name a mail mentions.
    entry: Option<craft_cloud::Entry>,
    /// What to call the sharer in that mail.
    sharer: Option<String>,
}

/// Record every share the request asked for.
///
/// One blocking hop, because each provider call here is synchronous and would
/// stall the runtime inline.
fn place(p: &(dyn Provider + Send + Sync), req: &ShareRequest, mint: bool) -> Placed {
    let mut out = Placed {
        shared: Vec::new(),
        failed: Vec::new(),
        keyed: Vec::new(),
        keyed_out: Vec::new(),
        entry: p.stat(&req.id).ok(),
        sharer: craft_cloud::Accounts::me(p).ok().map(|i| i.display),
    };

    for target in &req.targets {
        // Whether this address needs a keyed link is asked of the provider,
        // never taken from the request. A client naming an address proves
        // nothing about whether an account answers to it, and the answer
        // decides between two quite different kinds of share.
        let keyed = match target {
            ShareTarget::Email(address) if mint && !has_account(p, address) => Some(target.clone()),
            ShareTarget::Link if mint => Some(target.clone()),
            _ => None,
        };

        let options = craft_cloud::ShareOptions {
            note: req.note.clone(),
            // The provider's own mail carries the provider's own link, which a
            // recipient with no account cannot use. So for a keyed target this
            // service sends the mail instead, carrying the link that works.
            notify: req.notify && keyed.is_none(),
            password: req.password.clone(),
            expires: req.expires.clone(),
        };
        match p.share(&req.id, target, req.permission, &options) {
            Ok(s) => {
                if let Some(target) = keyed {
                    out.keyed.push((target, s.clone()));
                }
                out.shared.push(s);
            }
            Err(e) => {
                let code = match &e {
                    craft_cloud::Error::NotFound { .. } => "not_found",
                    craft_cloud::Error::Forbidden(_) => "forbidden",
                    craft_cloud::Error::Unreachable(_) => "unreachable",
                    _ => "failed",
                };
                out.failed.push(ShareFailure { target: target.clone(), code, detail: e.to_string() });
            }
        }
    }
    out
}

/// Whether an account at the provider answers to an address.
///
/// The contact search states the kind of share each match wants, so an address
/// an account holds comes back as a user or a group. Anything else counts as
/// no account, including a search the provider will not run. That is the safe
/// way round: the recipient then gets a key that works rather than a user
/// share to a user who does not exist.
fn has_account(p: &(dyn Provider + Send + Sync), address: &str) -> bool {
    let Ok(found) = p.search(address, 5) else { return false };
    found.iter().any(|c| {
        matches!(c.target, ShareTarget::User(_) | ShareTarget::Group(_))
            && (c.id.eq_ignore_ascii_case(address) || c.email.as_deref().is_some_and(|e| e.eq_ignore_ascii_case(address)))
    })
}

/// What a delivered invitation is reported as.
const DELIVERED: &str = "mail";

/// Ask the provider to mail every invitation.
///
/// The only delivery path. This service opens no connection to a mail server
/// and holds no mail credential, so a provider that sends no mail of its own
/// means the sharer passes the link on themselves. Reported rather than
/// hidden, which is why the link comes back in the response as well.
async fn deliver(p: &Shared, invitations: &[(String, String, i64)], sharer: &str, document: &str) -> Vec<&'static str> {
    if invitations.is_empty() {
        return Vec::new();
    }
    if !p.supports(craft_cloud::Capability::Mail) {
        return vec!["mail_unsupported"; invitations.len()];
    }
    let messages: Vec<craft_cloud::MailMessage> =
        invitations.iter().map(|(address, url, _)| crate::keyed::invitation(address, sharer, document, url)).collect();
    let count = messages.len();
    let p = p.clone();
    let sending = tokio::task::spawn_blocking(move || {
        messages
            .iter()
            .map(|m| match craft_cloud::Mail::send(p.as_ref(), m) {
                Ok(()) => DELIVERED,
                Err(craft_cloud::Error::Unsupported(_)) => "mail_unsupported",
                Err(e) => {
                    tracing::warn!(error = %e, "the provider would not send an invitation");
                    "mail_failed"
                }
            })
            .collect::<Vec<&'static str>>()
    })
    .await;
    sending.unwrap_or_else(|_| vec!["mail_failed"; count])
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub async fn shares(State(app): State<Arc<App>>, session: Session, Query(q): Query<IdQuery>) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    let id = q.id.clone();
    let listed = tokio::task::spawn_blocking(move || p.shares(&id)).await;
    match listed {
        Ok(Ok(mut shares)) => {
            // The dialog's "Copy link" reads this list after a grant. Replace
            // provider storage-manager URLs with the CollabCraft invite that
            // was minted for the same share, when one still exists.
            for share in &mut shares {
                if let Some(url) = invite_url_for_share(&app, &share.id).await {
                    share.url = Some(url);
                }
            }
            Json(shares).into_response()
        }
        Ok(Err(e)) => fail(e),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response(),
    }
}

async fn invite_url_for_share(app: &App, share_id: &str) -> Option<String> {
    app.store.keyed_links_for_share(share_id).await.into_iter().find_map(|link| link.invite_url)
}

/// Withdraw one share.
///
/// Withdrawing it also withdraws every keyed link minted from it. A key that
/// outlived its share would be a grant the sharer could no longer see and no
/// longer take back, which is the one thing a revocation has to prevent.
pub async fn unshare(State(app): State<Arc<App>>, session: Session, Path(share_id): Path<String>) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };
    let id = share_id.clone();
    match tokio::task::spawn_blocking(move || p.unshare(&id)).await {
        Ok(Ok(())) => {
            let dropped = app.store.drop_keyed_links_for_share(&share_id).await;
            if dropped > 0 {
                tracing::info!(share = %share_id, dropped, "withdrew the keyed links for a share");
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => fail(e),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response(),
    }
}

// ---- the collaboration token ----------------------------------------------

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    /// Given out rather than compiled into a client, so the relay can move
    /// without reissuing every app.
    pub relay: String,
    /// The room this token is for, which is the document's stable id.
    pub room: String,
}

/// Mint a relay token for one document.
///
/// Authorisation happens here, against the provider, which is the only thing
/// that knows whether this user may open this file. The relay then verifies a
/// signature and never asks again, so this is once per document rather than
/// once per edit.
pub async fn token(State(app): State<Arc<App>>, session: Session, Query(q): Query<IdQuery>) -> Response {
    let Some(p): Option<Shared> = app.provider_for(&session).await else { return not_linked() };

    // Stat rather than trust the client. An id arriving in a request proves
    // nothing about whether this user may open it, and the provider is the
    // authority on that.
    let entry = match tokio::task::spawn_blocking(move || p.stat(&q.id)).await {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return fail(e),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response();
        }
    };
    let permission = if entry.writable { Permission::Edit } else { Permission::View };
    match app.mint_token(&session, &entry.room, permission) {
        Ok(token) => Json(TokenResponse { token, relay: app.relay_url.clone(), room: entry.room }).into_response(),
        Err(detail) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "mint_failed", detail })).into_response(),
    }
}

// ---- serving the browser builds -------------------------------------------

/// Serve a browser build, if this user is entitled to that app.
///
/// The first path segment is the app. `/gridcraft/index.html` is GridCraft, and
/// a user without it gets 403 rather than the page. Enforcing it here rather
/// than in the client is the point: a client asking itself whether it may run
/// is no check at all.
///
/// Anything that is not an app directory is served unconditionally. Shared
/// assets and the index have nothing to gate.
pub async fn web(State(app): State<Arc<App>>, session: Option<Session>, req: axum::extract::Request) -> Response {
    let path = req.uri().path().trim_start_matches('/').to_owned();
    let first = path.split('/').next().unwrap_or_default().to_owned();

    if app.is_app(&first) {
        let Some(session) = session else {
            // Send them to sign in rather than refusing flatly: an anonymous
            // visitor has not been denied anything yet.
            return axum::response::Redirect::temporary("/auth/login").into_response();
        };
        if !app.entitlements().await.0.may_open(&session, &first) {
            return (StatusCode::FORBIDDEN, Json(ApiError { code: "app_not_permitted", detail: format!("you do not have access to {first}") }))
                .into_response();
        }
    }

    match tower::ServiceExt::oneshot(app.web.clone(), req).await {
        Ok(r) => {
            let mut response = r.into_response();
            if let Some(value) = cache_for(&path) {
                response.headers_mut().insert(axum::http::header::CACHE_CONTROL, value);
            }
            // Remember which app this browser is in. Share requests from a
            // worker carry cookies but not a Referer, and keyed links need
            // the app name to mint.
            if app.is_app(&first)
                && let Ok(value) = HeaderValue::from_str(&format!("{}={first}; Path=/; SameSite=Lax; Secure", crate::session::APP_COOKIE))
            {
                response.headers_mut().append(axum::http::header::SET_COOKIE, value);
            }
            response
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "static", detail: e.to_string() })).into_response(),
    }
}

/// Which apps this user may open.
pub async fn apps(State(app): State<Arc<App>>, session: Session) -> Response {
    Json(app.entitlements().await.0.apps_for_session(&session)).into_response()
}

/// How long a static asset may be cached.
///
/// A one-year immutable cache is only sound where the filename carries a
/// content hash, because the hash is then the cache key. Trunk emits those, as
/// in `gridcraft-web-b92841ed094e19aa_bg.wasm`. Several apps are built with
/// wasm-bindgen directly and emit plain names, as do the shared workers.
/// Marking one of those immutable means a redeploy never reaches anybody who
/// has already visited.
fn cache_for(path: &str) -> Option<axum::http::HeaderValue> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let value = if name.is_empty() || name.ends_with(".html") {
        // The entry point carries no hash and must never be cached, or a
        // deploy is invisible.
        "no-cache"
    } else if (name.ends_with(".wasm") || name.ends_with(".js")) && has_content_hash(name) {
        "public, max-age=31536000, immutable"
    } else if name.ends_with(".wasm") || name.ends_with(".js") {
        "public, max-age=300, must-revalidate"
    } else if name.ends_with(".otf") || name.ends_with(".ttf") || name.ends_with(".woff") || name.ends_with(".woff2") {
        // Fonts are large and change rarely. One app ships a 16 MB CJK face.
        "public, max-age=86400"
    } else {
        return None;
    };
    axum::http::HeaderValue::from_str(value).ok()
}

/// Whether a filename carries a content hash, as `-<hex>` before the
/// extension.
fn has_content_hash(name: &str) -> bool {
    let stem = name.trim_end_matches(".wasm").trim_end_matches(".js").trim_end_matches("_bg");
    stem.rsplit('-').next().is_some_and(|tail| tail.len() >= 8 && tail.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_from_an_app_path_names_that_app() {
        assert_eq!(app_slug_from_url("https://craft.example.net/deckcraft/").as_deref(), Some("deckcraft"));
        assert_eq!(app_slug_from_url("https://craft.example.net/gridcraft/index.html").as_deref(), Some("gridcraft"));
    }

    #[test]
    fn the_service_root_names_no_app() {
        assert_eq!(app_slug_from_url("https://craft.example.net/"), None);
        assert_eq!(app_slug_from_url("https://craft.example.net"), None);
    }

    #[test]
    fn the_app_cookie_names_the_open_build() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, HeaderValue::from_static("collabcraft_session=abc; collabcraft_app=deckcraft"));
        assert_eq!(cookie_value(&headers, crate::session::APP_COOKIE).as_deref(), Some("deckcraft"));
    }
}
