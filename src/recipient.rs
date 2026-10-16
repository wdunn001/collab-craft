//! Where a keyed link lands, and what the recipient may do once it has.
//!
//! The recipient has no account at the provider and no account here. So they
//! get a session that names one room, one document and one app, and every
//! route below re-reads the grant from the provider before answering. Nothing
//! is decided from the request.
//!
//! The document itself is read and written by this service using the sharer's
//! linked account. That is the whole reason a recipient needs no credential,
//! and it is why these routes exist rather than letting a recipient use the
//! ordinary file routes: those act as the signed-in user, and a recipient is
//! not one.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use craft_cloud::Permission;
use serde::Serialize;

use crate::api::ApiError;
use crate::keyed::{self, Key, Link, Refusal};
// One escaper for every page this service renders. Two would be one too many.
use crate::pages::escape;
use crate::session::{GUEST_COOKIE, Guest, InviteSession, Session, random_id};
use crate::state::App;

/// What a refusal looks like to somebody who followed a link.
///
/// The reason goes to the log and the recipient gets one sentence. Telling
/// them which check failed would say whether such a key exists, and anybody
/// can follow a link.
fn refuse(refusal: &Refusal, status: StatusCode) -> Response {
    tracing::info!(reason = %refusal, "a keyed link was refused");
    (status, Html(page(refusal.public()))).into_response()
}

/// Mint the session a recipient carries, and land them in the document.
///
/// The key is spent here and the session takes over, so a reload works while
/// the link itself is already used up. That ordering matters: a single-use
/// link whose landing page could not be reloaded would be a link that works
/// once and then appears broken to the person who just opened it.
pub async fn land(State(app): State<Arc<App>>, Path(raw): Path<String>) -> Response {
    if !app.keyed.enabled() {
        return refuse(&Refusal::Disabled, StatusCode::NOT_FOUND);
    }
    let key = match Key::parse(&raw) {
        Ok(k) => k,
        Err(e) => return refuse(&e, StatusCode::BAD_REQUEST),
    };

    let Some(link) = app.store.keyed_link(&key.handle).await else {
        return refuse(&Refusal::Unknown, StatusCode::NOT_FOUND);
    };
    let spent = app.store.keyed_uses(&key.handle).await;
    if let Err(e) = keyed::redeem(&app.secret, &link, &key, spent, now_unix()) {
        return refuse(&e, StatusCode::FORBIDDEN);
    }

    // The provider decides, every time. Checking only at minting would leave a
    // withdrawn share openable by anybody still holding the mail.
    let permission = match grant(&app, &link).await {
        Ok((_, p)) => p,
        Err(e) => return refuse(&e, StatusCode::FORBIDDEN),
    };

    // Spend last, and atomically. Two recipients racing for the last use of a
    // key must not both win, and a read-then-write here would hand it to both.
    if !app.store.spend_keyed_link(&key.handle, link.max_uses, app.keyed.ttl_secs).await {
        return refuse(&Refusal::Spent { spent: link.max_uses, allowed: link.max_uses }, StatusCode::FORBIDDEN);
    }

    let session = Session {
        // Derived from the handle, so two windows are one guest and revoking
        // the link can find the sessions it created.
        user: Guest::user_id(&key.handle),
        display: link.recipient.clone(),
        email: Some(link.recipient.clone()),
        // No groups, ever. Group membership is how entitlement is granted
        // here, and a recipient is entitled to one document.
        groups: Vec::new(),
        guest: Some(Guest { link: key.handle.clone(), room: link.room.clone(), doc: link.doc.clone(), app: link.app.clone(), permission }),
    };
    let id = random_id();
    if !app.store.put_session(&id, &session).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(page("this service could not start a session for that link"))).into_response();
    }

    tracing::info!(link = %key.handle, room = %link.room, app = %link.app, ?permission, "a recipient landed");

    let mut response = Html(handoff(&link.app, &id, app.keyed.base())).into_response();
    // Its own cookie, so following an invite does not sign out whoever is
    // already signed in on this browser. The ordinary cookie still wins when
    // both are present, because a real account carries more than this does.
    if let Ok(value) = HeaderValue::from_str(&format!("{GUEST_COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax; Secure")) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

/// What the provider still grants a recipient for one link, and the document
/// it grants.
///
/// Reads the document and its shares as the sharer, because the recipient has
/// no account to read them as. A sharer who has since unlinked their account
/// leaves nothing able to answer, so the key stops working.
///
/// The entry comes back as well as the permission. A recipient has no file
/// list, so this is the only place the document's name and its current version
/// can come from, and both are read here rather than remembered when the link
/// was minted. A document renamed since then is still the same document.
async fn grant(app: &App, link: &Link) -> Result<(craft_cloud::Entry, Permission), Refusal> {
    let Some(provider) = app.provider_for_owner(&link.owner).await else {
        return Err(Refusal::Withdrawn);
    };
    let doc = link.doc.clone();
    let answer = tokio::task::spawn_blocking(move || -> craft_cloud::Result<(craft_cloud::Entry, Vec<craft_cloud::Share>)> {
        let entry = provider.stat(&doc)?;
        let shares = provider.shares(&doc)?;
        Ok((entry, shares))
    })
    .await;

    match answer {
        Ok(Ok((entry, shares))) => {
            let permission = keyed::regrant(link, &entry.room, &shares)?;
            Ok((entry, permission))
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, link = %link.share, "the provider would not say whether a share still stands");
            Err(Refusal::Withdrawn)
        }
        Err(e) => {
            tracing::error!(error = %e, "the provider call panicked while checking a share");
            Err(Refusal::Withdrawn)
        }
    }
}

/// The grant for a recipient already holding a session.
///
/// Re-reads the link record as well as the share. The record is what
/// withdrawal deletes, so a session outliving it must stop working, and this
/// is the one place every recipient route passes through.
async fn standing(app: &App, guest: &Guest) -> Result<(Link, craft_cloud::Entry, Permission), Refusal> {
    let Some(link) = app.store.keyed_link(&guest.link).await else {
        return Err(Refusal::Unknown);
    };
    if link.room != guest.room || link.doc != guest.doc {
        return Err(Refusal::Moved);
    }
    if link.exp <= now_unix() {
        return Err(Refusal::Expired { exp: link.exp, now: now_unix() });
    }
    let (entry, permission) = grant(app, &link).await?;
    Ok((link, entry, permission))
}

/// Turn a refusal into the JSON an app can act on.
fn refuse_json(refusal: &Refusal) -> Response {
    tracing::info!(reason = %refusal, "a recipient request was refused");
    (StatusCode::FORBIDDEN, Json(ApiError { code: "link_invalid", detail: refusal.public().to_owned() })).into_response()
}

/// What a signed-in caller gets from these routes.
///
/// Answered as a missing route rather than a refused one. Somebody with an
/// account has the ordinary routes, which do more, so there is nothing here
/// for them to be refused.
fn not_a_recipient() -> Response {
    (StatusCode::NOT_FOUND, Json(ApiError { code: "not_a_recipient", detail: "this route is for a shared link".to_owned() })).into_response()
}

/// Everything a recipient's application needs before it can show them
/// anything.
///
/// One answer rather than four routes. A browser build asks this once on
/// startup, and the answer either says this is a keyed link or refuses. An app
/// that had to assemble the name, the version, the permission and the room
/// from separate calls would have four chances to half-open a document.
#[derive(Serialize)]
pub struct Join {
    pub token: String,
    pub relay: String,
    pub room: String,
    /// What this recipient may do, decided here on this request. Sent so a UI
    /// can present a read-only document as read-only rather than discovering
    /// it when the relay refuses an edit.
    pub permission: Permission,
    /// What to call the document. A recipient has no file list, so this is the
    /// only place the name can come from, and it is read from the provider on
    /// this request rather than remembered from the minting.
    pub name: String,
    /// The version the document is at now. A recipient's save is conditional
    /// on this, so work saved between their read and their save refuses the
    /// write rather than being overwritten.
    pub etag: Option<String>,
    /// The address this link was minted for. Sent so a title bar can say who
    /// the document was shared with. A recipient has no account anywhere, so
    /// there is no account menu to draw and nothing to sign out of.
    pub recipient: String,
}

/// A relay token for the one room a recipient's key names.
///
/// Separate from the ordinary token route because that one acts as the
/// signed-in user against the provider, and a recipient is not one.
pub async fn token(State(app): State<Arc<App>>, InviteSession(session): InviteSession) -> Response {
    let Some(guest) = session.guest.as_ref() else { return not_a_recipient() };
    let (link, entry, permission) = match standing(&app, guest).await {
        Ok(v) => v,
        Err(e) => return refuse_json(&e),
    };

    match app.mint_token(&session, &link.room, permission) {
        Ok(token) => Json(Join {
            token,
            relay: app.relay_url.clone(),
            room: link.room,
            permission,
            name: entry.name,
            etag: entry.etag,
            recipient: link.recipient,
        })
        .into_response(),
        Err(detail) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "mint_failed", detail })).into_response(),
    }
}

/// The document's bytes, read as the sharer.
pub async fn read(State(app): State<Arc<App>>, InviteSession(session): InviteSession) -> Response {
    let Some(guest) = session.guest.as_ref() else { return not_a_recipient() };
    let (link, _, _) = match standing(&app, guest).await {
        Ok(v) => v,
        Err(e) => return refuse_json(&e),
    };
    let Some(provider) = app.provider_for_owner(&link.owner).await else {
        return refuse_json(&Refusal::Withdrawn);
    };

    let doc = link.doc.clone();
    match tokio::task::spawn_blocking(move || provider.read(&doc)).await {
        Ok(Ok(bytes)) => ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response(),
        Ok(Err(e)) => crate::api::fail(e),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct WriteQuery {
    /// The version the recipient last saw, so a save refuses to overwrite work
    /// somebody else saved meanwhile.
    #[serde(default)]
    pub if_match: Option<String>,
}

/// Replace the document's bytes, if the share still allows it.
pub async fn write(
    State(app): State<Arc<App>>,
    InviteSession(session): InviteSession,
    Query(q): Query<WriteQuery>,
    body: axum::body::Bytes,
) -> Response {
    let Some(guest) = session.guest.as_ref() else { return not_a_recipient() };
    let (link, _, permission) = match standing(&app, guest).await {
        Ok(v) => v,
        Err(e) => return refuse_json(&e),
    };
    if permission != Permission::Edit {
        // Decided here on this request, not from the session. A share
        // downgraded to read-only has to stop a save already in flight.
        return (StatusCode::FORBIDDEN, Json(ApiError { code: "forbidden", detail: "this link opens the document for reading".to_owned() }))
            .into_response();
    }
    let Some(provider) = app.provider_for_owner(&link.owner).await else {
        return refuse_json(&Refusal::Withdrawn);
    };

    let doc = link.doc.clone();
    match tokio::task::spawn_blocking(move || provider.write(&doc, &body, q.if_match.as_deref())).await {
        Ok(Ok(entry)) => Json(entry).into_response(),
        Ok(Err(e)) => crate::api::fail(e),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { code: "panic", detail: e.to_string() })).into_response(),
    }
}

// ---- the two pages --------------------------------------------------------

/// Hand the recipient to the installed app, falling back to the browser build.
///
/// A desktop Craft app registers `craft+<app>:` and gets the session as a
/// bearer token, which is exactly how the device sign-in flow already hands a
/// session to a desktop app. The attempt goes through a hidden frame, because
/// navigating the page to an unregistered scheme leaves the user looking at a
/// browser error instead of the document.
///
/// Nothing in this page names the provider, carries a credential or carries
/// the key. The session cookie rides the response header, and the session id
/// in the scheme URL never leaves the recipient's own machine.
///
/// The browser target carries `?invite`, which grants nothing and proves
/// nothing. The cookie is the whole of the authority. It only tells the app
/// build that a keyed link is why it was loaded, so a service that cannot be
/// reached is reported to the recipient rather than mistaken for an ordinary
/// visit. Without it a network blip shows somebody an empty document and no
/// reason for it, and that is the one outcome worse than a plain refusal. See
/// `craft_cloud_client::invite`.
pub(crate) fn handoff(app_slug: &str, session_id: &str, base: &str) -> String {
    let slug = escape(app_slug);
    let target = format!("craft+{app_slug}://join?service={}&session={session_id}", crate::session::urlencode(base));
    let scheme = serde_json::to_string(&target).unwrap_or_else(|_| "\"\"".to_owned());
    let web = serde_json::to_string(&format!("/{app_slug}/?invite")).unwrap_or_else(|_| "\"\"".to_owned());
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>Opening the document</title></head>\
         <body><p>Opening the document.</p>\
         <p><a id=\"here\" href=\"/{slug}/?invite\">Open it in this browser instead</a></p>\
         <iframe id=\"handoff\" hidden></iframe>\
         <script>\
         (function(){{\
         var scheme={scheme},web={web};\
         try{{document.getElementById('handoff').src=scheme;}}catch(e){{}}\
         setTimeout(function(){{location.replace(web);}},1200);\
         }})();\
         </script></body></html>\n"
    )
}

/// One refusal, as a page rather than JSON, because a person is reading it.
fn page(message: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>This link does not work</title></head>\
         <body><h1>This link does not work</h1><p>{}</p></body></html>\n",
        escape(message)
    )
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
