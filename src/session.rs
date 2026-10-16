//! Signing in, and proving it on later calls.
//!
//! Identity comes from OIDC, so CollabCraft never sees a password and the
//! estate keeps one account per person. Authentik decides who somebody is and
//! which groups they are in; this service decides what that entitles them to.
//!
//! Two kinds of client need this and they cannot work the same way. A browser
//! can be redirected, so it gets the ordinary authorization code flow and a
//! cookie. A desktop app cannot host a redirect worth trusting, so it starts a
//! flow, sends the user to a browser, and polls until it can collect a bearer
//! token. Both end at the same session record.
//!
//! Linking a cloud account is deliberately separate from signing in. They are
//! different questions ("who are you" against "which storage account may I act
//! on"), they can have different answers, and a provider that is down must not
//! stop somebody signing in.

use std::sync::Arc;

use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::state::App;

/// The cookie a browser session rides in.
pub const COOKIE: &str = "collabcraft_session";

/// The cookie a keyed link's recipient rides in.
///
/// Its own name on purpose. Following an invitation must not sign out whoever
/// is already signed in on that browser, and a single cookie would do exactly
/// that.
pub const GUEST_COOKIE: &str = "collabcraft_guest";

/// Which Craft app a browser last opened under this service.
///
/// Set when a hosted app asset is served. Share requests often come from a
/// worker, which has no Referer, so the cookie is how those requests still
/// name the app that should open a keyed recipient link.
pub const APP_COOKIE: &str = "collabcraft_app";

/// Who is making a request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    /// Stable identifier from the identity provider. The OIDC subject, not an
    /// email: addresses get reassigned and subjects do not.
    pub user: String,
    pub display: String,
    pub email: Option<String>,
    /// Groups as the identity provider reports them. Entitlement is decided
    /// from these, so adding somebody to a group there is the whole of
    /// granting access here.
    pub groups: Vec<String>,
    /// Set when this session came from a keyed link rather than a sign-in.
    ///
    /// Defaulted on read, so sessions written before this existed still load.
    #[serde(default)]
    pub guest: Option<Guest>,
}

/// A recipient who followed a keyed link.
///
/// Present on a session means the holder has no account anywhere, so it
/// bounds what they may reach: one room, one document, one app. Entitlement
/// is computed from this and never from the request, which is what keeps a
/// recipient out of every other app this deployment hosts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Guest {
    /// The keyed link's lookup handle. Checked on every request, because
    /// withdrawing the share deletes the record and the session has to stop
    /// working with it.
    pub link: String,
    pub room: String,
    /// The provider's handle for the document. Used by the service on the
    /// recipient's behalf and never sent to them.
    pub doc: String,
    /// The one app this recipient may load.
    pub app: String,
    /// What was granted when the link was followed. A hint for the roster
    /// only: every request re-reads the grant from the provider.
    pub permission: craft_cloud::Permission,
}

impl Guest {
    /// The user identifier a recipient carries.
    ///
    /// Derived from the link handle, so two windows are one recipient and
    /// revoking the link can find the sessions it created. Prefixed so it can
    /// never collide with an identity provider's subject.
    pub fn user_id(handle: &str) -> String {
        format!("guest:{handle}")
    }
}

impl Session {
    /// Whether this session came from a keyed link.
    pub fn is_guest(&self) -> bool {
        self.guest.is_some()
    }
}

/// Rejecting a request that carries no usable session.
pub struct NoSession;

impl IntoResponse for NoSession {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, axum::Json(crate::api::ApiError { code: "unauthenticated", detail: "sign in first".to_owned() })).into_response()
    }
}

impl FromRequestParts<Arc<App>> for Session {
    type Rejection = NoSession;

    /// A session from either a cookie or a bearer token.
    ///
    /// Both name the same record. The difference is only how a client is able
    /// to carry it, and a browser cannot be asked to hold a bearer token
    /// safely while a desktop app cannot be asked to hold a cookie.
    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Session, NoSession> {
        if let Some(id) = carried(parts)
            && let Some(session) = app.store.session(&id).await
        {
            return Ok(session);
        }
        Err(NoSession)
    }
}

/// The session id a request carries, from whichever place it rides in.
///
/// A signed-in account wins over a keyed link. Somebody who is signed in and
/// then follows an invitation is still that person, and they hold more than
/// the invitation grants — on every route except the invite ones, which use
/// [`carried_invite`] so the document they were sent still opens.
fn carried(parts: &Parts) -> Option<String> {
    bearer(parts).or_else(|| cookie(parts, COOKIE)).or_else(|| cookie(parts, GUEST_COOKIE))
}

/// The session id for `/api/v1/invite/*`.
///
/// The landing page sets a guest cookie and then hands the browser to an app
/// build. A signed-in account cookie still wins on ordinary routes, but the
/// invite routes must read the guest: otherwise `invite_token` answers
/// `not_a_recipient`, the app treats the load as ordinary, and the recipient
/// (or a sharer testing their own link) sees an empty document.
fn carried_invite(parts: &Parts) -> Option<String> {
    bearer(parts).or_else(|| cookie(parts, GUEST_COOKIE)).or_else(|| cookie(parts, COOKIE))
}

/// A session taken for the keyed-link recipient routes.
///
/// Prefers the guest cookie so a signed-in browser that just followed an
/// invite still opens the shared document. Ordinary routes keep using
/// [`Session`], where the account wins.
pub struct InviteSession(pub Session);

impl FromRequestParts<Arc<App>> for InviteSession {
    type Rejection = NoSession;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<InviteSession, NoSession> {
        if let Some(id) = carried_invite(parts)
            && let Some(session) = app.store.session(&id).await
        {
            return Ok(InviteSession(session));
        }
        Err(NoSession)
    }
}

fn bearer(parts: &Parts) -> Option<String> {
    let raw = parts.headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned)
}

fn cookie(parts: &Parts, name: &str) -> Option<String> {
    let raw = parts.headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let (k, v) = part.split_once('=')?;
        if k.trim() == name {
            return Some(v.trim().to_owned());
        }
    }
    None
}

/// What an identity provider has to tell us, discovered rather than compiled
/// in so a deployment can point at its own.
#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
}

/// OIDC configuration, all from the environment.
#[derive(Clone, Debug)]
pub struct Oidc {
    pub client_id: String,
    pub client_secret: String,
    /// Where the provider sends the browser back. Must match what is
    /// registered, so it is configured rather than guessed from the request:
    /// a guessed one behind a proxy is how an open redirect starts.
    pub redirect_uri: String,
    pub discovery: Discovery,
}

impl Oidc {
    /// Read configuration and fetch the provider's metadata.
    ///
    /// Returns `None` when the service is deliberately running without
    /// sign-in, which is useful locally and must never be the case in a
    /// deployment.
    pub async fn from_env(http: &reqwest::Client) -> Option<Oidc> {
        let issuer = var("COLLABCRAFT_OIDC_ISSUER")?;
        let client_id = var("COLLABCRAFT_OIDC_CLIENT_ID")?;
        let client_secret = var("COLLABCRAFT_OIDC_CLIENT_SECRET")?;
        let redirect_uri = var("COLLABCRAFT_OIDC_REDIRECT_URI")?;

        let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let discovery: Discovery = match http.get(&url).send().await {
            Ok(r) => match r.json().await {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, url, "the identity provider's metadata did not parse");
                    return None;
                }
            },
            Err(e) => {
                tracing::error!(error = %e, url, "could not reach the identity provider");
                return None;
            }
        };
        tracing::info!(%issuer, "identity provider ready");
        Some(Oidc { client_id, client_secret, redirect_uri, discovery })
    }

    /// Where to send a browser to sign in.
    pub fn authorize_url(&self, state: &str) -> String {
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            self.discovery.authorization_endpoint,
            urlencode(&self.client_id),
            urlencode(&self.redirect_uri),
            urlencode("openid profile email groups"),
            urlencode(state),
        )
    }

    /// Exchange the code a browser came back with for the user's claims.
    pub async fn exchange(&self, http: &reqwest::Client, code: &str) -> Result<Session, String> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        let token: serde_json::Value =
            http.post(&self.discovery.token_endpoint).form(&form).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
        let access = token.get("access_token").and_then(|v| v.as_str()).ok_or("no access token")?;

        let info: serde_json::Value = http
            .get(&self.discovery.userinfo_endpoint)
            .bearer_auth(access)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;

        let user = info.get("sub").and_then(|v| v.as_str()).ok_or("no subject")?.to_owned();
        let display = info.get("name").or_else(|| info.get("preferred_username")).and_then(|v| v.as_str()).unwrap_or(&user).to_owned();
        let email = info.get("email").and_then(|v| v.as_str()).map(str::to_owned);
        let groups = info
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|g| g.as_str()).map(str::to_owned).collect())
            .unwrap_or_default();
        // Never a recipient. This path is a sign-in, and a keyed link is the
        // other thing entirely.
        Ok(Session { user, display, email, groups, guest: None })
    }
}

fn var(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// Percent-encode everything outside the unreserved set.
///
/// Stricter than necessary and never wrong, which is the right trade for a
/// value going into a redirect.
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(*b as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// An opaque random identifier, for session ids and CSRF state.
///
/// Taken from the operating system rather than a seeded generator: a
/// predictable session id is the same defect as no session id.
pub fn random_id() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).ok();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The same lookup, where not being signed in is an ordinary answer.
///
/// Used by routes that behave differently for an anonymous visitor rather than
/// refusing them. Serving an app directory is one: the right response is to
/// send somebody to sign in, not to return 401 to a browser asking for a page.
impl OptionalFromRequestParts<Arc<App>> for Session {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Option<Session>, std::convert::Infallible> {
        if let Some(id) = carried(parts) {
            return Ok(app.store.session(&id).await);
        }
        Ok(None)
    }
}
