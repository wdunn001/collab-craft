//! Sign-in routes, and linking a cloud account.
//!
//! A browser is redirected and gets a cookie. A desktop app cannot host a
//! redirect worth trusting, so it starts a flow, sends the user to a browser,
//! and polls until it can collect a bearer token. Both end at the same session
//! record, so everything downstream treats them identically.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};

use crate::session::{COOKIE, Session, random_id};
use crate::state::App;
use crate::store::{Pending, ProviderLink};

/// The cookie that binds a sign-in to the browser that began it.
///
/// Scoped to `/auth`, because the callback is its only reader. Short-lived,
/// because a sign-in that has not finished in ten minutes is abandoned.
const LOGIN_STATE_COOKIE: &str = "collabcraft_login";

// ---- browser ---------------------------------------------------------------

pub async fn login(State(app): State<Arc<App>>) -> Response {
    let Some(oidc) = app.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "this deployment has no identity provider configured").into_response();
    };
    // State is stored rather than merely echoed, so a callback carrying one we
    // never issued is rejected. On its own that only proves the state was ours,
    // not that this browser is the one that asked for it, so the flow also
    // carries a PKCE verifier and a nonce bound to this browser by cookie. The
    // callback checks both.
    let state = random_id();
    let verifier = random_id();
    let browser = random_id();
    let challenge = crate::session::pkce_challenge(&verifier);
    app.store.put_pending(&state, &Pending { verifier, browser: browser.clone() }).await;

    let mut response = Redirect::to(&oidc.authorize_url(&state, &challenge)).into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("{LOGIN_STATE_COOKIE}={browser}; Path=/auth; HttpOnly; SameSite=Lax; Secure; Max-Age=600")) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

#[derive(Deserialize)]
pub struct Callback {
    pub code: String,
    pub state: String,
}

pub async fn callback(State(app): State<Arc<App>>, headers: axum::http::HeaderMap, Query(q): Query<Callback>) -> Response {
    let Some(oidc) = app.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "no identity provider").into_response();
    };
    let Some(pending) = app.store.take_pending(&q.state).await else {
        return (StatusCode::BAD_REQUEST, "that sign-in request is unknown or has expired").into_response();
    };

    // The browser that began this flow carries the nonce. One that does not is
    // not the browser that asked, so a `state` an attacker obtained cannot be
    // spent in a victim's browser to plant the attacker's session there.
    let presented = crate::api::cookie_value(&headers, LOGIN_STATE_COOKIE);
    if pending.browser.is_empty() || presented.as_deref() != Some(pending.browser.as_str()) {
        return (StatusCode::BAD_REQUEST, "that sign-in did not start in this browser").into_response();
    }

    let session = match oidc.exchange(&app.http, &q.code, &pending.verifier).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "the sign-in could not be completed");
            return (StatusCode::BAD_GATEWAY, "the identity provider refused the sign-in").into_response();
        }
    };

    let id = random_id();
    if !app.store.put_session(&id, &session).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, "the session could not be stored").into_response();
    }

    let mut response = Redirect::to("/").into_response();
    // HttpOnly so script cannot read it, SameSite=Lax so it still survives the
    // redirect back from the identity provider.
    if let Ok(value) = HeaderValue::from_str(&format!("{COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax; Secure")) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    // The browser-binding cookie has done its work; clear it.
    if let Ok(value) = HeaderValue::from_str(&format!("{LOGIN_STATE_COOKIE}=; Path=/auth; HttpOnly; Max-Age=0")) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

pub async fn logout(State(app): State<Arc<App>>, session: Session) -> Response {
    // Dropping the record is what ends it. Clearing the cookie alone would
    // leave a usable session for anyone who copied it.
    app.store.drop_sessions_for(&session.user).await;
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("{COOKIE}=; Path=/; HttpOnly; Max-Age=0")) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

// ---- desktop ---------------------------------------------------------------

#[derive(Serialize)]
pub struct DeviceStart {
    /// The app keeps this and polls with it. Not shown to the user.
    pub device_code: String,
    /// Shown to the user by the app. They type it into the confirmation page in
    /// their browser, which is what ties this sign-in to a deliberate human
    /// action rather than to merely opening a link. The app MUST display it.
    pub user_code: String,
    /// Where to send the user's browser: this service's own confirmation page,
    /// not the identity provider directly.
    pub verify_url: String,
    /// How long to keep polling, in seconds.
    pub expires_in: u64,
    /// How long to wait between polls, in seconds.
    pub interval: u64,
}

/// A user code: eight characters from an alphabet with no look-alikes, so a
/// person reading it off one screen and typing it into another does not trip on
/// `0`/`O` or `1`/`I`.
fn user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).ok();
    let mut code = String::with_capacity(9);
    for (i, b) in bytes.iter().enumerate() {
        if i == 4 {
            code.push('-');
        }
        code.push(ALPHABET[(*b as usize) % ALPHABET.len()] as char);
    }
    code
}

/// Begin a sign-in for a client that cannot be redirected.
///
/// The app opens `verify_url` and displays `user_code`. The user signs in at
/// that page and types the code, which is the step that makes a silent redirect
/// no longer enough to complete the flow. Without it, anyone could start a flow,
/// get a victim to open the link, and collect the victim's session.
pub async fn device_start(State(app): State<Arc<App>>) -> Response {
    let Some(oidc) = app.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "no identity provider").into_response();
    };
    let device_code = random_id();
    let code = user_code();
    app.store.put_device(&device_code, &code).await;

    let origin = crate::session::origin_of(&oidc.redirect_uri).unwrap_or_default();
    let verify_url = format!("{origin}/device");
    Json(DeviceStart { device_code, user_code: code, verify_url, expires_in: 600, interval: 2 }).into_response()
}

#[derive(Deserialize)]
pub struct DevicePoll {
    pub device_code: String,
}

#[derive(Serialize)]
pub struct DeviceToken {
    /// Present it as `Authorization: Bearer`.
    pub token: String,
}

/// Collect the session once the user has finished in the browser.
///
/// Answers 428 while still waiting, which is a state rather than a failure, so
/// a client loops on it without treating it as an error.
pub async fn device_poll(State(app): State<Arc<App>>, Json(q): Json<DevicePoll>) -> Response {
    match app.store.take_device(&q.device_code).await {
        Some(Some(session_id)) => Json(DeviceToken { token: session_id }).into_response(),
        Some(None) => (
            StatusCode::PRECONDITION_REQUIRED,
            Json(crate::api::ApiError { code: "authorization_pending", detail: "waiting for the browser".to_owned() }),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, Json(crate::api::ApiError { code: "expired", detail: "that sign-in expired; start another".to_owned() }))
            .into_response(),
    }
}

/// The page a user lands on to approve a desktop sign-in.
///
/// Requires a signed-in browser. An anonymous visitor is sent to sign in first,
/// so by the time the form is submitted this service knows who is approving.
pub async fn device_page(State(app): State<Arc<App>>, session: Option<Session>) -> Response {
    let Some(session) = session else {
        return Redirect::to("/auth/login").into_response();
    };
    axum::response::Html(device_form(&app, &session, None)).into_response()
}

#[derive(Deserialize)]
pub struct DeviceConfirm {
    pub csrf: String,
    pub user_code: String,
}

/// Approve a desktop sign-in by the code the app is showing.
///
/// The session handed to the desktop is a fresh one for the approving user, so
/// the two are separate records that the same sign-out still ends together.
/// CSRF-guarded, because this mints a credential.
pub async fn device_approve(State(app): State<Arc<App>>, session: Session, axum::extract::Form(form): axum::extract::Form<DeviceConfirm>) -> Response {
    if !crate::pages::csrf_ok(&app.secret, &session.user, &form.csrf) {
        return axum::response::Html(device_form(&app, &session, Some("That form went stale. Try again."))).into_response();
    }
    let code = form.user_code.trim().to_ascii_uppercase();
    let Some(device_code) = app.store.device_for_user_code(&code).await else {
        return axum::response::Html(device_form(&app, &session, Some("That code is not valid or has expired."))).into_response();
    };
    let id = random_id();
    if !app.store.put_session(&id, &session).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, "a session could not be created").into_response();
    }
    app.store.complete_device(&device_code, &id).await;
    let body = "<h1>Signed in</h1><p class=\"lede\">You can return to the app. It is finishing the sign-in now.</p>";
    axum::response::Html(crate::pages::layout("Signed in", Some(&session), body)).into_response()
}

/// The approval form, optionally carrying a one-line error.
fn device_form(app: &App, session: &Session, error: Option<&str>) -> String {
    let token = crate::pages::csrf(&app.secret, &session.user);
    let note = error.map(|e| format!("<p class=\"error\">{}</p>", crate::pages::escape(e))).unwrap_or_default();
    let body = format!(
        "<h1>Approve a device sign-in</h1>\
         <p class=\"lede\">Enter the code your app is showing to sign it in as you. \
         Only do this for an app you started yourself.</p>\
         {note}\
         <form method=\"post\" action=\"/device\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input name=\"user_code\" autocomplete=\"off\" autocapitalize=\"characters\" spellcheck=\"false\" placeholder=\"XXXX-XXXX\" required>\
         <button type=\"submit\">Approve</button>\
         </form>",
        csrf = crate::pages::escape(&token),
    );
    crate::pages::layout("Approve a device sign-in", Some(session), &body)
}

// ---- linking a cloud account ----------------------------------------------

#[derive(Serialize)]
pub struct LinkStart {
    /// Open this in a browser. The provider authenticates the user there,
    /// which is why its own login backend works unchanged.
    pub login_url: String,
    /// Hand back to the poll route.
    pub handle: String,
}

/// Begin linking a cloud account.
///
/// Uses the provider's own desktop login flow, so this service never sees the
/// account password and gets a device-scoped credential it can revoke.
pub async fn link_start(State(app): State<Arc<App>>, session: Session) -> Response {
    let Some((config, _)) = app.provider_config().await else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(crate::api::ApiError { code: "provider_not_configured", detail: "this deployment has no cloud provider configured".to_owned() }),
        )
            .into_response();
    };
    if !config.uses_login_flow() {
        // Nothing to open in a browser. The client asks for a login name and
        // an app password and sends them to `link/password`.
        return (
            StatusCode::CONFLICT,
            Json(crate::api::ApiError { code: "password_link", detail: "this provider is linked with a login name and an app password".to_owned() }),
        )
            .into_response();
    }
    let base = config.base;
    let flow = tokio::task::spawn_blocking(move || {
        let http = crate::transport::ReqwestHttp;
        craft_nextcloud::begin(&http, &base)
    })
    .await;

    match flow {
        Ok(Ok(f)) => {
            let handle = random_id();
            app.store.put_link_flow(&handle, &session.user, &f.endpoint, &f.token).await;
            Json(LinkStart { login_url: f.login_url, handle }).into_response()
        }
        Ok(Err(e)) => (StatusCode::BAD_GATEWAY, Json(crate::api::ApiError { code: "provider_unreachable", detail: e.to_string() })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(crate::api::ApiError { code: "panic", detail: e.to_string() })).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LinkPoll {
    pub handle: String,
}

/// Finish linking, once the user has authenticated at the provider.
pub async fn link_poll(State(app): State<Arc<App>>, session: Session, Json(q): Json<LinkPoll>) -> Response {
    let Some(flow) = app.store.link_flow(&q.handle).await else {
        return (StatusCode::NOT_FOUND, Json(crate::api::ApiError { code: "expired", detail: "that link request expired".to_owned() }))
            .into_response();
    };
    if flow.user != session.user {
        // The handle belongs to somebody else. Refused rather than explained,
        // because the only way to hold one is to have been given it.
        return (StatusCode::FORBIDDEN, Json(crate::api::ApiError { code: "forbidden", detail: "that link request is not yours".to_owned() }))
            .into_response();
    }

    let polled = tokio::task::spawn_blocking(move || {
        let http = crate::transport::ReqwestHttp;
        let f = craft_nextcloud::LoginFlow { login_url: String::new(), endpoint: flow.endpoint, token: flow.token };
        f.poll(&http)
    })
    .await;

    match polled {
        Ok(Ok(Some(app_password))) => {
            // Bind the credential to the provider it was issued for, so a later
            // change of the deployment's address cannot re-point it elsewhere.
            let Some((config, _)) = app.provider_config().await else {
                return (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(crate::api::ApiError { code: "provider_not_configured", detail: "this deployment has no cloud provider configured".to_owned() }),
                )
                    .into_response();
            };
            let link = ProviderLink { user: app_password.user, password: app_password.password, base: config.base.clone(), kind: config.kind.clone() };
            if !app.store.put_provider_link(&session.user, &link).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(crate::api::ApiError { code: "store_failed", detail: "the link could not be saved".to_owned() }),
                )
                    .into_response();
            }
            app.store.drop_link_flow(&q.handle).await;
            StatusCode::NO_CONTENT.into_response()
        }
        // Still waiting on the browser. A state, not a failure.
        Ok(Ok(None)) => (
            StatusCode::PRECONDITION_REQUIRED,
            Json(crate::api::ApiError { code: "authorization_pending", detail: "waiting for the browser".to_owned() }),
        )
            .into_response(),
        Ok(Err(e)) => (StatusCode::BAD_GATEWAY, Json(crate::api::ApiError { code: "provider_unreachable", detail: e.to_string() })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(crate::api::ApiError { code: "panic", detail: e.to_string() })).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LinkPassword {
    pub user: String,
    pub password: String,
}

/// Link with a login name and an app password, for a provider with no browser
/// sign-in of its own.
///
/// Checked against the server before anything is stored. A credential the
/// server refuses answers 401 and is forgotten.
pub async fn link_password(State(app): State<Arc<App>>, session: Session, Json(q): Json<LinkPassword>) -> Response {
    let error = |status: StatusCode, code: &'static str, detail: &str| {
        (status, Json(crate::api::ApiError { code, detail: detail.to_owned() })).into_response()
    };
    if session.is_guest() {
        return error(StatusCode::FORBIDDEN, "forbidden", "a shared link carries no account to link");
    }
    let Some((config, _)) = app.provider_config().await else {
        return error(StatusCode::NOT_IMPLEMENTED, "provider_not_configured", "this deployment has no cloud provider configured");
    };
    let user = q.user.trim().to_owned();
    if user.is_empty() || q.password.is_empty() {
        return error(StatusCode::BAD_REQUEST, "invalid", "a login name and a password are both needed");
    }
    match crate::state::verify_link(&config, &user, &q.password).await {
        Ok(()) => {}
        Err(craft_cloud::Error::Unauthenticated) => return error(StatusCode::UNAUTHORIZED, "rejected", "the server did not accept that credential"),
        Err(e) => return error(StatusCode::BAD_GATEWAY, "provider_unreachable", &e.to_string()),
    }
    let link = ProviderLink { user, password: q.password, base: config.base.clone(), kind: config.kind.clone() };
    if !app.store.put_provider_link(&session.user, &link).await {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "store_failed", "the link could not be saved");
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Forget the linked account. The credential is revocable at the provider too,
/// which is the stronger control, but this is the one the user has here.
pub async fn unlink(State(app): State<Arc<App>>, session: Session) -> Response {
    app.store.drop_provider_link(&session.user).await;
    StatusCode::NO_CONTENT.into_response()
}
