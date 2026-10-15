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
use crate::store::ProviderLink;

// ---- browser ---------------------------------------------------------------

pub async fn login(State(app): State<Arc<App>>) -> Response {
    let Some(oidc) = app.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "this deployment has no identity provider configured").into_response();
    };
    // State is stored rather than merely echoed, so a callback carrying one we
    // never issued is rejected. Echoing it back would authenticate nothing.
    let state = random_id();
    app.store.put_pending(&state, "browser").await;
    Redirect::to(&oidc.authorize_url(&state)).into_response()
}

#[derive(Deserialize)]
pub struct Callback {
    pub code: String,
    pub state: String,
}

pub async fn callback(State(app): State<Arc<App>>, Query(q): Query<Callback>) -> Response {
    let Some(oidc) = app.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "no identity provider").into_response();
    };
    let Some(kind) = app.store.take_pending(&q.state).await else {
        return (StatusCode::BAD_REQUEST, "that sign-in request is unknown or has expired").into_response();
    };

    let session = match oidc.exchange(&app.http, &q.code).await {
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

    // A device flow parked its code as the pending kind. Completing it here is
    // what lets the waiting desktop app collect a token.
    if let Some(device) = kind.strip_prefix("device:") {
        app.store.complete_device(device, &id).await;
        return (StatusCode::OK, "Signed in. You can close this tab and go back to the app.").into_response();
    }

    let mut response = Redirect::to("/").into_response();
    // HttpOnly so script cannot read it, SameSite=Lax so it still survives the
    // redirect back from the identity provider.
    if let Ok(value) = HeaderValue::from_str(&format!("{COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax; Secure")) {
        response.headers_mut().insert(header::SET_COOKIE, value);
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
    /// Where to send the user's browser.
    pub verify_url: String,
    /// How long to keep polling, in seconds.
    pub expires_in: u64,
    /// How long to wait between polls, in seconds.
    pub interval: u64,
}

/// Begin a sign-in for a client that cannot be redirected.
pub async fn device_start(State(app): State<Arc<App>>) -> Response {
    let Some(oidc) = app.oidc.as_ref() else {
        return (StatusCode::NOT_IMPLEMENTED, "no identity provider").into_response();
    };
    let device_code = random_id();
    let state = random_id();
    app.store.put_pending(&state, &format!("device:{device_code}")).await;
    app.store.put_device(&device_code).await;

    Json(DeviceStart { device_code, verify_url: oidc.authorize_url(&state), expires_in: 600, interval: 2 }).into_response()
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
        let http = crate::transport::ReqwestHttp::default();
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
        let http = crate::transport::ReqwestHttp::default();
        let f = craft_nextcloud::LoginFlow { login_url: String::new(), endpoint: flow.endpoint, token: flow.token };
        f.poll(&http)
    })
    .await;

    match polled {
        Ok(Ok(Some(app_password))) => {
            let link = ProviderLink { user: app_password.user, password: app_password.password };
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
    if !app.store.put_provider_link(&session.user, &ProviderLink { user, password: q.password }).await {
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
