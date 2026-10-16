//! E-sign envelopes: create, send, status, completed.
//!
//! CollabCraft is the only place credentials and audit live. PdfCraft talks
//! these routes through craft-esign; it never names a vendor. The stub
//! provider finishes ceremonies without an external service so the vertical
//! slice can be proven before Documenso is wired.

mod documenso;
mod store;

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use craft_esign::{Envelope, EnvelopeDraft, EnvelopeEvent, EnvelopeStatus, EsignCapability, RecipientStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::ApiError;
use crate::session::Session;
use crate::state::App;

pub use store::EsignStore;

/// How envelopes are fulfilled in this deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderKind {
    Stub,
    Documenso,
}

impl ProviderKind {
    pub fn from_env() -> ProviderKind {
        match std::env::var("COLLABCRAFT_ESIGN_PROVIDER").unwrap_or_else(|_| "stub".into()).trim().to_ascii_lowercase().as_str() {
            "documenso" => ProviderKind::Documenso,
            _ => ProviderKind::Stub,
        }
    }
}

/// Runtime half of e-sign: durable store plus which provider answers.
pub struct EsignRuntime {
    pub store: EsignStore,
    pub kind: ProviderKind,
    pub documenso: Option<documenso::Client>,
}

impl EsignRuntime {
    pub async fn from_env(secret: &[u8]) -> Result<Option<EsignRuntime>, String> {
        let url = match std::env::var("COLLABCRAFT_ESIGN_DATABASE_URL") {
            Ok(u) if !u.trim().is_empty() => u,
            _ => {
                tracing::info!("COLLABCRAFT_ESIGN_DATABASE_URL unset: e-sign routes are disabled");
                return Ok(None);
            }
        };
        let store = EsignStore::connect(&url, secret).await.map_err(|e| e.to_string())?;
        store.migrate().await.map_err(|e| e.to_string())?;
        let kind = ProviderKind::from_env();
        let documenso = match kind {
            ProviderKind::Documenso => Some(documenso::Client::from_env()?),
            ProviderKind::Stub => None,
        };
        tracing::info!(?kind, "e-sign envelope store ready");
        Ok(Some(EsignRuntime { store, kind, documenso }))
    }

    fn capabilities(&self) -> Vec<EsignCapability> {
        match self.kind {
            ProviderKind::Stub => vec![EsignCapability::Envelopes, EsignCapability::Void, EsignCapability::Reminders, EsignCapability::Webhooks],
            ProviderKind::Documenso => vec![
                EsignCapability::Envelopes,
                EsignCapability::Void,
                EsignCapability::Reminders,
                EsignCapability::EmbeddedSigning,
                EsignCapability::Webhooks,
            ],
        }
    }

    fn responsible_party(&self) -> String {
        match self.kind {
            ProviderKind::Stub => "CollabCraft stub signing (not legally binding)".into(),
            ProviderKind::Documenso => "Documenso".into(),
        }
    }
}

#[derive(Serialize)]
struct CapsBody {
    capabilities: Vec<EsignCapability>,
    responsible_party: String,
    linked: bool,
    provider: String,
}

fn esign_fail(e: craft_esign::Error) -> Response {
    use craft_esign::Error as E;
    match e {
        E::Cloud(c) => crate::api::fail(c),
        other => {
            let (status, code) = match &other {
                E::Declined(_) => (StatusCode::CONFLICT, "declined"),
                E::Voided(_) => (StatusCode::CONFLICT, "voided"),
                E::Expired(_) => (StatusCode::GONE, "expired"),
                E::IdentityCheck(_) => (StatusCode::FORBIDDEN, "identity_check"),
                E::ProviderPolicy(_) => (StatusCode::FORBIDDEN, "provider_policy"),
                E::Unsupported(_) => (StatusCode::NOT_IMPLEMENTED, "unsupported"),
                E::Malformed { .. } => (StatusCode::BAD_GATEWAY, "malformed"),
                E::Invalid { .. } | E::Cloud(_) => (StatusCode::BAD_REQUEST, "invalid"),
            };
            (status, Json(ApiError { code, detail: other.to_string() })).into_response()
        }
    }
}

fn runtime(app: &App) -> Option<&EsignRuntime> {
    app.esign.as_ref()
}

fn esign_unconfigured() -> Response {
    (StatusCode::NOT_IMPLEMENTED, Json(ApiError { code: "unsupported", detail: "e-sign is not configured on this deployment".into() }))
        .into_response()
}

pub async fn capabilities(State(app): State<Arc<App>>, session: Session) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    let linked = app.provider_for(&session).await.is_some();
    Json(CapsBody {
        capabilities: rt.capabilities(),
        responsible_party: rt.responsible_party(),
        linked,
        provider: match rt.kind {
            ProviderKind::Stub => "stub".into(),
            ProviderKind::Documenso => "documenso".into(),
        },
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct CreateBody {
    pub draft: EnvelopeDraft,
    pub document: Vec<u8>,
    pub idempotency_key: String,
    #[serde(default)]
    pub send: bool,
}

pub async fn create(State(app): State<Arc<App>>, session: Session, Json(body): Json<CreateBody>) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    if session.is_guest() {
        return (StatusCode::FORBIDDEN, Json(ApiError { code: "forbidden", detail: "guests cannot create envelopes".into() })).into_response();
    }
    match rt.kind {
        ProviderKind::Stub => match stub_create(rt, &session, body).await {
            Ok(env) => Json(env).into_response(),
            Err(e) => esign_fail(e),
        },
        ProviderKind::Documenso => match documenso::create(rt, &app, &session, body).await {
            Ok(env) => Json(env).into_response(),
            Err(e) => esign_fail(e),
        },
    }
}

pub(crate) async fn stub_create(rt: &EsignRuntime, session: &Session, body: CreateBody) -> craft_esign::Result<Envelope> {
    if let Some(existing) = rt.store.by_idempotency(&session.user, &body.idempotency_key).await? {
        return Ok(existing);
    }
    let hash = hex_sha256(&body.document);
    let mut draft = body.draft;
    draft.sender.id = session.user.clone();
    let mut env = Envelope {
        id: new_id(),
        title: draft.title.clone(),
        message: draft.message.clone(),
        sender: draft.sender.clone(),
        document_id: draft.document_id.clone(),
        document_etag: draft.document_etag.clone(),
        content_sha256: hash,
        recipients: draft.recipients.clone(),
        placements: draft.placements.clone(),
        status: EnvelopeStatus::Draft,
        expires: draft.expires.clone(),
        created: Some(now_rfc3339()),
        completed_at: None,
    };
    rt.store.insert(&session.user, &body.idempotency_key, &env, &body.document).await?;
    if body.send {
        env = stub_send(rt, &session.user, &env.id).await?;
    }
    Ok(env)
}

pub async fn send(State(app): State<Arc<App>>, session: Session, Path(id): Path<String>) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    match rt.kind {
        ProviderKind::Stub => match stub_send(rt, &session.user, &id).await {
            Ok(env) => Json(env).into_response(),
            Err(e) => esign_fail(e),
        },
        ProviderKind::Documenso => match documenso::send(rt, &id).await {
            Ok(env) => Json(env).into_response(),
            Err(e) => esign_fail(e),
        },
    }
}

async fn stub_send(rt: &EsignRuntime, owner: &str, id: &str) -> craft_esign::Result<Envelope> {
    let mut env = rt.store.get(owner, id).await?.ok_or_else(|| craft_esign::Error::invalid("envelope", "not found"))?;
    if env.status != EnvelopeStatus::Draft && env.status != EnvelopeStatus::Sent {
        return Err(craft_esign::Error::ProviderPolicy(format!("cannot send from {:?}", env.status)));
    }
    env.status = EnvelopeStatus::Sent;
    rt.store.update_envelope(owner, &env).await?;
    for recipient in &env.recipients {
        let _ = rt.store.mint_signer_link(owner, id, &recipient.id, &recipient.email).await?;
    }
    rt.store.append_event(id, "sent", None, None).await?;
    Ok(env)
}

pub async fn status(State(app): State<Arc<App>>, session: Session, Path(id): Path<String>) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    match rt.store.get(&session.user, &id).await {
        Ok(Some(env)) => Json(env).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(ApiError { code: "not_found", detail: "envelope not found".into() })).into_response(),
        Err(e) => esign_fail(e),
    }
}

pub async fn completed(State(app): State<Arc<App>>, session: Session, Path(id): Path<String>) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    match rt.store.completed(&session.user, &id).await {
        Ok(doc) => Json(doc).into_response(),
        Err(e) => esign_fail(e),
    }
}

#[derive(Deserialize)]
pub struct VoidBody {
    pub reason: String,
}

pub async fn void(State(app): State<Arc<App>>, session: Session, Path(id): Path<String>, Json(body): Json<VoidBody>) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    match stub_void(rt, &session.user, &id, &body.reason).await {
        Ok(()) => Json(serde_json::json!({ "envelope": id })).into_response(),
        Err(e) => esign_fail(e),
    }
}

async fn stub_void(rt: &EsignRuntime, owner: &str, id: &str, reason: &str) -> craft_esign::Result<()> {
    let mut env = rt.store.get(owner, id).await?.ok_or_else(|| craft_esign::Error::invalid("envelope", "not found"))?;
    if env.status != EnvelopeStatus::Sent {
        return Err(craft_esign::Error::ProviderPolicy("only a sent envelope can be voided".into()));
    }
    env.status = EnvelopeStatus::Voided;
    rt.store.update_envelope(owner, &env).await?;
    rt.store.append_event(id, "voided", None, Some(reason)).await?;
    Ok(())
}

pub async fn remind(State(app): State<Arc<App>>, session: Session, Path((id, recipient)): Path<(String, String)>) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    let env = match rt.store.get(&session.user, &id).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(ApiError { code: "not_found", detail: "envelope not found".into() })).into_response();
        }
        Err(e) => return esign_fail(e),
    };
    if !env.recipients.iter().any(|r| r.id == recipient) {
        return (StatusCode::NOT_FOUND, Json(ApiError { code: "not_found", detail: "recipient not found".into() })).into_response();
    }
    if let Err(e) = rt.store.append_event(&id, "reminded", Some(&recipient), None).await {
        return esign_fail(e);
    }
    Json(serde_json::json!({ "envelope": id, "recipient": recipient })).into_response()
}

/// Stub-only: mark one recipient signed. When every required recipient has
/// signed, seal the envelope with the original document bytes.
pub async fn stub_sign(State(app): State<Arc<App>>, session: Session, Path((id, recipient)): Path<(String, String)>) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    if rt.kind != ProviderKind::Stub {
        return (StatusCode::NOT_FOUND, Json(ApiError { code: "not_found", detail: "stub sign is only on the stub provider".into() }))
            .into_response();
    }
    match stub_mark_signed(rt, &session.user, &id, &recipient).await {
        Ok(env) => Json(env).into_response(),
        Err(e) => esign_fail(e),
    }
}

async fn stub_mark_signed(rt: &EsignRuntime, owner: &str, id: &str, recipient: &str) -> craft_esign::Result<Envelope> {
    let mut env = rt.store.get(owner, id).await?.ok_or_else(|| craft_esign::Error::invalid("envelope", "not found"))?;
    if env.status != EnvelopeStatus::Sent {
        return Err(craft_esign::Error::ProviderPolicy("envelope is not awaiting signatures".into()));
    }
    let Some(r) = env.recipients.iter_mut().find(|r| r.id == recipient) else {
        return Err(craft_esign::Error::invalid("recipient", "not found"));
    };
    r.status = RecipientStatus::Signed;
    rt.store.append_event(id, "signed", Some(recipient), None).await?;
    let done = env.recipients.iter().filter(|r| r.required).all(|r| r.status == RecipientStatus::Signed);
    if done {
        env.status = EnvelopeStatus::Completed;
        env.completed_at = Some(now_rfc3339());
        let bytes = rt.store.document_bytes(owner, id).await?;
        rt.store.seal_completed(owner, id, &bytes, b"stub-evidence").await?;
        rt.store.append_event(id, "completed", None, None).await?;
    }
    rt.store.update_envelope(owner, &env).await?;
    Ok(env)
}

/// Documenso (or stub test) webhook intake.
pub async fn webhook(State(app): State<Arc<App>>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    let hdrs: Vec<(String, String)> = headers.iter().filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned()))).collect();
    match rt.kind {
        ProviderKind::Stub => {
            // Stub accepts a JSON array of EnvelopeEvent for tests.
            match serde_json::from_slice::<Vec<EnvelopeEvent>>(&body) {
                Ok(events) => {
                    for ev in &events {
                        let _ = rt.store.append_event(&ev.envelope_id, &ev.kind, ev.recipient_id.as_deref(), ev.detail.as_deref()).await;
                    }
                    Json(events).into_response()
                }
                Err(e) => (StatusCode::BAD_REQUEST, Json(ApiError { code: "invalid", detail: e.to_string() })).into_response(),
            }
        }
        ProviderKind::Documenso => match documenso::ingest(rt, &hdrs, &body).await {
            Ok(events) => Json(events).into_response(),
            Err(e) => esign_fail(e),
        },
    }
}

/// Landing page for an esign_signer keyed link (parallel to document invite).
pub async fn land_signer(State(app): State<Arc<App>>, Path(key): Path<String>) -> Response {
    let Some(rt) = runtime(&app) else {
        return esign_unconfigured();
    };
    match rt.store.redeem_signer_link(&key).await {
        Ok(Some(info)) => Json(serde_json::json!({
            "grant": "esign_signer",
            "envelope": info.envelope_id,
            "recipient": info.recipient_id,
            "email": info.email,
        }))
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(ApiError { code: "not_found", detail: "this link no longer works".into() })).into_response(),
        Err(e) => esign_fail(e),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn new_id() -> String {
    let mut raw = [0u8; 16];
    let _ = getrandom::fill(&mut raw);
    format!("env_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

fn now_rfc3339() -> String {
    // Keep the service free of a chrono dependency: unix seconds as a stable stamp.
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{secs}")
}

/// Router nest under `/api/v1/esign`.
pub fn router() -> axum::Router<Arc<App>> {
    axum::Router::new()
        .route("/capabilities", axum::routing::get(capabilities))
        .route("/envelopes", axum::routing::post(create))
        .route("/envelopes/{id}/send", axum::routing::post(send))
        .route("/envelopes/{id}", axum::routing::get(status))
        .route("/envelopes/{id}/completed", axum::routing::get(completed))
        .route("/envelopes/{id}/void", axum::routing::post(void))
        .route("/envelopes/{id}/remind/{recipient}", axum::routing::post(remind))
        .route("/envelopes/{id}/stub/sign/{recipient}", axum::routing::post(stub_sign))
        .route("/webhook", axum::routing::post(webhook))
}
