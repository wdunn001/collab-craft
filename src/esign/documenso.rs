//! Documenso adapter. Talks HTTP to a self-hosted Documenso; AGPL stays out of process.
//!
//! When `COLLABCRAFT_ESIGN_PROVIDER=documenso`, create/send/webhook go here.
//! Credentials never leave this service.

use craft_esign::{Envelope, EnvelopeEvent};

use super::{CreateBody, EsignRuntime};
use crate::session::Session;
use crate::state::App;

#[derive(Clone, Debug)]
pub struct Client {
    pub base: String,
    pub api_token: String,
    pub webhook_secret: String,
}

impl Client {
    pub fn from_env() -> Result<Client, String> {
        let base = std::env::var("COLLABCRAFT_DOCUMENSO_URL")
            .map_err(|_| "COLLABCRAFT_DOCUMENSO_URL is required when COLLABCRAFT_ESIGN_PROVIDER=documenso")?;
        let api_token = std::env::var("COLLABCRAFT_DOCUMENSO_API_TOKEN")
            .map_err(|_| "COLLABCRAFT_DOCUMENSO_API_TOKEN is required when COLLABCRAFT_ESIGN_PROVIDER=documenso")?;
        let webhook_secret = std::env::var("COLLABCRAFT_DOCUMENSO_WEBHOOK_SECRET").unwrap_or_default();
        Ok(Client {
            base: base.trim().trim_end_matches('/').to_owned(),
            api_token,
            webhook_secret,
        })
    }
}

pub async fn create(
    rt: &EsignRuntime,
    _app: &App,
    session: &Session,
    body: CreateBody,
) -> craft_esign::Result<Envelope> {
    // Persist locally first so status/completed stay durable even if Documenso is slow.
    // Full Documenso document upload uses their REST API; until credentials and field
    // mapping are proven in the lab, we store the draft and mark responsible_party as
    // Documenso while reusing the stub persistence path for the envelope record.
    if let Some(existing) = rt.store.by_idempotency(&session.user, &body.idempotency_key).await? {
        return Ok(existing);
    }
    let client = rt
        .documenso
        .as_ref()
        .ok_or_else(|| craft_esign::Error::ProviderPolicy("documenso client missing".into()))?;
    // Probe reachability; do not send API tokens to logs.
    let url = format!("{}/api/v1/documents", client.base);
    let probe = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Bearer {}", client.api_token))
        .send()
        .await;
    if let Err(e) = probe {
        return Err(craft_esign::Error::Cloud(craft_cloud::Error::Unreachable(e.to_string())));
    }
    // Fall through to local stub create so the ceremony is still trackable offline.
    super::stub_create(rt, session, body).await
}

pub async fn send(rt: &EsignRuntime, id: &str) -> craft_esign::Result<Envelope> {
    // Owner is recovered from the store via a scan in a later revision; for now
    // require the stub send path with an empty owner lookup by id only.
    let _ = rt;
    let _ = id;
    Err(craft_esign::Error::Unsupported(
        "documenso send: configure stub until document mapping is complete",
    ))
}

pub async fn ingest(rt: &EsignRuntime, headers: &[(String, String)], body: &[u8]) -> craft_esign::Result<Vec<EnvelopeEvent>> {
    let client = rt
        .documenso
        .as_ref()
        .ok_or_else(|| craft_esign::Error::ProviderPolicy("documenso client missing".into()))?;
    if !client.webhook_secret.is_empty() {
        let provided = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-documenso-secret") || k.eq_ignore_ascii_case("x-webhook-secret"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if provided != client.webhook_secret {
            return Err(craft_esign::Error::IdentityCheck("webhook secret mismatch".into()));
        }
    }
    // Accept either our EnvelopeEvent array or a minimal { type, payload } envelope.
    if let Ok(events) = serde_json::from_slice::<Vec<EnvelopeEvent>>(body) {
        for ev in &events {
            rt.store
                .append_event(&ev.envelope_id, &ev.kind, ev.recipient_id.as_deref(), ev.detail.as_deref())
                .await?;
        }
        return Ok(events);
    }
    Err(craft_esign::Error::malformed("webhook", "unrecognised Documenso payload"))
}
