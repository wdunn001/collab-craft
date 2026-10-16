//! Durable envelope store on Postgres.
//!
//! Valkey stays for sessions and document keyed links. E-sign audit and
//! completed documents need a store that does not expire underneath them.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use craft_esign::{CompletedDocument, Envelope, EnvelopeStatus};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::keyed::Key;

pub struct EsignStore {
    pool: PgPool,
    secret: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SignerLinkInfo {
    pub envelope_id: String,
    pub recipient_id: String,
    pub email: String,
}

impl EsignStore {
    pub async fn connect(url: &str, secret: &[u8]) -> Result<EsignStore, sqlx::Error> {
        let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
        Ok(EsignStore { pool, secret: secret.to_vec() })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS esign_envelopes (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                envelope_json JSONB NOT NULL,
                document BYTEA NOT NULL,
                completed BYTEA,
                evidence BYTEA,
                UNIQUE (owner, idempotency_key)
            )"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS esign_events (
                id BIGSERIAL PRIMARY KEY,
                envelope_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                recipient_id TEXT,
                detail TEXT,
                at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS esign_signer_links (
                handle TEXT PRIMARY KEY,
                verifier TEXT NOT NULL,
                owner TEXT NOT NULL,
                envelope_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                email TEXT NOT NULL,
                exp BIGINT NOT NULL,
                spent INT NOT NULL DEFAULT 0,
                max_uses INT NOT NULL DEFAULT 1
            )"#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn by_idempotency(&self, owner: &str, key: &str) -> craft_esign::Result<Option<Envelope>> {
        let row: Option<(serde_json::Value,)> = sqlx::query_as("SELECT envelope_json FROM esign_envelopes WHERE owner = $1 AND idempotency_key = $2")
            .bind(owner)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        match row {
            Some((json,)) => Ok(Some(serde_json::from_value(json).map_err(|e| craft_esign::Error::malformed("envelope", e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub async fn insert(&self, owner: &str, idempotency_key: &str, env: &Envelope, document: &[u8]) -> craft_esign::Result<()> {
        let json = serde_json::to_value(env).map_err(|e| craft_esign::Error::malformed("envelope", e.to_string()))?;
        sqlx::query("INSERT INTO esign_envelopes (id, owner, idempotency_key, envelope_json, document) VALUES ($1,$2,$3,$4,$5)")
            .bind(&env.id)
            .bind(owner)
            .bind(idempotency_key)
            .bind(json)
            .bind(document)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    pub async fn get(&self, owner: &str, id: &str) -> craft_esign::Result<Option<Envelope>> {
        let row: Option<(serde_json::Value,)> = sqlx::query_as("SELECT envelope_json FROM esign_envelopes WHERE owner = $1 AND id = $2")
            .bind(owner)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        match row {
            Some((json,)) => Ok(Some(serde_json::from_value(json).map_err(|e| craft_esign::Error::malformed("envelope", e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub async fn update_envelope(&self, owner: &str, env: &Envelope) -> craft_esign::Result<()> {
        let json = serde_json::to_value(env).map_err(|e| craft_esign::Error::malformed("envelope", e.to_string()))?;
        let n = sqlx::query("UPDATE esign_envelopes SET envelope_json = $1 WHERE owner = $2 AND id = $3")
            .bind(json)
            .bind(owner)
            .bind(&env.id)
            .execute(&self.pool)
            .await
            .map_err(db)?
            .rows_affected();
        if n == 0 {
            return Err(craft_esign::Error::invalid("envelope", "not found"));
        }
        Ok(())
    }

    pub async fn document_bytes(&self, owner: &str, id: &str) -> craft_esign::Result<Vec<u8>> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT document FROM esign_envelopes WHERE owner = $1 AND id = $2")
            .bind(owner)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|(b,)| b).ok_or_else(|| craft_esign::Error::invalid("envelope", "not found"))
    }

    pub async fn seal_completed(&self, owner: &str, id: &str, completed: &[u8], evidence: &[u8]) -> craft_esign::Result<()> {
        let n = sqlx::query("UPDATE esign_envelopes SET completed = $1, evidence = $2 WHERE owner = $3 AND id = $4")
            .bind(completed)
            .bind(evidence)
            .bind(owner)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db)?
            .rows_affected();
        if n == 0 {
            return Err(craft_esign::Error::invalid("envelope", "not found"));
        }
        Ok(())
    }

    pub async fn completed(&self, owner: &str, id: &str) -> craft_esign::Result<CompletedDocument> {
        type CompletedRow = (serde_json::Value, Option<Vec<u8>>, Option<Vec<u8>>);
        let row: Option<CompletedRow> = sqlx::query_as("SELECT envelope_json, completed, evidence FROM esign_envelopes WHERE owner = $1 AND id = $2")
            .bind(owner)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        let Some((json, completed, evidence)) = row else {
            return Err(craft_esign::Error::invalid("envelope", "not found"));
        };
        let env: Envelope = serde_json::from_value(json).map_err(|e| craft_esign::Error::malformed("envelope", e.to_string()))?;
        if env.status != EnvelopeStatus::Completed {
            return Err(craft_esign::Error::ProviderPolicy("envelope is not completed".into()));
        }
        Ok(CompletedDocument { envelope_id: id.to_owned(), bytes: completed.unwrap_or_default(), evidence: evidence.unwrap_or_default() })
    }

    pub async fn append_event(&self, envelope_id: &str, kind: &str, recipient_id: Option<&str>, detail: Option<&str>) -> craft_esign::Result<()> {
        sqlx::query("INSERT INTO esign_events (envelope_id, kind, recipient_id, detail) VALUES ($1,$2,$3,$4)")
            .bind(envelope_id)
            .bind(kind)
            .bind(recipient_id)
            .bind(detail)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    pub async fn mint_signer_link(&self, owner: &str, envelope_id: &str, recipient_id: &str, email: &str) -> craft_esign::Result<String> {
        let key = Key::mint();
        let verifier = esign_signer_verifier(&self.secret, &key)?;
        let exp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64 + 7 * 24 * 3600).unwrap_or(0);
        sqlx::query(
            "INSERT INTO esign_signer_links (handle, verifier, owner, envelope_id, recipient_id, email, exp, max_uses)
             VALUES ($1,$2,$3,$4,$5,$6,$7,1)
             ON CONFLICT (handle) DO NOTHING",
        )
        .bind(&key.handle)
        .bind(&verifier)
        .bind(owner)
        .bind(envelope_id)
        .bind(recipient_id)
        .bind(email)
        .bind(exp)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(key.wire())
    }

    pub async fn redeem_signer_link(&self, wire: &str) -> craft_esign::Result<Option<SignerLinkInfo>> {
        let key = Key::parse(wire).map_err(|_| craft_esign::Error::invalid("link", "bad shape"))?;
        type SignerRow = (String, String, String, String, String, i64, i32, i32);
        let row: Option<SignerRow> = sqlx::query_as(
            "SELECT verifier, owner, envelope_id, recipient_id, email, exp, spent, max_uses FROM esign_signer_links WHERE handle = $1",
        )
        .bind(&key.handle)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        let Some((verifier, _owner, envelope_id, recipient_id, email, exp, spent, max_uses)) = row else {
            return Ok(None);
        };
        let expected = esign_signer_verifier(&self.secret, &key)?;
        if expected != verifier {
            return Err(craft_esign::Error::invalid("link", "mismatch"));
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        if now > exp || spent >= max_uses {
            return Ok(None);
        }
        sqlx::query("UPDATE esign_signer_links SET spent = spent + 1 WHERE handle = $1").bind(&key.handle).execute(&self.pool).await.map_err(db)?;
        Ok(Some(SignerLinkInfo { envelope_id, recipient_id, email }))
    }
}

/// HMAC domain separate from document keyed links (`keyed-link:`).
fn esign_signer_verifier(secret: &[u8], key: &Key) -> craft_esign::Result<String> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).map_err(|_| craft_esign::Error::ProviderPolicy("bad secret".into()))?;
    mac.update(format!("esign-signer:{}", key.wire()).as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn db(e: sqlx::Error) -> craft_esign::Error {
    craft_esign::Error::Cloud(craft_cloud::Error::Unreachable(e.to_string()))
}
