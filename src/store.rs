//! Sessions and provider links, on the Valkey the estate already runs.
//!
//! No new datastore. Both kinds of record are small, both expire, and both are
//! wanted by every relay instance, which is exactly what this bus is for.
//!
//! A provider link holds a credential, so it is written with an expiry and
//! read only by this process. It never reaches a client: a client gets answers
//! from the API, never the means to produce them itself.

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

/// How long a signed-in session lasts without being refreshed.
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
/// How long a linked provider credential is kept.
///
/// Long, because relinking means a browser round trip the user did not ask
/// for. An app password is revocable at the provider, which is the real
/// control.
const LINK_TTL_SECS: u64 = 90 * 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderLink {
    /// The account name at the provider, which need not match the CollabCraft
    /// user: somebody may sign in with one identity and link another account.
    pub user: String,
    /// A device-scoped app password, revocable on its own at the provider.
    /// Never the account password.
    pub password: String,
}

/// One storage account a person connected, beyond the single legacy link.
///
/// The legacy link has no id and answers file handles that were issued before
/// connections existed. A connection has an id, and every file handle it
/// issues carries that id so a later call can find this account again.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub account: String,
    pub user: String,
    pub secret: String,
    pub base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contacts: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(default)]
    pub default: bool,
}

#[derive(Clone)]
pub struct Store {
    client: redis::Client,
    prefix: String,
}

impl Store {
    pub fn new(url: &str, prefix: impl Into<String>) -> Result<Store, String> {
        let client = redis::Client::open(url).map_err(|e| e.to_string())?;
        Ok(Store { client, prefix: prefix.into() })
    }

    async fn conn(&self) -> Option<redis::aio::MultiplexedConnection> {
        match self.client.get_multiplexed_async_connection().await {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::error!(error = %e, "the bus is unreachable");
                None
            }
        }
    }

    fn session_key(&self, id: &str) -> String {
        format!("{}:session:{id}", self.prefix)
    }

    fn link_key(&self, user: &str) -> String {
        format!("{}:link:{user}", self.prefix)
    }

    pub async fn put_session(&self, id: &str, session: &crate::session::Session) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        let Ok(body) = serde_json::to_string(session) else { return false };
        if c.set_ex::<_, _, ()>(self.session_key(id), body, SESSION_TTL_SECS).await.is_err() {
            return false;
        }
        // Indexed by user so signing out can end every session this person
        // has, not only the one whose cookie happens to be in hand.
        let index = self.user_sessions_key(&session.user);
        let _ = c.sadd::<_, _, ()>(&index, id).await;
        let _ = c.expire::<_, ()>(&index, SESSION_TTL_SECS as i64).await;
        true
    }

    fn user_sessions_key(&self, user: &str) -> String {
        format!("{}:usersessions:{user}", self.prefix)
    }

    /// End every session this user holds.
    pub async fn drop_sessions_for(&self, user: &str) {
        let Some(mut c) = self.conn().await else { return };
        let index = self.user_sessions_key(user);
        let ids: Vec<String> = c.smembers(&index).await.unwrap_or_default();
        for id in ids {
            let _ = c.del::<_, ()>(self.session_key(&id)).await;
        }
        let _ = c.del::<_, ()>(&index).await;
    }

    pub async fn session(&self, id: &str) -> Option<crate::session::Session> {
        let mut c = self.conn().await?;
        let body: String = c.get(self.session_key(id)).await.ok()?;
        serde_json::from_str(&body).ok()
    }

    pub async fn put_provider_link(&self, user: &str, link: &ProviderLink) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        let Ok(body) = serde_json::to_string(link) else { return false };
        c.set_ex::<_, _, ()>(self.link_key(user), body, LINK_TTL_SECS).await.is_ok()
    }

    pub async fn provider_link(&self, user: &str) -> Option<ProviderLink> {
        let mut c = self.conn().await?;
        let body: String = c.get(self.link_key(user)).await.ok()?;
        serde_json::from_str(&body).ok()
    }

    pub async fn drop_provider_link(&self, user: &str) {
        if let Some(mut c) = self.conn().await {
            let _ = c.del::<_, ()>(self.link_key(user)).await;
        }
    }
}

/// A half-finished attempt to link a cloud account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkFlow {
    /// Who started it. Checked on completion, so a handle cannot be redeemed
    /// by whoever happens to hold it.
    pub user: String,
    pub endpoint: String,
    pub token: String,
    /// Set when this flow should become a connection rather than the legacy link.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub base: String,
    #[serde(default)]
    pub as_connection: bool,
}

/// How long an unfinished sign-in or link attempt is kept.
///
/// Short. These are in-flight state, and one left lying around is a handle
/// somebody else could present.
const PENDING_TTL_SECS: u64 = 10 * 60;

impl Store {
    fn pending_key(&self, state: &str) -> String {
        format!("{}:pending:{state}", self.prefix)
    }

    fn device_key(&self, code: &str) -> String {
        format!("{}:device:{code}", self.prefix)
    }

    fn link_flow_key(&self, handle: &str) -> String {
        format!("{}:linkflow:{handle}", self.prefix)
    }

    /// Remember that we issued this `state`, and what it was for.
    pub async fn put_pending(&self, state: &str, kind: &str) {
        if let Some(mut c) = self.conn().await {
            let _ = c.set_ex::<_, _, ()>(self.pending_key(state), kind, PENDING_TTL_SECS).await;
        }
    }

    /// Consume a `state`. Returns `None` when it was never issued or has
    /// already been used, which is what makes it single-use.
    pub async fn take_pending(&self, state: &str) -> Option<String> {
        let mut c = self.conn().await?;
        let key = self.pending_key(state);
        let kind: Option<String> = c.get(&key).await.ok()?;
        let _ = c.del::<_, ()>(&key).await;
        kind
    }

    /// Park a device sign-in, not yet completed.
    pub async fn put_device(&self, code: &str) {
        if let Some(mut c) = self.conn().await {
            let _ = c.set_ex::<_, _, ()>(self.device_key(code), "", PENDING_TTL_SECS).await;
        }
    }

    /// Attach a session to a device sign-in, once the browser is done.
    pub async fn complete_device(&self, code: &str, session_id: &str) {
        if let Some(mut c) = self.conn().await {
            let _ = c.set_ex::<_, _, ()>(self.device_key(code), session_id, PENDING_TTL_SECS).await;
        }
    }

    /// Poll a device sign-in.
    ///
    /// The nesting is the answer. `None` means the code is unknown or expired,
    /// `Some(None)` means still waiting, `Some(Some(id))` means done. A client
    /// has to tell those apart: one is fatal and one is normal.
    pub async fn take_device(&self, code: &str) -> Option<Option<String>> {
        let mut c = self.conn().await?;
        let key = self.device_key(code);
        let value: Option<String> = c.get(&key).await.ok()?;
        let value = value?;
        if value.is_empty() {
            return Some(None);
        }
        let _ = c.del::<_, ()>(&key).await;
        Some(Some(value))
    }

    pub async fn put_link_flow(&self, handle: &str, user: &str, endpoint: &str, token: &str) {
        let Some(mut c) = self.conn().await else { return };
        let flow = LinkFlow {
            user: user.to_owned(),
            endpoint: endpoint.to_owned(),
            token: token.to_owned(),
            kind: String::new(),
            base: String::new(),
            as_connection: false,
        };
        if let Ok(body) = serde_json::to_string(&flow) {
            let _ = c.set_ex::<_, _, ()>(self.link_flow_key(handle), body, PENDING_TTL_SECS).await;
        }
    }

    pub async fn link_flow(&self, handle: &str) -> Option<LinkFlow> {
        let mut c = self.conn().await?;
        let body: String = c.get(self.link_flow_key(handle)).await.ok()?;
        serde_json::from_str(&body).ok()
    }

    pub async fn drop_link_flow(&self, handle: &str) {
        if let Some(mut c) = self.conn().await {
            let _ = c.del::<_, ()>(self.link_flow_key(handle)).await;
        }
    }

    pub async fn put_link_flow_as(&self, handle: &str, flow: &LinkFlow) {
        let Some(mut c) = self.conn().await else { return };
        if let Ok(body) = serde_json::to_string(flow) {
            let _ = c.set_ex::<_, _, ()>(self.link_flow_key(handle), body, PENDING_TTL_SECS).await;
        }
    }
}

/// The cloud provider this deployment configured for itself.
///
/// The one record here with no expiry, because it is configuration and not
/// state. The bus runs with `appendonly` and `noeviction`, so what is written
/// here survives a restart of either side.
///
/// No credential is involved. An address says where a provider is. The account
/// that acts against it is linked per user, and that record is the one holding
/// a credential.
impl Store {
    fn provider_config_key(&self) -> String {
        format!("{}:config:provider", self.prefix)
    }

    pub async fn provider_config(&self) -> Option<crate::settings::ProviderConfig> {
        let mut c = self.conn().await?;
        let body: String = c.get(self.provider_config_key()).await.ok()?;
        serde_json::from_str(&body).ok()
    }

    pub async fn put_provider_config(&self, config: &crate::settings::ProviderConfig) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        let Ok(body) = serde_json::to_string(config) else { return false };
        c.set::<_, _, ()>(self.provider_config_key(), body).await.is_ok()
    }

    /// Forget the stored provider, which puts the deployment back on whatever
    /// its environment names.
    pub async fn drop_provider_config(&self) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        c.del::<_, ()>(self.provider_config_key()).await.is_ok()
    }

    fn offers_key(&self) -> String {
        format!("{}:config:offers", self.prefix)
    }

    pub async fn offers(&self) -> Vec<crate::settings::Offer> {
        let Some(mut c) = self.conn().await else { return Vec::new() };
        let Ok(body) = c.get::<_, String>(self.offers_key()).await else { return Vec::new() };
        serde_json::from_str(&body).unwrap_or_default()
    }

    /// Remember one allowed kind without dropping the others.
    pub async fn upsert_offer(&self, offer: &crate::settings::Offer) -> bool {
        let mut offers = self.offers().await;
        if let Some(existing) = offers.iter_mut().find(|o| o.kind == offer.kind && o.base == offer.base) {
            *existing = offer.clone();
        } else {
            offers.push(offer.clone());
        }
        let Some(mut c) = self.conn().await else { return false };
        let Ok(body) = serde_json::to_string(&offers) else { return false };
        c.set::<_, _, ()>(self.offers_key(), body).await.is_ok()
    }

    fn google_secret_key(&self) -> String {
        format!("{}:config:google_secret", self.prefix)
    }

    /// The OAuth client secret, if an administrator typed one.
    ///
    /// Absent when the deployment uses `COLLABCRAFT_GOOGLE_CLIENT_SECRET` instead.
    pub async fn google_secret(&self) -> Option<String> {
        if let Some(from_env) = std::env::var("COLLABCRAFT_GOOGLE_CLIENT_SECRET").ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) {
            return Some(from_env);
        }
        let mut c = self.conn().await?;
        c.get(self.google_secret_key()).await.ok()
    }

    pub async fn put_google_secret(&self, secret: &str) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        c.set::<_, _, ()>(self.google_secret_key(), secret).await.is_ok()
    }

    fn connections_key(&self, user: &str) -> String {
        format!("{}:connections:{user}", self.prefix)
    }

    pub async fn connections(&self, user: &str) -> Vec<Connection> {
        let Some(mut c) = self.conn().await else { return Vec::new() };
        let Ok(body) = c.get::<_, String>(self.connections_key(user)).await else { return Vec::new() };
        serde_json::from_str(&body).unwrap_or_default()
    }

    async fn write_connections(&self, user: &str, connections: &[Connection]) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        let Ok(body) = serde_json::to_string(connections) else { return false };
        c.set_ex::<_, _, ()>(self.connections_key(user), body, LINK_TTL_SECS).await.is_ok()
    }

    pub async fn put_connection(&self, user: &str, connection: Connection) -> bool {
        let mut connections = self.connections(user).await;
        if connection.default {
            for other in &mut connections {
                other.default = false;
            }
        }
        if let Some(existing) = connections.iter_mut().find(|c| c.id == connection.id) {
            *existing = connection;
        } else {
            connections.push(connection);
        }
        self.write_connections(user, &connections).await
    }

    pub async fn drop_connection(&self, user: &str, id: &str) -> bool {
        let mut connections = self.connections(user).await;
        let before = connections.len();
        connections.retain(|c| c.id != id);
        if connections.len() == before {
            return true;
        }
        self.write_connections(user, &connections).await
    }

    pub async fn default_connection(&self, user: &str, id: &str) -> bool {
        let mut connections = self.connections(user).await;
        if !connections.iter().any(|c| c.id == id) {
            return false;
        }
        for connection in &mut connections {
            connection.default = connection.id == id;
        }
        self.write_connections(user, &connections).await
    }

    fn entitlements_key(&self) -> String {
        format!("{}:config:apps", self.prefix)
    }

    /// Who may open which app, where a deployment has said so on the setup
    /// page. Absent until somebody does, which leaves the environment in
    /// charge.
    pub async fn entitlements(&self) -> Option<crate::state::Permissions> {
        let mut c = self.conn().await?;
        let body: String = c.get(self.entitlements_key()).await.ok()?;
        serde_json::from_str(&body).ok()
    }

    pub async fn put_entitlements(&self, apps: &crate::state::Permissions) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        let Ok(body) = serde_json::to_string(apps) else { return false };
        c.set::<_, _, ()>(self.entitlements_key(), body).await.is_ok()
    }

    /// Forget them, which puts entitlement back on the environment.
    pub async fn drop_entitlements(&self) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        c.del::<_, ()>(self.entitlements_key()).await.is_ok()
    }
}

/// Keyed links, for a recipient with no account.
///
/// Three keys per link, each with the same expiry. The record is written once
/// and never rewritten, the use counter is its own integer so `INCR` can
/// settle a race without a script, and an index under the provider's share id
/// is what lets withdrawing a share withdraw every key minted from it.
///
/// No key material is stored. What the record holds is an HMAC over it, so a
/// copy of this keyspace opens no document.
impl Store {
    fn keyed_key(&self, handle: &str) -> String {
        format!("{}:keyed:{handle}", self.prefix)
    }

    fn keyed_uses_key(&self, handle: &str) -> String {
        format!("{}:keyed:{handle}:uses", self.prefix)
    }

    fn keyed_share_key(&self, share: &str) -> String {
        format!("{}:keyedshare:{share}", self.prefix)
    }

    /// Record a freshly minted link.
    pub async fn put_keyed_link(&self, handle: &str, link: &crate::keyed::Link, ttl_secs: u64) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        let Ok(body) = serde_json::to_string(link) else { return false };
        if c.set_ex::<_, _, ()>(self.keyed_key(handle), body, ttl_secs).await.is_err() {
            return false;
        }
        // Indexed by the provider's share, so withdrawing that withdraws this
        // without having to search the keyspace for it.
        let index = self.keyed_share_key(&link.share);
        let _ = c.sadd::<_, _, ()>(&index, handle).await;
        let _ = c.expire::<_, ()>(&index, ttl_secs as i64).await;
        true
    }

    pub async fn keyed_link(&self, handle: &str) -> Option<crate::keyed::Link> {
        let mut c = self.conn().await?;
        let body: String = c.get(self.keyed_key(handle)).await.ok()?;
        serde_json::from_str(&body).ok()
    }

    /// Every keyed link minted from one provider share.
    pub async fn keyed_links_for_share(&self, share: &str) -> Vec<crate::keyed::Link> {
        let Some(mut c) = self.conn().await else { return Vec::new() };
        let handles: Vec<String> = c.smembers(self.keyed_share_key(share)).await.unwrap_or_default();
        let mut links = Vec::new();
        for handle in handles {
            if let Some(link) = self.keyed_link(&handle).await {
                links.push(link);
            }
        }
        links
    }

    /// How many times a key has been spent.
    ///
    /// An absent counter means none, which is also what a fresh link looks
    /// like, so the two need not be told apart. A bus this cannot reach
    /// answers with the ceiling instead, so an outage refuses keys rather than
    /// admitting every one of them.
    pub async fn keyed_uses(&self, handle: &str) -> u32 {
        let Some(mut c) = self.conn().await else { return u32::MAX };
        c.get::<_, Option<u32>>(self.keyed_uses_key(handle)).await.ok().flatten().unwrap_or(0)
    }

    /// Spend one use. Returns whether this caller got one.
    ///
    /// `INCR` then compare, which is what makes it safe with more than one
    /// instance: two recipients racing for the last use of a key get
    /// different numbers and only one of them is inside the ceiling. A read
    /// followed by a write would hand that use to both.
    pub async fn spend_keyed_link(&self, handle: &str, max_uses: u32, ttl_secs: u64) -> bool {
        let Some(mut c) = self.conn().await else { return false };
        let key = self.keyed_uses_key(handle);
        let Ok(count) = c.incr::<_, _, i64>(&key, 1i64).await else { return false };
        // Expiry on every spend, so the counter never outlives the record it
        // counts for and a key cannot come back to life as unused.
        let _ = c.expire::<_, ()>(&key, ttl_secs as i64).await;
        count > 0 && count <= i64::from(max_uses)
    }

    /// Withdraw every key minted from one share.
    ///
    /// Called when the share itself is withdrawn. The record is what every
    /// recipient route re-reads, so deleting it ends the sessions it created
    /// as well as the links, and those sessions are dropped here too rather
    /// than left to expire.
    pub async fn drop_keyed_links_for_share(&self, share: &str) -> usize {
        let Some(mut c) = self.conn().await else { return 0 };
        let index = self.keyed_share_key(share);
        let handles: Vec<String> = c.smembers(&index).await.unwrap_or_default();
        for handle in &handles {
            let _ = c.del::<_, ()>(self.keyed_key(handle)).await;
            let _ = c.del::<_, ()>(self.keyed_uses_key(handle)).await;
        }
        let _ = c.del::<_, ()>(&index).await;
        for handle in &handles {
            self.drop_sessions_for(&crate::session::Guest::user_id(handle)).await;
        }
        handles.len()
    }
}
