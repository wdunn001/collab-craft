//! What the service holds, and how it reaches a provider for one user.

use std::collections::BTreeMap;
use std::sync::Arc;

use craft_cloud::{Permission, Provider};
use craft_nextcloud::{Account, Nextcloud};
use craft_webdav::WebDav;

use crate::session::Session;
use crate::transport::ReqwestHttp;

/// Which Craft apps a user may open.
///
/// Decided here rather than by the provider, because this is CollabCraft's own
/// question. A user with a perfectly good cloud account may still not be
/// entitled to run every app.
///
/// Configuration is a map of group name to app list, plus a default applied to
/// everyone who signs in. Groups arrive from the identity provider, so adding
/// somebody to a group in Authentik is the whole of granting access.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Permissions {
    default: Vec<String>,
    by_group: BTreeMap<String, Vec<String>>,
}

impl Permissions {
    /// Read from `COLLABCRAFT_APPS_DEFAULT` and `COLLABCRAFT_APPS_<GROUP>`.
    ///
    /// Nothing is compiled in, so a deployment decides its own catalogue and
    /// its own entitlements without a rebuild.
    pub fn from_env() -> Permissions {
        let default = std::env::var("COLLABCRAFT_APPS_DEFAULT").unwrap_or_default();
        let mut groups: Vec<(String, String)> = Vec::new();
        for (key, value) in std::env::vars() {
            if let Some(group) = key.strip_prefix("COLLABCRAFT_APPS_")
                && group != "DEFAULT"
            {
                groups.push((group.to_owned(), value));
            }
        }
        let named: Vec<(&str, &str)> = groups.iter().map(|(group, apps)| (group.as_str(), apps.as_str())).collect();
        Permissions::decide(&default, &named)
    }

    /// The same decision over values.
    ///
    /// Separated so entitlement is testable. Reading the environment inside a
    /// test would race every other test in the binary.
    pub fn decide(default: &str, by_group: &[(&str, &str)]) -> Permissions {
        Permissions { default: split(default), by_group: by_group.iter().map(|(group, apps)| (group.to_ascii_lowercase(), split(apps))).collect() }
    }

    /// Every app this session may open, deduplicated and sorted.
    ///
    /// A recipient holding a keyed link gets the one app that opens the one
    /// document they were sent, and nothing else. Deciding that here rather
    /// than at each route is what makes it true everywhere at once: every
    /// entitlement question in the service comes through this method.
    pub fn apps_for_session(&self, session: &Session) -> Vec<String> {
        if let Some(guest) = &session.guest {
            return vec![guest.app.clone()];
        }
        let mut out = self.default.clone();
        for group in &session.groups {
            if let Some(extra) = self.by_group.get(&group.to_ascii_lowercase()) {
                out.extend(extra.iter().cloned());
            }
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn may_open(&self, session: &Session, app: &str) -> bool {
        self.apps_for_session(session).iter().any(|a| a == app)
    }

    /// What everyone who signs in may open.
    pub fn default_apps(&self) -> &[String] {
        &self.default
    }

    /// What each named group adds on top, by group name in lower case.
    pub fn group_apps(&self) -> &BTreeMap<String, Vec<String>> {
        &self.by_group
    }

    /// Build one from values a person typed on the setup page.
    ///
    /// The group half arrives as one line per group, `group: app, app`. A
    /// repeating pair of fields would need script to add a row, and this page
    /// works without any.
    pub fn parse(default: &str, groups: &str) -> Permissions {
        let mut by_group = BTreeMap::new();
        for line in groups.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (group, apps) = line.split_once(':').unwrap_or((line, ""));
            let group = group.trim().to_ascii_lowercase();
            if group.is_empty() {
                continue;
            }
            by_group.insert(group, split(apps));
        }
        Permissions { default: split(default), by_group }
    }

    /// The group half, as the setup page's textarea wants it back.
    pub fn groups_text(&self) -> String {
        self.by_group.iter().map(|(group, apps)| format!("{group}: {}\n", apps.join(", "))).collect()
    }

    /// Build one from the checkbox page.
    ///
    /// `default` is the hosted apps checked for everybody. `names` is one
    /// group name per block, in order. `grants` is `index:app` for each box
    /// checked inside a block. An empty group name is a block still being
    /// filled in, and grants nothing.
    pub fn from_checks(default: &[String], names: &[String], grants: &[String]) -> Permissions {
        let mut by_group: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for name in names {
            let group = name.trim().to_ascii_lowercase();
            if !group.is_empty() {
                by_group.entry(group).or_default();
            }
        }
        for grant in grants {
            let Some((index, app)) = grant.split_once(':') else { continue };
            let Ok(index) = index.parse::<usize>() else { continue };
            let Some(name) = names.get(index) else { continue };
            let group = name.trim().to_ascii_lowercase();
            let app = app.trim();
            if group.is_empty() || app.is_empty() {
                continue;
            }
            by_group.entry(group).or_default().push(app.to_owned());
        }
        for apps in by_group.values_mut() {
            apps.sort();
            apps.dedup();
        }
        let mut default: Vec<String> = default.iter().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
        default.sort();
        default.dedup();
        Permissions { default, by_group }
    }

    /// Keep grants for applications this deployment does not host.
    ///
    /// Those apps are not on the checkbox page, so a save of the boxes would
    /// otherwise drop them. They stay granted until the application is hosted
    /// and somebody unchecks it, or until the stored entitlement is cleared.
    pub fn keep_absent(&mut self, previous: &Permissions, hosted: &[String]) {
        let present = |name: &str| hosted.iter().any(|hosted| hosted.eq_ignore_ascii_case(name));
        for name in &previous.default {
            if !present(name) && !self.default.iter().any(|have| have == name) {
                self.default.push(name.clone());
            }
        }
        self.default.sort();
        self.default.dedup();
        for (group, apps) in &previous.by_group {
            for app in apps {
                if present(app) {
                    continue;
                }
                let slot = self.by_group.entry(group.clone()).or_default();
                if !slot.iter().any(|have| have == app) {
                    slot.push(app.clone());
                }
            }
        }
        for apps in self.by_group.values_mut() {
            apps.sort();
            apps.dedup();
        }
    }
}

fn split(raw: &str) -> Vec<String> {
    raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

/// What this deployment can do, as against what the provider can do.
///
/// Reported for the same reason the provider's list is reported: a dialog
/// hides what it cannot deliver rather than offering a button that fails. The
/// provider's list answers "can this server share at all", and this one
/// answers "will this service do the parts it does itself".
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCapability {
    /// A share aimed at an address with no account produces a link carrying a
    /// one-time key. Absent where an organisation forbids them.
    KeyedLinks,
}

/// Everything the service needs at runtime.
pub struct App {
    /// Signs relay tokens. Shared with the relay and with nothing else.
    pub secret: Vec<u8>,
    /// Handed to clients so the relay can move without reissuing apps.
    pub relay_url: String,
    /// Which provider this deployment uses, and who may change that.
    ///
    /// One per deployment for now. The shape allows more than one later,
    /// because nothing above here names a provider.
    pub settings: crate::settings::Settings,
    pub permissions: Permissions,
    /// Session and link storage, on the Valkey the rest of the estate uses.
    pub store: crate::store::Store,
    /// Absent when this deployment runs without sign-in, which is a local
    /// convenience and never right in a deployment.
    pub oidc: Option<crate::session::Oidc>,
    /// Shared client for talking to the identity provider. One, because each
    /// new one costs a connection pool.
    pub http: reqwest::Client,
    /// Serves the browser builds, behind the per-app permission check.
    pub web: tower_http::services::ServeDir,
    /// Directory names under the web root, which are the apps this deployment
    /// actually hosts. Read once at startup rather than from disk per request.
    pub hosted: Vec<String>,
    /// Whether this deployment mints keyed links, and on what terms.
    pub keyed: crate::keyed::Policy,
    /// Durable e-sign envelopes. Absent when `COLLABCRAFT_ESIGN_DATABASE_URL` is unset.
    pub esign: Option<crate::esign::EsignRuntime>,
}

impl App {
    /// Whether a path segment names an app this deployment hosts.
    pub fn is_app(&self, name: &str) -> bool {
        !name.is_empty() && self.hosted.iter().any(|a| a == name)
    }

    /// Every app this session may actually open here.
    ///
    /// Entitlement crossed with what this deployment hosts. Both halves are
    /// needed: an entitlement to an app nobody deployed opens nothing, and a
    /// hosted app nobody is entitled to is a 403. The launcher draws from
    /// this, so a card that cannot work never appears.
    ///
    /// Takes the entitlement it should use. A caller that read it once for the
    /// request passes the same value everywhere on the page, and a page asking
    /// twice cannot answer itself differently halfway down.
    pub fn launchable(&self, entitled: &Permissions, session: &Session) -> Vec<String> {
        entitled.apps_for_session(session).into_iter().filter(|name| self.is_app(name)).collect()
    }

    /// Which provider this deployment uses, and where that came from.
    ///
    /// A value stored on the bus overrides the environment. Read per call
    /// rather than cached, because more than one instance may serve one
    /// deployment and a cache in each would disagree with the others after a
    /// change. A session is already read from the same bus on every request.
    pub async fn provider_config(&self) -> Option<(crate::settings::ProviderConfig, crate::settings::Source)> {
        self.settings.resolve(self.store.provider_config().await)
    }

    /// Who may open which app, and where that answer came from.
    ///
    /// The environment is the default and the setup page can override it. The
    /// same arrangement as the provider address, for the same reason. An
    /// administrator granting an app to a group should not need a redeploy,
    /// and a deployment that never visits the page keeps behaving exactly as
    /// its environment says.
    ///
    /// Read per request rather than cached. Entitlement decides what a person
    /// may open, so a change has to take effect for everybody at once.
    pub async fn entitlements(&self) -> (Permissions, crate::settings::Source) {
        match self.store.entitlements().await {
            Some(stored) => (stored, crate::settings::Source::Stored),
            None => (self.permissions.clone(), crate::settings::Source::Environment),
        }
    }

    /// What this deployment itself offers, beyond what the provider offers.
    pub fn service_capabilities(&self) -> Vec<ServiceCapability> {
        let mut out = Vec::new();
        if self.keyed.enabled() {
            out.push(ServiceCapability::KeyedLinks);
        }
        out
    }

    /// A provider acting as this user, or `None` when no account is linked.
    ///
    /// The credential never leaves this process. A client gets answers, never
    /// the means to produce them itself.
    ///
    /// A recipient holding a keyed link is refused outright rather than looked
    /// up. They have no account at the provider, so a lookup would find
    /// nothing anyway, and saying so here means every provider-backed route
    /// closes to them at once rather than each one having to remember.
    pub async fn provider_for(&self, session: &Session) -> Option<Arc<dyn Provider + Send + Sync>> {
        if session.is_guest() {
            return None;
        }
        self.provider_for_owner(&session.user).await
    }

    /// A provider acting as one named account holder.
    ///
    /// Used on a recipient's behalf. Reading a shared document as the sharer
    /// is what lets somebody with no account open it, and it is why the
    /// recipient never holds a credential of any kind.
    pub async fn provider_for_owner(&self, user: &str) -> Option<Arc<dyn Provider + Send + Sync>> {
        let legacy = match self.provider_config().await {
            Some((config, _)) => {
                let link = self.store.provider_link(user).await;
                link.and_then(|link| provider_from(&config, &link.user, &link.password))
            }
            None => None,
        };
        let connections = self.store.connections(user).await;
        if connections.is_empty() {
            return legacy;
        }
        let mut built = Vec::new();
        let mut default_id = None;
        for connection in connections {
            let config = crate::settings::ProviderConfig {
                kind: connection.kind.clone(),
                base: connection.base.clone(),
                contacts: connection.contacts.clone(),
            };
            let provider = if connection.kind == "google" {
                let client = connection.client_id.clone();
                let secret = self.store.google_secret().await.unwrap_or_default();
                Some(Arc::new(crate::google::Drive::new(client, secret, connection.secret.clone())) as Arc<dyn Provider + Send + Sync>)
            } else {
                provider_from(&config, &connection.user, &connection.secret)
            };
            let Some(provider) = provider else { continue };
            if connection.default {
                default_id = Some(connection.id.clone());
            }
            built.push((connection.id, provider));
        }
        if built.is_empty() {
            return legacy;
        }
        if default_id.is_none() && legacy.is_none() {
            default_id = built.first().map(|(id, _)| id.clone());
        }
        Some(Arc::new(crate::route::Routed::new(legacy, built, default_id)))
    }

    /// Sign a relay token for one room.
    ///
    /// The claims are the smallest set the relay needs to decide everything by
    /// itself: which room, who, what they may do, and when it stops being
    /// true. The relay never calls back here.
    pub fn mint_token(&self, session: &Session, room: &str, permission: Permission) -> Result<String, String> {
        // A peer id per token, not per user. Two windows open on the same
        // document are two peers, and the roster has to tell them apart.
        let peer = crate::session::random_id();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        crate::token::sign_at(&self.secret, room, &session.user, &session.display, matches!(permission, Permission::Edit), &peer, now)
            .map_err(|e| e.to_string())
    }
}

/// A provider of the configured kind, acting as one account.
///
/// The one place a kind becomes an implementation. Everything above here holds
/// a `dyn Provider` and never learns which it got.
pub fn provider_from(config: &crate::settings::ProviderConfig, user: &str, password: &str) -> Option<Arc<dyn Provider + Send + Sync>> {
    match config.kind.as_str() {
        "nextcloud" => Some(Arc::new(Nextcloud::new(Account::new(config.base.clone(), user, password), ReqwestHttp::default()))),
        "owncloud" => Some(Arc::new(Nextcloud::owncloud(Account::new(config.base.clone(), user, password), ReqwestHttp::default()))),
        "webdav" => Some(Arc::new(WebDav::new(&config.layout(), user, password, ReqwestHttp::default()))),
        "google" => Some(Arc::new(crate::google::Drive::new(String::new(), String::new(), password))),
        _ => None,
    }
}

/// Check a login name and password against the configured provider.
///
/// Used where a kind has no browser sign-in of its own. Nothing is stored
/// until the server has accepted the credential, so a typo is refused on the
/// spot and never turns into a link that fails on every later request.
pub async fn verify_link(config: &crate::settings::ProviderConfig, user: &str, password: &str) -> Result<(), craft_cloud::Error> {
    let provider = provider_from(config, user, password).ok_or(craft_cloud::Error::Unsupported("this kind of provider"))?;
    match tokio::task::spawn_blocking(move || craft_cloud::Accounts::me(provider.as_ref()).map(|_| ())).await {
        Ok(answer) => answer,
        Err(e) => Err(craft_cloud::Error::Unreachable(e.to_string())),
    }
}
