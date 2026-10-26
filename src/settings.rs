//! What a deployment configures about its cloud provider, and who may change
//! it.
//!
//! The environment is the default. A value stored on the bus overrides it. An
//! existing deployment therefore keeps working with nothing touched, and a new
//! one can be pointed at its provider from a page in a browser.
//!
//! Who may change it comes from the identity provider. Membership of a named
//! group is the whole of the permission. That is how every other entitlement
//! in this service is decided, so this one is decided the same way.
//!
//! Nothing here holds a credential. The address of a provider is configuration
//! and the account that acts against it is linked per user, which keeps those
//! two questions apart on purpose.

use serde::{Deserialize, Serialize};

use crate::session::Session;

/// The provider implementations this binary speaks.
///
/// The list lives here so the setup page can offer a choice out of what the
/// binary actually implements. Anything else is refused at the point of saving.
///
/// `webdav` is every server speaking RFC 4918, which is most of them: SabreDAV,
/// Apache, nginx, Seafile, a NAS, ownCloud Infinite Scale. It has no sharing,
/// so the share controls disappear and everything else works.
pub const KINDS: [&str; 5] = ["nextcloud", "owncloud", "webdav", "google", "git"];

/// What to call a kind in a heading.
pub fn kind_label(kind: &str) -> String {
    match kind {
        "nextcloud" => "Nextcloud".to_owned(),
        "owncloud" => "ownCloud".to_owned(),
        "webdav" => "WebDAV".to_owned(),
        "google" => "Google Drive".to_owned(),
        "git" => "Git".to_owned(),
        other => crate::pages::capitalise(other),
    }
}

/// Which provider answers, and where it lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// A stable identifier such as `nextcloud`. Used in configuration and in
    /// logs, never as a label for a user.
    pub kind: String,
    /// The server root, as `https://cloud.example.com`.
    ///
    /// For `webdav`, the files root instead, which may carry `{user}` where
    /// the server puts the login name, as `https://dav.example.com/files/{user}`.
    pub base: String,
    /// The CardDAV address-book home, for `webdav` only. The other kinds
    /// know where their own address books are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contacts: Option<String>,
}

impl ProviderConfig {
    /// Check and normalise what somebody typed into the setup form.
    ///
    /// The refusals are deliberately specific, because an administrator who
    /// pasted the wrong thing can act on each one. A trailing slash is
    /// accepted and removed, since every call site trims one anyway and
    /// storing the difference would be storing a trap.
    pub fn parse(kind: &str, base: &str) -> Result<ProviderConfig, &'static str> {
        let kind = kind.trim().to_ascii_lowercase();
        if !KINDS.contains(&kind.as_str()) {
            return Err("this service does not implement that kind of provider");
        }
        // Google has no server of the deployment's to name. The public API
        // address is fixed, so a blank field is that address and not a mistake.
        if kind == "google" && base.trim().is_empty() {
            return Ok(ProviderConfig { kind, base: "https://www.googleapis.com".to_owned(), contacts: None });
        }
        let base = base.trim().trim_end_matches('/').to_owned();
        let rest =
            base.strip_prefix("https://").or_else(|| base.strip_prefix("http://")).ok_or("the address has to begin with https:// or http://")?;
        if rest.is_empty() || rest.starts_with('/') {
            return Err("the address names no host");
        }
        // An address carrying a credential would put one in configuration
        // every administrator can read. A query or a fragment means somebody
        // pasted a page out of the provider's own interface.
        if rest.contains(['@', '?', '#', ' ']) {
            return Err("the address has to be a plain server address, with no credential, no query and no fragment");
        }
        Ok(ProviderConfig { kind, base, contacts: None })
    }

    /// Add an address-book home, checked the same way as the address.
    ///
    /// Empty means none. Only `webdav` reads it, so on any other kind it is
    /// dropped rather than stored to confuse a later reader.
    pub fn with_contacts(mut self, raw: &str) -> Result<ProviderConfig, &'static str> {
        let raw = raw.trim();
        if raw.is_empty() || self.kind != "webdav" {
            self.contacts = None;
            return Ok(self);
        }
        let checked = ProviderConfig::parse(&self.kind, raw).map_err(|_| "the address-book address has to be a plain https:// or http:// address")?;
        self.contacts = Some(checked.base);
        Ok(self)
    }

    /// What to call this provider in a heading.
    pub fn label(&self) -> String {
        kind_label(&self.kind)
    }

    /// Whether linking goes through the provider's own browser sign-in.
    ///
    /// Only Nextcloud has one that hands a client a credential (Login Flow
    /// v2). Every other kind is linked with a login name and an app password
    /// or token, which this service checks against the server before storing.
    pub fn uses_login_flow(&self) -> bool {
        self.kind == "nextcloud"
    }

    /// Where a `webdav` server keeps things.
    pub fn layout(&self) -> craft_webdav::Layout {
        craft_webdav::Layout::new(self.base.clone(), self.contacts.clone())
    }
}

/// Where the provider in use came from.
///
/// Reported so the setup page can say which of the two a deployment is
/// running on. An administrator looking at an address wants to know whether
/// changing the environment would change anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Environment,
    Stored,
}

/// What this deployment was started with, and who may change it afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The environment's provider. The default, overridden by anything stored.
    env: Option<ProviderConfig>,
    /// Groups from the identity provider whose members may change the stored
    /// provider, lower-cased for comparison.
    admins: Vec<String>,
}

impl Settings {
    /// Read `COLLABCRAFT_PROVIDER_URL`, `COLLABCRAFT_PROVIDER_KIND` and
    /// `COLLABCRAFT_ADMIN_GROUPS`.
    pub fn from_env() -> Settings {
        let mut settings = Settings::decide(
            var("COLLABCRAFT_PROVIDER_URL").as_deref(),
            var("COLLABCRAFT_PROVIDER_KIND").as_deref(),
            var("COLLABCRAFT_ADMIN_GROUPS").as_deref(),
        );
        if let Some(contacts) = var("COLLABCRAFT_PROVIDER_CONTACTS_URL") {
            settings.env = settings.env.map(|env| env.clone().with_contacts(&contacts).unwrap_or(env));
        }
        settings
    }

    /// The same decision over values.
    ///
    /// Separated so the override and the gate are testable. Reading the
    /// environment inside a test would race every other test in the binary.
    pub fn decide(url: Option<&str>, kind: Option<&str>, groups: Option<&str>) -> Settings {
        let kind = kind.map(str::trim).filter(|k| !k.is_empty()).unwrap_or(KINDS[0]);
        let env = url.map(str::trim).filter(|u| !u.is_empty()).and_then(|u| ProviderConfig::parse(kind, u).ok());
        let admins =
            groups.unwrap_or_default().split(',').map(str::trim).filter(|g| !g.is_empty()).map(str::to_ascii_lowercase).collect::<Vec<String>>();
        Settings { env, admins }
    }

    /// The environment's provider, which is the default.
    pub fn env_default(&self) -> Option<&ProviderConfig> {
        self.env.as_ref()
    }

    /// Which provider this deployment uses, and where that came from.
    ///
    /// A stored value wins. That ordering is the whole of the override: a
    /// deployment storing nothing behaves exactly as it did before this page
    /// existed, and one that stores a provider can be pointed somewhere new
    /// without an environment change.
    ///
    /// A stored record naming no address is ignored, so a half-written record
    /// cannot take a working deployment off its provider.
    pub fn resolve(&self, stored: Option<ProviderConfig>) -> Option<(ProviderConfig, Source)> {
        match stored {
            Some(stored) if !stored.base.trim().is_empty() => Some((stored, Source::Stored)),
            _ => self.env.clone().map(|c| (c, Source::Environment)),
        }
    }

    /// Groups whose members may change the stored provider.
    pub fn admin_groups(&self) -> &[String] {
        &self.admins
    }

    /// Whether this session may change the provider.
    ///
    /// A deployment naming no group has nobody who may, so the page refuses
    /// everybody and the control appears for nobody. A recipient holding a
    /// keyed link carries no group and is refused by the same rule, which is
    /// what keeps this closed to one without a second check anywhere.
    pub fn may_configure(&self, session: &Session) -> bool {
        if session.is_guest() || self.admins.is_empty() {
            return false;
        }
        session.groups.iter().any(|g| self.admins.contains(&g.to_ascii_lowercase()))
    }
}

/// Whether a provider answers at an address.
///
/// Nextcloud is asked for the beginning of its own desktop login flow. That
/// needs no credential and no account, and a server answering it is reachable,
/// speaks the protocol and is willing to issue a credential. ownCloud has no
/// such flow and is asked for its `status.php` instead. A WebDAV server is
/// asked `OPTIONS`. Proving it before the address is saved is the point: an
/// address that only fails later fails for every user at once.
///
/// What the provider hands back is dropped here. The flow is abandoned, and
/// the poll token it carries is never logged and never rendered.
pub async fn probe(config: &ProviderConfig) -> Result<(), String> {
    let config = config.clone();
    let probing = tokio::task::spawn_blocking(move || match config.kind.as_str() {
        "nextcloud" => craft_nextcloud::begin(&crate::transport::ReqwestHttp::default(), &config.base).map(|_| ()).map_err(|e| e.to_string()),
        "owncloud" => match craft_nextcloud::status(&crate::transport::ReqwestHttp::default(), &config.base) {
            Ok(s) if !s.installed => Err("the server answered and is not installed yet".to_owned()),
            Ok(s) if s.maintenance => Err("the server answered and is in maintenance mode".to_owned()),
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        },
        "webdav" => craft_webdav::probe(&crate::transport::ReqwestHttp::default(), &config.layout()),
        // Nothing to dial. The client id is checked when somebody connects.
        "google" => Ok(()),
        "git" => crate::git::probe(&config.base),
        other => Err(format!("this service does not implement a {other} provider")),
    })
    .await;
    match probing {
        Ok(answer) => answer,
        // The thread panicked. Reported, because a provider crate that panics
        // is a defect somebody has to see.
        Err(e) => Err(e.to_string()),
    }
}

fn var(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// One kind this deployment allows people to connect, in addition to the
/// provider the legacy link uses.
///
/// The secret for an OAuth kind is not here. It lives in the environment or
/// in a separate bus record, so a page that renders this struct cannot echo it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub kind: String,
    pub base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contacts: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
}

impl Offer {
    pub fn from_config(config: &ProviderConfig) -> Offer {
        Offer { kind: config.kind.clone(), base: config.base.clone(), contacts: config.contacts.clone(), client_id: String::new() }
    }

    pub fn config(&self) -> ProviderConfig {
        ProviderConfig { kind: self.kind.clone(), base: self.base.clone(), contacts: self.contacts.clone() }
    }
}

/// The Nextcloud this deployment was told about, if the operator set one.
///
/// Read when a page is drawn. Nothing here is compiled into the binary.
pub fn nextcloud_from_env() -> Option<String> {
    var("COLLABCRAFT_NEXTCLOUD_URL").and_then(|raw| ProviderConfig::parse("nextcloud", &raw).ok()).map(|config| config.base)
}

/// OAuth client id for Google Drive, from the environment.
pub fn google_client_from_env() -> Option<String> {
    var("COLLABCRAFT_GOOGLE_CLIENT_ID")
}
