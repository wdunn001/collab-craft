//! Talking to CollabCraft, from an app.
//!
//! This is the only way a Craft app reaches storage, sharing or contacts. It
//! holds no provider credential, knows no provider URL and implements no
//! provider protocol. Swapping Nextcloud for something else changes nothing
//! here and nothing in any app.
//!
//! Signing in uses the device flow, because a desktop app cannot host a
//! redirect worth trusting. The app asks CollabCraft to start one, opens the
//! user's browser, and polls until it can collect a bearer token. Whatever
//! happens in that browser is the identity provider's business, so OIDC works
//! without a line of OAuth code here.
//!
//! # One description of the API, two transports
//!
//! [`req`] names every call the service answers, and [`wire`] carries the
//! request and answer types those calls are made of. Neither opens a socket.
//! The transports do: a desktop build sends with `ureq` and blocks, a browser
//! build sends with the page's own `fetch` and returns futures. Each target
//! re-exports its own as [`Client`], so an app names one type on both.
//!
//! Method names, parameters and answer types are the same either way. The one
//! difference is that the desktop methods block and the browser methods are
//! `async`, and that difference cannot be removed from here: a browser has no
//! thread to block.
//!
//! Every desktop call blocks, so an app's UI thread must not call one
//! directly, and [`Client`] is cheap to move to a worker. A browser call
//! blocks nothing and belongs on the frame that asked for it.

use craft_cloud::{Capability, Permission, Share, ShareTarget};
use serde::{Deserialize, Serialize};

pub mod req;
pub mod wire;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
mod web;

/// Landing on a keyed link: the whole of what a browser build does when
/// somebody with no account follows a share.
///
/// The flow itself is browser only. A desktop app is handed its session by the
/// landing page's own scheme URL and never follows this path. The judgement
/// inside it is a pure function and compiles everywhere, so the decision that
/// tells a dead link from an ordinary visit can be tested without a browser.
pub mod invite;

#[cfg(not(target_arch = "wasm32"))]
pub use native::{Client, Transport};
#[cfg(target_arch = "wasm32")]
pub use web::Client;

pub use wire::{Call, Method, Request, Response, Target};

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("collabcraft could not be reached: {0}")]
    Unreachable(String),
    #[error("sign in again")]
    Unauthenticated,
    #[error("link a cloud account first")]
    NotLinked,
    #[error("{code}: {detail}")]
    Refused { code: String, detail: String },
    #[error("unexpected answer: {0}")]
    Malformed(String),
    /// A request that could not be encoded. A defect here rather than
    /// anything the service said, and named separately so it never reads as a
    /// refusal somebody can act on.
    #[error("this request could not be encoded: {0}")]
    Unsendable(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Where to open the provider's conversation app with no document in hand.
#[derive(Clone, Debug, Deserialize)]
pub struct ConversationHome {
    /// What the provider calls it (Talk, …).
    pub name: String,
    pub url: String,
}

/// What the server says about the signed-in user.
#[derive(Clone, Debug, Deserialize)]
pub struct Me {
    pub id: String,
    pub display: String,
    pub email: Option<String>,
    pub avatar: Option<String>,
    /// Apps this user may open.
    pub apps: Vec<String>,
    /// What the provider behind CollabCraft can do, so a UI hides what it
    /// cannot deliver rather than offering a button that fails.
    pub capabilities: Vec<Capability>,
    /// Until this is true, Open and Save have nowhere to go.
    pub provider_linked: bool,
    /// The provider's conversation lobby, when it has one.
    #[serde(default)]
    pub conversation: Option<ConversationHome>,
}

/// A relay token and where to take it.
#[derive(Clone, Debug, Deserialize)]
pub struct Join {
    pub token: String,
    pub relay: String,
    pub room: String,
}

/// The same, for somebody who arrived on a keyed link.
///
/// Carries everything the recipient's application needs before it can show
/// them anything. The service decides the permission on the request rather
/// than from the session, and a UI presents a read-only document as read-only
/// rather than discovering it when the relay refuses an edit.
#[derive(Clone, Debug, Deserialize)]
pub struct InviteJoin {
    pub token: String,
    pub relay: String,
    pub room: String,
    pub permission: Permission,
    /// What to call the document. A recipient has no file list, so this is the
    /// only place the name can come from.
    pub name: String,
    /// The version the document is at. A save is conditional on this, so work
    /// saved between the read and the save refuses the write rather than
    /// being overwritten.
    #[serde(default)]
    pub etag: Option<String>,
    /// The address the link was minted for, so a title bar can say who the
    /// document was shared with.
    pub recipient: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceStart {
    pub device_code: String,
    pub verify_url: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LinkStart {
    pub login_url: String,
    pub handle: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ShareRequest {
    pub id: String,
    pub targets: Vec<ShareTarget>,
    pub permission: Permission,
    pub note: Option<String>,
    pub notify: bool,
    /// The Craft app that opens a keyed recipient link.
    ///
    /// The service validates this against the deployment and the sharer's
    /// entitlement before minting a link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// A key the recipient must present. Only meaningful for a link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// `YYYY-MM-DD`, after which the share stops working.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ShareOutcome {
    pub shared: Vec<Share>,
    /// Named rather than counted, so a dialog can say which address failed.
    pub failed: Vec<ShareFailure>,
    /// CollabCraft entry links minted for recipients and public-link shares.
    #[serde(default)]
    pub keyed: Vec<KeyedOutcome>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ShareFailure {
    pub target: ShareTarget,
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct KeyedOutcome {
    pub target: ShareTarget,
    pub url: String,
    pub expires: i64,
    pub uses: u32,
    pub delivered: bool,
    pub delivery: String,
}
