//! The share dialog's backend, reaching the CollabCraft service.
//!
//! `craft-ui` draws the dialog and states each piece of work as a
//! `share::Request`. Nothing in that crate implements `share::ShareBackend`,
//! which is what keeps it free of a transport and buildable for the web. This
//! is the half that opens a socket.
//!
//! It lives beside the client rather than beside the dialog. Twelve
//! applications bind this one crate instead of each writing the same adapter,
//! and craft-ui never learns that a service exists.
//!
//! # The same dialog on the desktop and in the browser
//!
//! [`CollabCraft`] is one type on both targets, with the same constructors, so
//! an application writes the same two lines either way. Only the waiting
//! differs, and the dialog's contract already allows for that: `submit`
//! returns at once and the answer arrives through the `Replier` whenever it is
//! ready. A desktop build puts the call on a thread. A browser build has no
//! thread to put it on, so it spawns a task and the browser's own `fetch`
//! answers the `Replier` when it resolves.
//!
//! Every mapping between the dialog's vocabulary and the service's lives in
//! [`answer`], so both targets translate identically and a test covers the
//! translation with no transport at all.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use std::sync::Arc;

use craft_cloud_client::Client;
use craft_ui::share::{Answer, Replier, Request, ShareBackend};

mod answer;

#[cfg(test)]
mod tests;

/// Where each request's client comes from.
#[derive(Clone)]
enum Source {
    /// One client for the life of the dialog.
    Fixed(Client),
    /// A client built for each request.
    ///
    /// A desktop application collects its session through a browser,
    /// possibly long after the window opened, and keeps it somewhere only
    /// the application knows. Asking for a client per request means a share
    /// opened after that sign-in finds the session without a restart.
    Made(Arc<dyn Fn() -> Option<Client> + Send + Sync>),
}

/// A [`ShareBackend`] that reaches the CollabCraft service.
///
/// This is the only part of the dialog that opens a socket, and it opens it
/// to CollabCraft. Which provider sits behind that, and what credential
/// reaches it, are the service's business and are configured in one place.
#[derive(Clone)]
pub struct CollabCraft {
    source: Source,
    app: Option<String>,
}

impl CollabCraft {
    /// A backend on one client, for a host that already holds a session.
    pub fn new(client: Client) -> CollabCraft {
        CollabCraft { source: Source::Fixed(client), app: None }
    }

    /// Name the Craft app that opens links minted by this backend.
    #[must_use]
    pub fn for_app(mut self, app: impl Into<String>) -> CollabCraft {
        self.app = Some(app.into());
        self
    }

    /// A backend that asks the host for a client each time, so a session
    /// collected later is picked up without a restart.
    ///
    /// `None` from the factory means there is no service configured, which
    /// leaves the dialog unavailable rather than broken.
    pub fn from_fn(make: impl Fn() -> Option<Client> + Send + Sync + 'static) -> CollabCraft {
        CollabCraft { source: Source::Made(Arc::new(make)), app: None }
    }

    /// A backend from the environment around the application.
    ///
    /// On the desktop that is the process environment: `CRAFT_CLOUD_URL`, and
    /// `CRAFT_CLOUD_TOKEN` when a session has already been collected. In a
    /// browser it is the page, which usually says nothing because CollabCraft
    /// served the page itself.
    ///
    /// Neither is compiled in, which is what lets one build talk to any
    /// deployment. `None` means there is no service to talk to.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_env() -> Option<CollabCraft> {
        let mut client = Client::new(var("CRAFT_CLOUD_URL")?);
        if let Some(token) = var("CRAFT_CLOUD_TOKEN") {
            client = client.with_token(token);
        }
        Some(CollabCraft::new(client))
    }

    /// A backend from the page the application is running in.
    ///
    /// CollabCraft serves the browser builds itself, so the service is
    /// wherever the page came from and a build needs no configuration at all.
    /// One served from somewhere else reads `<meta name="craft-cloud-url">`.
    ///
    /// There is no token to look for. A signed-in browser and a recipient who
    /// followed a keyed link both carry a cookie this service set, and the
    /// browser attaches it. So this never answers `None`, and the signature
    /// stays the one a desktop build calls.
    #[cfg(target_arch = "wasm32")]
    pub fn from_env() -> Option<CollabCraft> {
        Some(CollabCraft::new(Client::from_page()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn var(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

fn client(source: &Source) -> Option<Client> {
    match source {
        Source::Fixed(client) => Some(client.clone()),
        Source::Made(make) => make(),
    }
}

/// What a request with no service configured is told.
const NOTHING_CONFIGURED: &str = "no cloud service is configured";

#[cfg(not(target_arch = "wasm32"))]
impl ShareBackend for CollabCraft {
    fn submit(&self, request: Request, reply: Replier) {
        let source = self.source.clone();
        let app = self.app.clone();
        // One thread per request. The dialog debounces its autocomplete,
        // so this is a handful at a time, and a lookup that is still
        // waiting cannot hold up a share the user has already pressed.
        // The client is built on this thread too: reading a saved session
        // off disk is not work for a frame.
        let spare = reply.dup();
        let started = std::thread::Builder::new().name("craft-share".to_owned()).spawn(move || match client(&source) {
            None => reply.refuse(NOTHING_CONFIGURED),
            Some(client) => match run_for(&client, request, app.as_deref()) {
                Ok(answer) => reply.answer(answer),
                Err(reason) => reply.refuse(reason),
            },
        });
        if let Err(e) = started {
            // The moved handle went with the closure that never ran, so the
            // spare is the only way to stop the dialog waiting forever.
            spare.refuse(format!("no thread to run this on: {e}"));
        }
    }
}

/// One request, on a thread of its own.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)] // kept as the no-app entry; callers that pin an app use `run_for`
fn run(client: &Client, request: Request) -> Result<Answer, String> {
    run_for(client, request, None)
}

#[cfg(not(target_arch = "wasm32"))]
fn run_for(client: &Client, request: Request, app: Option<&str>) -> Result<Answer, String> {
    use answer::say;

    match request {
        Request::Capabilities => Ok(answer::capabilities(client.me().map_err(say)?)),
        Request::Lookup { query, limit } => client.contacts(&query, limit).map(Answer::Lookup).map_err(say),
        Request::Access { id } => client.shares(&id).map(Answer::Access).map_err(say),
        Request::Grant(grant) => Ok(answer::granted(client.share(&answer::asked(grant, app)).map_err(say)?)),
        Request::Withdraw { share_id } => {
            client.unshare(&share_id).map_err(say)?;
            Ok(Answer::Withdrawn { share_id })
        }
        Request::Avatar { .. } => Err(answer::no_pictures()),
        Request::Destinations => Ok(answer::destinations(client.me().map_err(say)?)),
        Request::Link { .. } => Err(answer::connect_an_account(&client.link_start().map_err(say)?.login_url)),
    }
}

#[cfg(target_arch = "wasm32")]
impl ShareBackend for CollabCraft {
    fn submit(&self, request: Request, reply: Replier) {
        let source = self.source.clone();
        let app = self.app.clone();
        // A task rather than a thread, because a browser has neither one to
        // spare nor a way to block on one. Spawning cannot fail, so there is
        // no spare Replier to keep: every path below answers.
        wasm_bindgen_futures::spawn_local(async move {
            match client(&source) {
                None => reply.refuse(NOTHING_CONFIGURED),
                Some(client) => match run_for(&client, request, app.as_deref()).await {
                    Ok(answer) => reply.answer(answer),
                    Err(reason) => reply.refuse(reason),
                },
            }
        });
    }
}

/// One request, on a task of its own.
///
/// The desktop twin of this is the same sequence with no `await`. Both
/// translate through [`answer`], so the dialog is told the same thing either
/// way.
#[cfg(target_arch = "wasm32")]
async fn run(client: &Client, request: Request) -> Result<Answer, String> {
    run_for(client, request, None).await
}

#[cfg(target_arch = "wasm32")]
async fn run_for(client: &Client, request: Request, app: Option<&str>) -> Result<Answer, String> {
    use answer::say;

    match request {
        Request::Capabilities => Ok(answer::capabilities(client.me().await.map_err(say)?)),
        Request::Lookup { query, limit } => client.contacts(&query, limit).await.map(Answer::Lookup).map_err(say),
        Request::Access { id } => client.shares(&id).await.map(Answer::Access).map_err(say),
        Request::Grant(grant) => Ok(answer::granted(client.share(&answer::asked(grant, app)).await.map_err(say)?)),
        Request::Withdraw { share_id } => {
            client.unshare(&share_id).await.map_err(say)?;
            Ok(Answer::Withdrawn { share_id })
        }
        Request::Avatar { .. } => Err(answer::no_pictures()),
        Request::Destinations => Ok(answer::destinations(client.me().await.map_err(say)?)),
        Request::Link { .. } => Err(answer::connect_an_account(&client.link_start().await.map_err(say)?.login_url)),
    }
}
