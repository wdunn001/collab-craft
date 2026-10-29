//! The CollabCraft relay.
//!
//! Peers connect with a token Nextcloud minted. The relay verifies the
//! signature, puts them in a room keyed on the Nextcloud file id, assigns a
//! monotonic sequence to every edit and arbitrates scope locks. It makes no
//! access decisions of its own and never calls back into Nextcloud.
//!
//! Configuration, all from the environment:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `COLLABCRAFT_SECRET` | required | shared with the Nextcloud app |
//! | `COLLABCRAFT_VALKEY_URL` | `redis://valkey:6379/6` | the bus |
//! | `COLLABCRAFT_BIND` | `0.0.0.0:9444` | listen address |
//! | `COLLABCRAFT_KEYED_LINKS` | on | `off` forbids links for recipients with no account |
//! | `COLLABCRAFT_KEYED_LINK_TTL_HOURS` | 168 | how long one of those links lasts |
//! | `COLLABCRAFT_KEYED_LINK_USES` | 1 | how often one may be opened |
//! | `COLLABCRAFT_PROVIDER_URL` | none | the cloud provider, overridden by the setup page |
//! | `COLLABCRAFT_PROVIDER_KIND` | `nextcloud` | which implementation answers there |
//! | `COLLABCRAFT_ADMIN_GROUPS` | none | groups whose members may change that from the setup page |
//!
//! The provider is the one piece of configuration a page can change. The
//! environment stays the default. A value stored on the bus overrides it, so
//! an existing deployment keeps working with nothing touched.
//!
//! The Valkey URL uses the estate's DNS name rather than an address, so the
//! relay follows the instance if it moves. Database index 6 is free: the stack
//! README allocates 0 through 5 and 8, and the live keyspace also shows 10 and
//! 13 in use.

mod api;
mod auth;
mod bus;
mod esign;
mod git;
mod google;
mod keyed;
mod pages;
mod recipient;
mod room;
mod route;
mod session;
mod settings;
mod state;
mod store;
mod token;
mod transport;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use socketioxide::SocketIo;
use socketioxide::extract::{Data, SocketRef, State};
use tokio::sync::Mutex;

use bus::{Bus, LockOutcome};
use room::{Op, Peer, Refusal, Room, Submission, is_crdt_command};

/// Bytes one opaque frame may carry, base64 included.
///
/// Frames are passed through unread, so nothing downstream can judge the size. The relay has to.
const MAX_FRAME_BYTES: usize = 1024 * 1024;
use token::Claims;

const DEFAULT_VALKEY: &str = "redis://valkey:6379/6";
const DEFAULT_BIND: &str = "0.0.0.0:9444";

/// Shared relay state.
struct Relay {
    secret: Vec<u8>,
    bus: Mutex<Bus>,
    /// file id -> room. One lock, because ordering needs a single decision
    /// point and a per-room lock would not make the hot path meaningfully
    /// cheaper at this scale.
    rooms: Mutex<HashMap<String, Room>>,
}

/// What a peer sends in the Socket.IO handshake.
#[derive(Debug, Deserialize)]
struct Handshake {
    token: String,
}

// ---- payloads, matching craft-collab's proto ------------------------------

#[derive(Debug, Deserialize)]
struct SubmitMsg {
    local: Option<u64>,
    command: String,
    #[serde(default)]
    params: serde_json::Value,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ScopeMsg {
    scope: String,
}

#[derive(Debug, Deserialize)]
struct ResyncMsg {
    have: u64,
}

#[derive(Debug, Deserialize)]
struct FrameMsg {
    payload: String,
}

#[derive(Debug, Deserialize)]
struct EphemeralMsg {
    kind: String,
    #[serde(default)]
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JoinedMsg<'a> {
    doc: String,
    peer: &'a str,
    seq: u64,
    /// The CRDT id space this connection may mint character ids in. Never 0.
    space: u32,
    roster: &'a [Peer],
    locks: Vec<LockEntry>,
}

#[derive(Debug, Serialize)]
struct LockEntry {
    scope: String,
    holder: String,
}

#[derive(Debug, Serialize)]
struct ErrorMsg {
    doc: String,
    detail: String,
}

/// Key space for sessions and account links, kept apart from the relay's
/// own room keys so one can be cleared without touching the other.
const PREFIX_SERVICE: &str = "collabcraft:svc";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("collabcraft_relay=info".parse()?))
        .init();

    let secret = std::env::var("COLLABCRAFT_SECRET").map_err(|_| {
        "COLLABCRAFT_SECRET is not set. It must match the collabcraft app's relay_secret, \
         which the Nextcloud app generates on first use."
    })?;
    if secret.len() < 32 {
        return Err("COLLABCRAFT_SECRET is shorter than 32 characters; the app generates 48".into());
    }

    let valkey_url = std::env::var("COLLABCRAFT_VALKEY_URL").unwrap_or_else(|_| DEFAULT_VALKEY.to_owned());
    let bind = std::env::var("COLLABCRAFT_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned());

    let mut bus = Bus::connect(&valkey_url).await?;
    // Fail at startup, not on the first edit. A relay that accepts peers and
    // then refuses every submit is harder to diagnose than one that will not
    // start.
    bus.check_writable().await?;
    tracing::info!(%valkey_url, "bus ready");

    let secret_bytes = secret.clone().into_bytes();
    let relay = Arc::new(Relay { secret: secret_bytes.clone(), bus: Mutex::new(bus), rooms: Mutex::new(HashMap::new()) });

    // Cap the transport too. Room::submit refuses an oversized `params` after decoding, and a
    // cap there still means the bytes were read and parsed first. This refuses them at the
    // socket, which is the only place that costs nothing.
    let (layer, io) = SocketIo::builder().max_payload(MAX_FRAME_BYTES as u64).with_state(relay).build_layer();
    // ns returns () for the local adapter, so there is nothing to await here.
    io.ns("/", on_connect);

    // The API half. It signs the tokens the relay above verifies, which is why
    // both halves hold the same secret and neither has to ask the other
    // anything at runtime.
    let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build().unwrap_or_default();
    let oidc = session::Oidc::from_env(&http).await;
    if oidc.is_none() {
        tracing::warn!("no identity provider configured: every API route will refuse");
    }
    let store = store::Store::new(&valkey_url, PREFIX_SERVICE)?;
    let web_root = std::env::var("COLLABCRAFT_WEB_ROOT").unwrap_or_default();
    // Read once. A directory listing per request would be a disk hit on every
    // asset, and the set only changes on deploy.
    let hosted: Vec<String> = std::fs::read_dir(&web_root)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    if !web_root.is_empty() {
        tracing::info!(count = hosted.len(), "browser builds hosted");
    }
    let esign = esign::EsignRuntime::from_env(&secret_bytes).await?;
    let app_state = Arc::new(state::App {
        // Precompressed on disk, sent with the Content-Encoding header.
        // Brotli at a high level costs minutes per wasm bundle, which is
        // unaffordable per request and free once at deploy.
        web: tower_http::services::ServeDir::new(&web_root).precompressed_br().precompressed_gzip(),
        hosted,
        secret: secret_bytes,
        relay_url: std::env::var("COLLABCRAFT_PUBLIC_RELAY").unwrap_or_else(|_| format!("http://{bind}")),
        settings: settings::Settings::from_env(),
        permissions: state::Permissions::from_env(),
        keyed: keyed::Policy::from_env(),
        store,
        oidc,
        http,
        esign,
    });
    // What the deployment is actually on, which is the stored value where
    // there is one. Logged at startup because a deployment reading its own log
    // should not have to guess which of the two won.
    match app_state.provider_config().await {
        Some((config, settings::Source::Stored)) => {
            tracing::info!(kind = %config.kind, base = %config.base, "cloud provider, set on the setup page");
        }
        Some((config, settings::Source::Environment)) => {
            tracing::info!(kind = %config.kind, base = %config.base, "cloud provider, from the environment");
        }
        None => tracing::warn!("no cloud provider is configured: no account can be linked"),
    }
    if app_state.settings.env_default().is_none() && std::env::var("COLLABCRAFT_PROVIDER_URL").is_ok_and(|v| !v.trim().is_empty()) {
        tracing::warn!("COLLABCRAFT_PROVIDER_URL is set to something that is not a usable server address");
    }
    if app_state.settings.admin_groups().is_empty() {
        tracing::info!("COLLABCRAFT_ADMIN_GROUPS is not set: nobody may change the cloud provider from the setup page");
    }
    if app_state.keyed.enabled() {
        tracing::info!(ttl_secs = app_state.keyed.ttl_secs, uses = app_state.keyed.max_uses, "keyed links are enabled");
    } else {
        tracing::info!("keyed links are off: a share to an address with no account will mint nothing");
    }

    let api = axum::Router::new()
        .route("/me", axum::routing::get(api::me))
        .route("/files", axum::routing::get(api::list))
        .route("/files/shared", axum::routing::get(api::shared_with_me))
        .route("/files/content", axum::routing::get(api::read).put(api::write))
        .route("/files/meta", axum::routing::get(api::file_meta))
        .route("/files/new", axum::routing::post(api::create))
        .route("/contacts", axum::routing::get(api::contacts))
        .route("/conversation", axum::routing::get(api::conversation))
        .route("/shares", axum::routing::get(api::shares).post(api::share))
        .route("/shares/{id}", axum::routing::delete(api::unshare))
        .route("/token", axum::routing::get(api::token))
        .route("/apps", axum::routing::get(api::apps))
        // The recipient of a keyed link. Separate routes rather than the ones
        // above, because those act as the signed-in user against the provider
        // and a recipient is not one.
        .route("/invite/token", axum::routing::get(recipient::token))
        .route("/invite/content", axum::routing::get(recipient::read).put(recipient::write))
        .nest("/esign", esign::router());

    let auth_routes = axum::Router::new()
        .route("/login", axum::routing::get(auth::login))
        .route("/callback", axum::routing::get(auth::callback))
        .route("/logout", axum::routing::post(auth::logout))
        .route("/device/start", axum::routing::post(auth::device_start))
        .route("/device/poll", axum::routing::post(auth::device_poll))
        .route("/link/start", axum::routing::post(auth::link_start))
        .route("/link/poll", axum::routing::post(auth::link_poll))
        .route("/link/password", axum::routing::post(auth::link_password))
        .route("/link", axum::routing::delete(auth::unlink));

    // The web face. Server rendered out of this binary, so the service answers
    // a browser as well as an app. These are real routes, so each one wins
    // over the static fallback below.
    let web = axum::Router::new()
        .route("/", axum::routing::get(pages::launcher))
        // Where a hand-written entry page used to sit in the web root.
        .route("/index.html", axum::routing::get(pages::index_html))
        .route("/account", axum::routing::get(pages::account))
        .route("/account/link", axum::routing::post(pages::link_begin))
        .route("/account/link/finish", axum::routing::post(pages::link_finish))
        .route("/account/link/password", axum::routing::post(pages::link_password))
        .route("/account/link/google", axum::routing::get(pages::google_finish))
        .route("/account/unlink", axum::routing::post(pages::unlink))
        .route("/account/connection/default", axum::routing::post(pages::connection_default))
        .route("/account/signout", axum::routing::post(pages::signout))
        .route("/settings/provider", axum::routing::get(pages::provider).post(pages::provider_save))
        .route("/settings/apps", axum::routing::get(pages::apps).post(pages::apps_save));

    // with_state goes last, after every route including the fallback.
    // Applying it earlier leaves the fallback still wanting state, and the
    // router then will not serve at all.
    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .merge(web)
        .nest("/api/v1", api)
        .nest("/auth", auth_routes)
        // Where a keyed link lands. A real route, so it wins over the static
        // fallback below.
        .route("/invite/{key}", axum::routing::get(recipient::land))
        .route("/esign/invite/{key}", axum::routing::get(esign::land_signer))
        .fallback(api::web)
        .with_state(app_state);

    let app = app.layer(layer);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "relay listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;

    Ok(())
}

/// Admit a peer, or disconnect it.
async fn on_connect(socket: SocketRef, Data(handshake): Data<Handshake>, State(relay): State<Arc<Relay>>) {
    let now = now_unix();
    let claims = match token::verify(&handshake.token, &relay.secret, now) {
        Ok(c) => c,
        Err(e) => {
            // The reason goes to the log, not to the peer. A caller learning
            // which check failed learns something about the secret.
            tracing::warn!(error = %e, "rejecting a connection");
            let _ = socket.emit("error", &ErrorMsg { doc: String::new(), detail: "token rejected".to_owned() });
            let _ = socket.disconnect();
            return;
        }
    };

    let room_name = claims.room();
    let room_key = claims.rm.clone();
    let peer_id = claims.pid.clone();

    // Register the handlers and stash the claims BEFORE any await below.
    //
    // This ordering is the whole correctness of the join. The old code emitted
    // `joined` and then awaited a presence broadcast and a Valkey SCAN before
    // registering anything. A client does not wait: it receives `joined` and
    // immediately sends `lock` and `submit`. Those packets arrived at a socket
    // with no handler for them and Socket.IO dropped them silently, with no
    // error anywhere, so an edit simply never happened. Three runs in a row
    // lost the submit that way.
    //
    // Registering first costs nothing. A handler that fires before the room
    // entry exists still works, because every handler uses `entry().or_default()`
    // and reads the claims it needs from the socket's own extensions.
    socket.extensions.insert(claims.clone());
    socket.on("submit", on_submit);
    socket.on("lock", on_lock);
    socket.on("unlock", on_unlock);
    socket.on("resync", on_resync);
    socket.on("frame", on_frame);
    socket.on("ephemeral", on_ephemeral);
    socket.on_disconnect(on_disconnect);
    socket.join(room_name.clone());

    let locks = {
        let mut bus = relay.bus.lock().await;
        bus.holders(&room_key).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, room = %room_key, "could not read lock holders");
            Vec::new()
        })
    };

    // One id space per connection, from the bus, so two relays cannot grant the same one and a
    // restart cannot hand one out twice. A client that derived its own from its peer id could
    // collide with another peer's, and the two would then mint the same character ids and drop
    // each other's text.
    let space = {
        let mut bus = relay.bus.lock().await;
        match bus.next_space(&room_key).await {
            Ok(s) => s,
            Err(e) => {
                // Refuse rather than admit a peer with no space. Admitting it would mean
                // either silent divergence or a window that cannot type, and neither is
                // something a user could act on.
                tracing::error!(error = %e, room = %room_key, "could not grant an id space");
                let _ = socket.emit("error", &ErrorMsg { doc: room_name.clone(), detail: "relay could not start a session".to_owned() });
                let _ = socket.disconnect();
                return;
            }
        }
    };

    let joined = {
        let mut rooms = relay.rooms.lock().await;
        let room = rooms.entry(room_key.clone()).or_default();
        match room.join(Peer { peer: peer_id.clone(), display: claims.dsp.clone(), may_edit: claims.may_edit() }) {
            Ok(()) => {
                for (scope, holder) in &locks {
                    room.record_holder(scope.clone(), holder.clone());
                }
                let texts: Vec<(String, Vec<serde_json::Value>, bool)> =
                    room.texts().iter().map(|(scope, log)| (scope.clone(), log.ops().to_vec(), log.complete())).collect();
                Some((room.seq(), room.peers().to_vec(), texts, room.ephemeral()))
            }
            Err(_) => None,
        }
    };

    let Some((seq, roster, texts, ephemeral)) = joined else {
        tracing::warn!(room = %room_key, "refusing a peer: the document is full");
        let _ = socket.emit("error", &ErrorMsg { doc: room_name.clone(), detail: Refusal::Full.detail() });
        let _ = socket.disconnect();
        return;
    };

    let _ = socket.emit(
        "joined",
        &JoinedMsg {
            doc: room_name.clone(),
            peer: &peer_id,
            seq,
            space,
            roster: &roster,
            locks: locks.iter().map(|(s, h)| LockEntry { scope: s.clone(), holder: h.clone() }).collect(),
        },
    );

    // Catch the new peer up on text. The file it is about to open is behind every edit made
    // since that file was written, and the sequence is already past those edits, so they cannot
    // be replayed as ordered ops. These carry no sequence for that reason.
    for (scope, ops, complete) in texts {
        let _ = socket.emit("text_ops", &serde_json::json!({ "doc": room_name.clone(), "scope": scope, "ops": ops, "complete": complete }));
    }

    // And on where everybody is, so somebody arriving late does not have to wait for each
    // person to move before their marker appears.
    for (peer, kind, payload) in ephemeral {
        let _ = socket.emit("ephemeral", &serde_json::json!({ "doc": room_name.clone(), "origin": peer, "kind": kind, "payload": payload }));
    }

    let _ = socket.to(room_name.clone()).emit("presence", &serde_json::json!({ "doc": room_name, "roster": roster })).await;

    tracing::info!(uid = %claims.uid, peer = %peer_id, room = %room_key, may_edit = claims.may_edit(), "peer joined");
}

async fn on_submit(socket: SocketRef, Data(msg): Data<SubmitMsg>, State(relay): State<Arc<Relay>>) {
    let Some(claims) = socket.extensions.get::<Claims>() else { return };
    let room_name = claims.room();

    // Arbitrate BEFORE taking a sequence number. INCR is not refundable, so a
    // submit refused after the increment would burn that number and leave a
    // permanent gap. Every client holds an out-of-order op waiting for its
    // predecessor, so a gap that never arrives stalls the document until
    // somebody asks for a resync.
    //
    // This pre-flight reads the local lock mirror. The authoritative check is
    // still Room::submit below, so a scope another instance locked without this
    // relay seeing it can get past here. That residual case burns one number
    // and recovers by resync, which is the rare path rather than the common
    // one.
    // crdt.* commands merge; a scope on them is a client bug and is stripped
    // before the lock check so a held region cannot refuse the edit.
    let scope = if is_crdt_command(&msg.command) { None } else { msg.scope };
    let preflight = {
        let rooms = relay.rooms.lock().await;
        let holder = rooms.get(&claims.rm).and_then(|r| scope.as_deref().and_then(|sc| r.holder_of(sc))).map(str::to_owned);
        match holder {
            Some(h) if h != claims.pid => Err(Refusal::Locked { holder: h }),
            _ if !claims.may_edit() => Err(Refusal::ReadOnly),
            _ => Ok(()),
        }
    };
    if let Err(refusal) = preflight {
        let _ = socket.emit("error", &ErrorMsg { doc: room_name, detail: refusal.detail() });
        return;
    }

    // The sequence comes from Valkey, so two relay instances cannot hand out
    // the same number.
    let floor = {
        let rooms = relay.rooms.lock().await;
        rooms.get(&claims.rm).map(Room::seq).unwrap_or(0)
    };
    let seq = {
        let mut bus = relay.bus.lock().await;
        match bus.next_seq(&claims.rm, floor).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, room = %claims.rm, "could not assign a sequence");
                let _ = socket.emit("error", &ErrorMsg { doc: room_name, detail: "relay could not order that edit".to_owned() });
                return;
            }
        }
    };

    let outcome = {
        let mut rooms = relay.rooms.lock().await;
        let room = rooms.entry(claims.rm.clone()).or_default();
        room.submit(
            seq,
            Submission {
                peer_id: claims.pid.clone(),
                may_edit: claims.may_edit(),
                command: msg.command,
                params: msg.params,
                scope,
                local: msg.local,
            },
        )
    };

    match outcome {
        Ok(op) => {
            // Editing a scope you hold refreshes the lock. The TTL is 60s, so
            // without this a holder who keeps typing would lose the lock under
            // themselves and another peer could take the region mid-edit. Doing
            // it here needs no timer, because an active holder is by definition
            // submitting.
            if let Some(scope) = op.scope.as_deref() {
                let mut bus = relay.bus.lock().await;
                if let Err(e) = bus.refresh_lock(&claims.rm, scope, &claims.pid).await {
                    tracing::warn!(error = %e, scope, "could not refresh a held lock");
                }
            }
            // To the whole room, sender included. The sender recognises its own
            // op by the echoed local counter and confirms rather than reapplies.
            let _ = socket.within(room_name).emit("op", &OpMsg::new(&claims, &op)).await;
        }
        Err(refusal) => {
            let _ = socket.emit("error", &ErrorMsg { doc: room_name, detail: refusal.detail() });
        }
    }
}

#[derive(Debug, Serialize)]
struct OpMsg<'a> {
    doc: String,
    seq: u64,
    origin: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<u64>,
    command: &'a str,
    params: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

impl<'a> OpMsg<'a> {
    fn new(claims: &Claims, op: &'a Op) -> OpMsg<'a> {
        OpMsg {
            doc: claims.room(),
            seq: op.seq,
            origin: &op.origin,
            local: op.local,
            command: &op.command,
            params: &op.params,
            scope: op.scope.as_deref(),
        }
    }
}

async fn on_lock(socket: SocketRef, Data(msg): Data<ScopeMsg>, State(relay): State<Arc<Relay>>) {
    let Some(claims) = socket.extensions.get::<Claims>() else { return };
    let room_name = claims.room();

    if !claims.may_edit() {
        let _ = socket.emit("error", &ErrorMsg { doc: room_name, detail: Refusal::ReadOnly.detail() });
        return;
    }

    let outcome = {
        let mut bus = relay.bus.lock().await;
        bus.try_lock(&claims.rm, &msg.scope, &claims.pid).await
    };

    match outcome {
        Ok(LockOutcome::Granted) => {
            {
                let mut rooms = relay.rooms.lock().await;
                rooms.entry(claims.rm.clone()).or_default().record_lock(&claims.pid, msg.scope.clone());
            }
            let _ = socket.emit("lock_granted", &serde_json::json!({ "doc": room_name, "scope": msg.scope }));
            let _ = socket
                .to(room_name.clone())
                .emit("presence_lock", &serde_json::json!({ "doc": room_name, "scope": msg.scope, "holder": claims.pid }))
                .await;
        }
        Ok(LockOutcome::Held { holder }) => {
            {
                let mut rooms = relay.rooms.lock().await;
                rooms.entry(claims.rm.clone()).or_default().record_holder(msg.scope.clone(), holder.clone());
            }
            let _ = socket.emit("lock_denied", &serde_json::json!({ "doc": room_name, "scope": msg.scope, "holder": holder }));
        }
        Err(e) => {
            tracing::error!(error = %e, room = %claims.rm, "lock failed");
            let _ = socket.emit("error", &ErrorMsg { doc: room_name, detail: "relay could not take that lock".to_owned() });
        }
    }
}

async fn on_unlock(socket: SocketRef, Data(msg): Data<ScopeMsg>, State(relay): State<Arc<Relay>>) {
    let Some(claims) = socket.extensions.get::<Claims>() else { return };
    let room_name = claims.room();

    let released = {
        let mut bus = relay.bus.lock().await;
        bus.release(&claims.rm, &msg.scope, &claims.pid).await.unwrap_or(false)
    };
    {
        let mut rooms = relay.rooms.lock().await;
        rooms.entry(claims.rm.clone()).or_default().unlock(&claims.pid, &msg.scope);
    }

    // Only a real release is announced. Telling the room about an unlock for a
    // scope this peer never held would clear somebody else's busy marker.
    if released {
        let _ = socket.within(room_name.clone()).emit("lock_released", &serde_json::json!({ "doc": room_name, "scope": msg.scope })).await;
    }
}

async fn on_resync(socket: SocketRef, Data(msg): Data<ResyncMsg>, State(relay): State<Arc<Relay>>) {
    let Some(claims) = socket.extensions.get::<Claims>() else { return };
    let room_name = claims.room();

    let replay = {
        let rooms = relay.rooms.lock().await;
        rooms.get(&claims.rm).and_then(|r| r.since(msg.have))
    };

    match replay {
        Some(ops) => {
            for op in &ops {
                let _ = socket.emit("op", &OpMsg::new(&claims, op));
            }
        }
        None => {
            // The log no longer reaches back that far. A snapshot is the only
            // honest answer, and the relay holds no document, so the peer is
            // told to fetch it from Nextcloud over WebDAV.
            let seq = {
                let rooms = relay.rooms.lock().await;
                rooms.get(&claims.rm).map(Room::seq).unwrap_or(0)
            };
            let _ = socket.emit("snapshot", &serde_json::json!({ "doc": room_name, "seq": seq, "document": serde_json::Value::Null }));
        }
    }
}

/// Pass one opaque frame to the rest of the room.
///
/// Nothing here decodes the payload, assigns it a sequence or keeps a copy. That is the whole
/// point: a caller that signs its own frames and chains each to the previous hash keeps both
/// properties end to end, and a relay that re-read or re-ordered them would break the chain.
/// Not echoed to the sender, which already has it.
async fn on_frame(socket: SocketRef, Data(msg): Data<FrameMsg>, State(relay): State<Arc<Relay>>) {
    let Some(claims) = socket.extensions.get::<Claims>() else { return };
    let room_name = claims.room();
    let _ = &relay;

    if !claims.may_edit() {
        let _ = socket.emit("error", &ErrorMsg { doc: room_name, detail: Refusal::ReadOnly.detail() });
        return;
    }
    if msg.payload.len() > MAX_FRAME_BYTES {
        let _ = socket.emit("error", &ErrorMsg { doc: room_name, detail: Refusal::TooLarge { bytes: msg.payload.len() }.detail() });
        return;
    }

    let _ = socket.to(room_name.clone()).emit("frame", &serde_json::json!({ "doc": room_name, "origin": claims.pid, "payload": msg.payload })).await;
}

/// Record and pass on one latest-wins value about this peer.
///
/// A camera, a selection, a caret. Allowed without edit permission, because somebody watching a
/// design should still be able to say where they are looking. The newest value per peer and kind
/// is kept so a joining peer can be told where everybody is, and nothing here takes a sequence
/// number: ordering ephemeral state would make a stale camera wait behind an edit.
async fn on_ephemeral(socket: SocketRef, Data(msg): Data<EphemeralMsg>, State(relay): State<Arc<Relay>>) {
    let Some(claims) = socket.extensions.get::<Claims>() else { return };
    let room_name = claims.room();

    let remembered = {
        let mut rooms = relay.rooms.lock().await;
        rooms.entry(claims.rm.clone()).or_default().remember_ephemeral(&claims.pid, &msg.kind, msg.payload.clone())
    };
    if let Err(refusal) = remembered {
        let _ = socket.emit("error", &ErrorMsg { doc: room_name, detail: refusal.detail() });
        return;
    }

    let _ = socket
        .to(room_name.clone())
        .emit("ephemeral", &serde_json::json!({ "doc": room_name, "origin": claims.pid, "kind": msg.kind, "payload": msg.payload }))
        .await;
}

async fn on_disconnect(socket: SocketRef, State(relay): State<Arc<Relay>>) {
    let Some(claims) = socket.extensions.get::<Claims>() else { return };
    let room_name = claims.room();

    let (dropped, roster, empty) = {
        let mut rooms = relay.rooms.lock().await;
        let Some(room) = rooms.get_mut(&claims.rm) else { return };
        let dropped = room.leave(&claims.pid);
        let roster = room.peers().to_vec();
        let empty = room.is_empty();
        if empty {
            // Dropping the room frees the op history. The sequence stays in
            // Valkey, so a later peer continues from where this one left off
            // rather than starting again at 1.
            rooms.remove(&claims.rm);
        }
        (dropped, roster, empty)
    };

    // Releasing on disconnect is what makes a lock safe to take at all. One
    // that outlived its holder would wedge the region until the TTL lapsed.
    for scope in &dropped {
        let released = {
            let mut bus = relay.bus.lock().await;
            bus.release(&claims.rm, scope, &claims.pid).await.unwrap_or(false)
        };
        if released {
            let _ = socket.to(room_name.clone()).emit("lock_released", &serde_json::json!({ "doc": room_name, "scope": scope })).await;
        }
    }

    if !empty {
        let _ = socket.to(room_name.clone()).emit("presence", &serde_json::json!({ "doc": room_name, "roster": roster })).await;
    }

    tracing::info!(peer = %claims.pid, room = %claims.rm, locks_dropped = dropped.len(), "peer left");
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
