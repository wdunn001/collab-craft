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
mod sealed;
mod session;
mod settings;
mod state;
mod store;
mod token;
mod transport;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod review_repro;

#[cfg(test)]
mod review_reverify;

#[cfg(test)]
mod review_reverify2;

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

/// The largest document body a save may carry. Axum's own default is 2 MiB,
/// which refuses real documents, so this is the ceiling the API routes use.
const MAX_SAVE_BYTES: usize = 256 * 1024 * 1024;

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
    /// The sequence this connection has already applied, when it is resuming a session rather
    /// than loading the document fresh.
    ///
    /// Absent, or sent as `null`, on a fresh load: an older client that never sends the field
    /// decodes the same way, so this is a compatible extension rather than a breaking one. The
    /// join then baselines on the saved file's sequence as it always did. When it is present,
    /// the join baselines there instead, because that connection already knows what it has
    /// applied and resuming anywhere else either strands it behind a save it never loaded, or
    /// re-sends it ops it already has.
    #[serde(default)]
    applied: Option<u64>,
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

#[derive(Debug, Deserialize)]
struct SavedMsg {
    seq: u64,
}

/// Stashed on a socket once it has actually reached `Room::join`.
///
/// See the comment where it is inserted, in `on_connect`, and where it is read, in
/// `on_disconnect`. `Clone` because `Extensions::insert`/`get` require it, not because a copy
/// of this ever means anything beyond its own presence.
#[derive(Clone)]
struct JoinedRoom;

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
    let store = store::Store::new(&valkey_url, PREFIX_SERVICE)?.sealing_with(&secret_bytes);
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
        .nest("/esign", esign::router())
        // Axum caps a request body at 2 MiB by default, so a save of a real
        // document (a drawing, a sheet with images) was refused with 413 before
        // it ever reached the provider. Raise it to a document-sized ceiling.
        // The provider's own transport still bounds what it will read back.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_SAVE_BYTES));

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
        // Where a desktop sign-in is approved by its user code.
        .route("/device", axum::routing::get(auth::device_page).post(auth::device_approve))
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
        .route("/invite/{key}", axum::routing::get(recipient::offer).post(recipient::open))
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
    socket.on("saved", on_saved);
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

    // Where the document already was, read from the bus before the first peer
    // joins. A room rebuilt in memory starts at sequence zero, and handing out
    // a number a client has already seen is what made a reopen replay or stall.
    let retained_seq = {
        let mut bus = relay.bus.lock().await;
        bus.current_seq(&room_key).await.unwrap_or(0)
    };

    let joined = {
        let mut rooms = relay.rooms.lock().await;
        let room = rooms.entry(room_key.clone()).or_default();
        room.observe_seq(retained_seq);
        match room.join(Peer { peer: peer_id.clone(), display: claims.dsp.clone(), may_edit: claims.may_edit() }) {
            Ok(()) => {
                for (scope, holder) in &locks {
                    room.record_holder(scope.clone(), holder.clone());
                }
                // Catch the joiner up from where IT already is, not from where the
                // saved file is. A connection resuming a session knows what it has
                // already applied, and that is the only baseline that is correct
                // for it: the saved file's sequence can be ahead of it (a save
                // happened while it was gone, and resuming there would skip the
                // edits made before that save that it never saw) or behind it (it
                // is already caught up, and resuming at the file's sequence would
                // re-send ops it has). A fresh load has no applied sequence of its
                // own to offer, and the file it just read is at `saved_seq`, so
                // that is the only baseline available to it. Either way the ops
                // after the baseline bring it current, replayed as ordered ops so
                // the path is the same one a live edit already takes. When the
                // history no longer reaches that baseline, or a burned sequence
                // broke the run, there is nothing clean to replay, so the join
                // falls back to the current sequence and the retained text: the
                // joiner then leans on the file alone, the older behaviour.
                let baseline = handshake.applied.unwrap_or_else(|| room.saved_seq());
                match room.since(baseline) {
                    Some(replay) => Some((baseline, replay, Vec::new(), room.peers().to_vec(), room.ephemeral())),
                    None => {
                        let texts: Vec<(String, Vec<serde_json::Value>, bool)> =
                            room.texts().iter().map(|(scope, log)| (scope.clone(), log.ops().to_vec(), log.complete())).collect();
                        Some((room.seq(), Vec::new(), texts, room.peers().to_vec(), room.ephemeral()))
                    }
                }
            }
            Err(_) => None,
        }
    };

    let Some((seq, replay, texts, roster, ephemeral)) = joined else {
        tracing::warn!(room = %room_key, "refusing a peer: the document is full");
        let _ = socket.emit("error", &ErrorMsg { doc: room_name.clone(), detail: Refusal::Full.detail() });
        let _ = socket.disconnect();
        return;
    };

    // Mark this socket as having actually reached `Room::join`. `on_disconnect` is registered
    // near the top of this function, well before the bus calls that can still refuse the
    // connection (`next_space`, above). A socket disconnected for one of those reasons never
    // joined the room at all, and without this marker its disconnect would still call
    // `Room::leave` for its peer id, which can evict a different, live connection sharing that
    // id and drop its locks.
    socket.extensions.insert(JoinedRoom);

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

    // The ordered ops since the saved version. The joiner applies these on top
    // of the file it loads, exactly as it would a live edit, so the edits made
    // since the last save are not lost. Empty on the fallback path below.
    for op in &replay {
        let _ = socket.emit("op", &OpMsg::new(&claims, op));
    }

    // The fallback catch-up for text, used only when the ordered replay above
    // could not be built. The file the joiner opens is behind the edits made
    // since it was written, and the sequence is already past those edits, so
    // these carry no sequence.
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
    let Some(claims) = live_claims(&socket) else { return };
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
    let preflight = match &scope {
        Some(scope_name) => {
            let mirrored = {
                let rooms = relay.rooms.lock().await;
                rooms.get(&claims.rm).and_then(|r| r.holder_of(scope_name)).map(str::to_owned)
            };
            match mirrored {
                Some(holder) if holder != claims.pid => {
                    // The mirror is refreshed only on a local grant, refusal or release, so a
                    // lease that lapsed naturally in Valkey (its holder's socket went away
                    // without unlocking) leaves the mirror pointing at a holder who no longer
                    // has anything. Confirmed against the bus before refusing on it, rather
                    // than trusted outright: unlike the residual case above, a stale refusal
                    // here is a region the room stays wedged on until something else happens
                    // to touch the mirror, not a one-off burned sequence a resync clears up.
                    let current = {
                        let mut bus = relay.bus.lock().await;
                        bus.current_holder(&claims.rm, scope_name).await
                    };
                    match current {
                        Ok(Some(still)) if still != claims.pid => {
                            let mut rooms = relay.rooms.lock().await;
                            rooms.entry(claims.rm.clone()).or_default().record_holder(scope_name.clone(), still.clone());
                            Err(Refusal::Locked { holder: still })
                        }
                        Ok(_) => {
                            // Either the bus now agrees this peer holds it, or the lease
                            // lapsed and nobody does. Either way the mirror was wrong; forget
                            // it so later submits to this scope do not pay this round trip
                            // again.
                            let mut rooms = relay.rooms.lock().await;
                            rooms.entry(claims.rm.clone()).or_default().forget_lock(scope_name);
                            if claims.may_edit() { Ok(()) } else { Err(Refusal::ReadOnly) }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, room = %claims.rm, scope = %scope_name, "could not confirm a mirrored lock; trusting the mirror");
                            Err(Refusal::Locked { holder })
                        }
                    }
                }
                _ if !claims.may_edit() => Err(Refusal::ReadOnly),
                _ => Ok(()),
            }
        }
        None if !claims.may_edit() => Err(Refusal::ReadOnly),
        None => Ok(()),
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
    let Some(claims) = live_claims(&socket) else { return };
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
    let Some(claims) = live_claims(&socket) else { return };
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
    let Some(claims) = live_claims(&socket) else { return };
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
async fn on_frame(socket: SocketRef, Data(msg): Data<FrameMsg>) {
    // No relay state: a frame is neither sequenced nor stored, so there is nothing to reach
    // for. Every other handler takes it, and taking it here would suggest otherwise.
    let Some(claims) = live_claims(&socket) else { return };
    let room_name = claims.room();

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
    let Some(claims) = live_claims(&socket) else { return };
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

/// Record that the document was saved, so the file's own content is no longer
/// also replayed as operations.
///
/// The client reports the sequence the save reflects. Every retained CRDT
/// operation at or below it is now in the file, so the relay drops it: a joiner
/// that loads the saved file and then receives those operations would otherwise
/// apply them a second time. Requires edit permission: a reader never wrote the
/// file, so it cannot know what the file reflects, and trusting its report would
/// prune another editor's unsaved work out of the replay with no way to tell the
/// two cases apart afterwards. [`Room::checkpoint`] additionally caps the claimed
/// sequence at the room's own, so a save cannot move the join baseline ahead of
/// edits the room has actually ordered.
async fn on_saved(socket: SocketRef, Data(msg): Data<SavedMsg>, State(relay): State<Arc<Relay>>) {
    let Some(claims) = live_claims(&socket) else { return };
    if !claims.may_edit() {
        return;
    }
    let mut rooms = relay.rooms.lock().await;
    if let Some(room) = rooms.get_mut(&claims.rm) {
        room.checkpoint(msg.seq);
    }
}

async fn on_disconnect(socket: SocketRef, State(relay): State<Arc<Relay>>) {
    let Some(claims) = socket.extensions.get::<Claims>() else { return };
    // This socket never reached `Room::join` (refused at `next_space`, or the room was full),
    // so it was never counted into the room and has nothing to release. Calling `Room::leave`
    // anyway would still find the live connection sharing this peer id and evict it, taking
    // its locks with it.
    if socket.extensions.get::<JoinedRoom>().is_none() {
        return;
    }
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

/// The socket's claims, but only while its token still stands.
///
/// Authorisation is decided once, at connect, and cached on the socket. That
/// alone would let a withdrawn or downgraded share keep editing for as long as
/// the socket stays open, which has no bound. Re-reading expiry on every
/// message that changes the document bounds it to the token's own lifetime:
/// once the token lapses the peer is dropped and has to fetch another, and
/// minting one re-stats the provider and re-decides the grant. A client that
/// refreshes its token before then sees no interruption. Disconnecting is safe
/// from a handler, because `on_disconnect` releases every scope the peer held.
fn live_claims(socket: &SocketRef) -> Option<Claims> {
    let claims = socket.extensions.get::<Claims>()?;
    if claims.exp <= now_unix() {
        tracing::info!(room = %claims.rm, "a socket's token expired; dropping it so it must re-authorise");
        // `disconnect` consumes the handle, and this one is borrowed. The handle
        // is a cheap clonable reference to the same socket, so a clone drops it.
        let _ = socket.clone().disconnect();
        return None;
    }
    Some(claims)
}
