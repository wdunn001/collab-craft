//! A [`Hub`] for native apps, over `rust_socketio`.
//!
//! Behind the `native-hub` feature, because `rust_socketio` depends on
//! `native-tls` unconditionally and therefore cannot build for `wasm32`. A
//! browser build leaves this off and uses [`crate::web`] instead.
//!
//! The bridge is the whole point of this module. `rust_socketio` is async and
//! callback driven. [`Hub`] is synchronous and polled, because an egui app wants
//! to drain messages once per frame rather than be called back on another
//! thread. So callbacks push into a channel, [`NativeHub::poll`] drains it, and
//! sends go out through a task that owns the socket.
//!
//! The protocol itself is not here. [`emit`] and [`receive`] are the same
//! functions the browser hub calls, so the two peers cannot drift apart over
//! an event name.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rust_socketio::asynchronous::{Client, ClientBuilder};
use rust_socketio::{Event, Payload};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::error::{Error, Result};
use crate::hub::{EVENTS, Hub, emit, receive};
use crate::proto::{ClientMsg, ServerMsg};

/// A connection to the relay from a native app.
pub struct NativeHub {
    outbox: UnboundedSender<ClientMsg>,
    inbox: UnboundedReceiver<ServerMsg>,
    connected: Arc<AtomicBool>,
}

impl NativeHub {
    /// Connect, and keep the socket on a task of its own.
    ///
    /// Must be called from inside a Tokio runtime, which a native Craft app has
    /// because the relay client is the only async thing it owns.
    ///
    /// `url` is the relay root. `token` is what the Nextcloud app minted; it
    /// travels in the Socket.IO handshake auth, so it never appears in a query
    /// string and therefore never lands in an access log.
    ///
    /// `applied` is the sequence this connection has already applied, when it is resuming a
    /// [`crate::Session`] rather than opening the document fresh. Pass `Session::applied()`
    /// when reconnecting with a session that survived the drop, and `None` on a first join or
    /// after reloading the file. The relay joins at `applied` when it is given and at the
    /// saved file's sequence otherwise, so a reconnect is caught up on exactly what it missed
    /// rather than on what the file happened to be saved at.
    pub async fn connect(url: &str, token: &str, applied: Option<u64>) -> Result<NativeHub> {
        let (in_tx, inbox) = unbounded_channel::<ServerMsg>();
        let (outbox, mut out_rx) = unbounded_channel::<ClientMsg>();
        let connected = Arc::new(AtomicBool::new(false));

        let mut builder = ClientBuilder::new(url).auth(serde_json::json!({ "token": token, "applied": applied }));

        // "error" is in the list because the relay reports its own refusals
        // that way, and an app needs to show them rather than have them
        // swallowed into a log.
        for event in EVENTS {
            let tx = in_tx.clone();
            builder = builder.on(event, move |payload, _client| {
                let tx = tx.clone();
                Box::pin(async move {
                    for msg in decode_payload(event, payload) {
                        // A closed receiver means the app dropped the hub. Not
                        // an error, just nothing left to deliver to.
                        let _ = tx.send(msg);
                    }
                })
            });
        }

        let flag = connected.clone();
        builder = builder.on(Event::Close, move |_, _| {
            let flag = flag.clone();
            Box::pin(async move {
                flag.store(false, Ordering::Relaxed);
            })
        });

        let client: Client = builder.connect().await.map_err(|e| Error::Hub(e.to_string()))?;
        connected.store(true, Ordering::Relaxed);

        // One task owns the socket. Sends are queued rather than awaited by the
        // caller, which is what lets [`Hub::send`] stay synchronous.
        let flag = connected.clone();
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                let (event, body) = emit(&msg);
                if let Err(e) = client.emit(event, body).await {
                    log::warn!("relay send failed: {e}");
                    flag.store(false, Ordering::Relaxed);
                }
            }
            // The outbox closed, so the hub is gone. Close the socket rather
            // than leaking it for the process lifetime.
            let _ = client.disconnect().await;
        });

        Ok(NativeHub { outbox, inbox, connected })
    }
}

impl Hub for NativeHub {
    fn send(&mut self, msg: ClientMsg) -> Result<()> {
        self.outbox.send(msg).map_err(|_| Error::Hub("relay connection is gone".to_owned()))
    }

    fn poll(&mut self) -> Vec<ServerMsg> {
        let mut out = Vec::new();
        // try_recv, never recv. A frame must not block waiting for the relay.
        while let Ok(msg) = self.inbox.try_recv() {
            out.push(msg);
        }
        out
    }

    fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

/// Turn one Socket.IO payload into protocol messages.
///
/// A payload can carry several values, and a malformed one is skipped with a
/// log line. Dropping a message we cannot read beats tearing down a live
/// session over it.
fn decode_payload(event: &str, payload: Payload) -> Vec<ServerMsg> {
    let values: Vec<serde_json::Value> = match payload {
        Payload::Text(values) => values,
        Payload::Binary(_) => {
            log::debug!("ignoring a binary payload; the protocol is JSON");
            return Vec::new();
        }
        // Deprecated upstream in favour of Payload::Text, and still matched so
        // a relay on an older protocol does not go silently unread. The allow
        // is narrow on purpose: dropping the arm would turn an old server into
        // a session that connects and then receives nothing.
        #[allow(deprecated)]
        Payload::String(s) => match serde_json::from_str(&s) {
            Ok(v) => vec![v],
            Err(e) => {
                log::warn!("unreadable string payload on {event}: {e}");
                return Vec::new();
            }
        },
    };

    values.into_iter().filter_map(|v| receive(event, v)).collect()
}
