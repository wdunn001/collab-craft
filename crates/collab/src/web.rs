//! A [`Hub`] for a browser, over the JS `socket.io-client`.
//!
//! Behind the `web-hub` feature. `rust_socketio` depends on `native-tls` unconditionally and
//! therefore cannot build for `wasm32`, so a browser build leaves [`crate::native`] off and uses
//! this instead.
//!
//! The page supplies the client. `socket.io-client` is loaded as a script and leaves `io` on the
//! global object, which is what this reaches for by name. Nothing is bound at link time, so a
//! page that forgot the script gets a sentence saying so rather than a module that will not
//! instantiate.
//!
//! Callbacks push into a queue and [`WebHub::poll`] drains it, exactly as the native hub does,
//! because [`Hub`] is polled rather than called back. There is no channel and no lock: a browser
//! runs this on one thread, and a queue behind a [`RefCell`] is the honest description of that.
//!
//! The protocol itself is not repeated here. [`emit`] and [`receive`] are the same functions the
//! native hub calls, so a browser peer and a desktop peer cannot drift apart over an event name.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use js_sys::{Function, JSON, Object, Reflect};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};

use crate::error::{Error, Result};
use crate::hub::{EVENTS, Hub, emit, receive};
use crate::proto::{ClientMsg, ServerMsg};

/// A connection to the relay from a browser.
pub struct WebHub {
    socket: JsValue,
    inbox: Rc<RefCell<VecDeque<ServerMsg>>>,
    /// The handlers, kept alive while the socket can still call them. Dropping a [`Closure`]
    /// invalidates the function JavaScript is holding, and the next event would then tear the
    /// page down rather than deliver a message.
    _handlers: Vec<Closure<dyn FnMut(JsValue)>>,
}

impl WebHub {
    /// Connect, through the `socket.io-client` the page loaded.
    ///
    /// `url` is the relay root. `token` is what the service minted. It travels in the Socket.IO
    /// handshake auth, so it never appears in a query string and therefore never lands in an
    /// access log.
    ///
    /// `applied` is the sequence this connection has already applied, when it is resuming a
    /// [`crate::Session`] rather than opening the document fresh. Pass `Session::applied()`
    /// when reconnecting with a session that survived the drop, and `None` on a first join or
    /// after reloading the file. The relay joins at `applied` when it is given and at the
    /// saved file's sequence otherwise, so a reconnect is caught up on exactly what it missed
    /// rather than on what the file happened to be saved at.
    ///
    /// Returns as soon as the socket exists. Socket.IO connects in the background and queues what
    /// is sent meanwhile, and [`Hub::connected`] says whether it has arrived.
    pub fn connect(url: &str, token: &str, applied: Option<u64>) -> Result<WebHub> {
        let global = js_sys::global();
        let io = function(global.as_ref(), "io").ok_or_else(|| Error::Hub("this page has not loaded socket.io-client".to_owned()))?;

        let auth = Object::new();
        Reflect::set(&auth, &JsValue::from_str("token"), &JsValue::from_str(token)).map_err(js)?;
        let applied_js = match applied {
            Some(applied) => JsValue::from_f64(applied as f64),
            None => JsValue::NULL,
        };
        Reflect::set(&auth, &JsValue::from_str("applied"), &applied_js).map_err(js)?;
        let options = Object::new();
        Reflect::set(&options, &JsValue::from_str("auth"), &auth).map_err(js)?;

        let socket = io.call2(global.as_ref(), &JsValue::from_str(url), &options).map_err(js)?;
        let on = function(&socket, "on").ok_or_else(|| Error::Hub("socket.io gave back something that is not a socket".to_owned()))?;

        let inbox = Rc::new(RefCell::new(VecDeque::new()));
        let mut handlers = Vec::with_capacity(EVENTS.len());
        // "error" is in the set because the relay reports its own refusals that way, and an app
        // has to show them rather than have them swallowed into a log.
        for event in EVENTS {
            let queue = Rc::clone(&inbox);
            let handler = Closure::<dyn FnMut(JsValue)>::new(move |payload: JsValue| {
                if let Some(msg) = read(event, &payload) {
                    queue.borrow_mut().push_back(msg);
                }
            });
            on.call2(&socket, &JsValue::from_str(event), handler.as_ref()).map_err(js)?;
            handlers.push(handler);
        }

        Ok(WebHub { socket, inbox, _handlers: handlers })
    }
}

impl Hub for WebHub {
    fn send(&mut self, msg: ClientMsg) -> Result<()> {
        let (event, body) = emit(&msg);
        let payload = to_js(&body)?;
        let emitting = function(&self.socket, "emit").ok_or_else(|| Error::Hub("the relay connection is gone".to_owned()))?;
        emitting.call2(&self.socket, &JsValue::from_str(event), &payload).map_err(js)?;
        Ok(())
    }

    fn poll(&mut self) -> Vec<ServerMsg> {
        // Drained whole. A frame must not block waiting for the relay, and nothing here can
        // block: the queue is already full of what the callbacks delivered.
        self.inbox.borrow_mut().drain(..).collect()
    }

    fn connected(&self) -> bool {
        // Read off the socket each time rather than tracked here. Socket.IO reconnects on its
        // own, and a flag of ours would have to be told about every one of those.
        Reflect::get(&self.socket, &JsValue::from_str("connected")).ok().and_then(|value| value.as_bool()).unwrap_or(false)
    }
}

impl Drop for WebHub {
    /// Close the socket rather than leaving it open for the life of the page.
    fn drop(&mut self) {
        if let Some(disconnect) = function(&self.socket, "disconnect") {
            let _ = disconnect.call0(&self.socket);
        }
    }
}

/// One Socket.IO payload, as a protocol message.
///
/// The payload crosses as JSON text. `JSON.stringify` and `serde_json` agree on that, which is
/// one conversion with no schema of its own in the middle.
fn read(event: &str, payload: &JsValue) -> Option<ServerMsg> {
    let text = match JSON::stringify(payload).ok().and_then(|text| text.as_string()) {
        Some(text) => text,
        None => {
            log::warn!("a {event} payload could not be read as JSON");
            return None;
        }
    };
    match serde_json::from_str(&text) {
        Ok(value) => receive(event, value),
        Err(e) => {
            log::warn!("unreadable {event} payload: {e}");
            None
        }
    }
}

/// One JSON value, as something a Socket.IO client can send.
fn to_js(value: &serde_json::Value) -> Result<JsValue> {
    if value.is_null() {
        return Ok(JsValue::NULL);
    }
    let text = serde_json::to_string(value).map_err(|e| Error::malformed("client", e.to_string()))?;
    JSON::parse(&text).map_err(js)
}

/// One function off an object, by name.
fn function(object: &JsValue, name: &str) -> Option<Function> {
    Reflect::get(object, &JsValue::from_str(name)).ok()?.dyn_into().ok()
}

fn js(error: JsValue) -> Error {
    Error::Hub(describe(&error))
}

/// A JavaScript error in words.
///
/// An `Error` object serialises to `{}`, so its message is read off it rather than stringified.
/// Without this every browser failure reads the same.
fn describe(value: &JsValue) -> String {
    if let Some(text) = value.as_string() {
        return text;
    }
    if let Ok(message) = Reflect::get(value, &JsValue::from_str("message"))
        && let Some(text) = message.as_string()
    {
        return text;
    }
    JSON::stringify(value).ok().and_then(|text| text.as_string()).unwrap_or_else(|| "the browser gave an error it could not describe".to_owned())
}
