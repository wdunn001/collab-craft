//! Send a file handle to the connection that issued it.
//!
//! A handle issued for a connection starts with `cx:`, then that connection's
//! id, then the provider's own id. A handle with no such prefix is the legacy
//! single link, which is how every document saved before connections existed
//! still opens.

use std::sync::Arc;

use craft_cloud::{
    Accounts, Capability, Contact, Contacts, Conversations, Entry, Error, Files, Identity, Mail, MailMessage, Notification, Notifications, Permission,
    Provider, Result, Share, ShareOptions, ShareTarget, Sharing, Conversation,
};

const MARK: &str = "cx:";

/// `cx:{connection}:{provider id}`.
///
/// The connection id is 64 hex characters, so the first colon after the mark
/// is the split even when the provider's own id contains colons.
pub fn stamp(connection: &str, raw: &str) -> String {
    format!("{MARK}{connection}:{raw}")
}

/// The connection and the provider's own id, when this handle names one.
pub fn split(opaque: &str) -> Option<(&str, &str)> {
    let rest = opaque.strip_prefix(MARK)?;
    let (id, raw) = rest.split_once(':')?;
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((id, raw))
}

/// The legacy provider, plus every named connection.
pub struct Routed {
    legacy: Option<Arc<dyn Provider + Send + Sync>>,
    connections: Vec<(String, Arc<dyn Provider + Send + Sync>)>,
    default_id: Option<String>,
}

impl Routed {
    pub fn new(
        legacy: Option<Arc<dyn Provider + Send + Sync>>,
        connections: Vec<(String, Arc<dyn Provider + Send + Sync>)>,
        default_id: Option<String>,
    ) -> Routed {
        Routed { legacy, connections, default_id }
    }

    fn active(&self) -> Result<(&dyn Provider, Option<&str>)> {
        if let Some(id) = &self.default_id
            && let Some((_, provider)) = self.connections.iter().find(|(cid, _)| cid == id)
        {
            return Ok((provider.as_ref(), Some(id.as_str())));
        }
        if let Some(provider) = &self.legacy {
            return Ok((provider.as_ref(), None));
        }
        if let Some((id, provider)) = self.connections.first() {
            return Ok((provider.as_ref(), Some(id.as_str())));
        }
        Err(Error::Unsupported("storage"))
    }

    fn open<'a>(&'a self, opaque: &str) -> Result<(&'a dyn Provider, String)> {
        if let Some((id, raw)) = split(opaque) {
            let Some((_, provider)) = self.connections.iter().find(|(cid, _)| cid == id) else {
                return Err(Error::not_found("document", opaque));
            };
            return Ok((provider.as_ref(), raw.to_owned()));
        }
        let Some(provider) = &self.legacy else {
            return Err(Error::not_found("document", opaque));
        };
        Ok((provider.as_ref(), opaque.to_owned()))
    }

    fn issued(&self, connection: Option<&str>, mut entry: Entry) -> Entry {
        if let Some(connection) = connection {
            entry.room = stamp(connection, &entry.room);
            entry.id = stamp(connection, &entry.id);
        }
        entry
    }
}

impl Files for Routed {
    fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let (provider, connection) = self.active()?;
        let (path, connection) = match split(path) {
            Some((id, raw)) => {
                let (provider, _) = self.open(&stamp(id, raw))?;
                return provider.list(raw).map(|entries| entries.into_iter().map(|entry| self.issued(Some(id), entry)).collect());
            }
            None => (path, connection),
        };
        provider.list(path).map(|entries| entries.into_iter().map(|entry| self.issued(connection, entry)).collect())
    }

    fn shared_with_me(&self) -> Result<Vec<Entry>> {
        let (provider, connection) = self.active()?;
        provider.shared_with_me().map(|entries| entries.into_iter().map(|entry| self.issued(connection, entry)).collect())
    }

    fn read(&self, id: &str) -> Result<Vec<u8>> {
        let (provider, raw) = self.open(id)?;
        provider.read(&raw)
    }

    fn read_range(&self, id: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
        let (provider, raw) = self.open(id)?;
        provider.read_range(&raw, offset, length)
    }

    fn write(&self, id: &str, bytes: &[u8], if_match: Option<&str>) -> Result<Entry> {
        let (provider, raw) = self.open(id)?;
        let connection = split(id).map(|(id, _)| id.to_owned());
        provider.write(&raw, bytes, if_match).map(|entry| self.issued(connection.as_deref(), entry))
    }

    fn create(&self, folder: &str, name: &str, bytes: &[u8]) -> Result<Entry> {
        let (folder, connection) = match split(folder) {
            Some((id, raw)) => (raw.to_owned(), Some(id.to_owned())),
            None => {
                let (_, connection) = self.active()?;
                (folder.to_owned(), connection.map(str::to_owned))
            }
        };
        let provider = match &connection {
            Some(id) => self.connections.iter().find(|(cid, _)| cid == id).map(|(_, provider)| provider.as_ref()),
            None => self.legacy.as_ref().map(|provider| provider.as_ref()),
        };
        let Some(provider) = provider else { return Err(Error::Unsupported("storage")) };
        provider.create(&folder, name, bytes).map(|entry| self.issued(connection.as_deref(), entry))
    }

    fn stat(&self, id: &str) -> Result<Entry> {
        let (provider, raw) = self.open(id)?;
        let connection = split(id).map(|(id, _)| id.to_owned());
        provider.stat(&raw).map(|entry| self.issued(connection.as_deref(), entry))
    }
}

impl Sharing for Routed {
    fn share(&self, id: &str, with: &ShareTarget, permission: Permission, options: &ShareOptions) -> Result<Share> {
        let (provider, raw) = self.open(id)?;
        let connection = split(id).map(|(id, _)| id.to_owned());
        provider.share(&raw, with, permission, options).map(|mut share| {
            if let Some(connection) = &connection {
                share.id = stamp(connection, &share.id);
            }
            share
        })
    }

    fn shares(&self, id: &str) -> Result<Vec<Share>> {
        let (provider, raw) = self.open(id)?;
        let connection = split(id).map(|(id, _)| id.to_owned());
        provider.shares(&raw).map(|shares| {
            shares
                .into_iter()
                .map(|mut share| {
                    if let Some(connection) = &connection {
                        share.id = stamp(connection, &share.id);
                    }
                    share
                })
                .collect()
        })
    }

    fn unshare(&self, share_id: &str) -> Result<()> {
        let (provider, raw) = self.open(share_id)?;
        provider.unshare(&raw)
    }
}

impl Contacts for Routed {
    fn search(&self, query: &str, limit: usize) -> Result<Vec<Contact>> {
        self.active()?.0.search(query, limit)
    }
}

impl Notifications for Routed {
    fn notify(&self, user: &str, notification: &Notification) -> Result<()> {
        self.active()?.0.notify(user, notification)
    }
}

impl Mail for Routed {
    fn send(&self, message: &MailMessage) -> Result<()> {
        self.active()?.0.send(message)
    }
}

impl Accounts for Routed {
    fn me(&self) -> Result<Identity> {
        self.active()?.0.me()
    }
}

impl Conversations for Routed {
    fn conversation_name(&self) -> Option<String> {
        self.active().ok().and_then(|(provider, _)| provider.conversation_name())
    }

    fn conversation(&self, id: &str, title: &str) -> Result<Conversation> {
        let (provider, raw) = self.open(id)?;
        provider.conversation(&raw, title)
    }

    fn messages(&self, id: &str, after: Option<&str>) -> Result<Vec<craft_cloud::ChatMessage>> {
        let (provider, raw) = self.open(id)?;
        provider.messages(&raw, after)
    }

    fn post_message(&self, id: &str, text: &str) -> Result<craft_cloud::ChatMessage> {
        let (provider, raw) = self.open(id)?;
        provider.post_message(&raw, text)
    }
}

impl Provider for Routed {
    fn id(&self) -> &str {
        self.active().map(|(provider, _)| provider.id()).unwrap_or("routed")
    }

    fn capabilities(&self) -> Vec<Capability> {
        self.active().map(|(provider, _)| provider.capabilities()).unwrap_or_default()
    }
}
