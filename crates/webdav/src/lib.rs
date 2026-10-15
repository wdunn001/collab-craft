//! Any WebDAV server, offered through the `craft-cloud` contracts.
//!
//! Files are [RFC 4918] and contacts are [RFC 6352]. Neither belongs to a
//! vendor, so one implementation reaches SabreDAV, Apache `mod_dav`, nginx,
//! Seafile's SeafDAV, a Synology or QNAP, ownCloud Infinite Scale, `rclone
//! serve webdav`, and for contacts Baïkal, Radicale or any other CardDAV
//! server.
//!
//! What plain WebDAV cannot do is reported absent rather than faked. It has no
//! sharing, no notion of "shared with me", no notification and no mail. A
//! caller hides those controls. Files open, save with an etag check, and
//! co-edit through the relay all the same.
//!
//! The provider owns its transport, as every provider does. The requests and
//! parsers underneath come from `craft-nextcloud`, which builds plain WebDAV
//! and CardDAV once the roots are supplied.
//!
//! [RFC 4918]: https://www.rfc-editor.org/rfc/rfc4918
//! [RFC 6352]: https://www.rfc-editor.org/rfc/rfc6352
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use craft_cloud::{
    Capability, Contact as CloudContact, Entry as CloudEntry, EntryKind, Error as CloudError, Identity, MailMessage, Notification, Permission,
    Result as CloudResult, Share as CloudShare, ShareOptions, ShareTarget,
};
use craft_nextcloud::{Account, Contacts, Error, Files, Http, Method, Request};

#[cfg(test)]
mod tests;

/// The placeholder a configured address carries where the user name goes.
///
/// Servers disagree about whether the user is in the path. Nextcloud and
/// ownCloud put it there, SabreDAV's default and Apache usually do not. A
/// template covers both without a setting per server.
pub const USER: &str = "{user}";

/// Where one server keeps things, before a user is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The files root, absolute, optionally carrying [`USER`].
    pub files: String,
    /// The address-book home, absolute, optionally carrying [`USER`]. Absent
    /// on a server with no CardDAV.
    pub contacts: Option<String>,
}

impl Layout {
    pub fn new(files: impl Into<String>, contacts: Option<String>) -> Layout {
        Layout { files: files.into(), contacts: contacts.filter(|c| !c.trim().is_empty()) }
    }

    /// The files root for one user.
    pub fn files_for(&self, user: &str) -> String {
        fill(&self.files, user)
    }

    /// The address-book home for one user.
    pub fn contacts_for(&self, user: &str) -> Option<String> {
        self.contacts.as_deref().map(|c| fill(c, user))
    }

    /// The part of the files address before any user name. What a probe asks,
    /// since nobody is signed in yet.
    pub fn files_unpersonalised(&self) -> String {
        match self.files.find(USER) {
            Some(at) => self.files[..at].to_owned(),
            None => self.files.clone(),
        }
    }
}

/// Put a user name into a template, percent-encoded so it stays one segment.
fn fill(template: &str, user: &str) -> String {
    template.replace(USER, &craft_nextcloud::encode_segment(user)).trim_end_matches('/').to_owned()
}

/// `scheme://host[:port]`, with no path.
///
/// A CardDAV server answers with rooted hrefs, which are resolved against this.
pub fn origin(url: &str) -> String {
    match url.find("://") {
        Some(i) => match url[i + 3..].find('/') {
            Some(j) => url[..i + 3 + j].to_owned(),
            None => url.to_owned(),
        },
        None => url.to_owned(),
    }
}

/// One account on a WebDAV server, with a transport.
pub struct WebDav<H: Http> {
    account: Account,
    has_contacts: bool,
    http: H,
}

impl<H: Http> WebDav<H> {
    /// `user` and `password` are sent as Basic auth. Use an app password or a
    /// token wherever the server issues one.
    pub fn new(layout: &Layout, user: &str, password: &str, http: H) -> WebDav<H> {
        let files = layout.files_for(user);
        let mut account = Account::new(origin(&files), user, password).with_files_root(files);
        let contacts = layout.contacts_for(user);
        if let Some(book) = &contacts {
            account = account.with_addressbook_root(book.clone());
        }
        WebDav { account, has_contacts: contacts.is_some(), http }
    }

    fn files(&self) -> Files<'_> {
        Files::new(&self.account)
    }
}

/// Whether an address answers as a WebDAV server.
///
/// `OPTIONS` needs no credential on most servers and names the DAV classes in
/// a `DAV` header. A server that wants a credential first answers 401 with a
/// challenge, which proves it is there and guarding something. Anything else
/// is not a WebDAV server, or not at that address.
pub fn probe<H: Http>(http: &H, layout: &Layout) -> Result<(), String> {
    let url = layout.files_unpersonalised();
    let resp = http.send(Request::new(Method::Options, url.clone())).map_err(|e| e.to_string())?;
    if resp.is_success() && resp.get_header("dav").is_some() {
        return Ok(());
    }
    if resp.status == 401 && resp.get_header("www-authenticate").is_some() {
        return Ok(());
    }
    if resp.is_success() {
        return Err(format!("{url} answered, and named no DAV support"));
    }
    Err(format!("{url} answered HTTP {}", resp.status))
}

fn lift(e: Error) -> CloudError {
    match e {
        Error::Transport(detail) => CloudError::Unreachable(detail),
        Error::Status { status: 401, .. } => CloudError::Unauthenticated,
        Error::Status { status: 403, .. } => CloudError::Forbidden("the server refused".to_owned()),
        Error::Status { status: 404, path, .. } => CloudError::not_found("entry", path),
        Error::Status { status: 409 | 412, .. } => CloudError::Conflict("the document".to_owned()),
        Error::Status { method, status, .. } => CloudError::Unreachable(format!("{method} returned HTTP {status}")),
        Error::Ocs { message, .. } => CloudError::malformed("response", message),
        Error::Malformed { what, detail } => CloudError::Malformed { what, detail },
        Error::Invalid { what, detail } => CloudError::Invalid { what, detail },
    }
}

fn entry_from(e: craft_nextcloud::Entry) -> CloudEntry {
    CloudEntry {
        id: e.path.clone(),
        // A server reporting a file id (ownCloud Infinite Scale, SabreDAV with
        // the ownCloud plugin) keeps the room across a rename. Plain WebDAV has
        // nothing stable but the path, so a rename mid-session splits the room.
        room: if e.file_id.is_empty() { e.path.clone() } else { e.file_id.clone() },
        name: e.name,
        path: e.path,
        kind: if e.is_dir { EntryKind::Folder } else { EntryKind::File },
        size: (!e.is_dir).then_some(e.size),
        modified: (!e.modified.is_empty()).then_some(e.modified),
        mime: (!e.content_type.is_empty()).then_some(e.content_type),
        etag: (!e.etag.is_empty()).then_some(e.etag),
        writable: true,
        shared_by: None,
    }
}

impl<H: Http> craft_cloud::Files for WebDav<H> {
    fn list(&self, path: &str) -> CloudResult<Vec<CloudEntry>> {
        let at = if path.is_empty() { "/" } else { path };
        let mut out = Vec::new();
        for e in self.files().list(&self.http, at).map_err(lift)? {
            if e.path.trim_end_matches('/') == at.trim_end_matches('/') {
                continue;
            }
            out.push(entry_from(e));
        }
        Ok(out)
    }

    fn shared_with_me(&self) -> CloudResult<Vec<CloudEntry>> {
        // The contract asks for an empty list where the server cannot say.
        Ok(Vec::new())
    }

    fn read(&self, id: &str) -> CloudResult<Vec<u8>> {
        self.files().get(&self.http, id).map_err(lift)
    }

    fn write(&self, id: &str, bytes: &[u8], if_match: Option<&str>) -> CloudResult<CloudEntry> {
        self.files().put(&self.http, id, bytes.to_vec(), if_match).map_err(lift)?;
        craft_cloud::Files::stat(self, id)
    }

    fn create(&self, folder: &str, name: &str, bytes: &[u8]) -> CloudResult<CloudEntry> {
        let path = format!("{}/{}", folder.trim_end_matches('/'), name);
        self.files().put(&self.http, &path, bytes.to_vec(), None).map_err(lift)?;
        craft_cloud::Files::stat(self, &path)
    }

    fn stat(&self, id: &str) -> CloudResult<CloudEntry> {
        self.files().stat(&self.http, id).map(entry_from).map_err(lift)
    }
}

impl<H: Http> craft_cloud::Sharing for WebDav<H> {
    fn share(&self, _id: &str, _with: &ShareTarget, _permission: Permission, _options: &ShareOptions) -> CloudResult<CloudShare> {
        Err(CloudError::Unsupported("sharing"))
    }

    fn shares(&self, _id: &str) -> CloudResult<Vec<CloudShare>> {
        Err(CloudError::Unsupported("sharing"))
    }

    fn unshare(&self, _share_id: &str) -> CloudResult<()> {
        Err(CloudError::Unsupported("sharing"))
    }
}

impl<H: Http> craft_cloud::Contacts for WebDav<H> {
    fn search(&self, query: &str, limit: usize) -> CloudResult<Vec<CloudContact>> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() || !self.has_contacts {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for c in Contacts::new(&self.account).all(&self.http).map_err(lift)? {
            if out.len() >= limit {
                break;
            }
            let matches = c.name.to_lowercase().contains(&needle) || c.emails.iter().any(|e| e.to_lowercase().contains(&needle));
            // A plain CardDAV server knows addresses and nothing about accounts.
            let Some(email) = c.emails.first().cloned().filter(|_| matches) else { continue };
            out.push(CloudContact {
                id: email.clone(),
                target: ShareTarget::Email(email.clone()),
                name: if c.name.is_empty() { email.clone() } else { c.name },
                email: Some(email),
                avatar: None,
                is_group: false,
            });
        }
        Ok(out)
    }
}

impl<H: Http> craft_cloud::Notifications for WebDav<H> {
    fn notify(&self, _user: &str, _notification: &Notification) -> CloudResult<()> {
        Err(CloudError::Unsupported("notifications"))
    }
}

impl<H: Http> craft_cloud::Mail for WebDav<H> {
    fn send(&self, _message: &MailMessage) -> CloudResult<()> {
        Err(CloudError::Unsupported("mail"))
    }
}

impl<H: Http> craft_cloud::Accounts for WebDav<H> {
    /// The login name, once the server has accepted it.
    ///
    /// WebDAV has no profile to read. Asking for the root's own properties
    /// proves the credential, which is what linking needs: a wrong password
    /// is refused here and never stored.
    fn me(&self) -> CloudResult<Identity> {
        self.files().stat(&self.http, "/").map_err(lift)?;
        let user = self.account.user().to_owned();
        Ok(Identity { id: user.clone(), display: user, email: None, avatar: None })
    }
}

impl<H: Http> craft_cloud::Conversations for WebDav<H> {}

impl<H: Http> craft_cloud::Provider for WebDav<H> {
    fn id(&self) -> &str {
        "webdav"
    }

    fn capabilities(&self) -> Vec<Capability> {
        let mut out = vec![Capability::Files, Capability::Etags];
        if self.has_contacts {
            out.push(Capability::Contacts);
        }
        out
    }
}
