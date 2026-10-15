//! Nextcloud as one implementation of the `craft-cloud` contracts.
//!
//! Everything here maps a generic call onto this product's own APIs: WebDAV
//! for files, the OCS Share API for sharing, CardDAV for contacts, the Mail
//! app for mail. Nothing above this layer knows which of those it is getting.
//!
//! The provider owns its transport, because the contracts take none. That is
//! the difference between this crate's own modules, which accept an `Http` on
//! every call so they can be driven in a test with no server, and the provider
//! surface, which is what an application actually holds.

use craft_cloud::{
    Capability, Contact as CloudContact, Conversation as CloudConversation, Entry as CloudEntry, EntryKind, Error as CloudError, Identity,
    MailMessage, Notification, Permission, Result as CloudResult, Share as CloudShare, ShareOptions, ShareTarget,
};

use crate::http::{Http, Method};
use crate::mail::{Mail, MailAccount, NewMessage};
use crate::share::{NewShare, Permissions, ShareKind};
use crate::{Account, Contacts, Error, Files, Shares, send};

/// Which of the two servers sharing this protocol family is on the other end.
///
/// ownCloud Server is where Nextcloud forked from. Files, CardDAV, the OCS
/// Share API, the sharee search and `cloud/user` answer the same way on both.
/// What ownCloud lacks is everything Nextcloud added afterwards: Talk, the Mail
/// app and administrator notifications. The flavour decides only that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    Nextcloud,
    OwnCloud,
}

/// A Nextcloud (or ownCloud) account, with a transport, offered through the
/// generic contracts.
pub struct Nextcloud<H: Http> {
    account: Account,
    http: H,
    flavor: Flavor,
}

impl<H: Http> Nextcloud<H> {
    pub fn new(account: Account, http: H) -> Nextcloud<H> {
        Nextcloud { account, http, flavor: Flavor::Nextcloud }
    }

    /// An ownCloud Server account. See [`Flavor`] for what differs.
    pub fn owncloud(account: Account, http: H) -> Nextcloud<H> {
        Nextcloud { account, http, flavor: Flavor::OwnCloud }
    }

    pub fn flavor(&self) -> Flavor {
        self.flavor
    }

    /// Where a user's avatar is drawn.
    ///
    /// Through `index.php`, because ownCloud only routes it that way and
    /// Nextcloud answers both forms.
    fn avatar(&self, user: &str) -> String {
        match self.flavor {
            Flavor::Nextcloud => format!("{}/avatar/{}/64", self.account.base(), user),
            Flavor::OwnCloud => format!("{}/index.php/avatar/{}/64", self.account.base(), crate::encode_segment(user)),
        }
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    fn files(&self) -> Files<'_> {
        Files::new(&self.account)
    }

    fn share_api(&self) -> Shares<'_> {
        Shares::new(&self.account)
    }
}

/// This crate's errors in the vocabulary the contracts use.
///
/// The mapping is what makes a caller able to act without knowing the
/// provider. A 401 has to become `Unauthenticated` so a UI offers a sign-in,
/// and a 412 has to become `Conflict` so a save offers to reload rather than
/// to retry.
fn lift(e: Error) -> CloudError {
    match e {
        Error::Transport(detail) => CloudError::Unreachable(detail),
        Error::Status { status: 401, .. } => CloudError::Unauthenticated,
        // The reason, not the URL. An earlier revision put the endpoint in
        // these, so a share refused for a missing recipient read as
        // "entry not found: https://…/shares", which names the one thing that
        // was definitely there.
        Error::Status { status: 403, body, .. } => CloudError::Forbidden(reason(&body, "refused")),
        Error::Status { status: 404, body, .. } => CloudError::not_found("entry", reason(&body, "no such entry")),
        Error::Status { status: 409 | 412, body, .. } => CloudError::Conflict(reason(&body, "changed since you opened it")),
        // The same lesson as the arms above, one status further out. A Mail
        // send that SMTP refuses arrives as a 500 carrying "Could not send
        // message". That sentence is the only thing a user can act on. Where
        // the body carries nothing, the method and the status are all there
        // is to report.
        Error::Status { method, path, status, body } => match explanation(&body) {
            Some(detail) => CloudError::Unreachable(format!("{method} returned HTTP {status}: {detail}")),
            None => CloudError::Unreachable(format!("{method} {path} returned HTTP {status}")),
        },
        // OCS answers HTTP 200 and reports the real outcome in its own
        // envelope, so these codes are the only signal there is.
        Error::Ocs { code: 403 | 404, message } => CloudError::Forbidden(message),
        Error::Ocs { code, message } => CloudError::Malformed { what: "ocs", detail: format!("statuscode {code}: {message}") },
        Error::Malformed { what, detail } => CloudError::Malformed { what, detail },
        Error::Invalid { what, detail } => CloudError::Invalid { what, detail },
    }
}

/// The server's own explanation, out of a response body.
///
/// OCS puts a human sentence in `<message>` even when it answers with an HTTP
/// status. That sentence is the only part worth showing. The Mail app answers
/// JSON and puts the same thing in a `"message"` field. Both forms therefore
/// turn up here.
///
/// A scan does the reading, where a parser would read better.
/// [`Error::Status`] truncates the body it carries so a server answering with
/// a whole HTML error page cannot flood a log line. A parser cannot read a
/// document that stops in the middle. A scan still finds the sentence in a
/// truncated body as long as the sentence itself survived.
fn explanation(body: &str) -> Option<String> {
    for (open, close) in [("<message>", "</message>"), ("\"message\":\"", "\"")] {
        let Some(start) = body.find(open) else { continue };
        let rest = &body[start + open.len()..];
        let Some(end) = rest.find(close).filter(|end| *end > 0) else { continue };
        let found = rest[..end].trim();
        if !found.is_empty() {
            return Some(found.to_owned());
        }
    }
    None
}

/// The server's explanation, or `fallback` where it gave none.
fn reason(body: &str, fallback: &str) -> String {
    explanation(body).unwrap_or_else(|| fallback.to_owned())
}

fn entry_from(e: crate::dav::Entry, shared_by: Option<String>, writable: bool) -> CloudEntry {
    CloudEntry {
        // WebDAV addresses a file by path, so that is the handle. It is opaque
        // above this layer.
        id: e.path.clone(),
        // The file id survives a rename, which a room has to.
        room: if e.file_id.is_empty() { e.path.clone() } else { e.file_id.clone() },
        name: e.name,
        path: e.path,
        kind: if e.is_dir { EntryKind::Folder } else { EntryKind::File },
        size: (!e.is_dir).then_some(e.size),
        modified: (!e.modified.is_empty()).then_some(e.modified),
        mime: (!e.content_type.is_empty()).then_some(e.content_type),
        etag: (!e.etag.is_empty()).then_some(e.etag),
        writable,
        shared_by,
    }
}

impl<H: Http> craft_cloud::Files for Nextcloud<H> {
    fn list(&self, path: &str) -> CloudResult<Vec<CloudEntry>> {
        let at = if path.is_empty() { "/" } else { path };
        let mut out = Vec::new();
        for e in self.files().list(&self.http, at).map_err(lift)? {
            // PROPFIND Depth 1 includes the collection itself. A file picker
            // showing a folder inside itself is a bug users notice at once.
            if e.path.trim_end_matches('/') == at.trim_end_matches('/') {
                continue;
            }
            out.push(entry_from(e, None, true));
        }
        Ok(out)
    }

    fn shared_with_me(&self) -> CloudResult<Vec<CloudEntry>> {
        // The OCS Share API answers this, where WebDAV cannot: an incoming
        // share has no single parent folder to list.
        let url = format!("{}/ocs/v2.php/apps/files_sharing/api/v1/shares?shared_with_me=true", self.account.base());
        let req = self.account.request(Method::Get, url);
        let resp = send(&self.http, req).map_err(lift)?;
        crate::share::check_ocs(&resp.body).map_err(lift)?;

        let mut out = Vec::new();
        for g in crate::xml::groups(&resp.body, "element").map_err(lift)? {
            let Some(path) = g.get("path").filter(|p| !p.is_empty()).map(str::to_owned) else { continue };
            let permissions = Permissions(g.get("permissions").and_then(|p| p.parse().ok()).unwrap_or(1));
            let is_dir = g.get("item_type").is_some_and(|t| t == "folder");
            out.push(CloudEntry {
                id: path.clone(),
                // file_source is this file's id on the owner's side, which is
                // what both peers must agree on for a shared room.
                room: g.get("file_source").filter(|v| !v.is_empty()).unwrap_or(&path).to_owned(),
                name: path.rsplit('/').next().unwrap_or(&path).to_owned(),
                path,
                kind: if is_dir { EntryKind::Folder } else { EntryKind::File },
                size: g.get("item_size").and_then(|v| v.parse().ok()),
                modified: None,
                mime: g.get("mimetype").filter(|v| !v.is_empty()).map(str::to_owned),
                etag: None,
                writable: permissions.contains(Permissions::UPDATE),
                shared_by: g.get("displayname_owner").or_else(|| g.get("uid_owner")).filter(|v| !v.is_empty()).map(str::to_owned),
            });
        }
        Ok(out)
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
        // No if_match: a create is not replacing anything the caller has read.
        self.files().put(&self.http, &path, bytes.to_vec(), None).map_err(lift)?;
        craft_cloud::Files::stat(self, &path)
    }

    fn stat(&self, id: &str) -> CloudResult<CloudEntry> {
        // Depth 0. Filtering a Depth 1 listing cannot work here, because that
        // listing drops the very entry being asked about.
        self.files().stat(&self.http, id).map(|e| entry_from(e, None, true)).map_err(lift)
    }
}

impl<H: Http> craft_cloud::Sharing for Nextcloud<H> {
    fn share(&self, id: &str, with: &ShareTarget, permission: Permission, options: &ShareOptions) -> CloudResult<CloudShare> {
        let perms = match permission {
            Permission::View => Permissions::READ,
            Permission::Edit => Permissions::EDIT,
        };
        let mut new = match with {
            ShareTarget::User(u) => NewShare::with_user(id, u.clone()),
            ShareTarget::Group(g) => NewShare { kind: ShareKind::Group, share_with: g.clone(), ..NewShare::with_user(id, g.clone()) },
            ShareTarget::Email(a) => NewShare { kind: ShareKind::Email, share_with: a.clone(), ..NewShare::with_user(id, a.clone()) },
            ShareTarget::Link => NewShare::public_link(id),
        };
        new = new.permissions(perms).send_mail(options.notify);
        if let Some(n) = &options.note {
            new = new.note(n.clone());
        }
        // A key on a link, which is what reaches somebody with no account.
        if let Some(p) = &options.password {
            new = new.password(p.clone());
        }
        if let Some(d) = &options.expires {
            new = new.expires(d.clone());
        }
        let created = self.share_api().create(&self.http, &new).map_err(lift)?;
        Ok(share_from(created))
    }

    fn shares(&self, id: &str) -> CloudResult<Vec<CloudShare>> {
        Ok(self.share_api().list(&self.http, Some(id)).map_err(lift)?.into_iter().map(share_from).collect())
    }

    fn unshare(&self, share_id: &str) -> CloudResult<()> {
        self.share_api().delete(&self.http, share_id).map_err(lift)
    }
}

fn share_from(s: crate::share::Share) -> CloudShare {
    let target = match s.kind {
        Some(ShareKind::Group) => ShareTarget::Group(s.share_with.clone()),
        Some(ShareKind::Email) => ShareTarget::Email(s.share_with.clone()),
        Some(ShareKind::PublicLink) => ShareTarget::Link,
        _ => ShareTarget::User(s.share_with.clone()),
    };
    CloudShare {
        id: s.id,
        target,
        // The server knows what the recipient is called. It says so only
        // sometimes, and an account id is all there is to fall back on.
        display: (!s.share_with_name.trim().is_empty()).then(|| s.share_with_name.clone()),
        permission: if s.permissions.contains(Permissions::UPDATE) { Permission::Edit } else { Permission::View },
        url: (!s.url.is_empty()).then_some(s.url),
        note: None,
        created: None,
    }
}

impl<H: Http> craft_cloud::Contacts for Nextcloud<H> {
    fn search(&self, query: &str, limit: usize) -> CloudResult<Vec<CloudContact>> {
        let needle = query.trim();
        if needle.is_empty() {
            return Ok(Vec::new());
        }

        // Accounts and groups first, from the sharee search. It states the
        // share type for each match, so a colleague with an account is shared
        // as that account rather than as whatever address their vCard happens
        // to carry.
        let mut out: Vec<CloudContact> = Vec::new();
        match self.sharees(needle, limit) {
            Ok(found) => out.extend(found),
            // Not fatal. The address book below still answers, and half a list
            // beats an error for something somebody is typing into.
            Err(e) => log::warn!("the sharee search failed, falling back to the address book: {e}"),
        }

        // Then the address book, which is where the people who have no account
        // here live. They are reachable by address.
        let lowered = needle.to_lowercase();
        for c in Contacts::new(&self.account).all(&self.http).map_err(lift)? {
            if out.len() >= limit {
                break;
            }
            let matches = c.name.to_lowercase().contains(&lowered)
                || c.user_id.to_lowercase().contains(&lowered)
                || c.emails.iter().any(|e| e.to_lowercase().contains(&lowered));
            if !matches {
                continue;
            }
            let Some(id) = c.share_target().map(str::to_owned) else { continue };
            // The same person can reach here twice. The sharee search knows
            // them as an account and carries no address. The address book knows
            // the address and often not the account. Matching on the handle
            // alone misses that, because one side's handle is a user id and the
            // other's is an address.
            //
            // So match on anything that identifies a person, and when it is
            // somebody already listed, give the account row the address rather
            // than adding a row beside it. An account is the better share, and
            // a row that shows the address as well is the more useful one.
            let same = |existing: &CloudContact| {
                existing.id.eq_ignore_ascii_case(&id)
                    || (!c.user_id.is_empty() && existing.id.eq_ignore_ascii_case(&c.user_id))
                    || existing.email.as_deref().is_some_and(|e| c.emails.iter().any(|a| a.eq_ignore_ascii_case(e)))
                    || c.emails.iter().any(|a| a.eq_ignore_ascii_case(&existing.id))
                    || (!c.name.is_empty() && existing.name.eq_ignore_ascii_case(&c.name))
            };
            if let Some(listed) = out.iter_mut().find(|existing| same(existing)) {
                if listed.email.is_none() {
                    listed.email = c.emails.first().cloned();
                }
                continue;
            }
            let target = if c.user_id.is_empty() { ShareTarget::Email(id.clone()) } else { ShareTarget::User(id.clone()) };
            out.push(CloudContact {
                id,
                target,
                name: if c.name.is_empty() { c.user_id.clone() } else { c.name.clone() },
                email: c.emails.first().cloned(),
                avatar: (!c.user_id.is_empty()).then(|| self.avatar(&c.user_id)),
                is_group: false,
            });
        }
        Ok(out)
    }
}

/// Share types, as the OCS Share API numbers them.
const SHARE_TYPE_USER: i64 = 0;
const SHARE_TYPE_GROUP: i64 = 1;
const SHARE_TYPE_EMAIL: i64 = 4;

impl<H: Http> Nextcloud<H> {
    /// Accounts, groups and known addresses, from Nextcloud's own sharee
    /// search.
    ///
    /// This is the only source that states the share type, and it also applies
    /// the instance's rules about who may see whom.
    fn sharees(&self, needle: &str, limit: usize) -> CloudResult<Vec<CloudContact>> {
        let url = format!(
            "{}/ocs/v2.php/apps/files_sharing/api/v1/sharees?search={}&itemType=file&perPage={}&lookup=false",
            self.account.base().trim_end_matches('/'),
            crate::encode_segment(needle),
            limit.clamp(1, 50),
        );
        // JSON, because the answer is nested lists keyed by share type and the
        // crate's XML helpers flatten exactly the nesting that carries the
        // meaning.
        let req = self.account.request(Method::Get, url).header("accept", "application/json");
        let resp = send(&self.http, req).map_err(lift)?;
        let body: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| CloudError::malformed("sharees", e.to_string()))?;
        let data = body.pointer("/ocs/data").ok_or_else(|| CloudError::malformed("sharees", "no ocs data"))?;

        let mut out = Vec::new();
        // Exact matches first, so somebody who typed a whole address sees it
        // at the top rather than hunting for it.
        if let Some(exact) = data.get("exact").and_then(serde_json::Value::as_object) {
            for rows in exact.values() {
                collect_sharees(rows, &mut out, limit);
            }
        }
        for kind in ["users", "groups", "emails", "remotes"] {
            collect_sharees(data.get(kind).unwrap_or(&serde_json::Value::Null), &mut out, limit);
        }
        Ok(out)
    }
}

/// Turn one bucket of sharee results into contacts.
///
/// The share type travels with each row, so the target is read rather than
/// guessed. Guessing it is what produced user shares addressed to an email.
fn collect_sharees(rows: &serde_json::Value, out: &mut Vec<CloudContact>, limit: usize) {
    let Some(rows) = rows.as_array() else { return };
    for row in rows {
        if out.len() >= limit {
            return;
        }
        let Some(value) = row.get("value") else { continue };
        let Some(share_with) = value.get("shareWith").and_then(serde_json::Value::as_str) else { continue };
        let kind = value.get("shareType").and_then(serde_json::Value::as_i64).unwrap_or(SHARE_TYPE_USER);
        let target = match kind {
            SHARE_TYPE_GROUP => ShareTarget::Group(share_with.to_owned()),
            SHARE_TYPE_EMAIL => ShareTarget::Email(share_with.to_owned()),
            SHARE_TYPE_USER => ShareTarget::User(share_with.to_owned()),
            // A kind of share this client has no UI for, such as federated or
            // circle. Offering it would mean offering something that cannot be
            // rendered or withdrawn.
            _ => continue,
        };
        // The same person appears under both the exact and the partial
        // buckets, and twice in a list looks broken.
        if out.iter().any(|existing: &CloudContact| existing.target == target) {
            continue;
        }
        let label = row.get("label").and_then(serde_json::Value::as_str).unwrap_or(share_with);
        let email = if kind == SHARE_TYPE_EMAIL {
            Some(share_with.to_owned())
        } else {
            value.get("shareWithAdditionalInfo").and_then(serde_json::Value::as_str).map(str::to_owned)
        };
        out.push(CloudContact { id: share_with.to_owned(), target, name: label.to_owned(), email, avatar: None, is_group: kind == SHARE_TYPE_GROUP });
    }
}

impl<H: Http> craft_cloud::Notifications for Nextcloud<H> {
    fn notify(&self, user: &str, notification: &Notification) -> CloudResult<()> {
        if self.flavor == Flavor::OwnCloud {
            // ownCloud's notifications app takes no notification from a client.
            return Err(CloudError::Unsupported("notifications"));
        }
        // Nextcloud only lets an administrator raise a notification for
        // another account. A share already raises one by itself, so this is
        // for everything else and will refuse for an ordinary account.
        let url = format!("{}/ocs/v2.php/apps/notifications/api/v2/admin_notifications/{user}", self.account.base());
        let body = format!(
            "shortMessage={}&longMessage={}",
            crate::encode_segment(&notification.subject),
            crate::encode_segment(notification.body.as_deref().unwrap_or("")),
        );
        let req = self.account.request(Method::Post, url).header("content-type", "application/x-www-form-urlencoded").body(body.into_bytes());
        send(&self.http, req).map_err(lift)?;
        Ok(())
    }
}

/// Mail, through the Mail app.
///
/// An earlier revision refused this and said Nextcloud had no general send.
/// That was wrong. Mail is a separate app carrying its own API. An instance
/// running it sends to whoever the caller names.
///
/// The external recipient flow depends on exactly that. A share to somebody
/// with no account mints a keyed link. The link then has to reach them.
///
/// The send goes from one of this user's own mail accounts. The recipient
/// sees a person they can reply to.
impl<H: Http> craft_cloud::Mail for Nextcloud<H> {
    fn send(&self, message: &MailMessage) -> CloudResult<()> {
        if self.flavor == Flavor::OwnCloud {
            // There is no Mail app for ownCloud with an API to send through.
            return Err(CloudError::Unsupported("mail"));
        }
        let mail = Mail::new(&self.account);
        let accounts = mail.accounts(&self.http).map_err(lift)?;
        // The first account that can send, in the server's own order. That is
        // the order the Mail app itself composes from.
        let Some(from) = accounts.iter().find(|a| a.can_send()) else {
            // Nothing to grant here and nothing to retry. The capability list
            // leaves Mail out in this same case. A caller that checks first
            // never arrives here.
            return Err(CloudError::Unsupported("sending mail without a mail account that can send"));
        };
        let outgoing = NewMessage { to: message.to.clone(), subject: message.subject.clone(), body: message.body.clone(), html: message.html };
        mail.send(&self.http, from.id, &outgoing).map_err(lift)
    }
}

impl<H: Http> craft_cloud::Accounts for Nextcloud<H> {
    fn me(&self) -> CloudResult<Identity> {
        let url = format!("{}/ocs/v2.php/cloud/user", self.account.base());
        let req = self.account.request(Method::Get, url);
        let resp = send(&self.http, req).map_err(lift)?;
        crate::share::check_ocs(&resp.body).map_err(lift)?;
        let data = crate::xml::one_group(&resp.body, "data").map_err(lift)?;
        let id = data.get("id").filter(|v| !v.is_empty()).unwrap_or(self.account.user()).to_owned();
        Ok(Identity {
            display: data.get("displayname").filter(|v| !v.is_empty()).unwrap_or(&id).to_owned(),
            email: data.get("email").filter(|v| !v.is_empty()).map(str::to_owned),
            avatar: Some(self.avatar(&id)),
            id,
        })
    }
}

impl<H: Http> Nextcloud<H> {
    /// What this instance allows for public links.
    ///
    /// Read rather than assumed. An administrator can forbid public links, or
    /// require a password on every one, and a dialog that offers either anyway
    /// is offering something the server will refuse.
    ///
    /// A server that will not answer is treated as allowing nothing, so the
    /// failure is a missing button rather than one that does not work.
    /// What this instance reports about itself.
    ///
    /// One call, because the capabilities endpoint answers for every app
    /// at once. Nothing here is assumed. An administrator can turn public
    /// links off or never install Talk, and the dialog has to follow.
    fn instance_capabilities(&self) -> Vec<Capability> {
        let url = format!("{}/ocs/v2.php/cloud/capabilities", self.account.base().trim_end_matches('/'));
        let req = self.account.request(Method::Get, url).header("accept", "application/json");
        let Ok(resp) = send(&self.http, req) else { return Vec::new() };
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(&resp.body) else { return Vec::new() };
        let Some(all) = body.pointer("/ocs/data/capabilities") else { return Vec::new() };

        let mut out = Vec::new();
        // Talk, which Nextcloud ships as the `spreed` app. Absent on an
        // instance that never installed it.
        if all.get("spreed").is_some() {
            out.push(Capability::Conversation);
        }
        let Some(sharing) = all.get("files_sharing") else { return out };
        let public = sharing.get("public");
        let enabled = public.and_then(|p| p.get("enabled")).and_then(serde_json::Value::as_bool).unwrap_or(false);
        if enabled {
            out.push(Capability::LinkShares);
            if let Some(password) = public.and_then(|p| p.get("password")) {
                out.push(Capability::LinkPassword);
                if password.get("enforced").and_then(serde_json::Value::as_bool).unwrap_or(false) {
                    out.push(Capability::LinkPasswordRequired);
                }
            }
            if public.and_then(|p| p.get("expire_date")).and_then(|e| e.get("enabled")).and_then(serde_json::Value::as_bool).unwrap_or(false) {
                out.push(Capability::ShareExpiry);
            }
        }
        out
    }

    /// Whether this account can send mail right now.
    ///
    /// The capabilities endpoint cannot answer this one. Mail registers
    /// nothing there. An instance running it reads exactly like an instance
    /// that never installed it. Talk is the counter-example. That is why
    /// `spreed` above can be read from a single call.
    ///
    /// So this asks the app. The account list answers the stronger question
    /// anyway. It says whether this user has an account configured well
    /// enough to send. An instance without the app refuses the route. That
    /// reads as absent.
    ///
    /// The cost is a second call inside `capabilities`. A claimed capability
    /// that fails on first use costs more.
    fn can_send_mail(&self) -> bool {
        Mail::new(&self.account).accounts(&self.http).is_ok_and(|accounts| accounts.iter().any(MailAccount::can_send))
    }
}

/// Talk, keyed on the file id.
///
/// Nextcloud keys a file's conversation on the id and not the path. That is
/// what makes a rename harmless. Two people pressing the control land in the
/// same room, and they keep landing there after somebody moves the document.
impl<H: Http> craft_cloud::Conversations for Nextcloud<H> {
    fn conversation_name(&self) -> Option<String> {
        (self.flavor == Flavor::Nextcloud).then(|| "Talk".to_owned())
    }

    fn conversation(&self, id: &str, _title: &str) -> CloudResult<CloudConversation> {
        if self.flavor == Flavor::OwnCloud {
            return Err(CloudError::Unsupported("conversations"));
        }
        let file_id = craft_cloud::Files::stat(self, id)?.room;
        if file_id.is_empty() || !file_id.chars().all(|c| c.is_ascii_digit()) {
            // Without a file id there is nothing stable to key a room on, and a
            // room keyed on a path splits in two the moment somebody renames.
            return Err(CloudError::Unsupported("conversations for this entry"));
        }
        let base = self.account.base().trim_end_matches('/').to_owned();
        let url = format!("{base}/ocs/v2.php/apps/spreed/api/v1/file/{file_id}");
        let req = self.account.request(Method::Get, url).header("accept", "application/json");
        let resp = send(&self.http, req).map_err(lift)?;
        let body = serde_json::from_slice::<serde_json::Value>(&resp.body).map_err(|e| CloudError::malformed("talk conversation", e.to_string()))?;
        let token = body
            .pointer("/ocs/data/token")
            .and_then(serde_json::Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| CloudError::malformed("talk conversation", "the answer carried no room token"))?;
        Ok(CloudConversation { url: format!("{base}/call/{token}"), name: "Talk".to_owned() })
    }
}

impl<H: Http> craft_cloud::Provider for Nextcloud<H> {
    fn id(&self) -> &str {
        match self.flavor {
            Flavor::Nextcloud => "nextcloud",
            Flavor::OwnCloud => "owncloud",
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        // The constants are the ones every Nextcloud has. Everything about
        // sharing is read from the instance, because an administrator can turn
        // public links or link passwords off and the dialog has to follow.
        let mut out = vec![Capability::Files, Capability::SharedWithMe, Capability::Sharing, Capability::Contacts, Capability::Etags];
        if self.flavor == Flavor::OwnCloud {
            // Sharing, contacts and files are the whole of it. The share API
            // takes no sendMail flag there, so a recipient is not mailed by it.
            out.extend(self.instance_capabilities().into_iter().filter(|c| *c != Capability::Conversation));
            return out;
        }
        out.push(Capability::Notifications);
        // Nextcloud mails a share recipient through its own SMTP. That is
        // separate from sending arbitrary mail, which is the Mail app.
        out.push(Capability::ShareNotify);
        out.extend(self.instance_capabilities());
        // The capabilities endpoint says nothing about the Mail app. This is
        // asked separately. See `can_send_mail`.
        if self.can_send_mail() {
            out.push(Capability::Mail);
        }
        out
    }
}

#[cfg(test)]
mod share_tests {
    use super::*;

    fn raw(kind: ShareKind, with: &str, name: &str) -> crate::share::Share {
        crate::share::Share {
            id: "42".to_owned(),
            kind: Some(kind),
            path: "/Report.xlsx".to_owned(),
            share_with: with.to_owned(),
            share_with_name: name.to_owned(),
            permissions: Permissions::EDIT,
            url: String::new(),
            owner: "ada".to_owned(),
            expires: String::new(),
        }
    }

    #[test]
    fn a_share_keeps_the_name_the_server_put_on_it() {
        let one = share_from(raw(ShareKind::User, "bob", "Bob Jones"));
        assert_eq!(one.target, ShareTarget::User("bob".to_owned()));
        assert_eq!(one.display.as_deref(), Some("Bob Jones"), "a list of account ids tells a reader nothing");

        // Older servers and some share types answer without one.
        let bare = share_from(raw(ShareKind::User, "bob", ""));
        assert_eq!(bare.display, None, "an empty name is not a name");

        let group = share_from(raw(ShareKind::Group, "eng", "Engineering"));
        assert_eq!(group.target, ShareTarget::Group("eng".to_owned()));
        assert_eq!(group.display.as_deref(), Some("Engineering"));
    }
}
