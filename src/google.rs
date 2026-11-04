//! Google Drive as a storage kind.
//!
//! Its sign-in is Google's own OAuth. The suite's identity provider is a
//! different question and is not involved here. The client secret stays in
//! the environment or the bus. This type holds a refresh token for one user.

use craft_cloud::{
    Accounts, Capability, Contact, Contacts, Conversations, Entry, EntryKind, Error, Files, Identity, Mail, MailMessage, Notification, Notifications,
    Permission, Provider, Result, Share, ShareOptions, ShareTarget, Sharing,
};
use serde::Deserialize;

const DRIVE: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3";

/// One person's Google Drive.
pub struct Drive {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

impl Drive {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>, refresh_token: impl Into<String>) -> Drive {
        Drive { client_id: client_id.into(), client_secret: client_secret.into(), refresh_token: refresh_token.into() }
    }

    fn token(&self) -> Result<String> {
        if self.client_id.is_empty() || self.client_secret.is_empty() || self.refresh_token.is_empty() {
            return Err(Error::Unauthenticated);
        }
        let client = reqwest::blocking::Client::new();
        let response = client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("refresh_token", self.refresh_token.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        if response.status().as_u16() == 401 || response.status().as_u16() == 400 {
            return Err(Error::Unauthenticated);
        }
        let body: Token = response.json().map_err(|e| Error::malformed("token", e.to_string()))?;
        if body.access_token.is_empty() {
            return Err(Error::Unauthenticated);
        }
        Ok(body.access_token)
    }

    fn get(&self, url: &str) -> Result<reqwest::blocking::Response> {
        let token = self.token()?;
        let response = reqwest::blocking::Client::new().get(url).bearer_auth(token).send().map_err(|e| Error::Unreachable(e.to_string()))?;
        status(response)
    }
}

#[derive(Deserialize)]
struct Token {
    #[serde(default)]
    access_token: String,
}

#[derive(Deserialize)]
struct FileList {
    #[serde(default)]
    files: Vec<File>,
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(rename = "mimeType", default)]
    mime_type: String,
    #[serde(default)]
    size: Option<String>,
    #[serde(rename = "modifiedTime", default)]
    modified: Option<String>,
    #[serde(rename = "md5Checksum", default)]
    etag: Option<String>,
}

fn status(response: reqwest::blocking::Response) -> Result<reqwest::blocking::Response> {
    match response.status().as_u16() {
        200..=299 => Ok(response),
        401 => Err(Error::Unauthenticated),
        403 => Err(Error::Forbidden(response.status().to_string())),
        404 => Err(Error::not_found("document", "")),
        _ => Err(Error::Unreachable(response.status().to_string())),
    }
}

fn entry(file: File) -> Entry {
    let folder = file.mime_type == "application/vnd.google-apps.folder";
    Entry {
        id: file.id.clone(),
        room: file.id,
        name: file.name,
        path: String::new(),
        kind: if folder { EntryKind::Folder } else { EntryKind::File },
        size: file.size.and_then(|s| s.parse().ok()),
        modified: file.modified,
        mime: if folder { None } else { Some(file.mime_type) },
        etag: file.etag,
        writable: true,
        shared_by: None,
    }
}

const FIELDS: &str = "files(id,name,mimeType,size,modifiedTime,md5Checksum)";

impl Files for Drive {
    fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let parent = if path.is_empty() || path == "/" { "root" } else { path };
        let query = format!("'{parent}' in parents and trashed=false");
        let url = format!("{DRIVE}/files?q={}&fields={FIELDS}&pageSize=200", urlencoding(&query));
        let list: FileList = self.get(&url)?.json().map_err(|e| Error::malformed("files", e.to_string()))?;
        Ok(list.files.into_iter().map(entry).collect())
    }

    fn shared_with_me(&self) -> Result<Vec<Entry>> {
        let url = format!("{DRIVE}/files?q={}&fields={FIELDS}&pageSize=200", urlencoding("sharedWithMe and trashed=false"));
        let list: FileList = self.get(&url)?.json().map_err(|e| Error::malformed("files", e.to_string()))?;
        Ok(list.files.into_iter().map(entry).collect())
    }

    fn read(&self, id: &str) -> Result<Vec<u8>> {
        let url = format!("{DRIVE}/files/{}?alt=media", enc_id(id));
        Ok(self.get(&url)?.bytes().map_err(|e| Error::Unreachable(e.to_string()))?.to_vec())
    }

    fn write(&self, id: &str, bytes: &[u8], _if_match: Option<&str>) -> Result<Entry> {
        let token = self.token()?;
        let url = format!("{UPLOAD}/files/{}?uploadType=media", enc_id(id));
        let response = reqwest::blocking::Client::new()
            .patch(url)
            .bearer_auth(token)
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        let file: File = status(response)?.json().map_err(|e| Error::malformed("file", e.to_string()))?;
        Ok(entry(file))
    }

    fn create(&self, folder: &str, name: &str, bytes: &[u8]) -> Result<Entry> {
        let token = self.token()?;
        let parent = if folder.is_empty() || folder == "/" { "root".to_owned() } else { folder.to_owned() };
        let meta = format!(
            "{{\"name\":{},\"parents\":[{}]}}",
            serde_json::to_string(name).unwrap_or_else(|_| "\"\"".to_owned()),
            serde_json::to_string(&parent).unwrap_or_else(|_| "\"root\"".to_owned())
        );
        let boundary = "collabcraft";
        let mut body = Vec::new();
        body.extend(format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes());
        body.extend(bytes);
        body.extend(format!("\r\n--{boundary}--").into_bytes());
        let response = reqwest::blocking::Client::new()
            .post(format!("{UPLOAD}/files?uploadType=multipart"))
            .bearer_auth(token)
            .header("Content-Type", format!("multipart/related; boundary={boundary}"))
            .body(body)
            .send()
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        let file: File = status(response)?.json().map_err(|e| Error::malformed("file", e.to_string()))?;
        Ok(entry(file))
    }

    fn stat(&self, id: &str) -> Result<Entry> {
        let url = format!("{DRIVE}/files/{}?fields=id,name,mimeType,size,modifiedTime,md5Checksum", enc_id(id));
        let file: File = self.get(&url)?.json().map_err(|e| Error::malformed("file", e.to_string()))?;
        Ok(entry(file))
    }
}

impl Sharing for Drive {
    fn share(&self, _id: &str, _with: &ShareTarget, _permission: Permission, _options: &ShareOptions) -> Result<Share> {
        Err(Error::Unsupported("sharing"))
    }

    fn shares(&self, _id: &str) -> Result<Vec<Share>> {
        Ok(Vec::new())
    }

    fn unshare(&self, _share_id: &str) -> Result<()> {
        Err(Error::Unsupported("sharing"))
    }
}

impl Contacts for Drive {
    fn search(&self, _query: &str, _limit: usize) -> Result<Vec<Contact>> {
        Ok(Vec::new())
    }
}

impl Notifications for Drive {
    fn notify(&self, _user: &str, _notification: &Notification) -> Result<()> {
        Err(Error::Unsupported("notifications"))
    }
}

impl Mail for Drive {
    fn send(&self, _message: &MailMessage) -> Result<()> {
        Err(Error::Unsupported("mail"))
    }
}

impl Accounts for Drive {
    fn me(&self) -> Result<Identity> {
        let response = self.get("https://www.googleapis.com/oauth2/v2/userinfo")?;
        let body: UserInfo = response.json().map_err(|e| Error::malformed("account", e.to_string()))?;
        Ok(Identity { id: body.id, display: body.name.unwrap_or_else(|| body.email.clone().unwrap_or_default()), email: body.email, avatar: None })
    }
}

impl Conversations for Drive {}

impl Provider for Drive {
    fn id(&self) -> &str {
        "google"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::Files, Capability::SharedWithMe]
    }
}

#[derive(Deserialize)]
struct UserInfo {
    #[serde(default)]
    id: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

fn enc_id(id: &str) -> String {
    urlencoding(id)
}

fn urlencoding(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Where to send a browser, and the state to check when it returns.
pub fn authorize_url(client_id: &str, redirect: &str, state: &str) -> String {
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&state={}",
        urlencoding(client_id),
        urlencoding(redirect),
        urlencoding("https://www.googleapis.com/auth/drive"),
        urlencoding(state)
    )
}

/// Exchange a browser code for a refresh token.
pub fn exchange(client_id: &str, client_secret: &str, redirect: &str, code: &str) -> Result<String> {
    let response = reqwest::blocking::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect),
        ])
        .send()
        .map_err(|e| Error::Unreachable(e.to_string()))?;
    let body: Refresh = status(response)?.json().map_err(|e| Error::malformed("token", e.to_string()))?;
    if body.refresh_token.is_empty() {
        return Err(Error::Unauthenticated);
    }
    Ok(body.refresh_token)
}

#[derive(Deserialize)]
struct Refresh {
    #[serde(default)]
    refresh_token: String,
}
