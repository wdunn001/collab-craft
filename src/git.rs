//! Git as a storage kind.
//!
//! Files go through the GitHub / Gitea / Forgejo contents API. The app still
//! speaks only CollabCraft; this service holds the token and talks to the
//! remote. Sharing, mail and contacts are absent, the same way they are on
//! plain WebDAV.
//!
//! The configured address is a repository, `https://github.com/owner/repo` or
//! `https://git.example.com/owner/repo`. Linking is a login name and a token.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use craft_cloud::{
    Accounts, Capability, Contact, Contacts, Conversations, Entry, EntryKind, Error, Files, Identity, Mail, MailMessage, Notification, Notifications,
    Permission, Provider, Result, Share, ShareOptions, ShareTarget, Sharing,
};
use serde::{Deserialize, Serialize};

/// What Open / Save shows for a git-backed account: branch and remote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GitView {
    pub branch: String,
    pub remote: String,
}

/// One repository, with a token, offered through the `craft-cloud` contracts.
pub struct Git {
    api: String,
    owner: String,
    repo: String,
    user: String,
    token: String,
    branch: String,
}

impl Git {
    /// `base` is the repository URL. `password` is a personal access token.
    pub fn new(base: &str, user: &str, password: &str) -> Git {
        let parsed = parse_repo(base);
        Git {
            api: parsed.api,
            owner: parsed.owner,
            repo: parsed.repo,
            user: user.to_owned(),
            token: password.to_owned(),
            branch: "main".to_owned(),
        }
    }

    fn client(&self) -> reqwest::blocking::Client {
        reqwest::blocking::Client::new()
    }

    fn get(&self, url: &str) -> Result<reqwest::blocking::Response> {
        if self.token.is_empty() {
            return Err(Error::Unauthenticated);
        }
        let response = self
            .client()
            .get(url)
            .header("Accept", "application/json")
            .header("User-Agent", "collabcraft")
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        status(response)
    }

    /// Branch and repository URL for the Open / Save chrome.
    pub fn view(&self) -> GitView {
        GitView { branch: self.branch.clone(), remote: self.remote_url() }
    }

    fn remote_url(&self) -> String {
        if self.api == "https://api.github.com" {
            return format!("https://github.com/{}/{}", self.owner, self.repo);
        }
        let host = self.api.trim_end_matches("/api/v1").trim_end_matches('/');
        format!("{host}/{}/{}", self.owner, self.repo)
    }

    fn contents_url(&self, path: &str) -> Result<String> {
        if self.owner.is_empty() || self.repo.is_empty() {
            return Err(Error::Invalid { what: "repository", detail: "the address has to name owner/repo".to_owned() });
        }
        let rel = path.trim_matches('/');
        let encoded = if rel.is_empty() { String::new() } else { encode_path(rel) };
        Ok(format!("{}/repos/{}/{}/contents/{}?ref={}", self.api, self.owner, self.repo, encoded, encode_seg(&self.branch)))
    }
}

/// Where the contents API lives for one repository URL.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Parsed {
    api: String,
    owner: String,
    repo: String,
}

fn parse_repo(base: &str) -> Parsed {
    let trimmed = base.trim().trim_end_matches('/');
    let rest = trimmed.strip_prefix("https://").or_else(|| trimmed.strip_prefix("http://")).unwrap_or(trimmed);
    let (host, path) = match rest.split_once('/') {
        Some((h, p)) => (h, p.trim_matches('/')),
        None => (rest, ""),
    };
    let mut segs = path.split('/').filter(|s| !s.is_empty());
    let owner = segs.next().unwrap_or("").to_owned();
    let repo = segs.next().unwrap_or("").trim_end_matches(".git").to_owned();
    let api = if host.eq_ignore_ascii_case("github.com") || host.eq_ignore_ascii_case("www.github.com") {
        "https://api.github.com".to_owned()
    } else {
        let scheme = if trimmed.starts_with("http://") { "http" } else { "https" };
        format!("{scheme}://{host}/api/v1")
    };
    Parsed { api, owner, repo }
}

/// Whether a git host answers at this repository address.
///
/// GitHub's API root and Forgejo/Gitea's `/api/v1/version` need no credential.
/// A 200 means the host is there and speaks the contents API we use later.
pub fn probe(base: &str) -> std::result::Result<(), String> {
    let parsed = parse_repo(base);
    let url = if parsed.api == "https://api.github.com" {
        "https://api.github.com/".to_owned()
    } else {
        format!("{}/version", parsed.api)
    };
    let response = reqwest::blocking::Client::new()
        .get(&url)
        .header("User-Agent", "collabcraft")
        .send()
        .map_err(|e| e.to_string())?;
    let code = response.status().as_u16();
    // GitHub's root is public. Forgejo/Gitea often keep /api/v1/version
    // behind sign-in; 401/403 still means the host speaks the contents API.
    if code == 200 || code == 401 || code == 403 {
        return Ok(());
    }
    Err(format!("{url} answered HTTP {}", response.status()))
}

fn status(response: reqwest::blocking::Response) -> Result<reqwest::blocking::Response> {
    match response.status().as_u16() {
        200..=299 => Ok(response),
        401 => Err(Error::Unauthenticated),
        403 => Err(Error::Forbidden(response.status().to_string())),
        404 => Err(Error::not_found("entry", "")),
        409 | 412 => Err(Error::Conflict("the document".to_owned())),
        other => Err(Error::Unreachable(format!("HTTP {other}"))),
    }
}

#[derive(Deserialize)]
struct UserInfo {
    #[serde(default)]
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct Content {
    #[serde(default)]
    name: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    sha: String,
    #[serde(default)]
    size: u64,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    download_url: Option<String>,
}

fn entry_from(item: &Content) -> Entry {
    let folder = item.kind == "dir";
    Entry {
        id: item.path.clone(),
        room: item.sha.clone(),
        name: item.name.clone(),
        path: item.path.clone(),
        kind: if folder { EntryKind::Folder } else { EntryKind::File },
        size: (!folder).then_some(item.size),
        modified: None,
        mime: None,
        etag: (!item.sha.is_empty()).then_some(item.sha.clone()),
        writable: true,
        shared_by: None,
    }
}

impl Files for Git {
    fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let url = self.contents_url(path)?;
        let response = self.get(&url)?;
        let body: serde_json::Value = response.json().map_err(|e| Error::malformed("contents", e.to_string()))?;
        if let Ok(items) = serde_json::from_value::<Vec<Content>>(body.clone()) {
            return Ok(items.iter().map(entry_from).collect());
        }
        let item: Content = serde_json::from_value(body).map_err(|e| Error::malformed("contents", e.to_string()))?;
        Ok(vec![entry_from(&item)])
    }

    fn shared_with_me(&self) -> Result<Vec<Entry>> {
        Ok(Vec::new())
    }

    fn read(&self, id: &str) -> Result<Vec<u8>> {
        let url = self.contents_url(id)?;
        let item: Content = self.get(&url)?.json().map_err(|e| Error::malformed("file", e.to_string()))?;
        if let Some(download) = item.download_url.filter(|u| !u.is_empty()) {
            let bytes = self.get(&download)?.bytes().map_err(|e| Error::Unreachable(e.to_string()))?;
            return Ok(bytes.to_vec());
        }
        let encoded = item.content.unwrap_or_default().chars().filter(|c| !c.is_whitespace()).collect::<String>();
        STANDARD.decode(encoded.as_bytes()).map_err(|e| Error::malformed("content", e.to_string()))
    }

    fn write(&self, id: &str, bytes: &[u8], if_match: Option<&str>) -> Result<Entry> {
        self.put(id, bytes, if_match, "save")
    }

    fn create(&self, folder: &str, name: &str, bytes: &[u8]) -> Result<Entry> {
        let path = match folder.trim_matches('/') {
            "" => name.to_owned(),
            rest => format!("{rest}/{name}"),
        };
        self.put(&path, bytes, None, "create")
    }

    fn stat(&self, id: &str) -> Result<Entry> {
        let url = self.contents_url(id)?;
        let item: Content = self.get(&url)?.json().map_err(|e| Error::malformed("file", e.to_string()))?;
        Ok(entry_from(&item))
    }
}

impl Git {
    fn put(&self, path: &str, bytes: &[u8], sha: Option<&str>, message: &str) -> Result<Entry> {
        if self.token.is_empty() {
            return Err(Error::Unauthenticated);
        }
        let url = self.contents_url(path)?;
        let mut body = serde_json::json!({
            "message": message,
            "content": STANDARD.encode(bytes),
            "branch": self.branch,
        });
        if let Some(sha) = sha.filter(|s| !s.is_empty()) {
            body["sha"] = serde_json::Value::String(sha.to_owned());
        }
        let response = self
            .client()
            .put(&url)
            .header("Accept", "application/json")
            .header("User-Agent", "collabcraft")
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        let written: serde_json::Value = status(response)?.json().map_err(|e| Error::malformed("commit", e.to_string()))?;
        if let Some(content) = written.get("content") {
            let item: Content = serde_json::from_value(content.clone()).map_err(|e| Error::malformed("commit", e.to_string()))?;
            return Ok(entry_from(&item));
        }
        Files::stat(self, path)
    }
}

impl Sharing for Git {
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

impl Contacts for Git {
    fn search(&self, _query: &str, _limit: usize) -> Result<Vec<Contact>> {
        Ok(Vec::new())
    }
}

impl Notifications for Git {
    fn notify(&self, _user: &str, _notification: &Notification) -> Result<()> {
        Err(Error::Unsupported("notifications"))
    }
}

impl Mail for Git {
    fn send(&self, _message: &MailMessage) -> Result<()> {
        Err(Error::Unsupported("mail"))
    }
}

impl Accounts for Git {
    fn me(&self) -> Result<Identity> {
        let url = if self.api == "https://api.github.com" {
            "https://api.github.com/user".to_owned()
        } else {
            format!("{}/user", self.api)
        };
        let body: UserInfo = self.get(&url)?.json().map_err(|e| Error::malformed("account", e.to_string()))?;
        let login = if body.login.is_empty() { self.user.clone() } else { body.login };
        Ok(Identity {
            id: login.clone(),
            display: body.name.filter(|n| !n.is_empty()).unwrap_or_else(|| login.clone()),
            email: body.email,
            avatar: body.avatar_url,
        })
    }
}

impl Conversations for Git {}

impl Provider for Git {
    fn id(&self) -> &str {
        "git"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::Files, Capability::Etags]
    }
}

fn encode_path(path: &str) -> String {
    path.split('/').filter(|s| !s.is_empty()).map(encode_seg).collect::<Vec<_>>().join("/")
}

fn encode_seg(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_urls_use_the_public_api() {
        let parsed = parse_repo("https://github.com/fpoussin/solidcraft-designs/");
        assert_eq!(parsed.api, "https://api.github.com");
        assert_eq!(parsed.owner, "fpoussin");
        assert_eq!(parsed.repo, "solidcraft-designs");
    }

    #[test]
    fn forgejo_urls_use_api_v1_on_the_same_host() {
        let parsed = parse_repo("https://devops.quasarke.net/wdunn001/solidcraft.git");
        assert_eq!(parsed.api, "https://devops.quasarke.net/api/v1");
        assert_eq!(parsed.owner, "wdunn001");
        assert_eq!(parsed.repo, "solidcraft");
    }

    #[test]
    fn a_host_with_no_owner_repo_still_builds() {
        let git = Git::new("https://cloud.example.com", "alice", "pw");
        assert_eq!(git.id(), "git");
        assert!(git.contents_url("/").is_err());
    }

    #[test]
    fn the_open_save_chrome_gets_branch_and_remote() {
        let git = Git::new("https://github.com/fpoussin/solidcraft-designs", "alice", "pw");
        assert_eq!(git.view(), GitView { branch: "main".to_owned(), remote: "https://github.com/fpoussin/solidcraft-designs".to_owned() });
    }
}
