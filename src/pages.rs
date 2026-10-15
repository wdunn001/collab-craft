//! The web face of the service.
//!
//! Server rendered HTML, out of the same binary that holds the API. No
//! framework, no build step, no external asset. A page here therefore cannot
//! be broken by a CDN, costs nothing to deploy and works in a browser with
//! script turned off. `src/recipient.rs` already renders HTML this way.
//!
//! Three pages. The launcher lists what somebody may open. The account page
//! says who they are and whether their storage is linked. The provider page is
//! where a deployment says which cloud it uses.
//!
//! Every page decides what to draw from entitlement and capability. A control
//! that cannot work is never drawn, which is the rule the share dialog
//! follows and the reason an administrator who forbids public links sees no
//! Copy link button.
//!
//! What reaches a browser is bounded on purpose. A user sees their own
//! identity, the apps they may open and whether storage is linked. The
//! provider's address appears only for somebody entitled to change it, and for
//! the one page where a user links their own account, which cannot be done
//! without sending them to the provider.

use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use craft_cloud::Capability;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::session::{COOKIE, GUEST_COOKIE, Session, random_id};
use crate::settings::{ProviderConfig, Source};
use crate::state::{App, Permissions};

// ---- the shared layout ----------------------------------------------------

/// The suite's chrome, as one stylesheet.
///
/// Light and dark come from `prefers-color-scheme`, so the page follows the
/// desktop's own setting with nothing to choose and nothing to remember. The
/// tokens are the ones the Craft applications use for window, surface, line
/// and text, which is what makes a page here read as part of the suite.
///
/// Inline, because this deployment serves no stylesheet. One request draws the
/// whole page.
const STYLE: &str = "\
:root{color-scheme:light dark;--bg:#f3f3f3;--surface:#fff;--sunken:#fafafa;--line:#e3e3e3;--text:#242424;--dim:#616161;\
--accent:#1b6ac9;--on-accent:#fff;--danger:#c42b1c;--good:#107c41;--radius:10px;--shadow:0 1px 2px rgba(0,0,0,.06),0 10px 28px rgba(0,0,0,.05)}\
@media(prefers-color-scheme:dark){:root{--bg:#1d1d1d;--surface:#292929;--sunken:#232323;--line:#3d3d3d;--text:#eee;--dim:#b0b0b0;\
--accent:#6cb0f5;--on-accent:#12243a;--danger:#f1705f;--good:#5cc587;--shadow:0 1px 2px rgba(0,0,0,.4),0 10px 28px rgba(0,0,0,.35)}}\
*{box-sizing:border-box}\
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif}\
a{color:var(--accent)}\
header.bar{display:flex;align-items:center;gap:16px;padding:12px 20px;background:var(--surface);border-bottom:1px solid var(--line);\
position:sticky;top:0;z-index:2}\
header.bar .brand{display:flex;align-items:center;gap:9px;font-weight:650;letter-spacing:.2px;color:var(--text);text-decoration:none}\
header.bar nav{margin-left:auto;display:flex;align-items:center;gap:16px;font-size:14px}\
header.bar nav .who{color:var(--dim)}\
main{max-width:940px;margin:0 auto;padding:34px 20px 72px}\
h1{font-size:27px;line-height:1.2;margin:0 0 6px;font-weight:620}\
h2{font-size:17px;margin:34px 0 12px;font-weight:620}\
p.lede{color:var(--dim);margin:0 0 26px;max-width:62ch}\
p.hint{color:var(--dim);font-size:13px;margin:6px 0 0}\
section.panel{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}\
section.panel+section.panel{margin-top:18px}\
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(188px,1fr));gap:14px;margin:0;padding:0;list-style:none}\
.card{display:flex;flex-direction:column;gap:10px;padding:16px;background:var(--surface);border:1px solid var(--line);\
border-radius:var(--radius);text-decoration:none;color:var(--text);box-shadow:var(--shadow)}\
.card:hover{border-color:var(--accent)}\
.card .tile{display:grid;place-items:center;width:42px;height:42px;border-radius:9px;color:#fff;font-weight:680;font-size:19px;\
background:hsl(var(--h) 52% 42%)}\
.card .name{font-weight:620}\
.card .note{color:var(--dim);font-size:13px}\
dl.facts{display:grid;grid-template-columns:minmax(150px,auto) 1fr;gap:10px 22px;margin:0}\
dl.facts dt{color:var(--dim)}\
dl.facts dd{margin:0;overflow-wrap:anywhere}\
.row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:18px}\
.btn{display:inline-block;padding:9px 15px;border-radius:8px;border:1px solid transparent;background:var(--accent);color:var(--on-accent);\
font:inherit;font-weight:580;text-decoration:none;cursor:pointer}\
.btn.quiet{background:transparent;color:var(--text);border-color:var(--line)}\
.btn.quiet:hover{border-color:var(--accent)}\
.btn.risky{background:transparent;color:var(--danger);border-color:var(--line)}\
.strip{padding:11px 14px;border-radius:8px;border:1px solid var(--line);background:var(--sunken);margin:0 0 20px}\
.strip.good{border-color:var(--good)}\
.strip.bad{border-color:var(--danger)}\
.tag{display:inline-block;padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--dim);font-size:12px;\
vertical-align:1px}\
ul.plain{margin:0;padding-left:20px}\
label{display:block;font-weight:580;margin:16px 0 6px}\
input[type=url],select{width:100%;max-width:460px;padding:9px 11px;border-radius:8px;border:1px solid var(--line);\
background:var(--sunken);color:var(--text);font:inherit}\
code{background:var(--sunken);border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:13px}\
form.inline{display:inline}\
footer{color:var(--dim);font-size:13px;text-align:center;padding:0 20px 36px}\
";

/// The suite's mark, as inline geometry.
///
/// Drawn here because this deployment serves no image. Three sheets, offset,
/// in the accent colour.
const MARK: &str = "\
<svg width=\"20\" height=\"20\" viewBox=\"0 0 20 20\" fill=\"none\" aria-hidden=\"true\">\
<rect x=\"1\" y=\"5\" width=\"11\" height=\"11\" rx=\"2.5\" fill=\"currentColor\" opacity=\".35\"/>\
<rect x=\"4.5\" y=\"2.5\" width=\"11\" height=\"11\" rx=\"2.5\" fill=\"currentColor\" opacity=\".6\"/>\
<rect x=\"8\" y=\"6\" width=\"11\" height=\"11\" rx=\"2.5\" fill=\"currentColor\"/>\
</svg>";

/// One page, with the suite's chrome around it.
///
/// Takes the title, the session and the body. The nav follows the session.
/// Somebody signed in gets their name and a way to their account. A recipient
/// who followed a shared link gets neither, because they have no account here
/// to manage and a link to one could only disappoint them.
///
/// An anonymous visitor gets no nav at all. Whether they can sign in depends
/// on a deployment having an identity provider, which is a question for the
/// page and not for the chrome. The launcher asks it and draws the one
/// sign-in there is.
pub fn layout(title: &str, session: Option<&Session>, body: &str) -> String {
    let nav = match session {
        Some(s) if s.is_guest() => "<span class=\"who\">Shared with you</span>".to_owned(),
        Some(s) => format!("<span class=\"who\">{}</span><a href=\"/account\">Account</a>", escape(&s.display)),
        None => String::new(),
    };
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>{title} · CollabCraft</title><style>{STYLE}</style></head>\
         <body><header class=\"bar\"><a class=\"brand\" href=\"/\"><span style=\"color:var(--accent);display:flex\">{MARK}</span>CollabCraft</a>\
         <nav>{nav}</nav></header><main>{body}</main>\
         <footer>Craft, for documents that live in your own cloud.</footer></body></html>\n",
        title = escape(title),
    )
}

// ---- the launcher ---------------------------------------------------------

/// Everything somebody may open, as cards.
///
/// The set comes from `apps_for_session` crossed with what this deployment
/// hosts. An entitlement to an app nobody deployed draws no card, because a
/// card pointing at a build that is not there is a 404 with a nice tile on it.
///
/// An anonymous visitor is offered a sign-in. They have been refused nothing
/// yet, so refusing them here would be the wrong answer to the wrong question.
pub async fn launcher(State(app): State<Arc<App>>, session: Option<Session>) -> Response {
    let Some(session) = session else {
        return Html(layout("Welcome", None, &welcome(&app))).into_response();
    };

    let apps = app.launchable(&app.entitlements().await.0, &session);
    let linked = storage_linked(&app, &session).await;
    let mut body = String::new();

    if session.is_guest() {
        body.push_str("<h1>Shared with you</h1><p class=\"lede\">Somebody shared a document with you. It opens here.</p>");
    } else {
        body.push_str(&format!("<h1>Hello, {}</h1>", escape(first_word(&session.display))));
        body.push_str(match (apps.is_empty(), linked) {
            (true, _) => "<p class=\"lede\">Nothing has been granted to your account yet.</p>",
            (false, true) => "<p class=\"lede\">Your documents open from the storage you linked. Pick an application.</p>",
            (false, false) => {
                "<p class=\"lede\">Pick an application. Link your storage on the account page to open and save documents in your own cloud.</p>"
            }
        });
    }

    if apps.is_empty() {
        body.push_str(
            "<section class=\"panel\"><p>No application has been granted to you on this deployment. \
             Ask whoever runs it to grant one. Access here is granted by group membership at the identity provider.</p>",
        );
        if app.settings.may_configure(&session) {
            body.push_str("<div class=\"row\"><a class=\"btn quiet\" href=\"/settings/provider\">Cloud provider</a><a class=\"btn quiet\" href=\"/settings/apps\">Applications</a></div>");
        }
        body.push_str("</section>");
    } else {
        body.push_str("<ul class=\"grid\">");
        for slug in &apps {
            body.push_str(&card(slug));
        }
        body.push_str("</ul>");
    }

    if !session.is_guest() {
        body.push_str("<h2>This deployment</h2><section class=\"panel\"><dl class=\"facts\">");
        body.push_str(&format!("<dt>Storage</dt><dd>{}</dd>", if linked { "Linked to your account" } else { "Not linked yet" }));
        body.push_str(&format!("<dt>Applications</dt><dd>{} available to you</dd>", apps.len()));
        body.push_str("</dl><div class=\"row\"><a class=\"btn quiet\" href=\"/account\">Your account</a>");
        if app.settings.may_configure(&session) {
            body.push_str("<a class=\"btn quiet\" href=\"/settings/provider\">Cloud provider</a><a class=\"btn quiet\" href=\"/settings/apps\">Applications</a>");
        }
        body.push_str("</div></section>");
    }

    Html(layout("Applications", Some(&session), &body)).into_response()
}

/// What an anonymous visitor is shown.
///
/// A sign-in where there is an identity provider to sign in to. Where there is
/// none the page says so plainly, and draws no button, because a button to a
/// provider that was never configured can only fail.
pub fn welcome(app: &App) -> String {
    let mut body = String::from(
        "<h1>CollabCraft</h1><p class=\"lede\">The Craft applications, in your browser, \
         with documents that live in your own cloud and edits that arrive while somebody else is typing.</p><section class=\"panel\">",
    );
    if app.oidc.is_some() {
        body.push_str(
            "<p>Sign in to see the applications you may open.</p>\
             <div class=\"row\"><a class=\"btn\" href=\"/auth/login\">Sign in</a></div>",
        );
    } else {
        body.push_str("<p>This deployment has no identity provider configured. Nobody can sign in to it yet.</p>");
    }
    body.push_str("</section>");
    body
}

/// One application, as a card.
pub fn card(slug: &str) -> String {
    format!(
        "<li><a class=\"card\" href=\"/{slug}/\"><span class=\"tile\" style=\"--h:{hue}\" aria-hidden=\"true\">{initial}</span>\
         <span class=\"name\">{title}</span><span class=\"note\">Open in this browser</span></a></li>",
        slug = escape(slug),
        hue = hue(slug),
        initial = escape(&initial(slug)),
        title = escape(&app_title(slug)),
    )
}

/// A stable hue for one application, derived from its name.
///
/// No list of applications is held anywhere in this service. The set comes
/// from the deployment's own web root, so a deployment hosting something this
/// binary has never heard of still gets a tile that looks deliberate.
fn hue(slug: &str) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for b in slug.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(16_777_619);
    }
    h % 360
}

/// The letter on an application's tile.
fn initial(slug: &str) -> String {
    slug.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default()
}

/// What to call an application in a heading.
///
/// A slug such as `gridcraft` reads as GridCraft. The trailing `craft` is the
/// suite's own name, so it keeps its capital. Anything else gets its first
/// letter capitalised and nothing more.
pub fn app_title(slug: &str) -> String {
    match slug.strip_suffix("craft") {
        Some(head) if !head.is_empty() => format!("{}Craft", capitalise(head)),
        _ => capitalise(slug),
    }
}

/// One word, capitalised.
pub fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// The first word of a display name, for a greeting.
fn first_word(display: &str) -> &str {
    display.split_whitespace().next().unwrap_or(display)
}

// ---- the account page -----------------------------------------------------

/// What the provider says about a linked account.
struct Linked {
    display: String,
    email: Option<String>,
    capabilities: Vec<Capability>,
}

/// Who somebody is here, and what their storage can do.
///
/// Both answers come from one hop onto a blocking thread, because the provider
/// contracts are synchronous and two hops would cost two round trips to show
/// one panel.
async fn linked_account(app: &App, session: &Session) -> Option<Result<Linked, String>> {
    let provider = app.provider_for(session).await?;
    let answer = tokio::task::spawn_blocking(move || {
        let capabilities = provider.capabilities();
        craft_cloud::Accounts::me(provider.as_ref()).map(|id| Linked { display: id.display, email: id.email, capabilities })
    })
    .await;
    Some(match answer {
        Ok(Ok(linked)) => Ok(linked),
        Ok(Err(e)) => Err(e.to_string()),
        Err(e) => Err(e.to_string()),
    })
}

/// Whether this user has storage linked at all.
///
/// Reads the link record and opens nothing. A page that only has to say
/// "linked" or "not linked" must not wait on a provider to say it.
async fn storage_linked(app: &App, session: &Session) -> bool {
    !session.is_guest() && app.store.provider_link(&session.user).await.is_some()
}

/// What a capability is called where a person reads it.
///
/// Only the ones worth a sentence on an account page. A capability with no
/// label here is left out, because a list of internal names tells a user
/// nothing they can act on.
pub fn capability_label(capability: Capability) -> Option<&'static str> {
    match capability {
        Capability::Files => Some("Open and save documents"),
        Capability::SharedWithMe => Some("See what others shared with you"),
        Capability::Sharing => Some("Share a document"),
        Capability::LinkShares => Some("Share by link"),
        Capability::LinkPassword => Some("Put a password on a link"),
        Capability::ShareExpiry => Some("Expire a share"),
        Capability::ShareNotify => Some("Tell a recipient by mail"),
        Capability::Conversation => Some("Work together in a conversation"),
        Capability::Contacts => Some("Search your contacts"),
        _ => None,
    }
}

/// Who somebody is, which deployment they are on and whether storage is
/// linked.
///
/// Where the desktop application's Account settings link already points. An
/// anonymous visitor is sent to sign in, because this page is about an account
/// and they have not named one yet.
pub async fn account(State(app): State<Arc<App>>, session: Option<Session>, Query(q): Query<Flash>) -> Response {
    let Some(session) = session else {
        return Redirect::to("/auth/login").into_response();
    };
    if session.is_guest() {
        // A recipient holds no account here. Saying so is the whole page, and
        // the one application they may open is the only thing worth offering.
        let mut body = String::from(
            "<h1>Shared with you</h1><p class=\"lede\">You are here through a shared link. \
             There is no account on this deployment to manage. The link opens one document.</p>",
        );
        let apps = app.launchable(&app.entitlements().await.0, &session);
        if !apps.is_empty() {
            body.push_str("<ul class=\"grid\">");
            for slug in &apps {
                body.push_str(&card(slug));
            }
            body.push_str("</ul>");
        }
        return Html(layout("Shared with you", Some(&session), &body)).into_response();
    }

    let token = csrf(&app.secret, &session.user);
    let provider = app.provider_config().await;
    let linked = linked_account(&app, &session).await;
    let apps = app.launchable(&app.entitlements().await.0, &session);
    let mut body = String::new();

    if let Some(strip) = q.strip() {
        body.push_str(&strip);
    }
    body.push_str("<h1>Your account</h1><p class=\"lede\">This deployment knows you by your sign-in and acts on the storage you link here.</p>");

    body.push_str("<section class=\"panel\"><dl class=\"facts\">");
    body.push_str(&format!("<dt>Name</dt><dd>{}</dd>", escape(&session.display)));
    if let Some(email) = &session.email {
        body.push_str(&format!("<dt>Email</dt><dd>{}</dd>", escape(email)));
    }
    body.push_str(&format!(
        "<dt>Groups</dt><dd>{}</dd>",
        if session.groups.is_empty() { "None".to_owned() } else { escape(&session.groups.join(", ")) }
    ));
    body.push_str(&format!("<dt>Deployment</dt><dd>{}</dd>", escape(deployment_name(&app))));
    body.push_str("</dl><div class=\"row\">");
    body.push_str(&format!(
        "<form class=\"inline\" method=\"post\" action=\"/account/signout\">{}\
         <button class=\"btn quiet\" type=\"submit\">Sign out</button></form>",
        hidden_csrf(&token)
    ));
    body.push_str("</div></section>");

    // ---- storage
    body.push_str("<h2>Storage</h2><section class=\"panel\">");
    match (&linked, &provider) {
        (Some(Ok(linked)), _) => {
            body.push_str("<dl class=\"facts\">");
            body.push_str(&format!("<dt>Linked as</dt><dd>{}</dd>", escape(&linked.display)));
            if let Some(email) = &linked.email {
                body.push_str(&format!("<dt>Address</dt><dd>{}</dd>", escape(email)));
            }
            let can: Vec<&str> = linked.capabilities.iter().copied().filter_map(capability_label).collect();
            if !can.is_empty() {
                body.push_str("<dt>What it allows</dt><dd><ul class=\"plain\">");
                for line in can {
                    body.push_str(&format!("<li>{}</li>", escape(line)));
                }
                body.push_str("</ul></dd>");
            }
            body.push_str("</dl>");
            body.push_str(&format!(
                "<div class=\"row\"><form class=\"inline\" method=\"post\" action=\"/account/unlink\">{}\
                 <button class=\"btn risky\" type=\"submit\">Unlink this storage</button></form></div>",
                hidden_csrf(&token)
            ));
        }
        (Some(Err(detail)), _) => {
            body.push_str("<p>Storage is linked. It did not answer just now. Nothing can be opened or saved until it does.</p>");
            body.push_str(&format!("<p class=\"hint\">{}</p>", escape(detail)));
            body.push_str(&format!(
                "<div class=\"row\"><form class=\"inline\" method=\"post\" action=\"/account/link\">{}\
                 <button class=\"btn quiet\" type=\"submit\">Link it again</button></form>\
                 <form class=\"inline\" method=\"post\" action=\"/account/unlink\">{}\
                 <button class=\"btn risky\" type=\"submit\">Unlink</button></form></div>",
                hidden_csrf(&token),
                hidden_csrf(&token)
            ));
        }
        (None, Some(_)) => {
            // The provider is named nowhere here. A user about to link is sent to it and sees it there, which is
            // their own choice. The address itself is for the group entitled to change it.
            let how = match &provider {
                Some((config, _)) if !config.uses_login_flow() => {
                    "You give it a login name and an app password, which you can revoke at your server on its own."
                }
                _ => "You authenticate at your own provider. This service never sees your password.",
            };
            body.push_str(&format!(
                "<p>No storage is linked yet. Linking one lets this deployment open and save your documents in your own cloud. {how}</p>"
            ));
            body.push_str(&format!(
                "<div class=\"row\"><form class=\"inline\" method=\"post\" action=\"/account/link\">{}\
                 <button class=\"btn\" type=\"submit\">Link storage</button></form></div>",
                hidden_csrf(&token)
            ));
        }
        (None, None) => {
            // Nothing to link to. No button, because a button here would start
            // a flow with nowhere to go.
            body.push_str("<p>This deployment has no cloud provider configured. There is nothing to link yet.</p>");
            if app.settings.may_configure(&session) {
                body.push_str("<div class=\"row\"><a class=\"btn\" href=\"/settings/provider\">Configure the provider</a></div>");
            } else {
                body.push_str("<p class=\"hint\">Ask whoever runs this deployment to configure one.</p>");
            }
        }
    }
    body.push_str("</section>");

    // ---- applications
    body.push_str("<h2>Applications you may open</h2><section class=\"panel\">");
    if apps.is_empty() {
        body.push_str("<p>None yet. Access is granted by group membership at the identity provider.</p>");
    } else {
        body.push_str("<ul class=\"grid\">");
        for slug in &apps {
            body.push_str(&card(slug));
        }
        body.push_str("</ul>");
    }
    body.push_str("</section>");

    if app.settings.may_configure(&session) {
        body.push_str(
            "<h2>This deployment</h2><section class=\"panel\"><p>You may change the cloud provider for everybody here.</p>\
             <div class=\"row\"><a class=\"btn quiet\" href=\"/settings/provider\">Cloud provider</a><a class=\"btn quiet\" href=\"/settings/apps\">Applications</a></div></section>",
        );
    }

    Html(layout("Your account", Some(&session), &body)).into_response()
}

/// What to call this deployment.
///
/// Its own public address where it knows one. A deployment that was never told
/// its address says so, because guessing one from a request header behind a
/// proxy is how an open redirect starts.
fn deployment_name(app: &App) -> &str {
    let base = app.keyed.base();
    if base.is_empty() { "this service" } else { base }
}

// ---- linking storage ------------------------------------------------------

/// A form that only carries the proof it came from a page we served.
#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// The second half of a link, once the user has authenticated at the provider.
#[derive(Deserialize)]
pub struct LinkForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    handle: String,
}

/// Begin linking a cloud account.
///
/// Uses the provider's own desktop login flow, so this service never sees an
/// account password and ends up holding a credential that is revocable on its
/// own at the provider. The user has to authenticate there, which is the one
/// place a provider address legitimately reaches a browser: they are choosing
/// to link that account.
pub async fn link_begin(State(app): State<Arc<App>>, session: Session, Form(form): Form<CsrfForm>) -> Response {
    if !csrf_ok(&app.secret, &session.user, &form.csrf) {
        return stale(&session);
    }
    let Some((config, _)) = app.provider_config().await else {
        return Html(layout(
            "Storage",
            Some(&session),
            "<h1>No provider</h1><p class=\"lede\">This deployment has no cloud provider configured. There is nothing to link.</p>",
        ))
        .into_response();
    };

    if !config.uses_login_flow() {
        return Html(layout("Link your storage", Some(&session), &password_form(&app, &session, &config, "", None))).into_response();
    }

    let base = config.base.clone();
    let begun = tokio::task::spawn_blocking(move || craft_nextcloud::begin(&crate::transport::ReqwestHttp::default(), &base)).await;
    let flow = match begun {
        Ok(Ok(flow)) => flow,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "the provider would not begin a login");
            return Html(layout(
                "Storage",
                Some(&session),
                "<h1>Storage did not answer</h1><p class=\"lede\">The cloud provider would not begin a sign-in just now. \
                 Try again. Tell whoever runs this deployment if it keeps happening.</p>\
                 <section class=\"panel\"><div class=\"row\"><a class=\"btn quiet\" href=\"/account\">Back to your account</a></div></section>",
            ))
            .into_response();
        }
        Err(e) => return server_error(&session, &e.to_string()),
    };

    let handle = random_id();
    app.store.put_link_flow(&handle, &session.user, &flow.endpoint, &flow.token).await;
    let token = csrf(&app.secret, &session.user);
    let body = format!(
        "<h1>Link your storage</h1><p class=\"lede\">Sign in at your cloud provider in the page that opens. \
         Come back here afterwards and finish.</p><section class=\"panel\">\
         <div class=\"row\"><a class=\"btn\" href=\"{login}\" target=\"_blank\" rel=\"noopener noreferrer\">Open the provider sign-in</a></div>\
         <p class=\"hint\">The provider authenticates you. This service receives a credential scoped to it alone. \
         You can revoke it there. You can unlink it here.</p></section>\
         <section class=\"panel\"><p>Finished signing in?</p>\
         <form method=\"post\" action=\"/account/link/finish\">{csrf}<input type=\"hidden\" name=\"handle\" value=\"{handle}\">\
         <div class=\"row\"><button class=\"btn\" type=\"submit\">Finish linking</button>\
         <a class=\"btn quiet\" href=\"/account\">Cancel</a></div></form></section>",
        login = escape(&flow.login_url),
        csrf = hidden_csrf(&token),
        handle = escape(&handle),
    );
    Html(layout("Link your storage", Some(&session), &body)).into_response()
}

/// Finish linking, if the provider has issued the credential yet.
pub async fn link_finish(State(app): State<Arc<App>>, session: Session, Form(form): Form<LinkForm>) -> Response {
    if !csrf_ok(&app.secret, &session.user, &form.csrf) {
        return stale(&session);
    }
    let Some(flow) = app.store.link_flow(&form.handle).await else {
        return Redirect::to("/account?said=link_expired").into_response();
    };
    if flow.user != session.user {
        // The handle belongs to somebody else. Refused and not explained,
        // because the only way to hold one is to have been given it.
        return Redirect::to("/account?said=link_expired").into_response();
    }

    let polled = tokio::task::spawn_blocking(move || {
        let flow = craft_nextcloud::LoginFlow { login_url: String::new(), endpoint: flow.endpoint, token: flow.token };
        flow.poll(&crate::transport::ReqwestHttp::default())
    })
    .await;

    match polled {
        Ok(Ok(Some(password))) => {
            let link = crate::store::ProviderLink { user: password.user, password: password.password };
            if !app.store.put_provider_link(&session.user, &link).await {
                return Redirect::to("/account?said=link_failed").into_response();
            }
            app.store.drop_link_flow(&form.handle).await;
            tracing::info!(user = %session.user, "storage linked");
            Redirect::to("/account?said=linked").into_response()
        }
        // The provider has not finished with them yet. A state, and not a
        // failure, so the page offers the same button again.
        Ok(Ok(None)) => {
            let token = csrf(&app.secret, &session.user);
            let body = format!(
                "<h1>Still waiting</h1><p class=\"lede\">Your provider has not confirmed the sign-in yet. \
                 Finish it in the other page, then try again here.</p><section class=\"panel\">\
                 <form method=\"post\" action=\"/account/link/finish\">{csrf}<input type=\"hidden\" name=\"handle\" value=\"{handle}\">\
                 <div class=\"row\"><button class=\"btn\" type=\"submit\">Try again</button>\
                 <a class=\"btn quiet\" href=\"/account\">Cancel</a></div></form></section>",
                csrf = hidden_csrf(&token),
                handle = escape(&form.handle),
            );
            Html(layout("Still waiting", Some(&session), &body)).into_response()
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "the provider would not finish a login");
            Redirect::to("/account?said=link_failed").into_response()
        }
        Err(e) => server_error(&session, &e.to_string()),
    }
}

/// What somebody types to link a server with no browser sign-in of its own.
#[derive(Deserialize)]
pub struct PasswordLinkForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
}

/// The form for linking with a login name and an app password.
///
/// The password field is never filled back in. A refused attempt shows the
/// name again and asks for the password afresh.
fn password_form(app: &App, session: &Session, config: &crate::settings::ProviderConfig, user: &str, refused: Option<&str>) -> String {
    let token = csrf(&app.secret, &session.user);
    let mut body = String::new();
    if let Some(refused) = refused {
        body.push_str(&format!("<p class=\"strip bad\">{}</p>", escape(refused)));
    }
    body.push_str(&format!(
        "<h1>Link your storage</h1><p class=\"lede\">{label} has no sign-in page that hands this service a credential. \
         Give it a login name and an app password instead.</p><section class=\"panel\">\
         <form method=\"post\" action=\"/account/link/password\">{csrf}\
         <label for=\"user\">Login name</label>\
         <input id=\"user\" name=\"user\" autocomplete=\"username\" spellcheck=\"false\" value=\"{user}\">\
         <label for=\"password\">App password</label>\
         <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"off\">\
         <p class=\"hint\">Create an app password or a token in your server's own security settings wherever it offers one. \
         It can be revoked there on its own, without changing your real password. \
         The server is asked to accept it before anything is stored.</p>\
         <div class=\"row\"><button class=\"btn\" type=\"submit\">Link</button>\
         <a class=\"btn quiet\" href=\"/account\">Cancel</a></div></form></section>",
        label = escape(&config.label()),
        csrf = hidden_csrf(&token),
        user = escape(user),
    ));
    body
}

/// Link with a login name and an app password, once the server accepts them.
pub async fn link_password(State(app): State<Arc<App>>, session: Session, Form(form): Form<PasswordLinkForm>) -> Response {
    if !csrf_ok(&app.secret, &session.user, &form.csrf) {
        return stale(&session);
    }
    if session.is_guest() {
        return Redirect::to("/account").into_response();
    }
    let Some((config, _)) = app.provider_config().await else {
        return Redirect::to("/account").into_response();
    };
    let user = form.user.trim().to_owned();
    let refuse = |detail: &str| {
        let body = password_form(&app, &session, &config, &user, Some(detail));
        (StatusCode::BAD_REQUEST, Html(layout("Link your storage", Some(&session), &body))).into_response()
    };
    if user.is_empty() || form.password.is_empty() {
        return refuse("Both a login name and a password are needed.");
    }
    match crate::state::verify_link(&config, &user, &form.password).await {
        Ok(()) => {}
        Err(craft_cloud::Error::Unauthenticated) => return refuse("The server did not accept that login name and password."),
        Err(e) => {
            tracing::warn!(error = %e, "the provider would not confirm a credential");
            return refuse("The server did not answer as expected. Try again. Tell whoever runs this deployment if it keeps happening.");
        }
    }
    let link = crate::store::ProviderLink { user, password: form.password };
    if !app.store.put_provider_link(&session.user, &link).await {
        return Redirect::to("/account?said=link_failed").into_response();
    }
    tracing::info!(user = %session.user, kind = %config.kind, "storage linked with an app password");
    Redirect::to("/account?said=linked").into_response()
}

/// Forget the linked account.
pub async fn unlink(State(app): State<Arc<App>>, session: Session, Form(form): Form<CsrfForm>) -> Response {
    if !csrf_ok(&app.secret, &session.user, &form.csrf) {
        return stale(&session);
    }
    app.store.drop_provider_link(&session.user).await;
    tracing::info!(user = %session.user, "storage unlinked");
    Redirect::to("/account?said=unlinked").into_response()
}

/// End every session this person holds, and clear both cookies.
///
/// Dropping the records is what ends it. Clearing a cookie alone would leave a
/// usable session for anybody who copied it.
pub async fn signout(State(app): State<Arc<App>>, session: Session, Form(form): Form<CsrfForm>) -> Response {
    if !csrf_ok(&app.secret, &session.user, &form.csrf) {
        return stale(&session);
    }
    app.store.drop_sessions_for(&session.user).await;
    let mut response = Redirect::to("/").into_response();
    for name in [COOKIE, GUEST_COOKIE] {
        if let Ok(value) = HeaderValue::from_str(&format!("{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

// ---- the provider setup page ----------------------------------------------

/// What a page was asked to say after a redirect.
///
/// A redirect after a form keeps a reload from repeating the action. The
/// message is carried as a key and never as prose from the query, so nothing
/// a visitor types can be rendered back at them.
#[derive(Deserialize, Default)]
pub struct Flash {
    #[serde(default)]
    said: String,
}

impl Flash {
    fn strip(&self) -> Option<String> {
        let (tone, message) = match self.said.as_str() {
            "linked" => ("good", "Your storage is linked."),
            "unlinked" => ("good", "That storage is no longer linked."),
            "link_expired" => ("bad", "That link attempt expired. Start another."),
            "link_failed" => ("bad", "The provider would not finish linking. Try again."),
            "provider_saved" => ("good", "The provider answered and the address is saved. It is in use now."),
            "provider_cleared" => ("good", "The stored address is gone. This deployment is back on its environment default."),
            "apps_saved" => ("good", "Saved. Everybody signing in from now on gets this."),
            "apps_cleared" => ("good", "The stored entitlement is gone. This deployment is back on its environment default."),
            _ => return None,
        };
        Some(format!("<p class=\"strip {tone}\">{message}</p>"))
    }
}

/// The provider setup form.
#[derive(Deserialize)]
pub struct ProviderForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub base: String,
    /// The CardDAV address-book home, read for `webdav` only.
    #[serde(default)]
    pub contacts: String,
    /// `test`, `save` or `clear`.
    #[serde(default)]
    pub action: String,
}

/// Where a deployment says which cloud it uses.
///
/// Gated on a group from the identity provider. The page names the groups that
/// may change it, so somebody refused knows who to ask and somebody allowed
/// knows what they are speaking for.
pub async fn provider(State(app): State<Arc<App>>, session: Option<Session>, Query(q): Query<Flash>) -> Response {
    let Some(session) = session else {
        return Redirect::to("/auth/login").into_response();
    };
    if !app.settings.may_configure(&session) {
        return refuse_configure(&app, &session);
    }
    let in_use = app.provider_config().await;
    Html(layout("Cloud provider", Some(&session), &provider_body(&app, &session, in_use.as_ref(), q.strip().as_deref(), None))).into_response()
}

/// Test an address, save one, or go back to the environment default.
///
/// Saving tests first. An address that does not answer is not stored, because
/// a stored address that nobody proved reaches every user at once and the
/// person who typed it is the only one who can fix it.
pub async fn provider_save(State(app): State<Arc<App>>, session: Session, Form(form): Form<ProviderForm>) -> Response {
    if !app.settings.may_configure(&session) {
        return refuse_configure(&app, &session);
    }
    if !csrf_ok(&app.secret, &session.user, &form.csrf) {
        return stale(&session);
    }

    if form.action == "clear" {
        if !app.store.drop_provider_config().await {
            let strip = String::from("<p class=\"strip bad\">This service could not drop the stored address. The bus is unreachable.</p>");
            let in_use = app.provider_config().await;
            let body = provider_body(&app, &session, in_use.as_ref(), Some(&strip), None);
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(layout("Cloud provider", Some(&session), &body))).into_response();
        }
        tracing::info!(by = %session.user, "the stored cloud provider was cleared");
        return Redirect::to("/settings/provider?said=provider_cleared").into_response();
    }

    let in_use = app.provider_config().await;
    let typed = match ProviderConfig::parse(&form.kind, &form.base).and_then(|config| config.with_contacts(&form.contacts)) {
        Ok(config) => config,
        Err(detail) => {
            let strip = format!("<p class=\"strip bad\">{}</p>", escape(detail));
            let body = provider_body(&app, &session, in_use.as_ref(), Some(&strip), Some(&form));
            return (StatusCode::BAD_REQUEST, Html(layout("Cloud provider", Some(&session), &body))).into_response();
        }
    };

    if let Err(detail) = crate::settings::probe(&typed).await {
        tracing::info!(by = %session.user, kind = %typed.kind, "the address offered for the cloud provider did not answer");
        let strip = format!("<p class=\"strip bad\">That address did not answer as a cloud provider. {}</p>", escape(&detail));
        let body = provider_body(&app, &session, in_use.as_ref(), Some(&strip), Some(&form));
        return (StatusCode::BAD_GATEWAY, Html(layout("Cloud provider", Some(&session), &body))).into_response();
    }

    if form.action != "save" {
        let strip = String::from("<p class=\"strip good\">That address answered as a cloud provider. Nothing is saved yet.</p>");
        let body = provider_body(&app, &session, in_use.as_ref(), Some(&strip), Some(&form));
        return Html(layout("Cloud provider", Some(&session), &body)).into_response();
    }

    if !app.store.put_provider_config(&typed).await {
        let strip = String::from("<p class=\"strip bad\">That address answered. This service could not store it. The bus is unreachable.</p>");
        let body = provider_body(&app, &session, in_use.as_ref(), Some(&strip), Some(&form));
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(layout("Cloud provider", Some(&session), &body))).into_response();
    }
    // The address, never a credential. Who changed it, because this one
    // decides where every user's documents come from.
    tracing::info!(by = %session.user, kind = %typed.kind, base = %typed.base, "the cloud provider was changed");
    Redirect::to("/settings/provider?said=provider_saved").into_response()
}

/// The entitlement setup form.
#[derive(Deserialize)]
pub struct AppsForm {
    #[serde(default)]
    pub csrf: String,
    /// Comma separated, what everybody who signs in may open.
    #[serde(default)]
    pub default: String,
    /// One line per group, `group: app, app`.
    #[serde(default)]
    pub groups: String,
    /// `save` or `clear`.
    #[serde(default)]
    pub action: String,
}

/// Where a deployment says who may open which application.
///
/// Gated on the same group as the provider page. Entitlement decides what
/// every user sees, so it belongs to whoever decides where the documents live.
pub async fn apps(State(app): State<Arc<App>>, session: Option<Session>, Query(q): Query<Flash>) -> Response {
    let Some(session) = session else {
        return Redirect::to("/auth/login").into_response();
    };
    if !app.settings.may_configure(&session) {
        return refuse_configure(&app, &session);
    }
    let (entitled, source) = app.entitlements().await;
    let body = apps_body(&app, &session, &entitled, source, q.strip().as_deref(), None);
    Html(layout("Applications", Some(&session), &body)).into_response()
}

/// Save an entitlement, or go back to the environment default.
pub async fn apps_save(State(app): State<Arc<App>>, session: Session, Form(form): Form<AppsForm>) -> Response {
    if !app.settings.may_configure(&session) {
        return refuse_configure(&app, &session);
    }
    if !csrf_ok(&app.secret, &session.user, &form.csrf) {
        return stale(&session);
    }

    if form.action == "clear" {
        if !app.store.drop_entitlements().await {
            let (entitled, source) = app.entitlements().await;
            let strip = String::from("<p class=\"strip bad\">This service could not drop the stored entitlement. The bus is unreachable.</p>");
            let body = apps_body(&app, &session, &entitled, source, Some(&strip), None);
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(layout("Applications", Some(&session), &body))).into_response();
        }
        tracing::info!(by = %session.user, "the stored entitlement was cleared");
        return Redirect::to("/settings/apps?said=apps_cleared").into_response();
    }

    let typed = Permissions::parse(&form.default, &form.groups);
    if !app.store.put_entitlements(&typed).await {
        let strip = String::from("<p class=\"strip bad\">This service could not store that. The bus is unreachable.</p>");
        let body = apps_body(&app, &session, &typed, Source::Stored, Some(&strip), Some(&form));
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(layout("Applications", Some(&session), &body))).into_response();
    }
    // Who changed it, because this decides what every user may open.
    tracing::info!(by = %session.user, default = %form.default.trim(), "entitlement was changed");
    Redirect::to("/settings/apps?said=apps_saved").into_response()
}

/// The entitlement page's body.
///
/// Names what this deployment hosts beside the entitlement, because the two
/// together are what a person actually gets. An entitlement to something
/// nobody deployed grants nothing. Seeing that beats wondering why a card
/// never appeared.
pub fn apps_body(app: &App, session: &Session, entitled: &Permissions, source: Source, strip: Option<&str>, typed: Option<&AppsForm>) -> String {
    let token = csrf(&app.secret, &session.user);
    let mut body = String::new();
    if let Some(strip) = strip {
        body.push_str(strip);
    }
    body.push_str(
        "<h1>Applications</h1><p class=\"lede\">Who may open what. Everybody who signs in gets the default. \
         A group from the identity provider adds to it.</p>",
    );

    let tag = match source {
        Source::Stored => "set on this page",
        Source::Environment => "from the environment",
    };
    body.push_str(&format!(
        "<section class=\"panel\"><dl class=\"facts\"><dt>In use</dt><dd><span class=\"tag\">{tag}</span></dd>\
         <dt>Hosted here</dt><dd>{}</dd></dl>",
        if app.hosted.is_empty() { "nothing".to_owned() } else { escape(&sorted(&app.hosted).join(", ")) }
    ));

    // Anything granted that nobody deployed. Worth saying out loud. It is the
    // one mistake whose only symptom is a card that never appears.
    let missing = granted_but_absent(app, entitled);
    if !missing.is_empty() {
        body.push_str(&format!("<p class=\"hint\">Granted here and not deployed, so nobody can open it: {}.</p>", escape(&missing.join(", "))));
    }
    body.push_str("</section>");

    let default = match typed {
        Some(form) => form.default.clone(),
        None => entitled.default_apps().join(", "),
    };
    let groups = match typed {
        Some(form) => form.groups.clone(),
        None => entitled.groups_text(),
    };
    body.push_str(&format!(
        "<h2>Change it</h2><section class=\"panel\"><form method=\"post\" action=\"/settings/apps\">{}\
         <label for=\"default\">Everybody who signs in</label>\
         <input id=\"default\" name=\"default\" value=\"{}\" placeholder=\"gridcraft, wordcraft\">\
         <p class=\"hint\">Comma separated. Leave it empty to grant nothing by default.</p>\
         <label for=\"groups\">By group</label>\
         <textarea id=\"groups\" name=\"groups\" rows=\"5\" placeholder=\"editors: wordcraft, deckcraft\">{}</textarea>\
         <p class=\"hint\">One line per group, as <code>group: app, app</code>. A group name matches whatever case \
         the identity provider reports.</p>\
         <div class=\"row\"><button class=\"btn\" type=\"submit\" name=\"action\" value=\"save\">Save</button></div></form></section>",
        hidden_csrf(&token),
        escape(&default),
        escape(&groups)
    ));

    if source == Source::Stored {
        body.push_str(&format!(
            "<h2>Back to the default</h2><section class=\"panel\"><p>Dropping the stored entitlement puts this \
             deployment back on whatever its environment names.</p>\
             <form method=\"post\" action=\"/settings/apps\">{}\
             <div class=\"row\"><button class=\"btn risky\" type=\"submit\" name=\"action\" value=\"clear\">Drop the stored entitlement</button>\
             </div></form></section>",
            hidden_csrf(&token)
        ));
    }
    body.push_str("<div class=\"row\"><a class=\"btn quiet\" href=\"/account\">Back to your account</a></div>");
    body
}

/// Every application granted somewhere that this deployment does not host.
pub fn granted_but_absent(app: &App, entitled: &Permissions) -> Vec<String> {
    let mut out: Vec<String> =
        entitled.default_apps().iter().chain(entitled.group_apps().values().flatten()).filter(|name| !app.is_app(name)).cloned().collect();
    out.sort();
    out.dedup();
    out
}

fn sorted(names: &[String]) -> Vec<String> {
    let mut out = names.to_vec();
    out.sort();
    out
}

/// The setup page's body.
///
/// `typed` is what somebody just submitted, so a refused form comes back with
/// their own text in it. The address of the provider appears here and on no
/// other page, because this is the one group entitled to change it.
pub fn provider_body(
    app: &App,
    session: &Session,
    in_use: Option<&(ProviderConfig, Source)>,
    strip: Option<&str>,
    typed: Option<&ProviderForm>,
) -> String {
    let mut body = String::new();
    if let Some(strip) = strip {
        body.push_str(strip);
    }
    body.push_str(
        "<h1>Cloud provider</h1><p class=\"lede\">Where this deployment keeps documents. \
         Everybody who signs in here links their own account at the provider you name.</p>",
    );

    body.push_str("<section class=\"panel\"><dl class=\"facts\">");
    match in_use {
        Some((config, source)) => {
            let tag = match source {
                Source::Stored => "set on this page",
                Source::Environment => "from the environment",
            };
            body.push_str(&format!(
                "<dt>In use now</dt><dd>{} at {} <span class=\"tag\">{}</span></dd>",
                escape(&config.label()),
                escape(&config.base),
                escape(tag)
            ));
        }
        None => body.push_str("<dt>In use now</dt><dd>None. Nothing can be opened or saved until one answers.</dd>"),
    }
    body.push_str(&format!(
        "<dt>Environment default</dt><dd>{}</dd>",
        match app.settings.env_default() {
            Some(config) => format!("{} at {}", escape(&config.label()), escape(&config.base)),
            None => "None set".to_owned(),
        }
    ));
    body.push_str(&format!("<dt>Who may change this</dt><dd>{}</dd>", escape(&who_may(app))));
    body.push_str("</dl></section>");

    let token = csrf(&app.secret, &session.user);
    let kind_now = typed
        .map(|t| t.kind.trim().to_ascii_lowercase())
        .unwrap_or_else(|| in_use.map(|(config, _)| config.kind.clone()).unwrap_or_else(|| crate::settings::KINDS[0].to_owned()));
    let base_now = typed.map(|t| t.base.trim().to_owned()).unwrap_or_else(|| in_use.map(|(config, _)| config.base.clone()).unwrap_or_default());
    let contacts_now =
        typed.map(|t| t.contacts.trim().to_owned()).unwrap_or_else(|| in_use.and_then(|(config, _)| config.contacts.clone()).unwrap_or_default());

    body.push_str("<h2>Point it somewhere</h2><section class=\"panel\"><form method=\"post\" action=\"/settings/provider\">");
    body.push_str(&hidden_csrf(&token));
    body.push_str("<label for=\"kind\">Kind</label><select id=\"kind\" name=\"kind\">");
    for kind in crate::settings::KINDS {
        let selected = if kind == kind_now { " selected" } else { "" };
        body.push_str(&format!("<option value=\"{kind}\"{selected}>{}</option>", escape(&crate::settings::kind_label(kind))));
    }
    body.push_str("</select>");
    body.push_str(&format!(
        "<label for=\"base\">Address</label>\
         <input id=\"base\" name=\"base\" type=\"url\" inputmode=\"url\" autocomplete=\"off\" spellcheck=\"false\" \
         placeholder=\"https://cloud.example.com\" value=\"{}\">\
         <p class=\"hint\">For Nextcloud and ownCloud, the server root, with no path and no query. \
         For WebDAV, the files address itself. Write <code>{{user}}</code> where the server puts the login name, \
         as in <code>https://dav.example.com/files/{{user}}</code>. \
         A test asks the server to answer before anybody depends on it.</p>\
         <label for=\"contacts\">Address books (WebDAV only, optional)</label>\
         <input id=\"contacts\" name=\"contacts\" type=\"url\" inputmode=\"url\" autocomplete=\"off\" spellcheck=\"false\" \
         placeholder=\"https://dav.example.com/addressbooks/{{user}}\" value=\"{}\">\
         <p class=\"hint\">A CardDAV address-book home, for the contact picker. Leave it empty where the server has none.</p>",
        escape(&base_now),
        escape(&contacts_now)
    ));
    body.push_str(
        "<div class=\"row\"><button class=\"btn quiet\" type=\"submit\" name=\"action\" value=\"test\">Test</button>\
         <button class=\"btn\" type=\"submit\" name=\"action\" value=\"save\">Test and save</button></div></form>",
    );
    body.push_str("</section>");

    if matches!(in_use, Some((_, Source::Stored))) {
        body.push_str(&format!(
            "<h2>Back to the default</h2><section class=\"panel\"><p>Dropping the stored address puts this deployment \
             back on whatever its environment names.</p>\
             <form method=\"post\" action=\"/settings/provider\">{}\
             <div class=\"row\"><button class=\"btn risky\" type=\"submit\" name=\"action\" value=\"clear\">Drop the stored address</button>\
             </div></form></section>",
            hidden_csrf(&token)
        ));
    }
    body.push_str("<div class=\"row\"><a class=\"btn quiet\" href=\"/account\">Back to your account</a></div>");
    body
}

/// Who may change the provider, as a sentence.
pub fn who_may(app: &App) -> String {
    let groups = app.settings.admin_groups();
    match groups.len() {
        0 => "Nobody. This deployment names no group for it.".to_owned(),
        1 => format!("Members of the group {}.", groups.join("")),
        _ => format!("Members of these groups: {}.", groups.join(", ")),
    }
}

/// What somebody outside that group is told.
///
/// Names the group, because the useful answer to being refused is who to ask.
fn refuse_configure(app: &App, session: &Session) -> Response {
    let body = format!(
        "<h1>Not yours to change</h1><p class=\"lede\">The cloud provider for this deployment is set by group membership \
         at the identity provider.</p><section class=\"panel\"><p>{}</p><p class=\"hint\">{}</p>\
         <div class=\"row\"><a class=\"btn quiet\" href=\"/account\">Back to your account</a></div></section>",
        escape(&who_may(app)),
        escape(&carried(session))
    );
    (StatusCode::FORBIDDEN, Html(layout("Cloud provider", Some(session), &body))).into_response()
}

/// What a sign-in carrying no groups at all is told.
///
/// Named so the page and its test cannot drift apart on a sentence.
pub const NO_GROUPS: &str =
    "Your sign-in carried no groups at all. Either you are in none, or this application is not asking the identity provider for them.";

/// What the identity provider said this person is in.
///
/// A deployment whose groups scope is not bound to this application sends no
/// groups at all. That looks exactly like somebody who is in none of them. The
/// two are fixed in different places, so saying which one it is turns an hour
/// of guessing into a glance.
pub fn carried(session: &Session) -> String {
    if session.groups.is_empty() {
        return NO_GROUPS.to_owned();
    }
    format!("Your sign-in carried: {}.", session.groups.join(", "))
}

// ---- forms that prove where they came from --------------------------------

/// A token proving a form was served to this person by this service.
///
/// An HMAC over the user under the service secret. The session cookie is
/// already `SameSite=Lax`, which keeps a cross-site POST from carrying it.
/// This is the second lock: a form arriving without a token this service could
/// have minted is not acted on.
pub fn csrf(secret: &[u8], user: &str) -> String {
    match <Hmac<Sha256> as KeyInit>::new_from_slice(secret) {
        Ok(mut mac) => {
            mac.update(b"collabcraft-form-v1:");
            mac.update(user.as_bytes());
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        }
        Err(_) => String::new(),
    }
}

/// Whether a presented token is the one this user's forms carry.
///
/// Constant time, because [`Mac::verify_slice`] is. A byte comparison would
/// leak the token a byte at a time to anybody able to retry, and a form can
/// certainly be retried.
pub fn csrf_ok(secret: &[u8], user: &str, presented: &str) -> bool {
    let Ok(raw) = URL_SAFE_NO_PAD.decode(presented.as_bytes()) else { return false };
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(secret) else { return false };
    mac.update(b"collabcraft-form-v1:");
    mac.update(user.as_bytes());
    mac.verify_slice(&raw).is_ok()
}

fn hidden_csrf(token: &str) -> String {
    format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", escape(token))
}

/// What a form with no usable token gets.
///
/// Phrased as the common cause. A token this service did not mint usually
/// means a page that sat open while the session changed underneath it.
fn stale(session: &Session) -> Response {
    tracing::info!(user = %session.user, "a form arrived without a token this service minted");
    let body = "<h1>That form went stale</h1><p class=\"lede\">The page it came from is older than your session. \
         Open it again and repeat what you were doing.</p>\
         <section class=\"panel\"><div class=\"row\"><a class=\"btn quiet\" href=\"/account\">Back to your account</a></div></section>";
    (StatusCode::BAD_REQUEST, Html(layout("That form went stale", Some(session), body))).into_response()
}

/// A panic on a blocking thread, as a page.
fn server_error(session: &Session, detail: &str) -> Response {
    tracing::error!(detail, "a page could not be rendered");
    let body = "<h1>Something broke here</h1><p class=\"lede\">This service could not finish that. \
         Try again. Tell whoever runs this deployment if it keeps happening.</p>\
         <section class=\"panel\"><div class=\"row\"><a class=\"btn quiet\" href=\"/account\">Back to your account</a></div></section>";
    (StatusCode::INTERNAL_SERVER_ERROR, Html(layout("Something broke", Some(session), body))).into_response()
}

/// Where the hand-written entry page used to be.
///
/// A deployment that still has an `index.html` in its web root would otherwise
/// serve it on this path, and that file is no longer the entry point.
///
/// Temporary, because a permanent redirect is cached in every browser that
/// ever saw it. A deployment deciding to serve something of its own there
/// later would find it unreachable for anybody who had visited.
pub async fn index_html() -> Response {
    Redirect::temporary("/").into_response()
}

/// Escape the five characters that change the meaning of markup.
pub fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}
