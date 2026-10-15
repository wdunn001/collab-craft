//! Turning the dialog's requests into the service's, and the service's
//! answers into the dialog's.
//!
//! Every mapping here takes a value and gives a value back. None of them makes
//! a call. So the desktop backend and the browser backend use the same ones,
//! and a test covers them with no transport and no browser.

use craft_cloud_client::{Error, Me, ShareOutcome, ShareRequest};
use craft_ui::share::{Answer, Destination, Failure, Grant};

/// The one place a document can go today.
///
/// Opaque to the dialog, handed back with the save. A second provider is a
/// second entry rather than a change anywhere above here.
pub(crate) const DESTINATION: &str = "cloud";

/// The service's share request for one grant from the dialog.
///
/// No expiry. The dialog has no field for one, and inventing a date here would
/// put an end on a share nobody asked to end.
pub(crate) fn asked(grant: Grant, app: Option<&str>) -> ShareRequest {
    ShareRequest {
        id: grant.id,
        targets: grant.targets,
        permission: grant.permission,
        note: grant.note,
        notify: grant.notify,
        app: app.map(str::to_owned),
        password: grant.password,
        expires: None,
    }
}

/// What the provider behind the service can do.
pub(crate) fn capabilities(me: Me) -> Answer {
    Answer::Capabilities { capabilities: me.capabilities, linked: me.provider_linked }
}

/// Where a document that has never been saved could go.
///
/// A list of one, described by the account behind it. Two entries reading
/// "Cloud" would tell nobody which of their accounts a document is about to
/// land in, and that is the one thing somebody needs before pressing it.
pub(crate) fn destinations(me: Me) -> Answer {
    Answer::Destinations(vec![Destination {
        id: DESTINATION.to_owned(),
        name: "Cloud".to_owned(),
        account: me.email.or(Some(me.display)),
        linked: me.provider_linked,
    }])
}

/// A completed share, with both halves.
///
/// Partial success is the ordinary case. Sharing with five people where one
/// address is wrong shares with four and names the one that failed.
pub(crate) fn granted(mut outcome: ShareOutcome) -> Answer {
    // A keyed URL is the entry point the recipient can actually use. Keep the
    // provider share id for revocation, but never expose its storage-manager
    // URL when CollabCraft minted an app-scoped route for the same target.
    for keyed in outcome.keyed {
        if let Some(shared) = outcome.shared.iter_mut().find(|share| share.target == keyed.target) {
            shared.url = Some(keyed.url);
        }
    }
    let failed = outcome.failed.into_iter().map(|f| Failure { target: f.target, code: f.code, detail: f.detail }).collect();
    Answer::Granted { shared: outcome.shared, failed }
}

/// Why no contact pictures.
///
/// A contact's avatar URL is the provider's own, and an app reaching it would
/// be an app talking to the provider, which is the thing this whole
/// arrangement exists to prevent. Until CollabCraft relays pictures, the
/// dialog paints initials. A host that has decided it may fetch them wraps
/// this backend and answers that one request itself; nothing else changes.
pub(crate) fn no_pictures() -> String {
    "this build does not fetch contact pictures".to_owned()
}

/// Where to go to connect an account.
///
/// Opening a browser is the host application's business, so the URL is
/// reported rather than launched from here.
pub(crate) fn connect_an_account(login_url: &str) -> String {
    format!("open {login_url} to connect an account")
}

/// A client error in words a user can read.
pub(crate) fn say(e: Error) -> String {
    e.to_string()
}
