//! Room name from a relay token.
//!
//! The token is `base64url(payload).signature`. Reading the payload needs no key and proves
//! nothing. It is parsed only to learn the file id, and the relay still verifies the signature
//! before honouring anything. The room is keyed on the provider's file id and never on a path,
//! so a rename or a move mid-session does not split the peers.

use serde_json::Value as Json;

/// The room name the relay uses, read out of the token.
///
/// [`crate::Session`] drops any message whose doc does not match its own, so getting this
/// wrong looks exactly like a relay that answers nothing.
#[must_use]
pub fn doc_from_token(token: &str) -> Option<String> {
    let payload = token.split('.').next()?;
    let json = base64url(payload)?;
    let v: Json = serde_json::from_slice(&json).ok()?;
    // The service signs the room as `rm` (see the relay's token.rs). `fid` is
    // the legacy PHP claim. Reading `rm` first is what lets a reopened document
    // find the room it already has rather than minting a second one.
    if let Some(rm) = v.get("rm").and_then(Json::as_str) {
        return Some(format!("doc:{rm}"));
    }
    let fid = v.get("fid")?.as_u64()?;
    Some(format!("doc:{fid}"))
}

/// Decodes unpadded base64url, hand-rolled to avoid a dependency for one call.
fn base64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in s.bytes() {
        let six: u8 = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(six);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn reads_the_file_id() {
        // {"fid":42} unpadded base64url, no signature half needed by the parser.
        let payload = "eyJmaWQiOjQyfQ";
        assert_eq!(doc_from_token(payload).as_deref(), Some("doc:42"));
        assert_eq!(doc_from_token(&format!("{payload}.sig")).as_deref(), Some("doc:42"));
    }

    #[test]
    fn reads_the_room_claim() {
        // {"rm":"77"} unpadded base64url. The service signs the room as `rm`, so
        // a reopened document must resolve to the same room rather than falling
        // through to the legacy file-id path.
        let payload = "eyJybSI6Ijc3In0";
        assert_eq!(doc_from_token(payload).as_deref(), Some("doc:77"));
        assert_eq!(doc_from_token(&format!("{payload}.sig")).as_deref(), Some("doc:77"));
    }

    #[test]
    fn rejects_junk() {
        assert_eq!(doc_from_token("not-json"), None);
        assert_eq!(doc_from_token(""), None);
    }
}
