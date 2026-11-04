//! Per-scope RGA text for shared typing.
//!
//! Each text unit (a paragraph, a cell, a text frame) is one [`TextDoc`] keyed by an opaque
//! scope the app already uses for locks. CollabCraft carries the ops; this module is the merge.
//!
//! This lives here, not in `craft-cloud` and not in any one app binary. `craft-cloud` is the
//! file contracts. Concurrent typing is the relay's job, and every Craft app speaks this
//! crate.
//!
//! # Two rules the identities depend on
//!
//! **Every scope owns its allocator.** Character ids for text that was already in the file use
//! space 0, so two peers who load the same string reach the same identities. That only holds
//! when the counters a scope draws from cannot be moved by another scope. One allocator shared
//! across scopes made the ids depend on which scope was seeded first, and a peer that seeded
//! `/body/1` before `/body/0` then gave the same character a different id. An anchor meant two
//! different characters on the two replicas, and the text diverged with nothing reporting it.
//!
//! **New typing waits for the relay to name a space.** The relay grants one id space per
//! connection in [`crate::ServerMsg::Joined`]. Before that arrives this replica has no space of
//! its own, and a local edit is refused. Two peers that both typed in a default space minted the
//! same ids for different characters, and [`TextDoc::apply`] dropped each one as a duplicate
//! delivery.

use std::collections::HashMap;

use craft_crdt::ids::Allocator;
use craft_crdt::text::{TextDoc, TextOp};
use serde::{Deserialize, Serialize};

/// What rides as `params` on a [`crate::CRDT_TEXT`] command.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TextPayload {
    /// The text unit, as the app spells a lock scope.
    pub scope: String,
    /// Inserts and deletes, in the order this replica produced them.
    pub ops: Vec<TextOp>,
}

/// Why a text edit could not be made.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TextError {
    /// The relay has not named this connection's id space yet.
    ///
    /// Typing before that would mint ids in a space another peer is also using, and the two
    /// peers would then drop each other's characters.
    #[error("the relay has not granted an id space yet")]
    NoSpace,
    /// This replica has never loaded the scope being edited.
    ///
    /// Editing it would build an empty text and anchor the edit against characters that do not
    /// exist here, which renders in the wrong place on this replica alone.
    #[error("scope {0:?} was never seeded from the file")]
    Unseeded(String),
}

/// One text unit: the replicated text, and the counters its own ids come from.
#[derive(Default)]
struct Unit {
    doc: TextDoc,
    /// This scope's own allocator, so the ids it draws cannot depend on another scope.
    alloc: Allocator,
    /// Whether the file's text has been loaded. An unseeded unit refuses local edits and
    /// holds remote ops.
    seeded: bool,
    /// Remote ops that arrived before the file's text did, in arrival order.
    held: Vec<TextOp>,
}

/// One replica's texts, keyed by scope.
#[derive(Default)]
pub struct Texts {
    texts: HashMap<String, Unit>,
    /// The id space the relay granted this connection. `None` until it does.
    space: Option<u32>,
}

impl Texts {
    /// A replica with no id space yet.
    ///
    /// Local edits are refused until [`set_space`](Self::set_space). The relay grants the space
    /// in its join payload, so nothing has to guess one.
    #[must_use]
    pub fn new() -> Texts {
        Texts { texts: HashMap::new(), space: None }
    }

    /// A replica that mints new character ids in `space`.
    ///
    /// For tests and for a single-writer caller that owns the space itself. A live session takes
    /// the space from the relay.
    #[must_use]
    pub fn in_space(space: u32) -> Texts {
        Texts { texts: HashMap::new(), space: Some(space.max(1)) }
    }

    /// Record the id space the relay granted. Never 0: that space is the file's.
    pub fn set_space(&mut self, space: u32) {
        self.space = Some(space.max(1));
    }

    /// The granted id space, when the relay has named one.
    #[must_use]
    pub fn space(&self) -> Option<u32> {
        self.space
    }

    /// Whether a scope has been loaded from the file.
    #[must_use]
    pub fn is_seeded(&self, scope: &str) -> bool {
        self.texts.get(scope).is_some_and(|u| u.seeded)
    }

    /// Load a text unit from the file, and return the rendered text.
    ///
    /// Space-0 ids drawn from this scope's own allocator, so every replica that loads the same
    /// string reaches the same identities whatever else it loaded first. A unit already seeded
    /// is left alone. Ops that arrived before the text did are applied on top, which is what
    /// makes a seed after a burst of remote typing land correctly.
    pub fn seed(&mut self, scope: &str, text: &str) -> String {
        let unit = self.texts.entry(scope.to_owned()).or_default();
        if unit.seeded {
            return unit.doc.render();
        }
        if !text.is_empty() {
            let _ = unit.doc.local_insert(0, text, &mut unit.alloc, 0);
        }
        unit.seeded = true;
        let held = std::mem::take(&mut unit.held);
        for op in &held {
            unit.doc.apply(op);
        }
        unit.doc.render()
    }

    /// Record a local insert and return the ops to send.
    pub fn local_insert(&mut self, scope: &str, char_pos: usize, s: &str) -> Result<Vec<TextOp>, TextError> {
        let space = self.space.ok_or(TextError::NoSpace)?;
        let unit = self.unit_mut(scope)?;
        Ok(unit.doc.local_insert(char_pos, s, &mut unit.alloc, space))
    }

    /// Record a local delete and return the ops to send.
    pub fn local_delete(&mut self, scope: &str, char_pos: usize, len: usize) -> Result<Vec<TextOp>, TextError> {
        // A delete mints no id, and still needs the scope loaded: without the file's text there
        // is nothing at that position to tombstone.
        let unit = self.unit_mut(scope)?;
        Ok(unit.doc.local_delete(char_pos, len))
    }

    /// Replace a text unit with `new_text` by deleting the differing middle and inserting
    /// the rest. For a cell or a formula bar that commits a whole string rather than a
    /// keystroke. Concurrent replacements of the same unit still merge character by character.
    pub fn replace(&mut self, scope: &str, new_text: &str) -> Result<Vec<TextOp>, TextError> {
        let old = self.render(scope).ok_or_else(|| TextError::Unseeded(scope.to_owned()))?;
        if old == new_text {
            return Ok(Vec::new());
        }
        let old_chars: Vec<char> = old.chars().collect();
        let new_chars: Vec<char> = new_text.chars().collect();
        let mut pre = 0;
        while pre < old_chars.len() && pre < new_chars.len() && old_chars[pre] == new_chars[pre] {
            pre += 1;
        }
        let mut old_end = old_chars.len();
        let mut new_end = new_chars.len();
        while old_end > pre && new_end > pre && old_chars[old_end - 1] == new_chars[new_end - 1] {
            old_end -= 1;
            new_end -= 1;
        }
        let mut ops = Vec::new();
        if old_end > pre {
            ops.extend(self.local_delete(scope, pre, old_end - pre)?);
        }
        if new_end > pre {
            let insert: String = new_chars[pre..new_end].iter().collect();
            ops.extend(self.local_insert(scope, pre, &insert)?);
        }
        Ok(ops)
    }

    /// Apply remote ops and return the rendered text, when the scope is loaded.
    ///
    /// `None` means the ops were held. The scope has not been seeded here, and applying them
    /// against an empty text would anchor them on characters that do not exist on this replica.
    /// They are kept, and [`seed`](Self::seed) applies them once the text arrives.
    pub fn apply(&mut self, scope: &str, ops: &[TextOp]) -> Option<String> {
        let unit = self.texts.entry(scope.to_owned()).or_default();
        if !unit.seeded {
            unit.held.extend(ops.iter().cloned());
            return None;
        }
        for op in ops {
            unit.doc.apply(op);
        }
        Some(unit.doc.render())
    }

    /// The rendered text, if this replica has the scope.
    #[must_use]
    pub fn render(&self, scope: &str) -> Option<String> {
        self.texts.get(scope).filter(|u| u.seeded).map(|u| u.doc.render())
    }

    /// The unit for a scope, refusing one that was never loaded.
    fn unit_mut(&mut self, scope: &str) -> Result<&mut Unit, TextError> {
        match self.texts.get_mut(scope) {
            Some(unit) if unit.seeded => Ok(unit),
            _ => Err(TextError::Unseeded(scope.to_owned())),
        }
    }
}

/// Byte offset in a UTF-8 string to a live-character index.
#[must_use]
pub fn char_pos(text: &str, byte: usize) -> usize {
    text.get(..byte.min(text.len())).map(|s| s.chars().count()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn seeded(space: u32, scope: &str, text: &str) -> Texts {
        let mut t = Texts::in_space(space);
        t.seed(scope, text);
        t
    }

    #[test]
    fn concurrent_inserts_in_one_paragraph_converge() {
        let mut a = seeded(1, "/body/0", "hello");
        let mut b = seeded(2, "/body/0", "hello");
        let ops_a = a.local_insert("/body/0", 5, " world").unwrap();
        let ops_b = b.local_insert("/body/0", 5, " there").unwrap();
        let rendered_a = a.apply("/body/0", &ops_b).unwrap();
        let rendered_b = b.apply("/body/0", &ops_a).unwrap();
        assert_eq!(rendered_a, rendered_b);
        assert_eq!(rendered_a, "hello there world");
    }

    #[test]
    fn a_delete_tombstones_on_both_replicas() {
        let mut a = seeded(1, "/body/0", "cat");
        let mut b = seeded(2, "/body/0", "cat");
        let ops = a.local_delete("/body/0", 1, 1).unwrap();
        assert_eq!(a.render("/body/0").as_deref(), Some("ct"));
        assert_eq!(b.apply("/body/0", &ops).as_deref(), Some("ct"));
    }

    #[test]
    fn replace_merges_two_edits_of_the_same_cell() {
        let mut a = seeded(1, "B2", "hello");
        let mut b = seeded(2, "B2", "hello");
        let ops_a = a.replace("B2", "hello world").unwrap();
        let ops_b = b.replace("B2", "hello there").unwrap();
        let rendered_a = a.apply("B2", &ops_b).unwrap();
        let rendered_b = b.apply("B2", &ops_a).unwrap();
        assert_eq!(rendered_a, rendered_b);
        assert!(rendered_a.contains("hello"));
        assert!(rendered_a.contains("world"));
        assert!(rendered_a.contains("there"));
    }

    /// The defect that one shared allocator caused: the ids a scope drew moved when another
    /// scope was seeded first, so an anchor meant a different character on each replica.
    #[test]
    fn seeding_order_does_not_change_character_identity() {
        let mut a = Texts::in_space(10);
        a.seed("/body/0", "first");
        a.seed("/body/1", "second");

        let mut b = Texts::in_space(20);
        b.seed("/body/1", "second");
        b.seed("/body/0", "first");

        let ops = a.local_insert("/body/1", 6, "!").unwrap();
        assert_eq!(a.render("/body/1").as_deref(), Some("second!"));
        assert_eq!(b.apply("/body/1", &ops).as_deref(), Some("second!"));
    }

    #[test]
    fn typing_before_the_relay_grants_a_space_is_refused() {
        let mut t = Texts::new();
        t.seed("B2", "hello");
        assert_eq!(t.local_insert("B2", 5, "!"), Err(TextError::NoSpace));
        t.set_space(7);
        assert!(t.local_insert("B2", 5, "!").is_ok());
    }

    #[test]
    fn a_space_is_never_the_files_own() {
        let mut t = Texts::new();
        t.set_space(0);
        assert_eq!(t.space(), Some(1));
    }

    #[test]
    fn editing_an_unseeded_scope_is_refused() {
        let mut t = Texts::in_space(3);
        assert_eq!(t.local_insert("B2", 0, "x"), Err(TextError::Unseeded("B2".to_owned())));
        assert_eq!(t.local_delete("B2", 0, 1), Err(TextError::Unseeded("B2".to_owned())));
        assert_eq!(t.replace("B2", "x"), Err(TextError::Unseeded("B2".to_owned())));
    }

    /// Ops for a scope this replica has not loaded are held, then land when the text arrives.
    /// Applying them against an empty text put the characters at the head instead.
    #[test]
    fn ops_for_an_unseeded_scope_are_held_until_the_text_arrives() {
        let mut a = seeded(10, "B2", "hello");
        let ops = a.local_insert("B2", 5, "!").unwrap();

        let mut b = Texts::in_space(20);
        assert_eq!(b.apply("B2", &ops), None, "nothing to render yet");
        assert_eq!(b.render("B2"), None);

        assert_eq!(b.seed("B2", "hello"), "hello!");
        assert_eq!(b.render("B2").as_deref(), Some("hello!"));
    }

    /// A joining peer seeds the file, then applies the ops the relay replays. The held queue
    /// makes the order of those two steps irrelevant, which matters because the replay can
    /// arrive before the app has loaded the file.
    #[test]
    fn a_joiner_reaches_the_rooms_text_from_the_file_plus_replayed_ops() {
        let mut a = seeded(10, "/body/0", "base");
        let mut b = seeded(20, "/body/0", "base");
        let ops = a.local_insert("/body/0", 4, " and more").unwrap();
        let _ = b.apply("/body/0", &ops);

        // The replay reaches the joiner before it has opened the file.
        let mut c = Texts::in_space(30);
        assert_eq!(c.apply("/body/0", &ops), None);
        assert_eq!(c.seed("/body/0", "base"), "base and more");
        assert_eq!(c.render("/body/0").as_deref(), a.render("/body/0").as_deref());

        // And the joiner can write without reusing anybody's id, because its own space is
        // its own: only space 0 is shared, and only the file's text draws from it.
        let more = c.local_insert("/body/0", 13, "!").unwrap();
        assert_eq!(a.apply("/body/0", &more).as_deref(), Some("base and more!"));
        assert_eq!(b.apply("/body/0", &more).as_deref(), Some("base and more!"));
    }

    #[test]
    fn char_pos_counts_characters_not_bytes() {
        assert_eq!(char_pos("héllo", 0), 0);
        assert_eq!(char_pos("héllo", 1), 1);
        assert_eq!(char_pos("héllo", 3), 2);
    }
}
