//! Per-scope RGA text for shared typing.
//!
//! Each text unit (a paragraph, a cell, a text frame) is one [`TextDoc`] keyed by an opaque
//! scope the app already uses for locks. Character ids for text that was already in the file
//! use space 0, so two peers who open the same document start from the same identities. New
//! typing uses this replica's space. CollabCraft carries the ops; this module is the merge.
//!
//! This lives here, not in `craft-cloud` and not in any one app binary. `craft-cloud` is the
//! file contracts. Concurrent typing is the relay's job, and every Craft app speaks this
//! crate.

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

/// One replica's texts, keyed by scope.
pub struct Texts {
    texts: HashMap<String, TextDoc>,
    alloc: Allocator,
    space: u32,
}

impl Texts {
    /// A replica that will mint new character ids in `space` (never 0: that is the file).
    #[must_use]
    pub fn new(space: u32) -> Texts {
        Texts { texts: HashMap::new(), alloc: Allocator::new(), space: space.max(1) }
    }

    /// Switch the id space once the relay has named this peer.
    pub fn set_space(&mut self, space: u32) {
        self.space = space.max(1);
    }

    /// Load a text unit from the file. Space-0 ids, so every replica that sees the same
    /// string starts with the same identities. A unit already loaded is left alone.
    pub fn seed(&mut self, scope: &str, text: &str) {
        if self.texts.contains_key(scope) {
            return;
        }
        let mut doc = TextDoc::new();
        if !text.is_empty() {
            let _ = doc.local_insert(0, text, &mut self.alloc, 0);
        }
        self.texts.insert(scope.to_owned(), doc);
    }

    /// Record a local insert and return the ops to send.
    pub fn local_insert(&mut self, scope: &str, char_pos: usize, s: &str) -> Vec<TextOp> {
        let space = self.space;
        let alloc = &mut self.alloc;
        self.texts.entry(scope.to_owned()).or_default().local_insert(char_pos, s, alloc, space)
    }

    /// Record a local delete and return the ops to send.
    pub fn local_delete(&mut self, scope: &str, char_pos: usize, len: usize) -> Vec<TextOp> {
        self.texts.entry(scope.to_owned()).or_default().local_delete(char_pos, len)
    }

    /// Replace a text unit with `new_text` by deleting the differing middle and inserting
    /// the rest. For a cell or a formula bar that commits a whole string rather than a
    /// keystroke. Concurrent replacements of the same unit still merge character by character.
    pub fn replace(&mut self, scope: &str, new_text: &str) -> Vec<TextOp> {
        let old = self.render(scope).unwrap_or_default();
        if old == new_text {
            return Vec::new();
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
            ops.extend(self.local_delete(scope, pre, old_end - pre));
        }
        if new_end > pre {
            let insert: String = new_chars[pre..new_end].iter().collect();
            ops.extend(self.local_insert(scope, pre, &insert));
        }
        ops
    }

    /// Apply remote ops and return the rendered text.
    pub fn apply(&mut self, scope: &str, ops: &[TextOp]) -> String {
        let doc = self.texts.entry(scope.to_owned()).or_default();
        for op in ops {
            doc.apply(op);
        }
        doc.render()
    }

    /// The rendered text, if we have one.
    #[must_use]
    pub fn render(&self, scope: &str) -> Option<String> {
        self.texts.get(scope).map(TextDoc::render)
    }
}

/// Byte offset in a UTF-8 string to a live-character index.
#[must_use]
pub fn char_pos(text: &str, byte: usize) -> usize {
    text.get(..byte.min(text.len())).map(|s| s.chars().count()).unwrap_or(0)
}

/// A replica space derived from the relay's peer id. Never 0.
#[must_use]
pub fn space_for(peer: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in peer.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash.max(1)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn concurrent_inserts_in_one_paragraph_converge() {
        let mut a = Texts::new(1);
        let mut b = Texts::new(2);
        a.seed("/body/0", "hello");
        b.seed("/body/0", "hello");
        let ops_a = a.local_insert("/body/0", 5, " world");
        let ops_b = b.local_insert("/body/0", 5, " there");
        let rendered_a = a.apply("/body/0", &ops_b);
        let rendered_b = b.apply("/body/0", &ops_a);
        assert_eq!(rendered_a, rendered_b);
        assert_eq!(rendered_a, "hello there world");
    }

    #[test]
    fn a_delete_tombstones_on_both_replicas() {
        let mut a = Texts::new(1);
        let mut b = Texts::new(2);
        a.seed("/body/0", "cat");
        b.seed("/body/0", "cat");
        let ops = a.local_delete("/body/0", 1, 1);
        assert_eq!(a.render("/body/0").as_deref(), Some("ct"));
        assert_eq!(b.apply("/body/0", &ops), "ct");
    }

    #[test]
    fn replace_merges_two_edits_of_the_same_cell() {
        let mut a = Texts::new(1);
        let mut b = Texts::new(2);
        a.seed("B2", "hello");
        b.seed("B2", "hello");
        let ops_a = a.replace("B2", "hello world");
        let ops_b = b.replace("B2", "hello there");
        let rendered_a = a.apply("B2", &ops_b);
        let rendered_b = b.apply("B2", &ops_a);
        assert_eq!(rendered_a, rendered_b);
        assert!(rendered_a.contains("hello"));
        assert!(rendered_a.contains("world"));
        assert!(rendered_a.contains("there"));
    }

    #[test]
    fn space_for_never_uses_the_file_space() {
        assert_ne!(space_for("alice"), 0);
        assert_ne!(space_for(""), 0);
        assert_eq!(space_for("alice"), space_for("alice"));
        assert_ne!(space_for("alice"), space_for("bob"));
    }

    #[test]
    fn char_pos_counts_characters_not_bytes() {
        assert_eq!(char_pos("héllo", 0), 0);
        assert_eq!(char_pos("héllo", 1), 1);
        assert_eq!(char_pos("héllo", 3), 2);
    }
}
