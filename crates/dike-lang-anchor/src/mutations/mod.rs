//! Vulnerability injection: the six v1 mutation operators (D13).
//!
//! Each operator takes a *clean* program and produces one mutant per applicable
//! site, each carrying a `MutationLabel` naming the defect it just introduced.
//! The eval harness then asks whether an analyzer reports that defect. Applying
//! a mutation to already-broken code cannot be attributed, so the input is
//! expected to be a program the static track reports nothing on.
//!
//! **Mutation happens on text, not on the IR.** The IR supplies the *site* —
//! file, line, handler, declaration name — and the rewrite is a targeted edit to
//! the original source, so a mutant stays a readable Anchor program a human can
//! open and check. Round-tripping through `quote!` would reformat the whole file
//! and throw away comments, which makes both review and the diff-size guard
//! meaningless.
//!
//! One mutant per applicable site, never sites x operators: a mutant with two
//! injected defects cannot be scored, because a missed finding no longer tells
//! you which defect was missed.

pub mod operators;

use crate::ir::{AccountDecl, AccountsStruct, Handler, Program};
use dike_core::analyzer::SourceTree;
use dike_core::eval::MutationLabel;
use dike_core::finding::Severity;
use std::collections::BTreeSet;
use std::ops::Range;
use std::path::{Path, PathBuf};

pub use operators::{
    AccountToUnchecked, CheckedToBare, SignerToAccountInfo, StripConstraint, StripHasOne,
    StripSeedsBump,
};

/// One clean program plus one injected defect.
///
/// `files` carries only the files the operator actually rewrote, as
/// `(path, full new text)`. Materialization (Task 24) copies the tree and
/// overwrites exactly these — an untouched file is not carried, so a mutant
/// stays small regardless of program size.
#[derive(Debug, Clone, PartialEq)]
pub struct Mutant {
    pub label: MutationLabel,
    pub files: Vec<(PathBuf, String)>,
}

pub trait MutationOperator {
    fn name(&self) -> &'static str;
    /// The class an analyzer is expected to report on the mutant. Reuses the
    /// detector vocabulary in `detectors` — a label the detectors cannot emit
    /// would score every run as a miss.
    fn class(&self) -> &'static str;
    /// A pinned per-operator constant, like `Detector::confidence` and for the
    /// same reason: the harness compares runs across time (invariant 4).
    fn severity(&self) -> Severity;
    fn apply(&self, program: &Program, tree: &SourceTree) -> Vec<Mutant>;
}

pub fn all_operators() -> Vec<Box<dyn MutationOperator>> {
    vec![
        Box::new(SignerToAccountInfo),
        Box::new(AccountToUnchecked),
        Box::new(StripHasOne),
        Box::new(StripConstraint),
        Box::new(StripSeedsBump),
        Box::new(CheckedToBare),
    ]
}

// ---------------------------------------------------------------------------
// Site enumeration
// ---------------------------------------------------------------------------

/// A declaration to mutate, together with the handler it will be attributed to.
pub(crate) struct DeclSite<'a> {
    pub handler: &'a Handler,
    pub accounts: &'a AccountsStruct,
    pub decl: &'a AccountDecl,
}

/// Every account declaration reachable from a handler, each visited once.
///
/// An `#[derive(Accounts)]` struct can back more than one handler, but it is
/// declared once and so is a single mutation site. Attribution goes to the
/// first handler that reaches it; `Program::instructions` is already sorted by
/// name, so that choice is deterministic rather than parse-order dependent
/// (invariant 5).
pub(crate) fn decl_sites(program: &Program) -> Vec<DeclSite<'_>> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut sites = Vec::new();
    for handler in &program.instructions {
        let Some(accounts) = program.accounts_for(handler) else {
            continue;
        };
        for decl in &accounts.decls {
            if seen.insert((accounts.name.clone(), decl.name.clone())) {
                sites.push(DeclSite { handler, accounts, decl });
            }
        }
    }
    sites
}

pub(crate) fn file_text<'a>(tree: &'a SourceTree, path: &Path) -> Option<&'a str> {
    tree.files
        .iter()
        .find(|f| f.path == path)
        .map(|f| f.text.as_str())
}

/// Builds the label for an edit. `site` distinguishes two edits an operator
/// makes on the same line (there are none today, but the id is what history is
/// keyed on, so it must not depend on that staying true).
pub(crate) fn label_for(
    op: &dyn MutationOperator,
    handler: &Handler,
    file: &Path,
    line: u32,
    site: &str,
) -> MutationLabel {
    let seed = format!("{}|{}|{}|{}|{}", op.name(), file.display(), handler.name, line, site);
    MutationLabel {
        id: blake3::hash(seed.as_bytes()).to_hex()[..16].to_string(),
        class: op.class().to_string(),
        severity: op.severity(),
        file: file.to_path_buf(),
        line,
        handler: handler.name.clone(),
        operator: op.name().to_string(),
    }
}

// ---------------------------------------------------------------------------
// Text editing primitives
// ---------------------------------------------------------------------------

/// Byte range of the 1-based `line` in `text`, excluding its line terminator.
pub(crate) fn line_span(text: &str, line: u32) -> Option<Range<usize>> {
    if line == 0 {
        return None;
    }
    let mut start = 0usize;
    for (n, raw) in text.split_inclusive('\n').enumerate() {
        let end = start + raw.trim_end_matches(['\n', '\r']).len();
        if n as u32 + 1 == line {
            return Some(start..end);
        }
        start += raw.len();
    }
    None
}

/// The leading run of horizontal whitespace on the line containing `at`.
pub(crate) fn indent_of(text: &str, at: usize) -> &str {
    let start = text[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let rest = &text[start..];
    let n = rest
        .find(|c: char| c != ' ' && c != '\t')
        .unwrap_or(rest.len());
    &rest[..n]
}

/// Deletes `ranges` from `text`, collapsing any line the deletion empties.
///
/// Overlapping and touching ranges are merged first, so a caller that supplies
/// two deletions sharing a separator gets one deletion rather than a stale
/// offset into an already-shortened string.
pub(crate) fn remove_ranges(text: &str, ranges: Vec<Range<usize>>) -> String {
    let mut ranges: Vec<Range<usize>> = ranges.into_iter().filter(|r| r.start < r.end).collect();
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for r in ranges {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }

    let mut out = text.to_string();
    for r in merged.into_iter().rev() {
        let (mut start, mut end) = (r.start, r.end);
        let line_start = out[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = out[end..].find('\n').map(|i| end + i).unwrap_or(out.len());
        // A deleted item that had its own line leaves an indent-only line
        // behind; that is not a syntax error but it is noise in every diff a
        // reviewer reads, and it inflates the diff-size guard for no reason.
        if out[line_start..start].trim().is_empty() && out[end..line_end].trim().is_empty() {
            start = line_start;
            end = if line_end < out.len() { line_end + 1 } else { line_end };
        }
        out.replace_range(start..end, "");
    }
    out
}

/// One comma-separated item inside an `#[account(...)]` list.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AttrItem {
    /// Byte range of the item itself, trimmed — no surrounding whitespace and
    /// no comma.
    pub range: Range<usize>,
    /// The item's leading identifier: `has_one`, `seeds`, `bump`, `mut`.
    pub key: String,
}

/// Top-level items of the `#[account(...)]` attribute occupying
/// `[attr_line, attr_end_line]`, as byte ranges into `text`.
///
/// The scanner tracks bracket depth and skips string literals, because
/// `seeds = [b"vault", admin.key().as_ref()]` contains both a nested bracket
/// pair and a comma that is not an item separator. It deliberately does *not*
/// treat `'` as a literal delimiter: an account attribute has no reason to
/// contain a `char`, and Rust lifetimes (`'info`) would otherwise open a
/// literal that never closes and swallow the rest of the attribute.
pub(crate) fn account_attr_items(text: &str, attr_line: u32, attr_end_line: u32) -> Vec<AttrItem> {
    let (Some(first), Some(last)) = (line_span(text, attr_line), line_span(text, attr_end_line))
    else {
        return Vec::new();
    };
    let span = first.start..last.end;
    let slice = &text[span.clone()];
    let Some(marker) = slice.find("#[account") else {
        return Vec::new();
    };
    let Some(rel_open) = slice[marker..].find('(') else {
        return Vec::new();
    };
    let open = span.start + marker + rel_open;

    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut item_start = open + 1;
    let mut items: Vec<Range<usize>> = Vec::new();
    let mut i = open;
    while i < span.end {
        let c = bytes[i];
        if in_string {
            match c {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    items.push(item_start..i);
                    break;
                }
            }
            b',' if depth == 1 => {
                items.push(item_start..i);
                item_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }

    items
        .into_iter()
        .filter_map(|r| {
            let raw = &text[r.clone()];
            let lead = raw.len() - raw.trim_start().len();
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            let start = r.start + lead;
            let key: String = trimmed
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            Some(AttrItem { range: start..start + trimmed.len(), key })
        })
        .collect()
}

/// Widens an item's range to swallow the comma that separates it from its
/// neighbours, so removing it leaves a syntactically valid list.
///
/// Only the *trailing* comma, never the preceding one. Taking the preceding
/// comma is what a last item seems to need, but on a one-item-per-line
/// attribute that reaches back across a newline and merges two surviving lines
/// into one — three lines of diff for a one-item deletion. A trailing comma
/// before the closing paren is legal Rust, so the last item can simply leave
/// one behind; `tidy_inline_attr` cleans it up in the single-line case, where
/// it is merely ugly rather than wrong.
pub(crate) fn with_separator(text: &str, range: Range<usize>) -> Range<usize> {
    let bytes = text.as_bytes();
    let mut probe = range.end;
    while probe < bytes.len() && (bytes[probe] == b' ' || bytes[probe] == b'\t') {
        probe += 1;
    }
    if probe < bytes.len() && bytes[probe] == b',' {
        let mut end = probe + 1;
        while end < bytes.len() && (bytes[end] == b' ' || bytes[end] == b'\t') {
            end += 1;
        }
        return range.start..end;
    }
    range
}

/// Drops a comma left dangling before the close of a single-line
/// `#[account(...)]`, turning `#[account(mut, )]` into `#[account(mut)]`.
///
/// Scoped to a line that still carries the attribute's opening, because a
/// dangling comma on a *multi-line* attribute sits alone before `)]` on its own
/// line, which is both legal and the way the fixtures are already written.
pub(crate) fn tidy_inline_attr(text: &str, line: u32) -> String {
    let Some(span) = line_span(text, line) else {
        return text.to_string();
    };
    let source = &text[span.clone()];
    if !source.contains("#[account(") {
        return text.to_string();
    }
    let Some(close) = source.rfind(')') else {
        return text.to_string();
    };
    let head = source[..close].trim_end();
    let Some(head) = head.strip_suffix(',') else {
        return text.to_string();
    };
    let mut out = text.to_string();
    out.replace_range(span, &format!("{head}{}", &source[close..]));
    out
}

/// Rewrites `Wrapper<...>` in `line` to `replacement<'lt>`, preserving the
/// lifetime the original carried.
///
/// `wrapper` is matched only where it is not preceded by an identifier
/// character, so `Account<` never matches inside `UncheckedAccount<` or
/// `InterfaceAccount<`.
pub(crate) fn rewrite_wrapper(line: &str, wrapper: &str, replacement: &str) -> Option<String> {
    let needle = format!("{wrapper}<");
    let mut from = 0usize;
    let at = loop {
        let rel = line[from..].find(&needle)?;
        let at = from + rel;
        let preceded_by_ident = line[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if !preceded_by_ident {
            break at;
        }
        from = at + 1;
    };

    let open = at + needle.len() - 1;
    let bytes = line.as_bytes();
    let mut depth = 0i32;
    let mut close = None;
    for (i, &c) in bytes.iter().enumerate().skip(open) {
        match c {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;

    let args = &line[open + 1..close];
    let lifetime: String = match args.find('\'') {
        Some(i) => {
            let rest = &args[i + 1..];
            let n = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            format!("'{}", &rest[..n])
        }
        None => "'info".to_string(),
    };
    Some(format!(
        "{}{replacement}<{lifetime}>{}",
        &line[..at],
        &line[close + 1..]
    ))
}

/// Anchor refuses to compile a field it cannot validate unless the field
/// carries a `/// CHECK:` doc comment, so an operator that rewrites a typed
/// wrapper into an unvalidated one must add it or produce a mutant that never
/// reaches the analyzer at all. The comment goes directly above the field's own
/// line — after any `#[account(...)]` attribute — so the first line that
/// differs from the clean program is still the line the label points at.
///
/// Returns `text` unchanged when the field already documents itself.
pub(crate) fn insert_check_doc(text: &str, decl_line: u32) -> String {
    let Some(span) = line_span(text, decl_line) else {
        return text.to_string();
    };
    let prev_start = text[..span.start.saturating_sub(1)]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    if text[prev_start..span.start].contains("CHECK:") {
        return text.to_string();
    }
    let indent = indent_of(text, span.start).to_string();
    let mut out = text.to_string();
    out.insert_str(span.start, &format!("{indent}/// CHECK: injected by mutation\n"));
    out
}

/// The 1-based number of the first line where `after` departs from `before`,
/// or `None` if the two are identical.
///
/// Every operator derives its label's line from this rather than from the IR
/// site it started at. The two agree for a single-line edit, but an operator
/// that also inserts a line (`insert_check_doc`) or that deletes an item from a
/// multi-line attribute would otherwise report the declaration's line while the
/// visible change sits somewhere else — and the label is what an auditor
/// reading a scored miss opens the file at.
pub(crate) fn first_changed_line(before: &str, after: &str) -> Option<u32> {
    let mut a = before.lines();
    let mut b = after.lines();
    let mut n = 0u32;
    loop {
        n += 1;
        match (a.next(), b.next()) {
            (None, None) => return None,
            (x, y) if x != y => return Some(n),
            _ => {}
        }
    }
}

/// Index of the bracket closing the one at `open`, skipping string literals.
pub(crate) fn match_bracket(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let (o, c) = match bytes.get(open)? {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        _ => return None,
    };
    let mut depth = 0i32;
    let mut in_string = false;
    let mut i = open;
    while i < bytes.len() {
        let ch = bytes[i];
        if in_string {
            match ch {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
        } else if ch == b'"' {
            in_string = true;
        } else if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two deletions that share bytes must become one. Applied separately, the
    /// second would index into a string the first already shortened.
    #[test]
    fn remove_ranges_merges_overlapping_deletions() {
        let text = "keep AB CD keep";
        assert_eq!(remove_ranges(text, vec![5..8, 7..11]), "keep keep");
    }

    /// An item that had its own line takes the line with it; one that shared
    /// a line with surviving content does not.
    #[test]
    fn remove_ranges_collapses_only_the_lines_it_empties() {
        let one = |r: Range<usize>| vec![r, 0..0];
        assert_eq!(remove_ranges("a\n    b\nc\n", one(6..7)), "a\nc\n");
        assert_eq!(remove_ranges("a\n    b c\nd\n", one(8..9)), "a\n    b \nd\n");
    }

    /// `Account<` must not be found inside `UncheckedAccount<`.
    #[test]
    fn rewrite_wrapper_does_not_match_a_longer_identifier() {
        assert_eq!(
            rewrite_wrapper("    pub v: UncheckedAccount<'info>,", "Account", "Other"),
            None
        );
        assert_eq!(
            rewrite_wrapper("    pub v: Account<'a, Vault>,", "Account", "Other").unwrap(),
            "    pub v: Other<'a>,"
        );
    }

    /// `seeds = [b"vault", x.as_ref()]` carries a comma that is not an item
    /// separator, inside a bracket, next to a string literal.
    #[test]
    fn attr_items_split_on_top_level_commas_only() {
        let text = "#[account(mut, seeds = [b\"v\", a.as_ref()], bump)]\npub v: u8;\n";
        let keys: Vec<String> = account_attr_items(text, 1, 1)
            .into_iter()
            .map(|i| i.key)
            .collect();
        assert_eq!(keys, vec!["mut", "seeds", "bump"]);
    }
}
