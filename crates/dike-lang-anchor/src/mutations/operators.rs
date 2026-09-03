//! The six v1 mutation operators (D13).
//!
//! Every operator follows the same shape: find sites in the IR, rewrite the
//! original source text at each one, and — only if the text actually changed —
//! emit a `Mutant` whose label points at the first line that differs.
//!
//! Operators skip sites where the rewrite would not compile. A mutant Anchor
//! rejects is not a hard case for the analyzer, it is a mutant the harness
//! never gets to score, and Task 24's compile gate would drop it anyway; the
//! cheaper place to know that is here, where the reason is visible.

use super::{
    account_attr_items, decl_sites, file_text, first_changed_line, insert_check_doc, label_for,
    line_span, match_bracket, remove_ranges, rewrite_wrapper, tidy_inline_attr, with_separator,
    Mutant, MutationOperator,
};
use crate::detectors::{
    looks_like_authority, MISSING_AUTHORITY_BINDING, MISSING_OWNER_CHECK, MISSING_SIGNER,
    PDA_VALIDATION_GAP, REMOVED_GUARD, UNCHECKED_ARITHMETIC,
};
use crate::ir::{Constraint, Program, Wrapper};
use dike_core::analyzer::SourceTree;
use dike_core::finding::Severity;
use std::collections::BTreeSet;
use std::ops::Range;

/// Assembles a mutant from a rewritten file, or `None` if nothing changed.
fn mutant_from(
    op: &dyn MutationOperator,
    handler: &crate::ir::Handler,
    file: &std::path::Path,
    before: &str,
    after: String,
    site: &str,
) -> Option<Mutant> {
    let line = first_changed_line(before, &after)?;
    Some(Mutant {
        label: label_for(op, handler, file, line, site),
        files: vec![(file.to_path_buf(), after)],
    })
}

// ---------------------------------------------------------------------------

/// `Signer<'info>` -> `AccountInfo<'info>` on a privileged declaration.
pub struct SignerToAccountInfo;

impl MutationOperator for SignerToAccountInfo {
    fn name(&self) -> &'static str {
        "signer_to_account_info"
    }
    fn class(&self) -> &'static str {
        MISSING_SIGNER
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn apply(&self, program: &Program, tree: &SourceTree) -> Vec<Mutant> {
        let mut out = Vec::new();
        for site in decl_sites(program) {
            let d = site.decl;
            // A non-authority account losing its `Signer` type is not this
            // class of defect, and the static detector does not claim it is
            // (`signer.rs` gates on the same predicate) — injecting one would
            // score a correct silence as a miss.
            if !matches!(d.wrapper, Wrapper::Signer) || d.boxed || d.optional {
                continue;
            }
            if !looks_like_authority(&d.name) || d.is_address_pinned() {
                continue;
            }
            // The legacy `#[account(signer)]` still enforces the check after
            // the type changes, so the mutant would carry no defect at all.
            if d.constraints.iter().any(|c| matches!(c, Constraint::SignerAttr)) {
                continue;
            }
            let Some(text) = file_text(tree, &site.accounts.file) else {
                continue;
            };
            let Some(span) = line_span(text, d.line) else {
                continue;
            };
            let Some(rewritten) = rewrite_wrapper(&text[span.clone()], "Signer", "AccountInfo")
            else {
                continue;
            };
            let mut after = text.to_string();
            after.replace_range(span, &rewritten);
            let after = insert_check_doc(&after, d.line);
            out.extend(mutant_from(
                self,
                site.handler,
                &site.accounts.file,
                text,
                after,
                &d.name,
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------

/// `Account<'info, T>` -> `UncheckedAccount<'info>`.
pub struct AccountToUnchecked;

impl MutationOperator for AccountToUnchecked {
    fn name(&self) -> &'static str {
        "account_to_unchecked"
    }
    fn class(&self) -> &'static str {
        MISSING_OWNER_CHECK
    }
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn apply(&self, program: &Program, tree: &SourceTree) -> Vec<Mutant> {
        let mut out = Vec::new();
        for site in decl_sites(program) {
            let d = site.decl;
            if !matches!(d.wrapper, Wrapper::Account(_)) || d.boxed || d.optional {
                continue;
            }
            // `init`, `close` and `has_one` are all implemented against the
            // deserialized account type; none of them compile against an
            // `UncheckedAccount`.
            if d.is_init()
                || d.constraints.iter().any(|c| matches!(c, Constraint::Close(_) | Constraint::HasOne(_)))
            {
                continue;
            }
            let Some(text) = file_text(tree, &site.accounts.file) else {
                continue;
            };
            // A `seeds`/`bump` expression that reads the field's own data
            // (`bump = vault.bump`) stops compiling for the same reason. The
            // raw attribute text is the reliable place to see that: the IR
            // renders constraint values through `TokenStream::to_string`,
            // which spaces the punctuation apart.
            if let (Some(a), Some(b)) = (
                line_span(text, d.attr_line),
                line_span(text, d.attr_end_line),
            ) {
                if text[a.start..b.end].contains(&format!("{}.", d.name)) {
                    continue;
                }
            }
            let Some(span) = line_span(text, d.line) else {
                continue;
            };
            let Some(rewritten) =
                rewrite_wrapper(&text[span.clone()], "Account", "UncheckedAccount")
            else {
                continue;
            };
            let mut after = text.to_string();
            after.replace_range(span, &rewritten);
            let after = insert_check_doc(&after, d.line);
            out.extend(mutant_from(
                self,
                site.handler,
                &site.accounts.file,
                text,
                after,
                &d.name,
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------

/// Deletes one item from an `#[account(...)]` list, by key.
///
/// `strip_has_one`, `strip_constraint` and `strip_seeds_bump` differ only in
/// which keys they take and whether they take them one at a time, so the walk
/// lives here once.
fn strip_items(
    op: &dyn MutationOperator,
    program: &Program,
    tree: &SourceTree,
    keys: &[&str],
    together: bool,
) -> Vec<Mutant> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(std::path::PathBuf, usize)> = BTreeSet::new();
    for site in decl_sites(program) {
        let d = site.decl;
        if d.attr_line == 0 {
            continue;
        }
        let Some(text) = file_text(tree, &site.accounts.file) else {
            continue;
        };
        let items = account_attr_items(text, d.attr_line, d.attr_end_line);
        let matched: Vec<Range<usize>> = items
            .iter()
            .filter(|i| keys.contains(&i.key.as_str()))
            .map(|i| with_separator(text, i.range.clone()))
            .collect();
        if matched.is_empty() {
            continue;
        }
        // `seeds` and `bump` are one defect, not two: a PDA missing only its
        // bump does not compile, and a PDA missing only its seeds is a
        // different (and rejected) shape. Every other key is its own site.
        let groups: Vec<Vec<Range<usize>>> = if together {
            vec![matched]
        } else {
            matched.into_iter().map(|r| vec![r]).collect()
        };
        for group in groups {
            let start = group.iter().map(|r| r.start).min().unwrap_or(0);
            if !seen.insert((site.accounts.file.clone(), start)) {
                continue;
            }
            let after = remove_ranges(text, group);
            let after = match first_changed_line(text, &after) {
                Some(l) => tidy_inline_attr(&after, l),
                None => after,
            };
            out.extend(mutant_from(
                op,
                site.handler,
                &site.accounts.file,
                text,
                after,
                &format!("{}@{start}", d.name),
            ));
        }
    }
    out
}

/// Deletes a `has_one = X` binding.
pub struct StripHasOne;

impl MutationOperator for StripHasOne {
    fn name(&self) -> &'static str {
        "strip_has_one"
    }
    fn class(&self) -> &'static str {
        MISSING_AUTHORITY_BINDING
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn apply(&self, program: &Program, tree: &SourceTree) -> Vec<Mutant> {
        strip_items(self, program, tree, &["has_one"], false)
    }
}

/// Deletes a `constraint = ...` expression.
pub struct StripConstraint;

impl MutationOperator for StripConstraint {
    fn name(&self) -> &'static str {
        "strip_constraint"
    }
    fn class(&self) -> &'static str {
        REMOVED_GUARD
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn apply(&self, program: &Program, tree: &SourceTree) -> Vec<Mutant> {
        strip_items(self, program, tree, &["constraint"], false)
    }
}

/// Deletes `seeds = [...]` and `bump` together.
pub struct StripSeedsBump;

impl MutationOperator for StripSeedsBump {
    fn name(&self) -> &'static str {
        "strip_seeds_bump"
    }
    fn class(&self) -> &'static str {
        PDA_VALIDATION_GAP
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn apply(&self, program: &Program, tree: &SourceTree) -> Vec<Mutant> {
        strip_items(self, program, tree, &["seeds", "bump"], true)
    }
}

// ---------------------------------------------------------------------------

/// `x.checked_add(y).unwrap()` -> `x + y`, and the same for `_sub`, `_mul`,
/// `_div`.
pub struct CheckedToBare;

const CHECKED_OPS: [(&str, &str); 4] = [
    ("checked_add", "+"),
    ("checked_sub", "-"),
    ("checked_mul", "*"),
    ("checked_div", "/"),
];

/// Start of the postfix expression ending at the `.` at `dot`.
///
/// Walks back over identifier characters and field accesses, jumping over
/// balanced `(...)`/`[...]` so a receiver like `ctx.accounts.vault.amount` or
/// `balances[i]` survives intact. Anything else — whitespace, an operator, an
/// opening delimiter — ends the receiver.
fn receiver_start(line: &str, dot: usize) -> usize {
    let b = line.as_bytes();
    let mut i = dot;
    while i > 0 {
        let c = b[i - 1];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
            i -= 1;
        } else if c == b')' || c == b']' {
            let (open, close) = if c == b')' { (b'(', b')') } else { (b'[', b']') };
            let mut depth = 0i32;
            let mut j = i - 1;
            let found = loop {
                if b[j] == close {
                    depth += 1;
                } else if b[j] == open {
                    depth -= 1;
                    if depth == 0 {
                        break Some(j);
                    }
                }
                if j == 0 {
                    break None;
                }
                j -= 1;
            };
            match found {
                Some(j) => i = j,
                None => return i,
            }
        } else {
            return i;
        }
    }
    i
}

/// Every `checked_*` call on `line` that can be reduced to bare arithmetic, as
/// `(range to replace, replacement text)`.
///
/// A call whose `Option` is not immediately unwrapped is skipped: rewriting
/// `let x = a.checked_add(b);` to `let x = a + b;` changes the binding's type,
/// and a mutant that does not compile is a mutant the harness cannot score.
fn checked_calls(line: &str) -> Vec<(Range<usize>, String)> {
    let mut out = Vec::new();
    for (name, symbol) in CHECKED_OPS {
        let needle = format!(".{name}(");
        let mut from = 0usize;
        while let Some(rel) = line[from..].find(&needle) {
            let dot = from + rel;
            from = dot + needle.len();
            let open = dot + needle.len() - 1;
            let Some(close) = match_bracket(line, open) else {
                continue;
            };
            let args = line[open + 1..close].trim().to_string();
            if args.is_empty() {
                continue;
            }
            let mut end = close + 1;
            let rest = &line[end..];
            if let Some(stripped) = rest.strip_prefix(".unwrap()") {
                let _ = stripped;
                end += ".unwrap()".len();
            } else if let Some(m) = [".expect(", ".ok_or(", ".ok_or_else(", ".unwrap_or("]
                .into_iter()
                .find(|m| rest.starts_with(m))
            {
                let Some(c) = match_bracket(line, end + m.len() - 1) else {
                    continue;
                };
                end = c + 1;
            }
            let consumed_combinator = end > close + 1;
            if line[end..].starts_with('?') {
                end += 1;
            } else if !consumed_combinator {
                continue;
            }
            let start = receiver_start(line, dot);
            if start == dot {
                continue;
            }
            out.push((start..end, format!("{} {symbol} {args}", &line[start..dot])));
        }
    }
    out.sort_by_key(|(r, _)| r.start);
    out
}

impl MutationOperator for CheckedToBare {
    fn name(&self) -> &'static str {
        "checked_to_bare"
    }
    fn class(&self) -> &'static str {
        UNCHECKED_ARITHMETIC
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn apply(&self, program: &Program, tree: &SourceTree) -> Vec<Mutant> {
        let mut out = Vec::new();
        let mut seen: BTreeSet<(std::path::PathBuf, u32, usize)> = BTreeSet::new();
        for handler in &program.instructions {
            let Some(text) = file_text(tree, &handler.file) else {
                continue;
            };
            // The IR says which lines carry checked arithmetic and which
            // handler owns them; the text says how to rewrite it. A line can
            // hold more than one call, so each is its own site.
            let mut lines: Vec<u32> = handler
                .body
                .arithmetic
                .iter()
                .filter(|a| a.checked)
                .map(|a| a.line)
                .collect();
            lines.sort_unstable();
            lines.dedup();
            for line_no in lines {
                let Some(span) = line_span(text, line_no) else {
                    continue;
                };
                let source_line = &text[span.clone()];
                for (n, (range, replacement)) in checked_calls(source_line).into_iter().enumerate() {
                    if !seen.insert((handler.file.clone(), line_no, n)) {
                        continue;
                    }
                    let mut rewritten = source_line.to_string();
                    rewritten.replace_range(range, &replacement);
                    let mut after = text.to_string();
                    after.replace_range(span.clone(), &rewritten);
                    out.extend(mutant_from(
                        self,
                        handler,
                        &handler.file,
                        text,
                        after,
                        &format!("{line_no}#{n}"),
                    ));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutations::all_operators;
    use dike_core::analyzer::{SourceFile, SourceTree};
    use std::path::PathBuf;

    const CLEAN: &str = r#"
#[program]
pub mod vault {
    pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
        ctx.accounts.vault.amount = ctx.accounts.vault.amount.checked_sub(amount).unwrap();
        Ok(())
    }
}
#[account]
pub struct Vault { pub admin: Pubkey, pub amount: u64 }
#[derive(Accounts)]
pub struct W<'info> {
    pub admin: Signer<'info>,
    #[account(mut, has_one = admin, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}
"#;

    /// Multi-line attributes, a `constraint =`, and the `.ok_or(..)?` form of
    /// a checked call — the shapes the real fixture programs are written in,
    /// none of which `CLEAN` exercises.
    const MULTILINE: &str = r#"
#[program]
pub mod vault {
    pub fn deposit(ctx: Context<D>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.amount = vault.amount.checked_add(amount).ok_or(VaultError::Overflow)?;
        Ok(())
    }
}
#[account]
pub struct Vault { pub admin: Pubkey, pub amount: u64, pub bump: u8 }
#[derive(Accounts)]
pub struct D<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.admin.as_ref()],
        bump = vault.bump,
        has_one = admin,
        constraint = vault.amount > 0,
    )]
    pub vault: Account<'info, Vault>,

    pub admin: Signer<'info>,
}
"#;

    /// One `Account<'info, T>` declaration per shape that blocks the rewrite,
    /// plus one (`plain`) that permits it.
    const GUARDED: &str = r#"
#[program]
pub mod vault {
    pub fn go(ctx: Context<G>) -> Result<()> { Ok(()) }
}
#[account]
pub struct Vault { pub admin: Pubkey, pub bump: u8 }
#[derive(Accounts)]
pub struct G<'info> {
    #[account(init, payer = admin, space = 8)]
    pub created: Account<'info, Vault>,
    #[account(mut, close = admin)]
    pub closing: Account<'info, Vault>,
    #[account(mut, has_one = admin)]
    pub bound: Account<'info, Vault>,
    #[account(seeds = [b"v"], bump = derived.bump)]
    pub derived: Account<'info, Vault>,
    #[account(mut)]
    pub plain: Account<'info, Vault>,
    pub admin: Signer<'info>,
}
"#;

    fn tree_for(src: &str) -> SourceTree {
        SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("lib.rs"), text: src.to_string() }],
        }
    }

    fn apply_operator(op: impl MutationOperator, src: &str) -> Vec<Mutant> {
        let tree = tree_for(src);
        let program = crate::parser::parse_tree(&tree).program;
        op.apply(&program, &tree)
    }

    /// Lines changed, as a reviewer would count them: an edited line is one
    /// change, not an add plus a delete.
    fn line_diff_count(before: &str, after: &str) -> usize {
        let a: Vec<&str> = before.lines().collect();
        let b: Vec<&str> = after.lines().collect();
        let mut removed = a.clone();
        for line in &b {
            if let Some(i) = removed.iter().position(|x| x == line) {
                removed.remove(i);
            }
        }
        let mut added = b.clone();
        for line in &a {
            if let Some(i) = added.iter().position(|x| x == line) {
                added.remove(i);
            }
        }
        removed.len().max(added.len())
    }

    fn first_differing_line(before: &str, after: &str) -> u32 {
        first_changed_line(before, after).expect("the mutant is identical to the clean program")
    }

    #[test]
    fn signer_operator_produces_one_labeled_mutant() {
        let mutants = apply_operator(SignerToAccountInfo, CLEAN);
        assert_eq!(mutants.len(), 1);
        assert_eq!(mutants[0].label.class, "missing-signer");
        assert_eq!(mutants[0].label.handler, "withdraw");
        assert_eq!(mutants[0].label.severity, dike_core::Severity::Critical);
        assert_eq!(mutants[0].label.operator, "signer_to_account_info");
        let text = &mutants[0].files[0].1;
        assert!(text.contains("pub admin: AccountInfo<'info>"), "{text}");
        assert!(!text.contains("pub admin: Signer<'info>"));
    }

    /// Anchor rejects an unvalidated field with no `/// CHECK:` doc, so a
    /// mutant without one never survives Task 24's compile gate.
    #[test]
    fn wrapper_operators_document_the_unvalidated_field() {
        for text in [
            apply_operator(SignerToAccountInfo, CLEAN)[0].files[0].1.clone(),
            apply_operator(AccountToUnchecked, GUARDED)[0].files[0].1.clone(),
        ] {
            let doc = text
                .lines()
                .position(|l| l.contains("CHECK:"))
                .expect("no CHECK doc emitted");
            assert!(
                text.lines().nth(doc + 1).unwrap().contains("pub "),
                "the CHECK doc must sit on the field it documents:\n{text}"
            );
        }
    }

    #[test]
    fn strip_has_one_leaves_valid_attribute_syntax() {
        let text = &apply_operator(StripHasOne, CLEAN)[0].files[0].1;
        assert!(!text.contains("has_one"));
        assert!(!text.contains(", )") && !text.contains("(, "));
        assert!(text.contains("#[account(mut, seeds"), "{text}");
    }

    #[test]
    fn strip_has_one_removes_the_whole_line_in_a_multiline_attribute() {
        let mutants = apply_operator(StripHasOne, MULTILINE);
        assert_eq!(mutants.len(), 1);
        let text = &mutants[0].files[0].1;
        assert!(!text.contains("has_one"));
        // No indent-only leftover where the item used to be.
        assert!(
            !text.lines().any(|l| !l.is_empty() && l.trim().is_empty()),
            "{text}"
        );
        assert!(text.contains("bump = vault.bump,"), "{text}");
    }

    #[test]
    fn strip_constraint_removes_only_the_constraint_expression() {
        let mutants = apply_operator(StripConstraint, MULTILINE);
        assert_eq!(mutants.len(), 1);
        assert_eq!(mutants[0].label.class, "removed-guard");
        let text = &mutants[0].files[0].1;
        assert!(!text.contains("constraint ="), "{text}");
        assert!(text.contains("has_one = admin,"), "{text}");
        assert!(text.contains("seeds = [b\"vault\", vault.admin.as_ref()],"), "{text}");
    }

    #[test]
    fn checked_to_bare_rewrites_the_arithmetic() {
        let text = &apply_operator(CheckedToBare, CLEAN)[0].files[0].1;
        assert!(!text.contains("checked_sub"));
        assert!(text.contains("ctx.accounts.vault.amount - amount"), "{text}");
    }

    /// The real fixtures propagate with `.ok_or(..)?` rather than
    /// `.unwrap()`; an operator that only handles `unwrap` produces nothing
    /// on them.
    #[test]
    fn checked_to_bare_consumes_the_ok_or_question_mark_form() {
        let mutants = apply_operator(CheckedToBare, MULTILINE);
        assert_eq!(mutants.len(), 1);
        let text = &mutants[0].files[0].1;
        assert!(!text.contains("checked_add") && !text.contains("ok_or"), "{text}");
        assert!(text.contains("vault.amount = vault.amount + amount;"), "{text}");
    }

    /// A `checked_*` whose `Option` is kept would change the binding's type.
    #[test]
    fn checked_to_bare_leaves_an_unconsumed_option_alone() {
        assert!(checked_calls("let x = a.checked_add(b);").is_empty());
        assert!(!checked_calls("let x = a.checked_add(b)?;").is_empty());
    }

    #[test]
    fn each_mutant_changes_exactly_one_thing() {
        for src in [CLEAN, MULTILINE] {
            let tree = tree_for(src);
            let program = crate::parser::parse_tree(&tree).program;
            let mut total = 0;
            for op in all_operators() {
                for m in op.apply(&program, &tree) {
                    total += 1;
                    let diff_lines = line_diff_count(src, &m.files[0].1);
                    assert!(diff_lines <= 2, "{} changed {diff_lines} lines", op.name());
                }
            }
            assert!(total > 0, "no operator fired at all");
        }
    }

    #[test]
    fn strip_seeds_bump_removes_both() {
        let text = &apply_operator(StripSeedsBump, CLEAN)[0].files[0].1;
        assert!(!text.contains("seeds") && !text.contains("bump"), "{text}");
        assert!(text.contains("#[account(mut, has_one = admin)]"), "{text}");
    }

    #[test]
    fn strip_seeds_bump_is_one_mutant_not_two() {
        let mutants = apply_operator(StripSeedsBump, MULTILINE);
        assert_eq!(mutants.len(), 1);
        let text = &mutants[0].files[0].1;
        assert!(!text.contains("seeds =") && !text.contains("bump ="), "{text}");
        assert!(text.contains("has_one = admin,"), "{text}");
    }

    #[test]
    fn labels_point_at_the_line_that_changed() {
        for src in [CLEAN, MULTILINE] {
            let tree = tree_for(src);
            let program = crate::parser::parse_tree(&tree).program;
            for op in all_operators() {
                for m in op.apply(&program, &tree) {
                    let changed = first_differing_line(src, &m.files[0].1);
                    assert_eq!(m.label.line, changed, "operator {}", op.name());
                    assert!(m.label.line > 0);
                }
            }
        }
    }

    /// An accounts struct shared by two handlers is declared once and so is
    /// one site; without the guard every operator would emit a duplicate
    /// mutant per extra handler and the harness would count the same defect
    /// twice.
    #[test]
    fn a_shared_accounts_struct_yields_one_mutant() {
        const SHARED: &str = r#"
#[program]
pub mod vault {
    pub fn withdraw(ctx: Context<W>) -> Result<()> { Ok(()) }
    pub fn sweep(ctx: Context<W>) -> Result<()> { Ok(()) }
}
#[account]
pub struct Vault { pub admin: Pubkey }
#[derive(Accounts)]
pub struct W<'info> {
    pub admin: Signer<'info>,
    #[account(mut, has_one = admin)]
    pub vault: Account<'info, Vault>,
}
"#;
        let tree = tree_for(SHARED);
        let program = crate::parser::parse_tree(&tree).program;
        for op in all_operators() {
            let mutants = op.apply(&program, &tree);
            assert!(mutants.len() <= 1, "{} emitted {}", op.name(), mutants.len());
            // Attribution is the first handler by name, not by parse order.
            for m in mutants {
                assert_eq!(m.label.handler, "sweep", "operator {}", op.name());
            }
        }
        assert_eq!(apply_operator(StripHasOne, SHARED).len(), 1);
        assert_eq!(apply_operator(SignerToAccountInfo, SHARED).len(), 1);
    }

    /// Mutant ids are what the eval harness keys history on. If they moved
    /// between runs, every comparison across time would read as a fully new
    /// mutant set.
    #[test]
    fn ids_are_stable_and_distinct_per_site() {
        let a = apply_operator(StripSeedsBump, MULTILINE);
        let b = apply_operator(StripSeedsBump, MULTILINE);
        assert_eq!(a[0].label.id, b[0].label.id);

        let tree = tree_for(MULTILINE);
        let program = crate::parser::parse_tree(&tree).program;
        let mut ids: Vec<String> = all_operators()
            .iter()
            .flat_map(|op| op.apply(&program, &tree))
            .map(|m| m.label.id)
            .collect();
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count, "two sites share an id");
    }

    /// An operator must not fire where its rewrite would not compile: `init`,
    /// `close` and `has_one` are all defined against the deserialized type,
    /// and `bump = vault.bump` reads the field's own data.
    #[test]
    fn account_to_unchecked_skips_declarations_that_would_not_compile() {
        let mutants = apply_operator(AccountToUnchecked, GUARDED);
        let names: Vec<&str> = mutants
            .iter()
            .map(|m| m.files[0].1.as_str())
            .collect();
        assert_eq!(mutants.len(), 1, "fired on {names:?}");
        assert!(mutants[0].files[0].1.contains("pub plain: UncheckedAccount<'info>"));
    }

    /// The injected defect must be one the class actually names. A
    /// non-privileged `Signer` losing its type is not a missing *authority*
    /// check, and `signer.rs` deliberately stays silent on it — labelling it
    /// `missing-signer` would score a correct silence as a miss.
    #[test]
    fn signer_operator_skips_declarations_the_detector_would_not_report() {
        const MIXED: &str = r#"
#[program]
pub mod vault {
    pub fn go(ctx: Context<G>) -> Result<()> { Ok(()) }
}
#[derive(Accounts)]
pub struct G<'info> {
    pub admin: Signer<'info>,
    pub depositor: Signer<'info>,
    #[account(address = crate::ID)]
    pub owner: Signer<'info>,
    #[account(signer)]
    pub manager: AccountInfo<'info>,
    #[account(signer)]
    pub payer: Signer<'info>,
}
"#;
        let mutants = apply_operator(SignerToAccountInfo, MIXED);
        assert_eq!(mutants.len(), 1, "{:?}", mutants.iter().map(|m| &m.label.id).collect::<Vec<_>>());
        assert!(mutants[0].files[0].1.contains("pub admin: AccountInfo<'info>"));
        assert!(mutants[0].files[0].1.contains("pub depositor: Signer<'info>"));
        assert!(mutants[0].files[0].1.contains("pub owner: Signer<'info>"));
        // The legacy `#[account(signer)]` still enforces the check after the
        // type changes, so that declaration carries no injectable defect.
        assert!(mutants[0].files[0].1.contains("pub payer: Signer<'info>"));
    }

    /// Every operator's class must be one a detector can actually emit;
    /// otherwise the harness scores a correct report as a miss.
    #[test]
    fn operator_classes_are_in_the_detector_vocabulary() {
        let known = [
            MISSING_SIGNER,
            MISSING_OWNER_CHECK,
            MISSING_AUTHORITY_BINDING,
            PDA_VALIDATION_GAP,
            UNCHECKED_ARITHMETIC,
            REMOVED_GUARD,
        ];
        for op in all_operators() {
            assert!(known.contains(&op.class()), "{} emits {}", op.name(), op.class());
        }
    }

    /// Mutating already-broken code cannot be attributed, so the operators are
    /// developed against the clean fixture. This pins that they actually reach
    /// it — a silent zero would make the whole harness report perfect recall.
    #[test]
    fn every_operator_fires_on_the_clean_fixture_program() {
        let tree = SourceTree::load(std::path::Path::new(
            "../../tests/fixtures/programs/vault",
        ))
        .expect("clean fixture");
        let program = crate::parser::parse_tree(&tree).program;
        for op in all_operators() {
            let n = op.apply(&program, &tree).len();
            // `constraint = ...` does not appear in the clean fixture; it is
            // the one operator the fixture cannot exercise.
            if op.name() == "strip_constraint" {
                assert_eq!(n, 0);
            } else {
                assert!(n > 0, "{} produced no mutants", op.name());
            }
        }
    }
}
