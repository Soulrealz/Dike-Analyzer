use super::{
    MISSING_AUTHORITY_BINDING, MISSING_OWNER_CHECK, MISSING_SIGNER, PDA_VALIDATION_GAP,
    UNCHECKED_ARITHMETIC,
};
use crate::ir::{AccountsStruct, CheckKind, Handler};
use dike_core::finding::Finding;

/// A finding that was dropped because an imperative check in the handler
/// body (or a bare `#[access_control]`) appears to already cover it.
/// Suppressed findings are never silently discarded — the caller is
/// expected to report `reason` alongside the original `finding` so an
/// auditor can see what was pulled and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Suppression {
    pub finding: Finding,
    pub reason: String,
}

/// Recover the account a Track 1 finding is *about* from its evidence text.
///
/// `Finding` deliberately carries no account-name field — that would be a
/// language-specific need widening a domain-agnostic type — so the subject
/// has to be recovered from the human-readable evidence string instead.
///
/// This scans the evidence for backtick-delimited spans **in the order they
/// appear in the text**, not in `accounts.decls` declaration order, and
/// returns the first span whose content exactly equals some declared
/// account's name. Declaration-order scanning is wrong: `authority.rs`'s
/// evidence backticks BOTH the account name (`d.name`, e.g. `vault`) and the
/// authority-shaped state-struct field name it flags (e.g. `admin`), and
/// Anchor programs very commonly also declare an *account* named `admin`. If
/// that account happens to be declared before `vault` in the accounts
/// struct, a decl-order scan would return `admin` as the subject of a
/// finding that is really about `vault` — silently redirecting suppression
/// onto the wrong account (a false negative, the dangerous direction here).
/// All four account-oriented detectors (`signer.rs`, `owner.rs`,
/// `authority.rs`, `pda.rs`) put the account name as the FIRST backticked
/// token in their evidence, so scanning by textual position and matching
/// the first hit is correct by construction and immune to a second
/// backticked name (or a `{:?}` wrapper debug span, or a literal phrase
/// like `` `Signer<'info>` ``) appearing later in the same string.
fn subject_account(finding: &Finding, accounts: &AccountsStruct) -> Option<String> {
    let evidence = finding.evidence.as_str();
    let mut rest = evidence;
    loop {
        let start = rest.find('`')?;
        let after_start = &rest[start + 1..];
        let end = after_start.find('`')?;
        let span = &after_start[..end];
        if let Some(decl) = accounts.decls.iter().find(|d| d.name == span) {
            return Some(decl.name.clone());
        }
        rest = &after_start[end + 1..];
    }
}

/// Does `needle` occur in `haystack` at a position not preceded by an
/// identifier character? Plain substring `contains` is unsound for the
/// per-account checks in `apply` below: `"vault."` is a substring of
/// `"my_vault.admin"`, so a naive search would let a check that mentions
/// only `my_vault` suppress a finding on the unrelated account `vault`. This
/// requires the byte immediately before any candidate match to be either
/// absent (the match starts at position 0) or NOT in `[A-Za-z0-9_]` — the
/// same boundary an identifier lexer would enforce, without needing to
/// re-tokenize the whole string.
fn contains_anchored(haystack: &str, needle: &str) -> bool {
    !anchored_occurrences(haystack, needle).is_empty()
}

/// The position-returning core of `contains_anchored`, factored out so the
/// round-3 local equality-to-key adjacency scan (see `apply` below) can
/// reuse the exact same boundary rule instead of duplicating it. Returns the
/// start byte offset of every anchored occurrence of `needle` in `haystack`,
/// in order.
fn anchored_occurrences(haystack: &str, needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = haystack[search_from..].find(needle) {
        let abs = search_from + rel;
        let anchored = match haystack[..abs].chars().next_back() {
            None => true,
            Some(prev) => !(prev.is_ascii_alphanumeric() || prev == '_'),
        };
        if anchored {
            out.push(abs);
        }
        // Task 12 fix round 3, Item 3: advance past THIS occurrence's start
        // (accepted or rejected — either way there may be a later, distinct
        // match) by the byte length of the needle's first character, not a
        // fixed one byte. `abs` itself is always a valid char boundary of
        // `haystack` — a valid-UTF-8 needle can only match at one, so a
        // multi-byte character elsewhere in the haystack (an accented error
        // message, say) can never cause a panic here. The actual hazard is a
        // needle that itself STARTS with a non-ASCII `XID_Start` character
        // (Rust identifiers may begin with one): advancing by a fixed one
        // byte would land mid-character inside that first codepoint's own
        // encoding, and the next `haystack[search_from..]` slice would panic
        // with "byte index is not a char boundary".
        search_from = abs
            + needle
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
        if search_from > haystack.len() {
            break;
        }
    }
    out
}

/// Is `ch` part of a bare field-access chain (`vault.admin`,
/// `ctx.accounts.vault.admin`)? Deliberately excludes `(` and `)` so a chain
/// can never extend through a method call or an enclosing function call —
/// see `equality_to_key_suppresses` below.
fn is_chain_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'
}

/// Consume the maximal run of `is_chain_char` bytes starting at `from`,
/// returning the end offset (exclusive).
fn consume_chain_forward(s: &str, from: usize) -> usize {
    let mut end = from;
    for ch in s[from..].chars() {
        if is_chain_char(ch) {
            end += ch.len_utf8();
        } else {
            break;
        }
    }
    end
}

/// Consume the maximal run of `is_chain_char` bytes ending at `upto`
/// (exclusive), scanning backward, returning the start offset.
fn consume_chain_backward(s: &str, upto: usize) -> usize {
    let mut start = upto;
    for ch in s[..upto].chars().rev() {
        if is_chain_char(ch) {
            start -= ch.len_utf8();
        } else {
            break;
        }
    }
    start
}

/// Task 12 fix round 3, Item 1: the local equality-to-key adjacency scan.
/// Recovers the single most common plain-`require!` identity-validation
/// idiom in Anchor code —
/// `require!(ctx.accounts.vault.admin == ctx.accounts.admin.key(), E::X)` —
/// which neither round 2 disjunct catches: the `.key()` call is anchored to
/// `admin`, not `vault`, and the check's kind is `Require`, not
/// `RequireKeysEq`. This disjunct is deliberately independent of
/// `CheckKind` — recovering the plain `require!` idiom is the entire point.
///
/// A clause-splitting design (split `compact` on `&&`/`||`, require one
/// clause to hold both an anchored `X.` and a `.key()`) was proposed and
/// REJECTED on review: `require!(compute_hash(ctx.accounts.vault.seed) ==
/// ctx.accounts.mint.key(), E::Bad)` has no `&&` anywhere, so the "clause"
/// is the whole text; it contains anchored `vault.` and `.key()`, so
/// clause-splitting would suppress a finding on `vault` even though only
/// `mint`'s key is involved. Bare co-occurrence within a boundary is not
/// relatedness. This scan instead requires the two operands to be
/// IMMEDIATELY adjacent across the `==`, on `compact` (whitespace already
/// stripped):
///
/// Forward order (`X.field == other.key()`): find each anchored occurrence
/// of `X.` (reusing `anchored_occurrences`); from that occurrence's own
/// start, consume a maximal chain run (e.g. `vault.admin` — note this
/// deliberately does NOT include the `ctx.accounts.` prefix, since the scan
/// starts at the anchor position itself, not the full path); require the
/// chain to be followed immediately by `==`; consume a second maximal chain
/// run right after; require that second run to be followed immediately by
/// `()` and to itself end in `.key`.
///
/// Mirror order (`other.key() == X.field`): symmetric, but the anchor
/// (`X.`) sits on the right of `==` inside a longer path
/// (`ctx.accounts.vault.admin`), so recovering "what's immediately before
/// the `==`" requires first walking backward from the anchor through the
/// FULL chain (including the `ctx.accounts.` prefix this time) to find
/// where that whole path starts, THEN checking what precedes it.
///
/// `(` and `)` are excluded from the chain charset specifically so a chain
/// can never extend through a method call or an enclosing function call —
/// this is what correctly rejects `compute_hash(ctx.accounts.vault.seed) ==
/// ctx.accounts.mint.key()`: the chain from anchored `vault.` stops at the
/// closing `)`, never reaching `==`.
fn equality_to_key_suppresses(compact: &str, name: &str) -> bool {
    let needle = format!("{}.", name);
    for start in anchored_occurrences(compact, &needle) {
        // Forward: X.field == other...key()
        let chain1_end = consume_chain_forward(compact, start);
        if compact[chain1_end..].starts_with("==") {
            let after_eq = chain1_end + 2;
            let chain2_end = consume_chain_forward(compact, after_eq);
            let chain2 = &compact[after_eq..chain2_end];
            if compact[chain2_end..].starts_with("()") && chain2.ends_with(".key") {
                return true;
            }
        }

        // Mirror: other...key() == X.field
        //
        // Task 12 fix round 4, Item 1: this used to recover `before_eq` and
        // `call_end` by subtracting a fixed byte count (2, for "==" or
        // "()") from a boundary and then slicing at the result. `checked_sub`
        // guards integer underflow only — it says nothing about whether the
        // *result* lands on a UTF-8 char boundary. `full_chain_start` is
        // always a boundary (it comes from `consume_chain_backward`, which
        // walks `chars()`), but the two bytes immediately BEFORE it are not
        // guaranteed to be the ASCII bytes of "==" — they could be the tail
        // of a multi-byte character (e.g. `日` or `🎉` in an identifier
        // immediately preceding the chain, or immediately before the `==`),
        // in which case the blind subtraction lands mid-character and the
        // following slice panics ("byte index is not a char boundary").
        //
        // Fixed by using `str::ends_with` on a prefix slice instead, which
        // is boundary-safe by construction: slicing `&compact[..N]` for a
        // boundary `N` is always valid, and `ends_with` itself never
        // constructs an intermediate slice at a non-boundary offset. Once
        // `ends_with("==")` (or `"()"`) has confirmed the final two bytes of
        // that prefix are the ASCII characters `=`/`(`/`)`, subtracting 2
        // from the prefix's length necessarily lands on a boundary — ASCII
        // bytes are always exactly one byte and always a boundary on both
        // sides.
        let full_chain_start = consume_chain_backward(compact, start);
        let head = &compact[..full_chain_start];
        if head.ends_with("==") {
            let before_eq = full_chain_start - 2; // safe: "==" is two ASCII bytes
            let head2 = &compact[..before_eq];
            if head2.ends_with("()") {
                let call_end = before_eq - 2; // safe: "()" is two ASCII bytes
                let chain0_start = consume_chain_backward(compact, call_end);
                let chain0 = &compact[chain0_start..call_end];
                if chain0.ends_with(".key") {
                    return true;
                }
            }
        }
    }
    false
}

/// Split `findings` into what survives and what an imperative check (or a
/// bare `#[access_control]`, for the two authority classes only) covers.
///
/// Deliberately narrow — recall is this project's primary metric, and
/// over-suppressing is the expensive error here. Naming account `X` inside a
/// check is NOT sufficient by itself; each class requires a specific,
/// anchored idiom in the check's text (see the rule breakdown in the first
/// large comment block inside this function for the exact per-class rules
/// and their history):
/// - `missing-signer` on `X`: only an anchored `X.is_signer`, or a bare
///   `#[access_control]`. Key equality (any `CheckKind`, including
///   `require_keys_eq!`) never suppresses this class — it proves identity,
///   not a signature.
/// - `missing-owner-check` / `missing-authority-binding` on `X`: an anchored
///   `X.key()`, or `CheckKind::RequireKeysEq` plus anchored `X.`, or an
///   `X.field == other.key()` equality in either operand order (see
///   `equality_to_key_suppresses`). `missing-authority-binding` additionally
///   falls back to a bare `#[access_control]`; `missing-owner-check` never
///   does. `CheckKind::AccessControl` itself is excluded from the
///   named-check search for both classes.
/// - `unchecked-arithmetic` and `pda-validation-gap` are never suppressed. A
///   `require!` does not make arithmetic safe, and nothing short of
///   re-deriving the PDA validates a seeds/bump pair.
pub fn apply(
    findings: Vec<Finding>,
    handler: &Handler,
    accounts: &AccountsStruct,
) -> (Vec<Finding>, Vec<Suppression>) {
    let has_access_control =
        handler.body.checks.iter().any(|c| c.kind == CheckKind::AccessControl);

    let mut kept = Vec::new();
    let mut suppressed = Vec::new();

    for f in findings {
        let class = f.class.as_str().to_string();
        let suppressible_by_access_control =
            class == MISSING_SIGNER || class == MISSING_AUTHORITY_BINDING;
        let never_suppressed = class == UNCHECKED_ARITHMETIC || class == PDA_VALIDATION_GAP;

        if never_suppressed {
            kept.push(f);
            continue;
        }

        let subject = subject_account(&f, accounts);
        // Fix round 1 (Task 12 critical defect): naming an account in a
        // check's `referenced_accounts` means only that an `Ident` token
        // spelling that name appeared SOMEWHERE in the check's macro
        // arguments — `identifiers()` walks every token, including field
        // names, error-enum variants, and unrelated locals. It does NOT mean
        // the check validates that account's identity/authority, and it does
        // NOT say anything about WHERE in the check that name appeared or
        // what role it played there. That second gap is fix round 2's
        // subject (Defect A below): `referenced_accounts` is purely "does
        // this name appear anywhere", so it is not itself a link between a
        // specific sub-expression (like a `.key()` call) and a specific
        // account. Anchoring that link is the whole point of the per-account
        // substring tests below, rather than asking "does `.key()` appear
        // anywhere in the check's text at all".
        //
        // Fix round 2 (Task 12, two residual over-suppression defects):
        //
        // Defect A — the `.key()` test was not anchored to the subject. Round
        // 1 asked only whether `.key()` appeared ANYWHERE in the check's
        // text, which is exactly the same class of bug round 1 fixed one
        // level up: `require!(ctx.accounts.owner.key() == expected &&
        // ctx.accounts.vault.is_initialized, ...)` validates `owner`, not
        // `vault` — but `vault` is in `referenced_accounts` (its name token
        // appears in the macro args) and `.key()` appears somewhere in the
        // text (on `owner`), so the old rule suppressed a `vault` finding a
        // check about `owner` has nothing to say about. The fix is to
        // require the compact text to contain `X.key()` — i.e. `.key()`
        // called ON THE SUBJECT — not merely present somewhere.
        //
        // Defect B — key equality is not proof of a signature. Round 1 let
        // `CheckKind::RequireKeysEq` suppress ANY class on a name match
        // alone, including `missing-signer`. But
        // `require_keys_eq!(ctx.accounts.vault.admin,
        // ctx.accounts.admin.key())` proves only that the caller-supplied
        // `admin` account's pubkey equals the value stored in `vault.admin`
        // — that is IDENTITY, not AUTHORIZATION. An attacker can pass the
        // correct pubkey as a read-only, non-signing account; nothing about
        // a key comparison touches the transaction's signature set. So no
        // key-equality check of any kind may ever suppress `missing-signer`.
        //
        // The corrected per-class rule — a named check suppresses a finding
        // of class `C` on account `X` only when:
        //
        //   `missing-signer`: ONLY when the compact text contains
        //   `X.is_signer`. `require!(ctx.accounts.admin.is_signer, E::X)` is
        //   the actual Anchor idiom that proves signing. A key comparison —
        //   `RequireKeysEq` included — never suppresses this class, full
        //   stop. (The bare-`#[access_control]` class fallback below is
        //   untouched by this fix.)
        //
        //   `missing-owner-check` / `missing-authority-binding`: when the
        //   compact text contains `X.key()` (the subject's OWN key is being
        //   compared — anchored, per Defect A), OR the check's kind is
        //   `CheckKind::RequireKeysEq` AND the compact text contains `X.` (a
        //   dereference of `X`). That second disjunct is deliberately scoped
        //   to `RequireKeysEq` alone and is principled, not a loophole:
        //   `require_keys_eq!` compares `Pubkey`s and nothing else, so ANY
        //   dereference of `X` appearing inside one is necessarily part of a
        //   pubkey comparison. This is what preserves suppression for the
        //   *stored-field* side of the idiom —
        //   `require_keys_eq!(vault.admin, admin.key())` must still suppress
        //   `missing-authority-binding` on `vault`, even though `vault.` is
        //   not followed by `.key()` — `vault.admin` is a struct field, not
        //   a `Pubkey` method call, but it's still a `Pubkey` because the
        //   macro guarantees it. This is the pass's core capability and must
        //   not be lost while fixing Defect B.
        //
        //   `CheckKind::AccessControl` remains excluded from this search
        //   entirely (see item 3 from round 1, unchanged): the spec is
        //   explicit that `missing-owner-check` is never suppressed by a
        //   bare `#[access_control]`, and it must not slip through this
        //   named-check path by textually naming an account either.
        //   `AccessControl` checks are handled solely by the
        //   `has_access_control` fallback branch.
        //
        //   `unchecked-arithmetic` / `pda-validation-gap`: never suppressed
        //   (handled by the `never_suppressed` early return above this
        //   block).
        //
        // Substring safety: `X.key()`, `X.is_signer`, and the `RequireKeysEq`
        // `X.` test are all substring tests over a whitespace-stripped
        // string, so a naive `contains` is unsound — `"vault."` is a
        // substring of `"my_vault.admin"`. This project has already shipped
        // one bug of exactly this shape (`looks_like_authority` flagging
        // `admin_token_account` by raw substring match). `contains_anchored`
        // below requires the character immediately preceding a candidate
        // match to be either absent (start of string) or NOT an identifier
        // character (`[A-Za-z0-9_]`) — e.g. `.` or `,` or `(` — so a match
        // inside `my_vault.` is rejected when testing for `vault.` (preceded
        // by `y`), while a real `ctx.accounts.vault.key()` match (preceded by
        // `.`) is accepted. Note: `proc-macro2` renders
        // `ctx.accounts.vault.admin` as `ctx . accounts . vault . admin`, so
        // stripping all whitespace yields the compact form these substring
        // tests assume (round 1 established this).
        //
        // Fix round 3 (Task 12, Item 1): a third, `CheckKind`-independent
        // disjunct for `missing-owner-check` / `missing-authority-binding` —
        // see `equality_to_key_suppresses` above for the full rationale and
        // the rejected clause-splitting alternative. In short: a plain
        // `require!(X.field == other.key(), ...)` (or the mirror order)
        // proves the same identity binding as `require_keys_eq!` does, just
        // spelled with `==` instead of the macro. Recovering that idiom is
        // this round's entire purpose, so unlike the `RequireKeysEq` + `X.`
        // disjunct above, this one applies regardless of `CheckKind`.
        //
        // Known residual (Item 4, deliberately NOT fixed): negation.
        // `require!(!(vault.admin == admin.key()), E::X)` asserts the
        // OPPOSITE of what suppression assumes — it's a check that the
        // fields do NOT match — yet both this new adjacency scan and the
        // pre-existing `X.key()` path still suppress, because neither looks
        // for an enclosing `!(...)`. Detecting that from
        // `TokenStream::to_string()` output would need paren-depth
        // bookkeeping across a scope boundary, which edges toward
        // re-parsing Rust — something this layer deliberately does not do.
        // Tracked as a known gap, not fixed here.
        //
        // Why `owner.rs` and `authority.rs` look different from this and from
        // each other: `owner.rs::raw_is_identity_pinning` has no field name
        // to anchor a bare `==` to (it isn't checking a specific struct
        // field), so its `==` branch was removed entirely — a bare `==` is
        // never accepted there. `authority.rs::raw_pins_field` DOES have a
        // field name to anchor to (it separately requires the field's name
        // to appear in the same raw-constraint text), so `==` is safely kept
        // there. This file's `RequireKeysEq` + `X.` disjunct is a third,
        // different anchor: it is safe not because of a field-name pairing
        // but because `require_keys_eq!`'s ENTIRE ARGUMENT LIST is
        // `Pubkey`-typed by construction, so nothing else `X.` could mean
        // inside one. None of these three should be "fixed" to match the
        // others — each is narrowly justified by a different structural
        // guarantee, and unifying them would either reintroduce a false
        // negative or lose real coverage.
        let named_check = subject.as_ref().and_then(|name| {
            handler.body.checks.iter().find(|c| {
                if c.kind == CheckKind::AccessControl {
                    return false;
                }
                if !c.referenced_accounts.iter().any(|r| r == name) {
                    return false;
                }
                let compact: String = c.text.chars().filter(|ch| !ch.is_whitespace()).collect();
                if class == MISSING_SIGNER {
                    let needle = format!("{}.is_signer", name);
                    contains_anchored(&compact, &needle)
                } else if class == MISSING_OWNER_CHECK || class == MISSING_AUTHORITY_BINDING {
                    let key_needle = format!("{}.key()", name);
                    if contains_anchored(&compact, &key_needle) {
                        return true;
                    }
                    if c.kind == CheckKind::RequireKeysEq {
                        let dot_needle = format!("{}.", name);
                        if contains_anchored(&compact, &dot_needle) {
                            return true;
                        }
                    }
                    equality_to_key_suppresses(&compact, name)
                } else {
                    false
                }
            })
        });

        if let Some(check) = named_check {
            suppressed.push(Suppression {
                reason: format!(
                    "imperative {:?} check at line {} references `{}`",
                    check.kind,
                    check.line,
                    subject.unwrap_or_default()
                ),
                finding: f,
            });
        } else if has_access_control && suppressible_by_access_control {
            let reason = match &subject {
                Some(name) => format!(
                    "handler carries #[access_control]; authority validation of `{}` may be \
                     delegated to it",
                    name
                ),
                None => "handler carries #[access_control]; authority validation may be \
                          delegated to it, but the finding's subject account could not be \
                          resolved from its evidence"
                    .to_string(),
            };
            suppressed.push(Suppression { reason, finding: f });
        } else {
            kept.push(f);
        }
    }
    (kept, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::{all_detectors, Detector};
    use crate::parser::parse_tree;
    use dike_core::analyzer::{SourceFile, SourceTree};
    use std::path::PathBuf;

    /// Parses `src`, runs every detector against the (single) handler it
    /// declares, then applies suppression. Panics if the fixture declares
    /// zero or more than one handler — every fixture in this module is
    /// written to have exactly one, so a mismatch means the fixture itself
    /// is broken and should fail loudly rather than silently pick one.
    fn findings_and_suppressions_for(src: &str) -> (Vec<Finding>, Vec<Suppression>) {
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("src/lib.rs"), text: src.into() }],
        };
        let out = parse_tree(&tree);
        assert_eq!(out.program.instructions.len(), 1, "fixture must declare exactly one handler");
        let handler = &out.program.instructions[0];
        let accounts = out.program.accounts_for(handler).cloned().unwrap_or_default();
        let detectors = all_detectors();
        let findings: Vec<Finding> = detectors
            .iter()
            .flat_map(|d| d.run(&out.program, handler, &accounts))
            .collect();
        apply(findings, handler, &accounts)
    }

    /// RENAMED and REWRITTEN for Task 12 fix round 2, Defect B. The old name
    /// (`require_keys_eq_suppresses_missing_signer_on_the_named_account`)
    /// described the exact behavior Defect B identifies as wrong: a
    /// `require_keys_eq!` proves key EQUALITY, not a SIGNATURE — an attacker
    /// can supply the correct pubkey in a read-only, non-signing account.
    /// Loosening the rule to keep the old assertion passing would restore
    /// the defect, so this test now asserts the corrected behavior: the
    /// finding on `authority` must SURVIVE, not be suppressed.
    #[test]
    fn require_keys_eq_does_not_suppress_missing_signer_on_the_named_account() {
        let (kept, _suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require_keys_eq!(ctx.accounts.vault.admin, ctx.accounts.authority.key());
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub authority: AccountInfo<'info>,
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-signer" && f.evidence.contains("`authority`")),
            "a require_keys_eq! key-equality check must never suppress missing-signer: kept={:#?}",
            kept
        );
    }

    /// Strengthened per Task 12 mandatory correction 3: the plan's original
    /// fixture declared BOTH `authority: AccountInfo<'info>` and
    /// `raw: UncheckedAccount<'info>` and only asserted `.any(...)` on
    /// `missing-owner-check`, which can pass via `authority` alone even if
    /// suppression for `raw` were broken. Here `raw` is the ONLY unchecked
    /// wrapper (`authority` is a `Signer`, so it can never generate a
    /// missing-owner-check finding), and the assertion pins both the count
    /// and that the surviving finding actually names `raw`.
    #[test]
    fn access_control_suppresses_authority_classes_only() {
        let (kept, _) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                #[access_control(only_admin(&ctx))]
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    let x = ctx.accounts.vault.amount - 1;
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub authority: Signer<'info>,
                pub raw: UncheckedAccount<'info>,
                #[account(has_one = admin)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            !kept.iter().any(|f| f.class.as_str() == "missing-signer"),
            "authority is a Signer, so there should be no missing-signer finding at all"
        );

        let owner_findings: Vec<_> =
            kept.iter().filter(|f| f.class.as_str() == "missing-owner-check").collect();
        assert_eq!(
            owner_findings.len(),
            1,
            "exactly one missing-owner-check finding should survive, on `raw`: {:#?}",
            owner_findings
        );
        assert!(
            owner_findings[0].evidence.contains("`raw`"),
            "the surviving missing-owner-check finding must name `raw`, not some other account: {}",
            owner_findings[0].evidence
        );

        assert!(kept.iter().any(|f| f.class.as_str() == "unchecked-arithmetic"));
    }

    /// Task 12 fix round 1, critical defect: a bounds/balance check that
    /// merely reads a field off the account (`vault.amount`) must NOT
    /// suppress a genuine finding on that account. Before the fix,
    /// `referenced_accounts` contained `vault` purely because the expression
    /// walks through `ctx.accounts.vault.amount`, and the old rule treated
    /// any name-match as validation — silently eating the
    /// missing-authority-binding finding below. This is not a contrived
    /// fixture: `tests/fixtures/programs/vault/src/lib.rs` contains this
    /// exact pattern (a `require!` bounds check on `vault.amount`).
    #[test]
    fn a_bounds_check_referencing_the_account_does_not_suppress() {
        let (kept, suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                    require!(amount <= ctx.accounts.vault.amount, VaultError::InsufficientFunds);
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub admin: Signer<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-authority-binding"
                && f.evidence.contains("`vault`")),
            "a bounds check on vault.amount must not suppress the missing-authority-binding \
             finding on `vault`; kept={:#?} suppressed={:#?}",
            kept,
            suppressed
        );
        assert!(
            !suppressed.iter().any(|s| s.finding.class.as_str() == "missing-authority-binding"),
            "the bounds check must not have suppressed anything: {:#?}",
            suppressed
        );
    }

    /// RENAMED and REWRITTEN AGAIN for Task 12 fix round 3, Item 2. Fix round
    /// 2 renamed this test (from `a_require_containing_dot_key_still_suppresses`)
    /// to `a_require_with_dot_key_on_a_different_account_does_not_suppress`
    /// and asserted that `require!(ctx.accounts.vault.admin ==
    /// ctx.accounts.admin.key(), ...)` must NOT suppress
    /// `missing-authority-binding` on `vault`, on the reasoning that a bare
    /// `require!`/`==` gives no structural `Pubkey`-typing guarantee the way
    /// `require_keys_eq!` does.
    ///
    /// Round 3 corrects that reasoning: this expression genuinely validates
    /// `vault.admin` against `admin`'s key — it's spelled `==` instead of
    /// `require_keys_eq!`, but it is the exact same identity comparison, and
    /// it is (per the round-3 brief) arguably the single most common
    /// imperative identity-validation idiom in Anchor code. The local
    /// equality-to-key adjacency scan added this round
    /// (`equality_to_key_suppresses`) recognizes it directly: it requires
    /// the subject's chain and the `.key()` call to be IMMEDIATELY adjacent
    /// across `==` (with `(`/`)` excluded from the chain charset so a
    /// wrapping function call breaks the adjacency — see
    /// `equality_to_key_suppresses`'s doc comment for the rejected
    /// clause-splitting alternative and its counterexample). That structural
    /// adjacency requirement is what makes trusting this idiom safe without
    /// needing `require_keys_eq!`'s macro-level `Pubkey` guarantee.
    ///
    /// So the assertion inverts: the finding on `vault` must now be
    /// SUPPRESSED. This project only inverts a test's assertion when the
    /// behavior it pinned was itself wrong, and says so in the open — this
    /// is that case, not a quiet edit. (Renamed accordingly; the old name
    /// described exactly the behavior now understood to be a false
    /// negative.)
    #[test]
    fn a_require_comparing_a_stored_field_to_a_key_suppresses_that_account() {
        let (kept, suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require!(ctx.accounts.vault.admin == ctx.accounts.admin.key(), VaultError::WrongAdmin);
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub admin: Signer<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            !kept.iter().any(|f| f.class.as_str() == "missing-authority-binding"),
            "require!(vault.admin == admin.key()) validates vault.admin's identity and must \
             suppress missing-authority-binding on `vault`: kept={:#?}",
            kept
        );
        assert!(suppressed
            .iter()
            .any(|s| s.finding.class.as_str() == "missing-authority-binding"
                && s.finding.evidence.contains("`vault`")));
    }

    /// Positive counterpart to the test above: a plain `require!` whose
    /// `.key()` call is anchored TO THE SUBJECT ITSELF must still suppress.
    /// This isolates the anchoring fix from the `RequireKeysEq`-only `X.`
    /// disjunct — this path works for ANY check kind, not just
    /// `require_keys_eq!`, as long as `.key()` is called on the subject.
    #[test]
    fn a_require_with_dot_key_on_the_subject_itself_still_suppresses() {
        let (kept, suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, expected_mint: Pubkey) -> Result<()> {
                    require!(ctx.accounts.mint.key() == expected_mint, VaultError::WrongMint);
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub authority: Signer<'info>,
                pub mint: UncheckedAccount<'info>,
            }
        "#,
        );
        assert!(
            !kept.iter().any(|f| f.class.as_str() == "missing-owner-check"),
            "a `.key()` check anchored to `mint` itself must suppress missing-owner-check: kept={:#?}",
            kept
        );
        assert!(suppressed.iter().any(|s| s.finding.class.as_str() == "missing-owner-check"
            && s.finding.evidence.contains("`mint`")));
    }

    /// Closes the item-2.3 bypass: `#[access_control]` naming an account
    /// textually must not suppress `missing-owner-check` via the named-check
    /// path. Before the fix, `AccessControl`'s `referenced_accounts`
    /// (populated the same way as any other check) let a
    /// `validate(&ctx.accounts.mint)` argument slip through the general
    /// named-check search and suppress owner-check anyway, even though the
    /// spec says owner-check is never suppressed by a bare
    /// `#[access_control]`.
    #[test]
    fn access_control_naming_an_account_does_not_suppress_missing_owner_check() {
        let (kept, _) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                #[access_control(validate(&ctx.accounts.mint))]
                pub fn withdraw(ctx: Context<W>) -> Result<()> { Ok(()) }
            }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub authority: Signer<'info>,
                pub mint: UncheckedAccount<'info>,
            }
        "#,
        );
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-owner-check"
                && f.evidence.contains("`mint`")),
            "missing-owner-check on `mint` must survive #[access_control(validate(&ctx.accounts.mint))]: {:#?}",
            kept
        );
    }

    /// Task 12 fix round 2, Defect A: the `.key()` test was not anchored to
    /// the subject. `owner.key()` proves `owner`'s identity and says nothing
    /// about `vault`, but `vault` was in `referenced_accounts` (its name
    /// token appears in the macro args) and the old rule asked only "does
    /// `.key()` appear ANYWHERE in the check's text" — so a finding on
    /// `vault` was wrongly suppressed by a check that validates `owner`.
    ///
    /// Also exercises Defect B by construction: `owner`'s own missing-signer
    /// finding must survive too, because a `.key()` comparison — even
    /// correctly anchored to `owner` itself — proves identity, not a
    /// signature. It is not the `.key()`-suppresses-missing-signer example
    /// from before this fix.
    #[test]
    fn a_key_check_on_one_account_does_not_suppress_a_different_account() {
        let (kept, suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, expected_owner: Pubkey) -> Result<()> {
                    require!(ctx.accounts.owner.key() == expected_owner
                        && ctx.accounts.vault.amount > 0, VaultError::Bad);
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub payer: Signer<'info>,
                pub owner: AccountInfo<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-authority-binding"
                && f.evidence.contains("`vault`")),
            "a `.key()` check that validates `owner` must not suppress a finding on `vault`: \
             kept={:#?} suppressed={:#?}",
            kept,
            suppressed
        );
        // Per Defect B's rule, a `.key()` comparison never suppresses
        // missing-signer, even when anchored to the right account — key
        // equality is identity, not a signature. So `owner`'s missing-signer
        // finding survives too; it is not "still suppressed", as an earlier
        // draft of this test assumed.
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-signer" && f.evidence.contains("`owner`")),
            "a `.key()` check never proves a signature, so missing-signer on `owner` must survive: \
             kept={:#?}",
            kept
        );
    }

    /// Task 12 fix round 2, Defect B: key equality is not proof of a
    /// signature. `require_keys_eq!(ctx.accounts.vault.admin,
    /// ctx.accounts.admin.key())` proves the caller-supplied `admin`
    /// account's pubkey equals the value stored in `vault.admin` — that is
    /// identity, not authorization. An attacker can pass the correct pubkey
    /// as a read-only, non-signing account. This must NOT suppress a
    /// missing-signer finding on `admin`.
    #[test]
    fn require_keys_eq_vault_admin_key_equality_does_not_prove_admin_signed() {
        let (kept, _suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require_keys_eq!(ctx.accounts.vault.admin, ctx.accounts.admin.key());
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub payer: Signer<'info>,
                pub admin: UncheckedAccount<'info>,
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-signer" && f.evidence.contains("`admin`")),
            "a require_keys_eq! key-equality check must never suppress missing-signer: kept={:#?}",
            kept
        );
    }

    /// Regression guard for the capability the whole pass exists to
    /// provide: `require_keys_eq!(vault.admin, admin.key())` must still
    /// suppress `missing-authority-binding` on `vault` (the stored-field
    /// side). Fix round 2 must not trade Defect B for this capability.
    #[test]
    fn require_keys_eq_still_suppresses_missing_authority_binding_on_the_stored_field_account() {
        let (kept, suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require_keys_eq!(ctx.accounts.vault.admin, ctx.accounts.admin.key());
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub payer: Signer<'info>,
                pub admin: UncheckedAccount<'info>,
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            !kept.iter().any(|f| f.class.as_str() == "missing-authority-binding"),
            "require_keys_eq! must still suppress missing-authority-binding on `vault`: kept={:#?}",
            kept
        );
        assert!(suppressed
            .iter()
            .any(|s| s.finding.class.as_str() == "missing-authority-binding"));
    }

    /// The actual Anchor idiom that proves a signature:
    /// `require!(ctx.accounts.admin.is_signer, E::X)`. This must suppress
    /// missing-signer on `admin`.
    #[test]
    fn is_signer_check_suppresses_missing_signer() {
        let (kept, suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require!(ctx.accounts.admin.is_signer, VaultError::NotSigner);
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub admin: AccountInfo<'info>,
            }
        "#,
        );
        assert!(!kept.iter().any(|f| f.class.as_str() == "missing-signer"));
        assert!(suppressed.iter().any(|s| s.finding.class.as_str() == "missing-signer"));
    }

    /// Substring-boundary regression: this project has already shipped one
    /// bug of exactly this shape (`looks_like_authority` flagging
    /// `admin_token_account` by raw substring match). Here `vault` is
    /// referenced bare (a real token, so it legitimately lands in
    /// `referenced_accounts`), but the only field-access pattern in the
    /// check's compact text is `my_vault.admin.key()` — an UNRELATED
    /// account. A naive, unanchored `contains("vault.")` search would find
    /// a false hit inside `my_vault.` (preceded by identifier char `y`) and
    /// wrongly suppress the `missing-authority-binding` finding on `vault`.
    /// The anchored search must reject that occurrence and keep the
    /// finding.
    #[test]
    fn substring_boundary_vault_vs_my_vault() {
        let (kept, suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require_keys_eq!(vault, ctx.accounts.my_vault.admin.key());
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub authority: Signer<'info>,
                pub my_vault: UncheckedAccount<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-authority-binding"
                && f.evidence.contains("`vault`")),
            "a false substring hit inside `my_vault.` must not suppress the finding on `vault`: \
             kept={:#?} suppressed={:#?}",
            kept,
            suppressed
        );
    }

    #[test]
    fn unrelated_requires_do_not_suppress() {
        let (kept, _) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                    require!(amount > 0, ErrorCode::Zero);
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> { pub authority: AccountInfo<'info> }
        "#,
        );
        assert!(kept.iter().any(|f| f.class.as_str() == "missing-signer"));
    }

    /// Worked expectation 2: the chain from the anchored `vault.` occurrence
    /// is cut short by the enclosing `compute_hash(...)` call's closing
    /// paren — `(` and `)` are deliberately excluded from the adjacency
    /// scan's chain charset, so the run from `vault.` never reaches `==`.
    /// Only `mint`'s key is actually being compared here; `vault.seed` is
    /// merely an argument to an unrelated function. Must NOT suppress.
    #[test]
    fn a_field_wrapped_in_a_function_call_does_not_suppress_via_adjacency_scan() {
        let (kept, _suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require!(compute_hash(ctx.accounts.vault.seed) == ctx.accounts.mint.key(), VaultError::Bad);
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub seed: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub authority: Signer<'info>,
                pub mint: UncheckedAccount<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-authority-binding"
                && f.evidence.contains("`vault`")),
            "vault.seed inside compute_hash(...) must not be treated as identity validation of \
             vault: kept={:#?}",
            kept
        );
    }

    /// Worked expectation 3: `vault` is referenced after a `&&`, but its
    /// chain (`vault.is_initialized`) is never followed by `==` — it's a
    /// separate boolean clause, not an equality operand. Also the regression
    /// pin (unchanged per round 3 instructions) that the local scan must not
    /// leak across an `&&` boundary: see
    /// `a_key_check_on_one_account_does_not_suppress_a_different_account`
    /// above, which already exercises this shape end to end. This test adds
    /// the adjacency-scan-specific worked expectation from the round-3 spec.
    #[test]
    fn a_boolean_clause_after_and_and_does_not_suppress_via_adjacency_scan() {
        let (kept, _suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, expected_owner: Pubkey) -> Result<()> {
                    require!(ctx.accounts.owner.key() == expected_owner
                        && ctx.accounts.vault.is_initialized, VaultError::Bad);
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub is_initialized: bool }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub payer: Signer<'info>,
                pub owner: AccountInfo<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            kept.iter().any(|f| f.class.as_str() == "missing-authority-binding"
                && f.evidence.contains("`vault`")),
            "vault.is_initialized after && must not be treated as identity validation of vault: \
             kept={:#?}",
            kept
        );
    }

    /// Worked expectation 4: the mirror order, `.key() == X.field`.
    /// `ctx.accounts.admin.key() == ctx.accounts.vault.admin` validates
    /// `vault.admin` against `admin`'s key just as surely as the forward
    /// order does — only the operand order is swapped. Must suppress.
    #[test]
    fn a_require_with_the_key_call_first_still_suppresses_via_mirror_scan() {
        let (kept, suppressed) = findings_and_suppressions_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require!(ctx.accounts.admin.key() == ctx.accounts.vault.admin, VaultError::WrongAdmin);
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub admin: Signer<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        assert!(
            !kept.iter().any(|f| f.class.as_str() == "missing-authority-binding"),
            "the mirror-order require! must suppress missing-authority-binding on `vault`: \
             kept={:#?}",
            kept
        );
        assert!(suppressed
            .iter()
            .any(|s| s.finding.class.as_str() == "missing-authority-binding"
                && s.finding.evidence.contains("`vault`")));
    }

    /// Task 12 fix round 3, Item 3: `contains_anchored` (via its
    /// `anchored_occurrences` helper) must advance past a REJECTED match by
    /// the rejected needle's first character's UTF-8 length, not a fixed one
    /// byte. This is unreachable through a multi-byte character elsewhere in
    /// the haystack (a match's start position is always a valid char
    /// boundary because a valid-UTF-8 needle can only match at one) — the
    /// trigger is specifically a needle that itself STARTS with a non-ASCII
    /// `XID_Start` character, which Rust identifiers are permitted to use.
    /// `\u{e9}toileadmin` ("étoile") is used as the account name below — it
    /// STARTS with the non-ASCII character `\u{e9}` (2 UTF-8 bytes), which
    /// is a valid Rust `XID_Start` identifier character. `is_signer` is
    /// checked on an unrelated identifier that merely contains the same
    /// bytes as a non-anchored substring (`mon\u{e9}toileadmin.is_signer`,
    /// rejected because the byte before the match is `n`), followed later
    /// by a properly anchored `\u{e9}toileadmin.is_signer`. Before the fix,
    /// rejecting the first (non-anchored) match would advance `search_from`
    /// by a single byte — landing in the middle of `\u{e9}`'s 2-byte UTF-8
    /// encoding — and the next `haystack[search_from..]` slice would panic
    /// ("byte index is not a char boundary"). This test proves no panic and
    /// that the later, properly anchored occurrence is still found.
    #[test]
    fn non_ascii_leading_account_name_does_not_panic_on_a_rejected_match() {
        let (kept, suppressed) = findings_and_suppressions_for(
            "
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require!(ctx.accounts.mon\u{e9}toileadmin.is_signer || ctx.accounts.\u{e9}toileadmin.is_signer, VaultError::NotSigner);
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub mon\u{e9}toileadmin: AccountInfo<'info>,
                pub \u{e9}toileadmin: AccountInfo<'info>,
            }
        ",
        );
        assert!(
            !kept.iter().any(|f| f.class.as_str() == "missing-signer"
                && f.evidence.contains("`\u{e9}toileadmin`")),
            "the properly anchored \u{e9}toileadmin.is_signer occurrence must still suppress \
             missing-signer on \u{e9}toileadmin without panicking on the earlier rejected match: \
             kept={:#?}",
            kept
        );
        assert!(suppressed.iter().any(|s| s.finding.class.as_str() == "missing-signer"
            && s.finding.evidence.contains("`\u{e9}toileadmin`")), "suppressed={:#?}", suppressed);
    }

    /// Task 12 fix round 4, Item 1: the mirror branch of
    /// `equality_to_key_suppresses` used to recover `before_eq` and
    /// `call_end` with `full_chain_start.checked_sub(2)` /
    /// `before_eq.checked_sub(2)`. `checked_sub` only guards against integer
    /// underflow — it says nothing about whether the resulting byte offset
    /// is a valid UTF-8 char boundary. When a multi-byte character sits
    /// immediately before the recovered chain start (or immediately before
    /// the `==`), the blind subtraction lands mid-character and the
    /// following `compact[..]` slice panics with "byte index is not a char
    /// boundary".
    ///
    /// Each case below was confirmed to panic against the pre-fix code
    /// (extracted into a standalone binary and run with `rustc`) before this
    /// test was written:
    ///
    /// - `"日vault.admin"` (name `vault`): PANIC — "byte index 1 is not a
    ///   char boundary; it is inside '日' (bytes 0..3) of `日vault.admin`".
    ///   `日` (3 bytes) sits immediately before the recovered chain start.
    /// - `"flag日==ctx.accounts.vault.admin"` (name `vault`): PANIC — "byte
    ///   index 5 is not a char boundary; it is inside '日' (bytes 4..7) of
    ///   `flag日==ctx.accounts.vault.admin`". Here `日` sits immediately
    ///   before the `==`, one level further back in the recovery chain.
    /// - `"🎉vault.admin"` (name `vault`): PANIC — "byte index 2 is not a
    ///   char boundary; it is inside '🎉' (bytes 0..4) of
    ///   `🎉vault.admin`". Same shape as the first case with a 4-byte
    ///   character.
    ///
    /// The existing `é`-based test (`é` is 2 bytes) exercises the one case
    /// that happens to be safe under the old arithmetic — `2 - 2 == 0`
    /// always lands on a boundary regardless of what precedes it — so it
    /// left this gap completely untested. These three cases pick 3-byte and
    /// 4-byte characters specifically because they are the ones the old
    /// fixed `- 2` cannot land safely on.
    ///
    /// The fix (using `str::ends_with` on a boundary-anchored prefix instead
    /// of blind byte arithmetic) makes all three return normally instead of
    /// panicking; none of them describes a real suppression idiom, so `false`
    /// is the only sensible result and is asserted here as a bonus, but
    /// "does not panic" is this test's real point.
    #[test]
    fn multibyte_character_immediately_before_chain_or_equals_does_not_panic() {
        assert!(!equality_to_key_suppresses("日vault.admin", "vault"));
        assert!(!equality_to_key_suppresses("flag日==ctx.accounts.vault.admin", "vault"));
        assert!(!equality_to_key_suppresses("🎉vault.admin", "vault"));
    }

    /// Discriminates `subject_account`'s textual-position scan from a
    /// declaration-order scan (Task 12 mandatory correction 1). `admin` is
    /// declared BEFORE `vault` in the accounts struct, and the finding is a
    /// `missing-authority-binding` on `vault` whose evidence backticks BOTH
    /// `vault` (the account, first in the text) and `admin` (the unbound
    /// state-struct field, second in the text). A declaration-order scan
    /// over `accounts.decls` would hit `admin` first (it comes first in
    /// `decls`) and return `"admin"` — wrong. The textual-position scan
    /// returns `"vault"`, because `vault` is the first backticked span in
    /// the evidence string regardless of where either name sits in
    /// `decls`.
    #[test]
    fn subject_account_uses_textual_position_not_declaration_order() {
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile {
                path: PathBuf::from("src/lib.rs"),
                text: r#"
                    #[program]
                    pub mod vault {
                        pub fn withdraw(ctx: Context<W>) -> Result<()> { Ok(()) }
                    }
                    #[account]
                    pub struct Vault { pub admin: Pubkey, pub amount: u64 }
                    #[derive(Accounts)]
                    pub struct W<'info> {
                        pub admin: Signer<'info>,
                        #[account(mut)]
                        pub vault: Account<'info, Vault>,
                    }
                "#
                .into(),
            }],
        };
        let out = parse_tree(&tree);
        let handler = &out.program.instructions[0];
        let accounts = out.program.accounts_for(handler).cloned().unwrap_or_default();

        // Sanity: `admin` really is declared before `vault` in this fixture.
        let admin_idx = accounts.decls.iter().position(|d| d.name == "admin").unwrap();
        let vault_idx = accounts.decls.iter().position(|d| d.name == "vault").unwrap();
        assert!(admin_idx < vault_idx, "fixture must declare admin before vault");

        let authority_detector = crate::detectors::authority::MissingAuthorityBindingDetector;
        let findings = authority_detector.run(&out.program, handler, &accounts);
        assert_eq!(findings.len(), 1, "vault.admin should be flagged as an unbound authority field");
        assert!(
            findings[0].evidence.contains("`vault`") && findings[0].evidence.contains("`admin`"),
            "evidence must backtick both the account (vault) and the unbound field (admin): {}",
            findings[0].evidence
        );

        let subject = subject_account(&findings[0], &accounts);
        assert_eq!(
            subject.as_deref(),
            Some("vault"),
            "subject_account must return the finding's real subject (vault), not the first \
             declared account whose name happens to appear in the evidence (admin)"
        );
    }
}
