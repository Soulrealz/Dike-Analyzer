pub mod arithmetic;
pub mod authority;
pub mod owner;
pub mod pda;
pub mod signer;
pub mod suppression;

pub use suppression::{apply, Suppression};

use crate::ir::{AccountDecl, AccountsStruct, Handler, Program};
use dike_core::finding::{Finding, Location, Severity, Track, VulnClass};

pub const MISSING_SIGNER: &str = "missing-signer";
pub const MISSING_OWNER_CHECK: &str = "missing-owner-check";
pub const MISSING_AUTHORITY_BINDING: &str = "missing-authority-binding";
pub const PDA_VALIDATION_GAP: &str = "pda-validation-gap";
pub const UNCHECKED_ARITHMETIC: &str = "unchecked-arithmetic";
/// Track 2 only — the absence of an arbitrary `constraint = ...` is not a
/// structural signal (D16).
pub const REMOVED_GUARD: &str = "removed-guard";

/// Pure. No I/O, no network, no clock. Track 1's numbers must never move
/// for any reason other than a code change to a detector.
pub trait Detector {
    fn class(&self) -> &'static str;
    fn severity(&self) -> Severity;
    /// A per-detector constant, not a computed value.
    fn confidence(&self) -> f32;
    fn run(&self, program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding>;
}

pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(signer::MissingSignerDetector),
        Box::new(owner::MissingOwnerCheckDetector),
        Box::new(authority::MissingAuthorityBindingDetector),
        Box::new(pda::PdaValidationGapDetector),
        Box::new(arithmetic::UncheckedArithmeticDetector),
    ]
}

/// The single construction point for a Track 1 finding. `key` is the finding's
/// subject within the handler — an account name for account-oriented detectors,
/// a fixed class token for body-oriented ones — and it is what keeps two findings
/// of the same class in the same handler distinct.
pub fn finding_at(
    detector: &dyn Detector,
    handler: &Handler,
    key: &str,
    line: u32,
    evidence: String,
) -> Finding {
    let location = Location { file: handler.file.clone(), line, handler: handler.name.clone() };
    let id = {
        let seed = format!("{}|{}|{}", location.handler_id(), detector.class(), key);
        blake3::hash(seed.as_bytes()).to_hex()[..16].to_string()
    };
    Finding {
        id,
        class: VulnClass::new(detector.class()),
        severity: detector.severity(),
        confidence: detector.confidence(),
        track: Track::Static,
        location,
        evidence,
        citations: vec![],
    }
}

/// Like `finding_at`, but for account-oriented detectors whose fix lives on
/// the field's type line (as opposed to `finding_at`'s constraint-oriented
/// callers, whose fix lives inside the `#[account(...)]` attribute). Thin
/// delegation to `finding_at`, keyed on the account's name and pointed at
/// `decl.line` — preserved exactly as before this was factored out.
pub fn finding_from(
    detector: &dyn Detector,
    handler: &Handler,
    decl: &AccountDecl,
    evidence: String,
) -> Finding {
    finding_at(detector, handler, &decl.name, decl.line, evidence)
}

/// Account names that conventionally denote a privileged party.
pub(crate) const AUTHORITY_NAMES: [&str; 7] =
    ["authority", "admin", "owner", "signer", "payer", "delegate", "manager"];

/// Generic suffix segments that carry no authority meaning on their own but,
/// paired with an authority word in the segment before them, still denote a
/// privileged account (`admin_account`, `authority_info`, `owner_pubkey`,
/// `signer_key`).
const GENERIC_SUFFIXES: [&str; 4] = ["info", "key", "pubkey", "account"];

/// Fix round 1: naive whole-name substring matching over-fired on compound
/// names like `admin_token_account` (an `Account<TokenAccount>` that merely
/// receives payment, not a privileged signer). Matching is now confined to
/// the `_`-delimited segment(s) that actually carry meaning: the last
/// segment (`vault_authority`, `fee_payer`), or — when the last segment is a
/// generic, meaning-free suffix — the segment before it
/// (`admin_account`, `authority_info`, `owner_pubkey`, `signer_key`).
/// `admin_token_account`/`payer_token_account` correctly no longer match,
/// because their second-to-last segment is `token`, not an authority word.
/// Matching stays substring (not exact) *within* a segment, so `feepayer`
/// and `subadmin` still match — recall over precision.
pub(crate) fn looks_like_authority(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('_').filter(|s| !s.is_empty()).collect();
    let Some(&last) = segments.last() else {
        return false;
    };
    if AUTHORITY_NAMES.iter().any(|n| last.contains(n)) {
        return true;
    }
    if GENERIC_SUFFIXES.contains(&last) && segments.len() >= 2 {
        let prev = segments[segments.len() - 2];
        if AUTHORITY_NAMES.iter().any(|n| prev.contains(n)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::looks_like_authority;

    /// `key` (an account name here) is what keeps two `finding_from`
    /// findings of the same class, in the same handler, distinct — nothing
    /// else pinned this property before this test.
    #[test]
    fn finding_at_gives_different_accounts_different_ids() {
        use crate::detectors::pda::PdaValidationGapDetector;
        use crate::detectors::Detector;
        use crate::parser::parse_tree;
        use dike_core::analyzer::{SourceFile, SourceTree};
        use std::path::PathBuf;

        const SRC: &str = r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
            }
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub admin: Signer<'info>,
                #[account(seeds = [b"vault"])]
                pub vault: Account<'info, Vault>,
                #[account(seeds = [b"escrow"])]
                pub escrow: Account<'info, Escrow>,
            }
        "#;
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("src/lib.rs"), text: SRC.into() }],
        };
        let out = parse_tree(&tree);
        let d = PdaValidationGapDetector;
        let findings: Vec<_> = out
            .program
            .instructions
            .iter()
            .flat_map(|h| {
                let accounts = out.program.accounts_for(h).cloned().unwrap_or_default();
                d.run(&out.program, h, &accounts)
            })
            .collect();
        assert_eq!(findings.len(), 2, "both accounts should be flagged for a seeds/bump gap");
        assert_ne!(
            findings[0].id, findings[1].id,
            "two findings of the same class in the same handler but on different accounts \
             must receive different ids"
        );
    }

    #[test]
    fn last_segment_authority_words_match() {
        for name in [
            "admin",
            "authority",
            "vault_authority",
            "update_authority",
            "pool_admin",
            "mint_authority",
            "fee_payer",
        ] {
            assert!(looks_like_authority(name), "expected {name} to match");
        }
    }

    #[test]
    fn generic_suffix_with_authority_second_to_last_segment_matches() {
        for name in ["admin_account", "authority_info", "owner_pubkey", "signer_key"] {
            assert!(looks_like_authority(name), "expected {name} to match");
        }
    }

    #[test]
    fn compound_token_account_names_do_not_match() {
        for name in ["admin_token_account", "payer_token_account"] {
            assert!(!looks_like_authority(name), "expected {name} to NOT match");
        }
    }

    #[test]
    fn substring_matching_within_a_segment_still_works() {
        assert!(looks_like_authority("feepayer"));
        assert!(looks_like_authority("subadmin"));
    }

    #[test]
    fn unrelated_names_do_not_match() {
        for name in ["vault", "mint", "token_program", "system_program", "amount"] {
            assert!(!looks_like_authority(name), "expected {name} to NOT match");
        }
    }

    /// `suppression::subject_account` recovers a finding's subject by
    /// scanning its evidence for a backticked account name — this only
    /// works because the three SUPPRESSIBLE classes (missing-signer,
    /// missing-owner-check, missing-authority-binding) all name their
    /// subject account in backticks. This is scoped to exactly those three,
    /// not "every detector": `unchecked-arithmetic`'s evidence backticks the
    /// *handler* name (a body-oriented finding has no account subject), and
    /// `apply`'s `never_suppressed` guard short-circuits both
    /// unchecked-arithmetic and pda-validation-gap before `subject_account`
    /// is ever called on their findings, so their evidence format cannot
    /// break suppression. A blanket "every detector" version of this test
    /// would fail against unchecked-arithmetic on its first run for a
    /// reason that has nothing to do with a real defect.
    #[test]
    fn suppressible_classes_name_their_subject_account_in_backticks() {
        use crate::detectors::{
            all_detectors, MISSING_AUTHORITY_BINDING, MISSING_OWNER_CHECK, MISSING_SIGNER,
        };
        use crate::parser::parse_tree;
        use dike_core::analyzer::{SourceFile, SourceTree};
        use std::path::PathBuf;

        const SRC: &str = r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> { Ok(()) }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub payer: Signer<'info>,
                pub authority: AccountInfo<'info>,
                pub mint: UncheckedAccount<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#;
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("src/lib.rs"), text: SRC.into() }],
        };
        let out = parse_tree(&tree);
        let handler = &out.program.instructions[0];
        let accounts = out.program.accounts_for(handler).cloned().unwrap_or_default();

        let findings: Vec<_> = all_detectors()
            .iter()
            .flat_map(|d| d.run(&out.program, handler, &accounts))
            .collect();

        let suppressible = [MISSING_SIGNER, MISSING_OWNER_CHECK, MISSING_AUTHORITY_BINDING];
        let checked: Vec<_> =
            findings.iter().filter(|f| suppressible.contains(&f.class.as_str())).collect();
        assert!(!checked.is_empty(), "fixture must actually produce suppressible findings");

        for f in checked {
            assert!(
                accounts.decls.iter().any(|d| f.evidence.contains(&format!("`{}`", d.name))),
                "finding of class {:?} must name a declared account in backticks: {}",
                f.class,
                f.evidence
            );
        }
    }

    /// Closes a coverage hole left after Task 11's review: `owner.rs` and
    /// `signer.rs` are the only `finding_from` callers, and neither had any
    /// test pinning a concrete `location.line`. A silent swap of
    /// `decl.line` for `decl.attr_line` inside `finding_from` previously
    /// failed nothing. The fixture below gives a field a genuinely
    /// multi-line `#[account(...)]` attribute so `decl.line` and
    /// `decl.attr_line` are guaranteed to differ, then pins that the
    /// `missing-owner-check` finding (built via `finding_from`) lands on
    /// `decl.line`, never `decl.attr_line`.
    #[test]
    fn finding_from_points_at_decl_line_not_attr_line() {
        use crate::detectors::owner::MissingOwnerCheckDetector;
        use crate::detectors::{Detector, MISSING_OWNER_CHECK};
        use crate::parser::parse_tree;
        use dike_core::analyzer::{SourceFile, SourceTree};
        use std::path::PathBuf;

        const SRC: &str = r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
            }
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(
                    mut,
                )]
                pub mint: UncheckedAccount<'info>,
            }
        "#;
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("src/lib.rs"), text: SRC.into() }],
        };
        let out = parse_tree(&tree);
        let handler = &out.program.instructions[0];
        let accounts = out.program.accounts_for(handler).cloned().unwrap_or_default();
        let decl = accounts.decl("mint").unwrap();
        assert_ne!(
            decl.attr_line, decl.line,
            "fixture must give attr_line and decl.line distinct values, or this test proves nothing"
        );
        assert_ne!(decl.attr_line, 0, "fixture's attribute must actually be parsed");

        let d = MissingOwnerCheckDetector;
        let findings = d.run(&out.program, handler, &accounts);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.line, decl.line);
        assert_ne!(findings[0].location.line, decl.attr_line);

        let expected_id = {
            let seed = format!("{}|{}|{}", findings[0].location.handler_id(), MISSING_OWNER_CHECK, "mint");
            blake3::hash(seed.as_bytes()).to_hex()[..16].to_string()
        };
        assert_eq!(findings[0].id, expected_id, "id must be derived from (handler_id, class, key)");
    }
}
