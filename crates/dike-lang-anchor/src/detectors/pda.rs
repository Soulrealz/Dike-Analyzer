use super::{Detector, PDA_VALIDATION_GAP};
use crate::ir::{AccountDecl, AccountsStruct, Handler, Program, Wrapper};
use dike_core::finding::{Finding, Severity};

pub struct PdaValidationGapDetector;

/// The deserialized account type a declaration carries, if it has one.
///
/// Only these two wrappers name a program-owned type. `Signer`, `Program` and
/// `SystemAccount` are validated by their own rules, and an unchecked wrapper
/// has no type to compare across handlers — that absence is what
/// `missing-owner-check` is for.
fn account_type(d: &AccountDecl) -> Option<&str> {
    match &d.wrapper {
        Wrapper::Account(t) | Wrapper::InterfaceAccount(t) => Some(t.as_str()),
        _ => None,
    }
}

/// The accounts structs in which this program derives `ty` as a PDA.
///
/// Sorted, because `Program::accounts_structs` is a `BTreeMap` and the
/// evidence string is part of a `Finding` (Rule 5).
fn derived_in(program: &Program, ty: &str) -> Vec<String> {
    program
        .accounts_structs
        .iter()
        .filter(|(_, s)| {
            s.decls.iter().any(|d| d.has_seeds() && account_type(d) == Some(ty))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

impl Detector for PdaValidationGapDetector {
    fn class(&self) -> &'static str {
        PDA_VALIDATION_GAP
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> f32 {
        0.65
    }

    fn run(&self, program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding> {
        let mut out = Vec::new();
        for d in &accounts.decls {
            let line = if d.attr_line != 0 { d.attr_line } else { d.line };

            // An inconsistent pair — one of `seeds`/`bump` present, the other
            // missing. Anchor rejects this at compile time ("bump must be
            // provided with seeds", verified against anchor-lang 0.30), so it
            // cannot occur in a program that builds. Kept because it costs one
            // comparison and it is still the right answer for source that does
            // not compile, which a triage tool does get handed.
            if d.has_seeds() != d.has_bump() {
                let (has, missing) =
                    if d.has_seeds() { ("seeds", "bump") } else { ("bump", "seeds") };
                out.push(super::finding_at(
                    self,
                    handler,
                    &accounts.file,
                    &d.name,
                    line,
                    format!(
                        "`{}` declares `{has}` without a matching `{missing}` constraint. A PDA \
                         validation must pin both the derivation seeds and the bump — an \
                         inconsistent pair leaves the account's identity unverified.",
                        d.name
                    ),
                ));
                continue;
            }

            // The reachable gap: this program derives the type somewhere, so
            // it knows the account is a PDA, and this handler takes it without
            // pinning the derivation. `Account<'info, T>` still proves owner
            // and discriminator, so the caller cannot forge one — but any
            // other account of the same type is accepted, including one the
            // caller owns.
            //
            // The cross-handler comparison is what keeps this quiet: an
            // account no handler ever derives yields no evidence that it is a
            // PDA at all, and firing on it would mean firing on every account
            // in every program.
            if d.has_seeds() || d.is_address_pinned() {
                continue;
            }
            let Some(ty) = account_type(d) else { continue };
            let sites = derived_in(program, ty);
            if sites.is_empty() {
                continue;
            }
            out.push(super::finding_at(
                self,
                handler,
                &accounts.file,
                &d.name,
                line,
                format!(
                    "`{}` is an `{ty}` with no `seeds` constraint, but this program derives \
                     `{ty}` as a PDA in {}. Nothing here pins which account was passed, so any \
                     `{ty}` the program owns is accepted — including one the caller created.",
                    d.name,
                    sites
                        .iter()
                        .map(|s| format!("`{s}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::Detector;
    use crate::parser::parse_tree;
    use dike_core::analyzer::{SourceFile, SourceTree};
    use std::path::PathBuf;

    fn findings_for(src: &str) -> Vec<dike_core::Finding> {
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("src/lib.rs"), text: src.into() }],
        };
        let out = parse_tree(&tree);
        let d = PdaValidationGapDetector;
        out.program
            .instructions
            .iter()
            .flat_map(|h| {
                let accounts = out.program.accounts_for(h).cloned().unwrap_or_default();
                d.run(&out.program, h, &accounts)
            })
            .collect()
    }

    const BASE: &str = r#"
        #[program]
        pub mod vault {
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            pub admin: Signer<'info>,
            #[account(ATTR)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    #[test]
    fn seeds_and_bump_together_does_not_flag() {
        let src = BASE.replace("ATTR", "seeds = [b\"vault\"], bump");
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn seeds_without_bump_flags_one_gap() {
        let src = BASE.replace("ATTR", "seeds = [b\"vault\"]");
        let f = findings_for(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "pda-validation-gap");
        assert_eq!(f[0].severity, dike_core::Severity::High);
        assert!((f[0].confidence - 0.65).abs() < 1e-6);
        assert!(f[0].evidence.contains("`vault`"));
    }

    #[test]
    fn bump_without_seeds_flags_one_gap() {
        let src = BASE.replace("ATTR", "bump");
        let f = findings_for(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "pda-validation-gap");
    }

    #[test]
    fn neither_seeds_nor_bump_does_not_flag() {
        let src = BASE.replace("ATTR", "mut");
        assert!(findings_for(&src).is_empty());
    }

    /// Two handlers over the same account type: one pins the derivation, the
    /// other does not. `SEEDS` is what the second one declares.
    const TWO_HANDLERS: &str = r#"
        #[program]
        pub mod vault {
            pub fn initialize(ctx: Context<Initialize>) -> Result<()> { Ok(()) }
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        pub struct Initialize<'info> {
            #[account(init, payer = admin, seeds = [b"vault"], bump)]
            pub vault: Account<'info, Vault>,
            #[account(mut)]
            pub admin: Signer<'info>,
        }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            #[account(ATTR)]
            pub vault: Account<'info, Vault>,
            pub admin: Signer<'info>,
        }
    "#;

    /// The defect this class is actually about, and the one `strip_seeds_bump`
    /// injects: the program derives this account elsewhere, so it knows the
    /// account is a PDA, and this handler accepts whatever address the caller
    /// passes.
    #[test]
    fn an_account_pinned_elsewhere_but_not_here_is_a_gap() {
        let src = TWO_HANDLERS.replace("ATTR", "mut");
        let f = findings_for(&src);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].class.as_str(), "pda-validation-gap");
        assert_eq!(f[0].location.handler, "withdraw");
        assert!((f[0].confidence - 0.65).abs() < 1e-6);
    }

    /// The clean fixture's property, and the reason the noise floor stays at
    /// zero: pinned in every handler that takes it is correct code.
    #[test]
    fn an_account_pinned_in_every_handler_is_not_a_gap() {
        let src = TWO_HANDLERS.replace("ATTR", "mut, seeds = [b\"vault\"], bump");
        assert!(findings_for(&src).is_empty(), "{:#?}", findings_for(&src));
    }

    /// Nothing in the program says this type is ever derived, so there is no
    /// evidence it is a PDA at all. Reporting it would fire on every account
    /// in every program.
    #[test]
    fn an_account_no_handler_ever_derives_is_not_a_gap() {
        let src = TWO_HANDLERS
            .replace("init, payer = admin, seeds = [b\"vault\"], bump", "init, payer = admin")
            .replace("ATTR", "mut");
        assert!(findings_for(&src).is_empty(), "{:#?}", findings_for(&src));
    }

    /// `address = ...` pins the identity directly, which is what the seeds
    /// would have proved. Flagging it would be reporting the absence of one
    /// specific spelling of a check that is present.
    #[test]
    fn an_account_pinned_by_address_instead_is_not_a_gap() {
        let src = TWO_HANDLERS.replace("ATTR", "mut, address = KNOWN_VAULT");
        assert!(findings_for(&src).is_empty(), "{:#?}", findings_for(&src));
    }

    /// Aggregation, not just an alarm: an auditor has to be able to check the
    /// claim, and the claim is "you derive this elsewhere". Naming where turns
    /// the finding into something answerable without a second search.
    #[test]
    fn the_evidence_names_where_the_account_is_derived() {
        let src = TWO_HANDLERS.replace("ATTR", "mut");
        let f = findings_for(&src);
        assert!(f[0].evidence.contains("`vault`"), "{}", f[0].evidence);
        assert!(f[0].evidence.contains("Initialize"), "{}", f[0].evidence);
    }

    #[test]
    fn is_deterministic_across_runs() {
        let src = BASE.replace("ATTR", "bump");
        let a = findings_for(&src);
        let b = findings_for(&src);
        assert_eq!(a, b);
    }
}
