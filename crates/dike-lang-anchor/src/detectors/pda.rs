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

/// The last path segment of a call name, so `Pubkey::create_program_address`
/// and a bare `create_program_address` both match.
fn callee(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

/// A `u8` argument the caller fills whose name reads as a bump seed.
///
/// The argument is the whole defect. A bump the *program* persisted and reuses
/// is the ordinary way to sign a CPI and appears in almost every real Anchor
/// program; a bump the *caller* chooses is the one that can be non-canonical.
fn caller_supplied_bump(handler: &Handler) -> Option<&str> {
    handler
        .args
        .iter()
        .find(|a| a.ty == "u8" && a.name.contains("bump"))
        .map(|a| a.name.as_str())
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

        // A caller-supplied bump reaching `create_program_address`
        // (sealevel-attacks category 7). Unlike the two rules below this is a
        // property of the handler body, not of a declaration, so it is
        // evaluated once per handler rather than per account.
        //
        // `create_program_address` derives from exactly the bump it is given
        // and fails only if that bump yields no valid address. Several bumps
        // usually do, so a caller who picks a non-canonical one derives a
        // different address that passes every check written against it.
        // `find_program_address` is the fix: it returns the canonical bump, so
        // a body that calls it has something to compare against and is left
        // alone here.
        if let Some(call) = handler.body.calls.iter().find(|c| callee(&c.name) == "create_program_address")
        {
            let canonical = handler.body.calls.iter().any(|c| callee(&c.name) == "find_program_address");
            if let (false, Some(bump)) = (canonical, caller_supplied_bump(handler)) {
                out.push(super::finding_at(
                    self,
                    handler,
                    &handler.file,
                    bump,
                    call.line,
                    format!(
                        "`{}` is a caller-supplied bump passed to `create_program_address`, and \
                         this handler never derives the canonical bump to compare it against. \
                         `create_program_address` accepts any bump that yields a valid address, \
                         so a caller may pick a non-canonical one and derive a different account \
                         that satisfies every check written against this address. Derive with \
                         `find_program_address`, or pin the account with Anchor's `seeds` and \
                         `bump` constraints.",
                        bump
                    ),
                ));
            }
        }
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

    /// Category 7 of sealevel-attacks, in the shape the Anchor authors wrote
    /// it. `create_program_address` accepts whatever bump it is handed, so a
    /// caller passing a non-canonical one derives a *different* valid address.
    fn bump_program(call: &str, args: &str) -> String {
        format!(
            r#"
            #[program]
            pub mod bumpy {{
                pub fn set_value(ctx: Context<BumpSeed>{args}) -> Result<()> {{
                    let address = {call}(&[key.to_le_bytes().as_ref(), &[bump]], ctx.program_id)?;
                    if address != ctx.accounts.data.key() {{
                        return Err(ProgramError::InvalidArgument.into());
                    }}
                    Ok(())
                }}
            }}
            #[derive(Accounts)]
            pub struct BumpSeed<'info> {{
                pub data: Account<'info, Data>,
            }}
        "#
        )
    }

    #[test]
    fn a_caller_supplied_bump_reaching_create_program_address_is_reported() {
        // Fails if the rule is absent.
        let f = findings_for(&bump_program("Pubkey::create_program_address", ", key: u64, bump: u8"));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].class.as_str(), PDA_VALIDATION_GAP);
        assert!(f[0].evidence.contains("bump"), "{}", f[0].evidence);
    }

    #[test]
    fn find_program_address_alone_is_not_reported() {
        // The `secure` variant. Fails if the rule fires on any derivation call
        // rather than on `create_program_address` specifically.
        let f = findings_for(&bump_program("Pubkey::find_program_address", ", key: u64, bump: u8"));
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn a_handler_that_derives_nothing_is_not_reported() {
        // The `recommended` variant pins the derivation with Anchor's own
        // `seeds`/`bump` constraints and does no arithmetic on addresses.
        // Fails if the rule fires on the presence of a bump argument alone.
        let src = r#"
            #[program]
            pub mod bumpy {
                pub fn set_value(ctx: Context<BumpSeed>, key: u64, bump: u8) -> Result<()> { Ok(()) }
            }
            #[derive(Accounts)]
            pub struct BumpSeed<'info> {
                pub data: Account<'info, Data>,
            }
        "#;
        assert!(findings_for(src).is_empty());
    }

    #[test]
    fn a_canonical_bump_computed_alongside_is_not_reported() {
        // `find_program_address` returns the canonical bump, so a body that
        // calls both has something to compare against. Fails if the
        // `find_program_address` exclusion is dropped.
        let src = r#"
            #[program]
            pub mod bumpy {
                pub fn set_value(ctx: Context<BumpSeed>, key: u64, bump: u8) -> Result<()> {
                    let (expected, canonical) = Pubkey::find_program_address(&[key.to_le_bytes().as_ref()], ctx.program_id);
                    let address = Pubkey::create_program_address(&[key.to_le_bytes().as_ref(), &[bump]], ctx.program_id)?;
                    if canonical != bump { return Err(ProgramError::InvalidArgument.into()); }
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct BumpSeed<'info> {
                pub data: Account<'info, Data>,
            }
        "#;
        let f = findings_for(src);
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn a_stored_bump_is_not_reported() {
        // Signing a CPI with a bump the program itself persisted is the normal
        // correct pattern and is everywhere in real Anchor code. Fails if the
        // caller-supplied-argument condition is dropped — which would
        // reproduce the precision collapse the 2026-09-19 adjudication found.
        let f = findings_for(&bump_program("Pubkey::create_program_address", ", key: u64"));
        assert!(f.is_empty(), "{f:#?}");
    }
}
