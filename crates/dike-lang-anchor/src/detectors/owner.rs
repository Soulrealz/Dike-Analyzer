use super::{finding_from, Detector, MISSING_OWNER_CHECK};
use crate::ir::{AccountsStruct, Constraint, Handler, Program};
use dike_core::finding::{Finding, Severity};

pub struct MissingOwnerCheckDetector;

impl Detector for MissingOwnerCheckDetector {
    fn class(&self) -> &'static str {
        MISSING_OWNER_CHECK
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> f32 {
        0.75
    }

    fn run(&self, _program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding> {
        accounts
            .decls
            .iter()
            .filter(|d| {
                d.is_unchecked()
                    && !d.is_address_pinned()
                    && !d.has_seeds()
                    && !d.constraints.iter().any(|c| match c {
                        Constraint::Owner(_) => true,
                        Constraint::Raw(text) => raw_is_identity_pinning(text),
                        _ => false,
                    })
                    && !pinned_by_sibling(accounts, &d.name)
            })
            .map(|d| {
                finding_from(
                    self,
                    handler,
                    d,
                    format!(
                        "`{}` is declared `{:?}` — Anchor performs no owner check and no \
                         discriminator check on this wrapper. Nothing (`address =`, `owner =`, \
                         `seeds`, or a manual `constraint = ...` that pins its identity) pins \
                         it, so an attacker may substitute an arbitrary account.",
                        d.name, d.wrapper
                    ),
                )
            })
            .collect()
    }
}

/// `Constraint::Raw` is the parser's catch-all for any `#[account(...)]` key
/// it doesn't otherwise model — `constraint = amount > 0` and
/// `constraint = mint.key() == expected_mint` both land here. Treating every
/// `Raw` constraint as identity-pinning (the original rule) is a false
/// negative on the former: nothing there actually pins who `mint` is.
/// Fix round 1: only a `Raw` constraint whose text plausibly concerns
/// identity counts as pinning. Anchor's proc-macro2 token stringification
/// inserts spaces around dots and before an empty `()` group (`vault . admin
/// == admin . key ()`), so whitespace is stripped before the substring
/// check to make this robust to that formatting rather than fragile to it.
/// Fix round 2: a standalone `==` is not a reliable identity signal — a
/// plain value comparison like `constraint = amount == 0` contains `==` but
/// pins nothing about WHO the account is, and suppressing on it is a false
/// negative in the dangerous direction. Both specified positive cases
/// (`mint.key() == expected_mint`, `vault.admin == admin.key()`) already
/// contain `.key()`, so keying on `.key()` alone loses no required coverage
/// while dropping a family of false suppressions — strictly more
/// recall-favorable, which is the right bias here.
fn raw_is_identity_pinning(text: &str) -> bool {
    compact(text).contains(".key()")
}

/// Anchor's proc-macro2 stringification inserts spaces around dots and before
/// an empty `()` group (`vault . admin == admin . key ()`), so every substring
/// check here strips whitespace first rather than being fragile to it.
fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Whether another declaration in the same accounts struct pins `name`.
///
/// Anchor lets one account constrain another. An `UncheckedAccount` named in a
/// sibling's `seeds` is fixed by that derivation: pass a different account and
/// the sibling's address no longer derives, so the sibling fails to load. A
/// sibling `constraint = other.field == name.key()` pins it against data
/// already stored on chain. Both are idiomatic, and both are invisible to a
/// rule that reads one declaration at a time — measured 2026-09-19, this was
/// three of the four false positives in the project's first adjudication of
/// real-program output (`benchmarks/adjudication/`).
///
/// An `init` sibling is excluded deliberately. It is created at whatever
/// address its seeds derive to, so naming the unchecked account there
/// constrains nothing: the caller picks the account and the PDA follows.
/// `init_if_needed` goes with it — its pin holds only in the branch where the
/// account already exists, and a conditional pin is not one. This is the
/// recall-favorable side of the call, which is the right side for a check that
/// deletes findings.
fn pinned_by_sibling(accounts: &AccountsStruct, name: &str) -> bool {
    let needle = format!("{name}.key()");
    accounts.decls.iter().any(|other| {
        other.name != name
            && !other.is_init()
            && other.constraints.iter().any(|c| match c {
                Constraint::Seeds(text) | Constraint::Raw(text) | Constraint::Address(text) => {
                    compact(text).contains(&needle)
                }
                _ => false,
            })
    })
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
        let d = MissingOwnerCheckDetector;
        out.program
            .instructions
            .iter()
            .flat_map(|h| {
                let accounts = out.program.accounts_for(h).cloned().unwrap_or_default();
                d.run(&out.program, h, &accounts)
            })
            .collect()
    }

    /// Adjudicated false positive, polyclone `Refund` (2026-09-19). `user` is
    /// an `UncheckedAccount` whose identity is pinned by two *siblings*: it
    /// appears in the seeds of `position` and `user_balance`, and
    /// `position.user == user.key()` names it directly. Passing a different
    /// `user` derives a different `position`, which will not exist or will
    /// belong to that other user.
    ///
    /// Anchor lets one declaration pin another. A rule that reads a single
    /// declaration cannot see it.
    const PINNED_BY_SIBLING_SEEDS: &str = r#"
        #[program]
        pub mod market {
            pub fn refund(ctx: Context<Refund>) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        pub struct Refund<'info> {
            #[account(mut)]
            pub caller: Signer<'info>,
            /// CHECK: used only for PDA derivation
            pub user: UncheckedAccount<'info>,
            #[account(
                mut,
                seeds = [POSITION_SEED, market.key().as_ref(), user.key().as_ref()],
                bump = position.bump,
                constraint = position.user == user.key() @ Error::Unauthorized,
            )]
            pub position: Account<'info, Position>,
            #[account(seeds = [USER_SEED, user.key().as_ref()], bump = user_balance.bump)]
            pub user_balance: Account<'info, UserBalance>,
        }
    "#;

    #[test]
    fn an_unchecked_account_named_in_a_siblings_seeds_is_pinned() {
        let f = findings_for(PINNED_BY_SIBLING_SEEDS);
        assert!(f.is_empty(), "`user` is pinned by position/user_balance seeds: {f:#?}");
    }

    /// Adjudicated false positive, prediction-market `PlaceBet` (2026-09-19).
    /// Same shape, and the direct pin is a sibling's `constraint`.
    #[test]
    fn an_unchecked_account_named_in_a_siblings_constraint_is_pinned() {
        let src = r#"
            #[program]
            pub mod market {
                pub fn place_bet(ctx: Context<PlaceBet>) -> Result<()> { Ok(()) }
            }
            #[derive(Accounts)]
            pub struct PlaceBet<'info> {
                #[account(
                    mut,
                    seeds = [USER_SEED, bettor.key().as_ref()],
                    bump = user_balance.bump,
                    constraint = user_balance.owner == bettor.key() @ Error::Unauthorized,
                )]
                pub user_balance: Account<'info, UserBalance>,
                /// CHECK: authorized by an Ed25519-signed intent
                pub bettor: UncheckedAccount<'info>,
                #[account(mut)]
                pub relayer: Signer<'info>,
            }
        "#;
        let f = findings_for(src);
        assert!(f.is_empty(), "`bettor` is pinned by user_balance: {f:#?}");
    }

    /// The pin must come from an account that itself has a fixed address. An
    /// `init` sibling is created at whatever address its seeds derive to, so
    /// naming the unchecked account in *its* seeds constrains nothing — the
    /// caller picks the account and the PDA follows. Suppressing on that
    /// would be a false negative in the dangerous direction.
    #[test]
    fn a_pin_from_an_init_sibling_does_not_count() {
        let src = r#"
            #[program]
            pub mod market {
                pub fn open(ctx: Context<Open>) -> Result<()> { Ok(()) }
            }
            #[derive(Accounts)]
            pub struct Open<'info> {
                pub beneficiary: UncheckedAccount<'info>,
                #[account(
                    init, payer = payer, space = 64,
                    seeds = [POSITION_SEED, beneficiary.key().as_ref()], bump
                )]
                pub position: Account<'info, Position>,
                #[account(mut)]
                pub payer: Signer<'info>,
            }
        "#;
        let f = findings_for(src);
        assert_eq!(f.len(), 1, "an init sibling pins nothing: {f:#?}");
        assert_eq!(f[0].class.as_str(), "missing-owner-check");
    }

    /// The control: an unchecked account no sibling mentions is still a
    /// finding. Without this the fix above could silence the detector wholly.
    #[test]
    fn an_unchecked_account_no_sibling_mentions_is_still_reported() {
        let src = r#"
            #[program]
            pub mod market {
                pub fn sweep(ctx: Context<Sweep>) -> Result<()> { Ok(()) }
            }
            #[derive(Accounts)]
            pub struct Sweep<'info> {
                pub destination: UncheckedAccount<'info>,
                #[account(seeds = [VAULT_SEED], bump = vault.bump)]
                pub vault: Account<'info, Vault>,
            }
        "#;
        let f = findings_for(src);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].evidence.contains("`destination`"));
    }

    const VULNERABLE: &str = r#"
        #[program]
        pub mod vault {
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            pub mint: UncheckedAccount<'info>,
            #[account(mut)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    #[test]
    fn flags_unchecked_account_with_no_pin() {
        let f = findings_for(VULNERABLE);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "missing-owner-check");
        assert_eq!(f[0].severity, dike_core::Severity::High);
        assert_eq!(f[0].track, dike_core::Track::Static);
        assert_eq!(f[0].location.handler, "withdraw");
        assert!((f[0].confidence - 0.75).abs() < 1e-6);
    }

    #[test]
    fn evidence_names_the_account_in_backticks() {
        let f = findings_for(VULNERABLE);
        assert!(f[0].evidence.contains("`mint`"));
    }

    #[test]
    fn does_not_flag_owner_pinned_unchecked_account() {
        let src = VULNERABLE.replace(
            "pub mint: UncheckedAccount<'info>,",
            "#[account(owner = token_program.key())]\n            pub mint: UncheckedAccount<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_flag_seeded_unchecked_account() {
        let src = VULNERABLE.replace(
            "pub mint: UncheckedAccount<'info>,",
            "#[account(seeds = [b\"mint\"], bump)]\n            pub mint: UncheckedAccount<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_flag_address_pinned_unchecked_account() {
        let src = VULNERABLE.replace(
            "pub mint: UncheckedAccount<'info>,",
            "#[account(address = crate::MINT)]\n            pub mint: UncheckedAccount<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_flag_typed_account() {
        assert!(findings_for(
            &VULNERABLE.replace(
                "pub mint: UncheckedAccount<'info>,",
                "pub mint: Account<'info, Vault>,"
            )
        )
        .is_empty());
    }

    #[test]
    fn is_deterministic_across_runs() {
        let a = findings_for(VULNERABLE);
        let b = findings_for(VULNERABLE);
        assert_eq!(a, b);
    }

    // Fix round 1: a non-identity `Raw` constraint (e.g. a bounds check) must
    // NOT suppress the finding — only a constraint that plausibly pins the
    // account's identity (a `.key()` comparison or an equality check) may.
    #[test]
    fn non_identity_raw_constraint_does_not_suppress_the_finding() {
        let src = VULNERABLE.replace(
            "pub mint: UncheckedAccount<'info>,",
            "#[account(mut, constraint = amount > 0)]\n            pub mint: UncheckedAccount<'info>,",
        );
        let f = findings_for(&src);
        assert_eq!(f.len(), 1, "a bounds-check constraint pins nothing about identity");
    }

    #[test]
    fn key_comparison_raw_constraint_suppresses_the_finding() {
        let src = VULNERABLE.replace(
            "pub mint: UncheckedAccount<'info>,",
            "#[account(constraint = mint.key() == expected_mint)]\n            pub mint: UncheckedAccount<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn equality_raw_constraint_suppresses_the_finding() {
        let src = VULNERABLE.replace(
            "pub mint: UncheckedAccount<'info>,",
            "#[account(constraint = vault.admin == admin.key())]\n            pub mint: UncheckedAccount<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn raw_is_identity_pinning_unit_cases() {
        assert!(!raw_is_identity_pinning("constraint = amount > 0"));
        assert!(raw_is_identity_pinning("constraint = mint . key () == expected_mint"));
        assert!(raw_is_identity_pinning("constraint = vault . admin == admin . key ()"));
    }

    // Fix round 2: a bare `==` comparison with no `.key()` call pins nothing
    // about WHO the account is (a value comparison, not an identity check),
    // so it must NOT suppress the finding.
    #[test]
    fn value_equality_raw_constraint_does_not_suppress_the_finding() {
        let src = VULNERABLE.replace(
            "pub mint: UncheckedAccount<'info>,",
            "#[account(mut, constraint = amount == 0)]\n            pub mint: UncheckedAccount<'info>,",
        );
        let f = findings_for(&src);
        assert_eq!(f.len(), 1, "a value comparison pins nothing about identity");
    }
}
