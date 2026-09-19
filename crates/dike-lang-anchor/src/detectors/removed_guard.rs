use super::{looks_like_authority, Detector, REMOVED_GUARD};
use crate::ir::{AccountDecl, AccountsStruct, Constraint, Handler, Program, Wrapper};
use dike_core::finding::{Finding, Severity};

/// A guard that should be there and is not.
///
/// The class was Track-2-only on the reasoning that "the absence of an
/// arbitrary expression is not a structural signal a detector can see". That
/// is true of an arbitrary expression and false of the one programs actually
/// write. Surveyed 2026-09-19 over three real Anchor programs, every
/// `constraint` but two had the same shape:
///
/// ```text
/// constraint = config.admin      == admin.key()
/// constraint = position.user     == user.key()
/// constraint = market.resolver   == resolver.key()
/// constraint = user_balance.owner == bettor.key()
/// ```
///
/// An account stores a `Pubkey` field, the handler takes an account of that
/// name, and the constraint says they must be the same. That is `has_one`
/// written by hand, and its absence *is* structural: the accounts struct
/// declares both halves of a binding and then does not make it.
///
/// So the rule is Anchor's own convention. A stored `Pubkey` field `f` on
/// account `a`, an account also called `f` in the same struct, and nothing
/// tying them together.
///
/// Authority-named fields are left to `missing-authority-binding`, which
/// already covers them and would otherwise report the same defect twice. This
/// detector is the same idea for the fields that are not authorities —
/// `user`, `maker`, `resolver`, `mint` — where nothing was watching at all.
pub struct RemovedGuardDetector;

impl Detector for RemovedGuardDetector {
    fn class(&self) -> &'static str {
        REMOVED_GUARD
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> f32 {
        // Below `missing-authority-binding`'s 0.70: the same shape of
        // evidence, about a field with no privileged name to corroborate it.
        0.60
    }

    fn run(&self, program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding> {
        let mut out = Vec::new();
        for decl in &accounts.decls {
            // An account being created here stores its fields for the first
            // time; there is no value yet for a guard to check against. The
            // same reasoning `missing-authority-binding` applies to `init`.
            if decl.constraints.iter().any(|c| matches!(c, Constraint::Init)) {
                continue;
            }
            for field in bindable_fields(program, decl) {
                // Both halves of the binding must be present for its absence
                // to mean anything. Without a counterpart account the stored
                // field is just data this handler never compares.
                if !accounts.decls.iter().any(|d| d.name == field) {
                    continue;
                }
                if binding_exists(accounts, decl, &field) {
                    continue;
                }
                let line = if decl.attr_line != 0 { decl.attr_line } else { decl.line };
                out.push(super::finding_at(
                    self,
                    handler,
                    &format!("{}.{}", decl.name, field),
                    line,
                    format!(
                        "`{0}` stores `{1}`, and this handler takes an account called \
                         `{1}`, but nothing requires them to be the same: no \
                         `has_one = {1}`, no `constraint = {0}.{1} == {1}.key()`, no \
                         `address`, and `{0}` is not derived from `{1}`. The two are \
                         declared as a pair and never checked against each other, so a \
                         caller may pass any `{1}`.",
                        decl.name, field
                    ),
                ));
            }
        }
        out
    }
}

/// `Pubkey` fields of the state struct behind `decl` that another account
/// could be bound to, excluding the authority-named ones that
/// `missing-authority-binding` already reports.
fn bindable_fields(program: &Program, decl: &AccountDecl) -> Vec<String> {
    let ty = match &decl.wrapper {
        Wrapper::Account(t) | Wrapper::InterfaceAccount(t) => t,
        _ => return Vec::new(),
    };
    let Some(state) = program.state_structs.get(ty) else {
        return Vec::new();
    };
    state
        .fields
        .iter()
        .filter(|(_, ty)| ty == "Pubkey")
        .map(|(name, _)| name.clone())
        .filter(|name| !looks_like_authority(name))
        .collect()
}

/// Whether anything in this accounts struct ties `owner.field` to the account
/// called `field`.
///
/// Four spellings, all idiomatic, all equivalent to Anchor:
/// `has_one = field` on the storing account; a `constraint` naming
/// `owner.field` on either account; `address = owner.field` on the counterpart;
/// and deriving the storing account's PDA from the counterpart's key, which
/// binds them without mentioning the field at all.
fn binding_exists(accounts: &AccountsStruct, owner: &AccountDecl, field: &str) -> bool {
    if owner.has_one_targets().iter().any(|t| t == field) {
        return true;
    }
    let compact = |s: &str| -> String { s.chars().filter(|c| !c.is_whitespace()).collect() };
    let qualified = format!("{}.{}", owner.name, field);

    // The storing account's own seeds derive from the counterpart: passing a
    // different one derives a different address, so the pair is already tied.
    if owner.constraints.iter().any(|c| match c {
        Constraint::Seeds(text) => compact(text).contains(&format!("{field}.key()")),
        _ => false,
    }) {
        return true;
    }

    accounts.decls.iter().any(|d| {
        d.constraints.iter().any(|c| match c {
            Constraint::Raw(text) | Constraint::Address(text) => {
                compact(text).contains(&qualified)
            }
            _ => false,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_tree;
    use dike_core::analyzer::{SourceFile, SourceTree};
    use std::path::PathBuf;

    fn findings_for(src: &str) -> Vec<dike_core::Finding> {
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("src/lib.rs"), text: src.into() }],
        };
        let out = parse_tree(&tree);
        let d = RemovedGuardDetector;
        out.program
            .instructions
            .iter()
            .flat_map(|h| {
                let accounts = out.program.accounts_for(h).cloned().unwrap_or_default();
                d.run(&out.program, h, &accounts)
            })
            .collect()
    }

    /// `ATTR` is what the `deal` account declares.
    const PAIR: &str = r#"
        #[program]
        pub mod escrow {
            pub fn settle(ctx: Context<Settle>) -> Result<()> { Ok(()) }
        }
        #[account]
        pub struct Deal { pub maker: Pubkey, pub amount: u64 }
        #[derive(Accounts)]
        pub struct Settle<'info> {
            pub caller: Signer<'info>,
            /// CHECK: the maker this deal belongs to
            pub maker: UncheckedAccount<'info>,
            #[account(ATTR)]
            pub deal: Account<'info, Deal>,
        }
    "#;

    /// The defect: both halves of the binding are declared and nothing makes
    /// it. Any `maker` may be passed for any `deal`.
    #[test]
    fn a_stored_field_and_its_namesake_account_with_nothing_binding_them_is_a_gap() {
        let f = findings_for(&PAIR.replace("ATTR", "mut"));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].class.as_str(), "removed-guard");
        assert_eq!(f[0].severity, dike_core::Severity::High);
        assert!((f[0].confidence - 0.60).abs() < 1e-6);
        assert!(f[0].evidence.contains("`deal`") && f[0].evidence.contains("`maker`"));
    }

    #[test]
    fn a_constraint_naming_the_field_is_the_binding() {
        let src = PAIR.replace("ATTR", "mut, constraint = deal.maker == maker.key() @ E::No");
        assert!(findings_for(&src).is_empty(), "{:#?}", findings_for(&src));
    }

    #[test]
    fn has_one_is_the_binding() {
        let src = PAIR.replace("ATTR", "mut, has_one = maker @ E::No");
        assert!(findings_for(&src).is_empty(), "{:#?}", findings_for(&src));
    }

    /// Deriving the storing account from the counterpart binds the pair
    /// without naming the field: pass a different `maker` and the address no
    /// longer derives. Reporting this would be the false positive that the
    /// owner detector had to learn about the hard way.
    #[test]
    fn deriving_the_account_from_the_counterpart_is_the_binding() {
        let src = PAIR.replace("ATTR", "mut, seeds = [b\"deal\", maker.key().as_ref()], bump = deal.bump");
        assert!(findings_for(&src).is_empty(), "{:#?}", findings_for(&src));
    }

    /// Without an account of that name there is no pair, and a stored key the
    /// handler never takes is not something it failed to check. This is what
    /// keeps the rule off every account in every program.
    #[test]
    fn a_stored_field_with_no_counterpart_account_is_not_a_gap() {
        let src = r#"
            #[program]
            pub mod escrow {
                pub fn peek(ctx: Context<Peek>) -> Result<()> { Ok(()) }
            }
            #[account]
            pub struct Deal { pub maker: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct Peek<'info> {
                pub caller: Signer<'info>,
                #[account(mut)]
                pub deal: Account<'info, Deal>,
            }
        "#;
        assert!(findings_for(src).is_empty(), "{:#?}", findings_for(src));
    }

    /// An authority-named field is `missing-authority-binding`'s to report.
    /// Reporting it here as well would put the same defect on the same
    /// handler twice under two class names.
    #[test]
    fn an_authority_named_field_is_left_to_the_authority_detector() {
        let src = r#"
            #[program]
            pub mod escrow {
                pub fn sweep(ctx: Context<Sweep>) -> Result<()> { Ok(()) }
            }
            #[account]
            pub struct Config { pub admin: Pubkey }
            #[derive(Accounts)]
            pub struct Sweep<'info> {
                pub admin: Signer<'info>,
                #[account(mut)]
                pub config: Account<'info, Config>,
            }
        "#;
        assert!(findings_for(src).is_empty(), "{:#?}", findings_for(src));
    }

    /// An account being created stores its fields for the first time, so
    /// there is no stored value for a guard to check against.
    #[test]
    fn an_init_account_has_nothing_to_bind_yet() {
        let src = PAIR.replace("ATTR", "init, payer = caller, space = 64");
        assert!(findings_for(&src).is_empty(), "{:#?}", findings_for(&src));
    }

    #[test]
    fn is_deterministic_across_runs() {
        let src = PAIR.replace("ATTR", "mut");
        assert_eq!(findings_for(&src), findings_for(&src));
    }
}
