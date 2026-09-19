use super::{looks_like_authority, Detector, REMOVED_GUARD};
use crate::detectors::owner::pinned_by_sibling;
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
///
/// A second shape, added 2026-09-19. The `constraint`s programs write are not
/// all name-to-name bindings: `vault_token_account.owner == vault.key()` ties a
/// token account to the PDA that accounts for its balance, and no account is
/// called `owner`, so the rule above cannot see it. Its absence is still
/// structural — the handler credits `vault.amount` on the strength of a
/// transfer into an account whose identity nothing fixes.
///
/// So the second rule is: the account reaches a value-moving CPI in this
/// handler's body (`HandlerBody::reaches_value_sink`), it is named after an
/// account this handler state-writes, and nothing pins its identity.
///
/// **The name condition carries more of the discrimination than the dataflow
/// does**, and the evidence string says so. An unpinned account reaching a
/// transfer is the ordinary case: the counterparty's own token account is
/// exactly that, and the token program enforces that the signing authority
/// owns it. What is different about the program's own side is that state is
/// written on the strength of the transfer, and the name is the only handle
/// this slice has on that relationship. A program that names its vault token
/// account `treasury` while writing state to `vault` is a known false
/// negative, recorded in `docs/PROJECT_CONTEXT.md`.
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
            if let Some(state) = named_after_written_state(handler, decl) {
                if handler.body.reaches_value_sink.contains(&decl.name)
                    && !identity_is_pinned(accounts, decl)
                {
                    let line = if decl.attr_line != 0 { decl.attr_line } else { decl.line };
                    out.push(super::finding_at(
                        self,
                        handler,
                        &accounts.file,
                        &decl.name,
                        line,
                        format!(
                            "`{0}` receives or sends value in this handler, and it is \
                             named after `{1}`, whose state this handler writes — so \
                             `{1}` is credited on the strength of a transfer through \
                             `{0}`. Nothing fixes which account `{0}` is: no `seeds`, \
                             no `address`, no `has_one`, and no constraint naming it. \
                             A caller may substitute a different token account while \
                             `{1}` is updated as though the transfer had landed. Note \
                             that the tie between `{0}` and `{1}` is inferred from the \
                             name, not proven; confirm it before acting.",
                            decl.name, state
                        ),
                    ));
                }
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
                    &accounts.file,
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

/// The account this handler state-writes that `decl` appears to be named
/// after: `vault` for `vault_token_account`, `vault` for `vault_token`.
///
/// The suffix must be non-empty. `vault` itself reaches value sinks as the CPI
/// `authority`, and the account that holds the state is not the account the
/// state accounts for — an empty suffix would report the state account against
/// itself.
///
/// A name heuristic, and the honest limit of this slice: the real relationship
/// is "this token account holds the balance `{state}` accounts for", which the
/// constraint `StripConstraint` deletes expressed directly and nothing here
/// recovers in general.
fn named_after_written_state(handler: &Handler, decl: &AccountDecl) -> Option<String> {
    handler
        .body
        .state_writes
        .iter()
        .map(|w| &w.account)
        // Longest match wins, so `vault_config_token` prefers `vault_config`
        // over `vault` when the handler writes both. `max_by_key` on the length
        // alone would let two equally long candidates resolve by iteration
        // order, so the name breaks the tie (Rule 5).
        .filter(|a| decl.name.len() > a.len() && decl.name.starts_with(a.as_str()))
        .max_by_key(|a| (a.len(), a.as_str()))
        .cloned()
}

/// Whether anything in this accounts struct fixes which account `decl` is.
///
/// Five spellings, all idiomatic. `seeds` derives the address; `address =` and
/// `owner =` pin it outright; a `has_one` ties it to stored data; any
/// constraint anywhere in the struct that *names* this account is doing so in
/// order to constrain it — the spelling the clean `vault` fixture uses, where
/// `constraint = vault_token_account.owner == vault.key()` is declared on the
/// sibling `vault`; and `pinned_by_sibling` covers a sibling deriving from
/// `{name}.key()`.
///
/// `pinned_by_sibling` is reused rather than reimplemented: its doc comment
/// records three adjudicated false positives, including why `init` siblings
/// are excluded.
fn identity_is_pinned(accounts: &AccountsStruct, decl: &AccountDecl) -> bool {
    decl.has_seeds()
        || decl.is_address_pinned()
        || !decl.has_one_targets().is_empty()
        || named_in_any_constraint(accounts, &decl.name)
        || pinned_by_sibling(accounts, &decl.name)
}

/// Whether any constraint in the struct mentions `name` as a whole identifier.
///
/// Whole-identifier, not substring: `vault` is a substring of
/// `vault_token_account`, so a substring test would let a constraint about the
/// token account silence a finding about the vault and the other way round.
fn named_in_any_constraint(accounts: &AccountsStruct, name: &str) -> bool {
    accounts.decls.iter().any(|d| {
        d.constraints.iter().any(|c| {
            let text = match c {
                Constraint::Raw(t)
                | Constraint::Address(t)
                | Constraint::Owner(t)
                | Constraint::Seeds(t)
                | Constraint::Close(t) => t.as_str(),
                Constraint::Bump(Some(t)) => t.as_str(),
                _ => return false,
            };
            text.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                .any(|tok| tok == name)
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

    /// `SINK` is the handler body, `ATTR` is what `vault_token` declares and
    /// `VATTR` is what `vault` declares. Three placeholders rather than a
    /// `str::replace` on a whole line: the pin this rule must respect is
    /// declared on the *sibling*, so tests need to vary both attributes, and
    /// matching a multi-line slice by its exact indentation is a test that
    /// breaks on a reformat.
    ///
    /// The shape is `tests/fixtures/programs/leaky_vault`'s `deposit`: the
    /// vault's own token account is the destination of a transfer,
    /// `vault.amount` is credited on the strength of it, and nothing says
    /// which token account it is.
    const SINK_PAIR: &str = r#"
        #[program]
        pub mod leaky {
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.amount = vault.amount + amount;
                SINK
                Ok(())
            }
        }
        #[account]
        pub struct Vault { pub amount: u64, pub bump: u8 }
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            #[account(VATTR)]
            pub vault: Account<'info, Vault>,
            #[account(ATTR)]
            pub vault_token: Account<'info, TokenAccount>,
            #[account(mut)]
            pub depositor_token: Account<'info, TokenAccount>,
            pub depositor: Signer<'info>,
            pub token_program: Program<'info, Token>,
        }
    "#;

    const TRANSFER: &str = r#"
        let cpi_accounts = Transfer {
            from: ctx.accounts.depositor_token.to_account_info(),
            to: ctx.accounts.vault_token.to_account_info(),
            authority: ctx.accounts.depositor.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
    "#;

    /// `VATTR` is substituted first: `"ATTR"` is a substring of `"VATTR"`, so
    /// replacing `ATTR` first would corrupt the sibling's placeholder into
    /// `V<attr>`.
    fn sink_pair_with(vattr: &str, attr: &str, sink: &str) -> String {
        SINK_PAIR
            .replace("VATTR", vattr)
            .replace("ATTR", attr)
            .replace("SINK", sink)
    }

    fn sink_pair(attr: &str, sink: &str) -> String {
        sink_pair_with("mut", attr, sink)
    }

    /// The defect this rule exists for. `vault_token` reaches a transfer, is
    /// named after `vault` — whose state this handler writes — and nothing
    /// pins it, so a caller may substitute any token account while
    /// `vault.amount` is credited as though the vault received the tokens.
    #[test]
    fn an_unpinned_account_named_after_written_state_that_reaches_a_transfer_is_a_gap() {
        let f = findings_for(&sink_pair("mut", TRANSFER));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].class.as_str(), "removed-guard");
        assert_eq!(f[0].subject.as_deref(), Some("vault_token"));
        assert_eq!(f[0].severity, dike_core::Severity::High);
        assert!((f[0].confidence - 0.60).abs() < 1e-6);
    }

    /// Condition 1. Same declarations, no transfer: an account nothing moves
    /// value through is not this rule's business, whatever it is named.
    ///
    /// Breaks if: the dataflow condition is dropped and the rule keys on the
    /// name alone.
    #[test]
    fn an_account_that_reaches_no_sink_is_not_reported() {
        let f = findings_for(&sink_pair("mut", ""));
        assert!(f.is_empty(), "{f:#?}");
    }

    /// Condition 2, the clean-fixture half. `depositor_token` reaches the same
    /// transfer and nothing pins it either — and it is correct code. It is the
    /// depositor's own account, and the token program enforces that the
    /// signing authority owns it. An unpinned account reaching a transfer is
    /// the ordinary case, not a defect; only `vault_token` is reported.
    ///
    /// Breaks if: the "named after state this handler writes" condition is
    /// dropped. That framing was tried and rejected — see the design's §7.2.
    #[test]
    fn a_counterparty_account_reaching_the_same_transfer_is_not_reported() {
        let f = findings_for(&sink_pair("mut", TRANSFER));
        assert!(!f.iter().any(|x| x.subject.as_deref() == Some("depositor_token")), "{f:#?}");
    }

    /// Condition 2, the boundary. `vault` itself reaches sinks as the CPI
    /// `authority` and is trivially "named after" itself, but the account
    /// holding the state is not the account the state accounts for. The suffix
    /// must be non-empty.
    ///
    /// Breaks if: the name test becomes `starts_with` with no length check.
    #[test]
    fn the_state_account_itself_is_not_reported_as_its_own_token_account() {
        let sink = r#"
            let cpi_accounts = Transfer {
                from: ctx.accounts.vault_token.to_account_info(),
                to: ctx.accounts.depositor_token.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            };
            token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts), amount)?;
        "#;
        let f = findings_for(&sink_pair("mut", sink));
        assert!(!f.iter().any(|x| x.subject.as_deref() == Some("vault")), "{f:#?}");
        assert!(f.iter().any(|x| x.subject.as_deref() == Some("vault_token")), "{f:#?}");
    }

    /// Condition 3, the spelling the clean `vault` fixture actually uses
    /// (`vault/src/lib.rs:91`): a constraint on the *sibling* that names this
    /// account. That is the site `StripConstraint` deletes, so this test and
    /// the positive one above are the two halves of the mutation the rule now
    /// has to catch.
    #[test]
    fn a_sibling_constraint_naming_the_account_is_the_pin() {
        let src = sink_pair_with(
            "mut, constraint = vault_token.owner == vault.key() @ E::Wrong",
            "mut",
            TRANSFER,
        );
        let f = findings_for(&src);
        assert!(!f.iter().any(|x| x.subject.as_deref() == Some("vault_token")), "{f:#?}");
    }

    /// Condition 3, the other idiomatic spellings. Seeds derive the address
    /// and `address =` pins it outright: either makes substitution impossible.
    #[test]
    fn seeds_or_an_address_pin_the_account() {
        let seeded = findings_for(&sink_pair(
            "mut, seeds = [b\"vt\", vault.key().as_ref()], bump",
            TRANSFER,
        ));
        assert!(!seeded.iter().any(|x| x.subject.as_deref() == Some("vault_token")), "{seeded:#?}");

        let pinned = findings_for(&sink_pair("mut, address = vault.token_account", TRANSFER));
        assert!(!pinned.iter().any(|x| x.subject.as_deref() == Some("vault_token")), "{pinned:#?}");
    }

    /// The evidence must not claim more than the rule knows. Condition 2 is a
    /// name heuristic and it carries more of the discrimination than the
    /// dataflow does; a reader who takes the evidence at face value must not
    /// come away believing the tool proved a relationship it inferred from a
    /// prefix.
    ///
    /// Breaks if: the evidence is rewritten to assert the account "must" be
    /// bound, or drops the name rationale.
    #[test]
    fn the_evidence_names_the_heuristic_rather_than_claiming_proof() {
        let f = findings_for(&sink_pair("mut", TRANSFER));
        let e = &f[0].evidence;
        assert!(e.contains("named after"), "{e}");
        assert!(e.contains("`vault_token`") && e.contains("`vault`"), "{e}");
    }

    #[test]
    fn the_value_sink_rule_is_deterministic_across_runs() {
        let src = sink_pair("mut", TRANSFER);
        assert_eq!(findings_for(&src), findings_for(&src));
    }
}
