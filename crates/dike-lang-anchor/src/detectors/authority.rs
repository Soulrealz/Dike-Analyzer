use super::{looks_like_authority, Detector, MISSING_AUTHORITY_BINDING};
use crate::ir::{AccountsStruct, Constraint, Handler, Program, Wrapper};
use dike_core::finding::{Finding, Severity};

pub struct MissingAuthorityBindingDetector;

impl Detector for MissingAuthorityBindingDetector {
    fn class(&self) -> &'static str {
        MISSING_AUTHORITY_BINDING
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> f32 {
        0.70
    }

    fn run(&self, program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding> {
        // A struct with no signer at all is a missing-signer finding, not an
        // unbound-authority one; emitting both would double-report the same
        // underlying bug on the same handler.
        if !accounts.decls.iter().any(|d| d.enforces_signer()) {
            return Vec::new();
        }

        accounts
            .decls
            .iter()
            // A plain `init` account has no pre-existing authority to bind:
            // `has_one` validates that a caller-supplied account matches a
            // value already stored on-chain, but on `init` the authority
            // field is being *written* here for the first time, not checked
            // against anything. Flagging it would be a false positive on
            // every `initialize`-style handler.
            //
            // `init_if_needed` is deliberately NOT skipped here even though
            // `d.is_init()` also matches it: the account MAY ALREADY EXIST
            // on-chain in that branch, and Anchor performs no automatic
            // re-validation that a caller-supplied *existing* account's
            // stored authority matches anything. That is exactly the gap
            // this detector exists to catch, so skipping `init_if_needed`
            // would be a real recall gap on a realistic Anchor pattern.
            .filter(|d| !d.constraints.iter().any(|c| matches!(c, Constraint::Init)))
            .flat_map(|d| {
                let has_one_targets = d.has_one_targets();
                let raw_texts: Vec<&str> = d
                    .constraints
                    .iter()
                    .filter_map(|c| match c {
                        Constraint::Raw(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();

                authority_fields(program, d)
                    .into_iter()
                    .filter(|field| {
                        !has_one_targets.iter().any(|t| t == field)
                            && !raw_texts.iter().any(|text| raw_pins_field(text, field))
                            // The handler must actually claim this authority.
                            // Measured 2026-09-06 over 28k LOC of real
                            // programs: without this, 101 of 119 findings were
                            // handlers that merely READ a config account
                            // storing an admin key — a production messaging
                            // stack tripped it from `send`, `clear` and `burn`
                            // alike. A struct that declares an account named
                            // after the stored field means to act as it, and
                            // not binding it is the defect; a struct that
                            // declares no such account is not acting on that
                            // authority at all and has nothing to bind.
                            //
                            // Keyed on the accounts struct rather than the
                            // handler body because real programs delegate
                            // (`fn claim(ctx) { claim::handler(ctx) }`), so
                            // the body holds no state writes to reason from.
                            && accounts.decls.iter().any(|c| claims_authority(&c.name, field))
                    })
                    .map(move |field| {
                        let line = if d.attr_line != 0 { d.attr_line } else { d.line };
                        super::finding_at(
                            self,
                            handler,
                            // Account AND field: one account can store two
                            // unbound authority fields, and keying on the
                            // account alone gave them the same id and would
                            // now collapse them into one row.
                            &format!("{}.{}", d.name, field),
                            line,
                            format!(
                                "`{}` (`{:?}`) has a `{}` field that looks like an authority but \
                                 is not named in a `has_one` constraint and is not pinned by any \
                                 `constraint = ...` expression. Anchor performs no check that the \
                                 caller-supplied `{}` matches the account stored in `{}`.",
                                d.name, d.wrapper, field, field, d.name
                            ),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Roles that mean "this handler acts as the account's authority".
///
/// Deliberately narrower than [`crate::detectors::AUTHORITY_NAMES`], which
/// also carries `payer` and `signer`. Nearly every `init`-style struct
/// declares a `payer`, and `signer` is a wrapper name as much as a role, so
/// counting either as a claim would put the over-firing straight back.
const CLAIMING_ROLES: [&str; 5] = ["authority", "admin", "owner", "delegate", "manager"];

/// Does declaring an account called `decl` amount to claiming the stored
/// authority field `field`?
///
/// Exact name first, because `has_one = admin` binds `vault.admin` to the
/// account literally called `admin` and that is the common case. Then the
/// role match, because real programs drift: the vulnerable fixture stores
/// `Vault.admin` and declares the account as `authority`, which is the same
/// claim under a different word. Requiring literal equality there would be a
/// recall gap on a shape the project's own fixture demonstrates.
fn claims_authority(decl: &str, field: &str) -> bool {
    if decl == field {
        return true;
    }
    let role = |n: &str| {
        let lower = n.to_ascii_lowercase();
        CLAIMING_ROLES.iter().any(|r| lower.split('_').any(|seg| seg == *r))
    };
    role(decl) && role(field)
}

/// A `Raw` constraint only counts as binding `field` when its text both
/// mentions the field AND looks like an identity check — mirrors
/// `owner.rs::raw_is_identity_pinning`. A naive "mentions the field name"
/// test alone over-suppresses: `#[account(init, payer = admin, ...)]`
/// parses to `Constraint::Raw("payer = admin")`, whose text contains
/// `admin` but pins nothing about who the *stored* authority is — `payer`
/// only says who pays rent for account creation. Anchor's proc-macro2 token
/// stringification inserts spaces around dots and before an empty `()`
/// group (`vault . admin == admin . key ()`), so whitespace is stripped
/// before both checks to make this robust to that formatting.
///
/// Note the `==` branch here is safe in a way `owner.rs`'s bare
/// `raw_is_identity_pinning` is not: this function *also* requires `field`
/// to appear in the same text, which anchors the `==` to that specific
/// field — `constraint = amount == 0` cannot suppress an `admin` finding,
/// because the compacted text doesn't contain `admin` at all. `owner.rs`
/// has no such anchor (it isn't checking a specific field name), which is
/// why its `==` branch had to be removed there. Dropping `==` here instead
/// would itself be a false negative: `constraint = vault.admin ==
/// expected_admin` is a real Anchor idiom (both sides already `Pubkey`, so
/// no `.key()` call appears) that must still suppress.
fn raw_pins_field(text: &str, field: &str) -> bool {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains(field) && (compact.contains(".key()") || compact.contains("=="))
}

/// Resolve the state struct behind `decl`'s wrapper and return the names of
/// its fields that are `Pubkey`-typed and look like an authority. Requires
/// `Program` (rather than just `AccountsStruct`) because the state struct
/// table lives on `Program`, not on the accounts struct itself.
fn authority_fields(program: &Program, decl: &crate::ir::AccountDecl) -> Vec<String> {
    let ty = match &decl.wrapper {
        Wrapper::Account(t) | Wrapper::InterfaceAccount(t) => t,
        _ => return Vec::new(),
    };
    let Some(state) = program.state_structs.get(ty) else { return Vec::new() };
    state
        .fields
        .iter()
        .filter(|(name, field_ty)| field_ty.contains("Pubkey") && looks_like_authority(name))
        .map(|(name, _)| name.clone())
        .collect()
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
        let d = MissingAuthorityBindingDetector;
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
        #[account]
        pub struct Vault { pub admin: Pubkey, pub amount: u64 }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            pub admin: Signer<'info>,
            #[account(mut, HASONE)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    /// Measured 2026-09-06 over 28k LOC of real programs: this detector
    /// produced 101 of 119 findings, and the bulk were handlers that merely
    /// *read* a global config account which happens to store an admin key.
    /// A production messaging stack tripped it five times on one settings
    /// account, from `send`, `clear` and `burn` — user-facing operations that
    /// act on nobody's authority.
    ///
    /// The signal that separates the two: does this handler's accounts struct
    /// declare an account named after the stored authority field? If it takes
    /// an `admin` account, it means to act as `admin`, and failing to bind it
    /// is the bug. If it takes no such account, the stored `admin` is
    /// somebody else's business and there is nothing here to bind.
    ///
    /// Body-independent on purpose: real programs delegate
    /// (`pub fn claim(ctx) -> Result<()> { claim::handler(ctx) }`), so the
    /// handler body carries no state writes to key off, and a rule that
    /// needed one would silence every delegating program.
    #[test]
    fn does_not_flag_a_handler_that_only_reads_a_config_it_never_acts_as() {
        let src = r#"
            #[program]
            pub mod messaging {
                pub fn send(ctx: Context<Send>) -> Result<()> { Ok(()) }
            }
            #[account]
            pub struct Settings { pub admin: Pubkey, pub fee: u64 }
            #[derive(Accounts)]
            pub struct Send<'info> {
                pub sender: Signer<'info>,
                pub settings: Account<'info, Settings>,
            }
        "#;
        assert!(
            findings_for(src).is_empty(),
            "`send` declares no `admin` account, so it never claims that authority: {:#?}",
            findings_for(src)
        );
    }

    /// The complement, and the reason the rule is a name match rather than a
    /// blanket "only flag admin-looking handlers": the moment a struct DOES
    /// take the account the stored field names, the binding is the developer's
    /// stated intent and its absence is the defect. This is the shape every
    /// `strip_has_one` mutant has, so it is also what keeps eval recall at
    /// 1.000.
    #[test]
    fn still_flags_a_handler_that_declares_the_authority_it_never_binds() {
        let src = r#"
            #[program]
            pub mod messaging {
                pub fn set_fee(ctx: Context<SetFee>) -> Result<()> { Ok(()) }
            }
            #[account]
            pub struct Settings { pub admin: Pubkey, pub fee: u64 }
            #[derive(Accounts)]
            pub struct SetFee<'info> {
                pub admin: Signer<'info>,
                #[account(mut)]
                pub settings: Account<'info, Settings>,
            }
        "#;
        let f = findings_for(src);
        assert_eq!(f.len(), 1, "expected the unbound admin to be reported: {f:#?}");
        assert!(f[0].evidence.contains("admin"));
    }

    #[test]
    fn flags_state_authority_field_with_no_has_one() {
        let f = findings_for(&BASE.replace("HASONE", ""));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "missing-authority-binding");
        assert_eq!(f[0].severity, dike_core::Severity::High);
        assert!(f[0].evidence.contains("admin"));
    }

    #[test]
    fn does_not_flag_when_has_one_is_present() {
        assert!(findings_for(&BASE.replace("HASONE", "has_one = admin")).is_empty());
    }

    #[test]
    fn does_not_flag_when_a_raw_constraint_mentions_the_field() {
        let src = BASE.replace("HASONE", "constraint = vault.admin == admin.key()");
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_double_report_when_the_struct_has_no_signer_at_all() {
        let src = BASE
            .replace("HASONE", "")
            .replace("pub admin: Signer<'info>,", "pub other: AccountInfo<'info>,");
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_flag_state_structs_without_an_authority_field() {
        let src = BASE
            .replace("HASONE", "")
            .replace("pub admin: Pubkey, pub amount: u64", "pub amount: u64");
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn evidence_names_the_account_in_backticks() {
        let f = findings_for(&BASE.replace("HASONE", ""));
        assert!(f[0].evidence.contains("`vault`"));
    }

    #[test]
    fn points_at_the_attribute_line_not_the_field_line() {
        // A multi-line `#[account(...)]` block makes attr_line and decl.line
        // genuinely different (several physical lines apart), so this test
        // can actually fail if the detector reports decl.line instead.
        const SRC: &str = r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub admin: Signer<'info>,
                #[account(
                    mut,
                    constraint = true,
                )]
                pub vault: Account<'info, Vault>,
            }
        "#;
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("src/lib.rs"), text: SRC.into() }],
        };
        let out = parse_tree(&tree);
        let accounts = out.program.accounts_structs.get("Withdraw").unwrap();
        let decl = accounts.decl("vault").unwrap();
        assert_ne!(decl.attr_line, decl.line, "fixture must give attr_line and decl.line distinct values");

        let f = findings_for(SRC);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].location.line, decl.attr_line);
        assert_ne!(f[0].location.line, decl.line);
    }

    #[test]
    fn falls_back_to_decl_line_when_there_is_no_attribute() {
        // No `#[account(...)]` attribute at all on `vault` means attr_line is
        // 0; the finding must fall back to decl.line, never point at line 0.
        let src = BASE.replace("#[account(mut, HASONE)]\n            ", "").replace("HASONE", "");
        let f = findings_for(&src);
        assert_eq!(f.len(), 1);
        assert!(f[0].location.line > 0);
    }

    #[test]
    fn flags_only_the_unbound_field_when_one_of_two_authority_fields_has_a_has_one() {
        // Adversarial case 2: a state struct with TWO authority-ish Pubkey
        // fields, only one of which is bound by `has_one`. Only the unbound
        // one should be flagged.
        const SRC: &str = r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
            }
            #[account]
            pub struct Vault {
                pub admin: Pubkey,
                pub update_authority: Pubkey,
                pub amount: u64,
            }
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub admin: Signer<'info>,
                #[account(mut, has_one = admin)]
                pub vault: Account<'info, Vault>,
            }
        "#;
        let f = findings_for(SRC);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "missing-authority-binding");
        assert!(f[0].evidence.contains("update_authority"));
        assert!(!f[0].evidence.contains("`admin`"));
    }

    /// Where the narrowing actually draws the line, stated as its own case.
    ///
    /// It is NOT "only the field the struct names": a struct that deals in
    /// authority roles at all keeps every unbound authority field it stores,
    /// because a second one nobody binds is worth an auditor's minute
    /// (Rule 3). What it excludes is a struct that claims no authority role —
    /// a handler taking a `sender` or a `user` and reading a config that
    /// happens to store an `admin`. That is the shape which produced 101 of
    /// 119 findings over 28k LOC of real programs, five of them on one
    /// settings account in audited production code.
    #[test]
    fn a_config_read_by_a_non_authority_handler_is_not_an_unbound_authority() {
        const SRC: &str = r#"
            #[program]
            pub mod market {
                pub fn place_bet(ctx: Context<PlaceBet>) -> Result<()> { Ok(()) }
            }
            #[account]
            pub struct Config { pub admin: Pubkey, pub pending_admin: Pubkey, pub fee: u64 }
            #[derive(Accounts)]
            pub struct PlaceBet<'info> {
                pub user: Signer<'info>,
                pub config: Account<'info, Config>,
            }
        "#;
        assert!(
            findings_for(SRC).is_empty(),
            "`place_bet` claims no authority role; the stored admin is not its business: {:#?}",
            findings_for(SRC)
        );
    }

    #[test]
    fn flags_init_if_needed_accounts_with_an_unbound_authority_field() {
        // `init_if_needed` differs from plain `init`: the account MAY
        // already exist on-chain, and Anchor performs no automatic
        // re-validation in that branch that a caller-supplied *existing*
        // account's stored authority matches anything. That is exactly the
        // gap this detector exists to catch, so — unlike plain `init` —
        // `init_if_needed` must still be flagged when unbound.
        let src = BASE
            .replace("HASONE", "")
            .replace("mut, ", "init_if_needed, payer = admin, space = 8 + 32 + 8, ");
        let f = findings_for(&src);
        assert_eq!(f.len(), 1, "init_if_needed accounts may already exist and must still be checked");
        assert_eq!(f[0].class.as_str(), "missing-authority-binding");
    }

    #[test]
    fn does_not_flag_init_accounts_which_have_no_pre_existing_authority_to_bind() {
        // `init` accounts are being created, not checked against a stored
        // value — the `payer = admin` constraint that comes along with
        // `init` pins who pays rent, not who the authority is, and must not
        // suppress-by-coincidence either (that's what fix round 1 addresses).
        let src = BASE
            .replace("HASONE", "")
            .replace("mut, ", "init, payer = admin, space = 8 + 32 + 8, ");
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn payer_constraint_does_not_suppress_a_non_init_finding() {
        // `payer = admin` mentions the field name `admin` as a raw
        // substring but is not an identity check, so on a *non-init*
        // account it must not suppress the finding (isolates fix (b) from
        // fix (a) above).
        let src = BASE.replace("HASONE", "payer = admin");
        let f = findings_for(&src);
        assert_eq!(f.len(), 1, "`payer = admin` pins nothing about identity");
    }

    #[test]
    fn space_constraint_does_not_suppress_the_finding() {
        let src = BASE.replace("HASONE", "space = 8 + 32");
        let f = findings_for(&src);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn raw_pins_field_unit_cases() {
        assert!(raw_pins_field("vault.admin == admin.key()", "admin"));
        assert!(raw_pins_field("vault . admin == admin . key ()", "admin"));
        assert!(!raw_pins_field("payer = admin", "admin"));
        assert!(!raw_pins_field("space = 8 + 32", "admin"));
    }

    #[test]
    fn is_deterministic_across_runs() {
        let src = BASE.replace("HASONE", "");
        let a = findings_for(&src);
        let b = findings_for(&src);
        assert_eq!(a, b);
    }
}
