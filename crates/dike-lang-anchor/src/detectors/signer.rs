use super::{finding_from, looks_like_authority, Detector, MISSING_SIGNER};
use crate::ir::{AccountsStruct, Handler, Program, Wrapper};
use dike_core::finding::{Finding, Severity};

pub struct MissingSignerDetector;

impl Detector for MissingSignerDetector {
    fn class(&self) -> &'static str {
        MISSING_SIGNER
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> f32 {
        0.90
    }

    fn run(&self, _program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding> {
        accounts
            .decls
            .iter()
            .filter(|d| {
                !matches!(d.wrapper, Wrapper::Program(_) | Wrapper::SystemAccount | Wrapper::Sysvar(_))
                    && looks_like_authority(&d.name)
                    && !d.enforces_signer()
                    && !d.is_address_pinned()
            })
            .map(|d| {
                finding_from(
                    self,
                    handler,
                    d,
                    format!(
                        "`{}` is named as a privileged account but is declared `{:?}` with no \
                         `Signer<'info>` type, `signer` constraint, or `address =` pin. Anyone \
                         may pass an arbitrary account here.",
                        d.name, d.wrapper
                    ),
                )
            })
            .collect()
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
        let d = MissingSignerDetector;
        out.program
            .instructions
            .iter()
            .flat_map(|h| {
                let accounts = out.program.accounts_for(h).cloned().unwrap_or_default();
                d.run(&out.program, h, &accounts)
            })
            .collect()
    }

    const VULNERABLE: &str = r#"
        #[program]
        pub mod vault {
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            pub authority: AccountInfo<'info>,
            #[account(mut)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    const SAFE: &str = r#"
        #[program]
        pub mod vault {
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            pub authority: Signer<'info>,
            #[account(mut)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    #[test]
    fn flags_authority_without_signer() {
        let f = findings_for(VULNERABLE);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "missing-signer");
        assert_eq!(f[0].severity, dike_core::Severity::Critical);
        assert_eq!(f[0].track, dike_core::Track::Static);
        assert_eq!(f[0].location.handler, "withdraw");
        assert!((f[0].confidence - 0.90).abs() < 1e-6);
    }

    #[test]
    fn evidence_names_the_account_in_backticks() {
        let f = findings_for(VULNERABLE);
        assert!(f[0].evidence.contains("`authority`"));
    }

    #[test]
    fn does_not_flag_typed_signer() {
        assert!(findings_for(SAFE).is_empty());
    }

    #[test]
    fn does_not_flag_legacy_signer_attribute() {
        let src = SAFE.replace(
            "pub authority: Signer<'info>,",
            "#[account(signer)]\n            pub authority: AccountInfo<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_flag_address_pinned_authority() {
        let src = SAFE.replace(
            "pub authority: Signer<'info>,",
            "#[account(address = crate::ADMIN)]\n            pub authority: AccountInfo<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn is_deterministic_across_runs() {
        let a = findings_for(VULNERABLE);
        let b = findings_for(VULNERABLE);
        assert_eq!(a, b);
    }
}
