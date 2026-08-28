use super::{Detector, PDA_VALIDATION_GAP};
use crate::ir::{AccountsStruct, Handler, Program};
use dike_core::finding::{Finding, Severity};

pub struct PdaValidationGapDetector;

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

    fn run(&self, _program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding> {
        accounts
            .decls
            .iter()
            // An account with neither `seeds` nor `bump` may simply not be a
            // PDA — only an inconsistent pair (one present, the other
            // missing) is a gap.
            .filter(|d| d.has_seeds() != d.has_bump())
            .map(|d| {
                let line = if d.attr_line != 0 { d.attr_line } else { d.line };
                let (has, missing) =
                    if d.has_seeds() { ("seeds", "bump") } else { ("bump", "seeds") };
                super::finding_at(
                    self,
                    handler,
                    &d.name,
                    line,
                    format!(
                        "`{}` declares `{has}` without a matching `{missing}` constraint. A PDA \
                         validation must pin both the derivation seeds and the bump — an \
                         inconsistent pair leaves the account's identity unverified.",
                        d.name
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

    #[test]
    fn is_deterministic_across_runs() {
        let src = BASE.replace("ATTR", "bump");
        let a = findings_for(&src);
        let b = findings_for(&src);
        assert_eq!(a, b);
    }
}
