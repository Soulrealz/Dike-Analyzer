use super::Detector;
use crate::ir::{AccountsStruct, Handler, Program};
use dike_core::finding::{Finding, Severity};

pub struct UncheckedArithmeticDetector;

impl Detector for UncheckedArithmeticDetector {
    fn class(&self) -> &'static str {
        super::UNCHECKED_ARITHMETIC
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> f32 {
        0.35
    }

    fn run(&self, _program: &Program, handler: &Handler, _accounts: &AccountsStruct) -> Vec<Finding> {
        let unchecked: Vec<u32> = handler
            .body
            .arithmetic
            .iter()
            .filter(|a| !a.checked)
            .map(|a| a.line)
            .collect();
        if unchecked.is_empty() {
            return Vec::new();
        }
        let lines = unchecked.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ");
        let evidence = format!(
            "Unchecked arithmetic in `{}` at line(s) {}. Solana programs build in \
             release mode, where overflow wraps silently rather than panicking.",
            handler.name, lines
        );
        // This detector emits at most one finding per handler, so the key
        // only needs to be stable — a fixed class token, not a line-derived
        // value. A line-derived id would churn whenever unrelated code above
        // the handler shifts, which is actively harmful to an eval harness
        // that compares runs over time. Findings still merge on
        // `(handler_id, class)`, never on `id` (see
        // `dike_core::Finding::merge_key`), so this is safe.
        vec![super::finding_at(self, handler, "arithmetic", unchecked[0], evidence)]
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
        let d = UncheckedArithmeticDetector;
        out.program
            .instructions
            .iter()
            .flat_map(|h| {
                let accounts = out.program.accounts_for(h).cloned().unwrap_or_default();
                d.run(&out.program, h, &accounts)
            })
            .collect()
    }

    #[test]
    fn flags_a_handler_with_bare_arithmetic_once() {
        // Line numbers below are 1-indexed against this literal, counting
        // the leading newline right after `r#"` as the end of line 1: the
        // `-` subtraction is on line 5, the `* 3 / 100` is on line 6. This
        // pins the assertion to the actual line computation rather than to
        // the evidence template's hard-coded text (fix round 1, item 3).
        let f = findings_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                    ctx.accounts.vault.amount = ctx.accounts.vault.amount - amount;
                    let fee = amount * 3 / 100;
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> { pub authority: Signer<'info> }
        "#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "unchecked-arithmetic");
        assert_eq!(f[0].severity, dike_core::Severity::Medium);
        assert!((f[0].confidence - 0.35).abs() < 1e-6);
        assert!(f[0].evidence.contains("5"), "evidence should name line 5: {}", f[0].evidence);
        assert!(f[0].evidence.contains("6"), "evidence should name line 6: {}", f[0].evidence);
        assert_eq!(f[0].location.line, 5, "location must point at the first unchecked op's real line");
    }

    #[test]
    fn flags_compound_assignment_arithmetic() {
        // Task 8 fixed a bug where `+=`/`-=`/`*=`/`/=` (parsed by syn 2.x as
        // `Expr::Binary` with a `BinOp::*Assign`, not `Expr::Assign`) were
        // invisible to the IR, silently defeating this whole detector class.
        // That fix is tested at the parser layer; this pins the same
        // property at the detector layer so an op-keyed filter added here
        // later cannot quietly re-open the hole.
        let f = findings_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                    ctx.accounts.vault.amount += amount;
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> { pub authority: Signer<'info> }
        "#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "unchecked-arithmetic");
    }

    #[test]
    fn does_not_flag_fully_checked_arithmetic() {
        let f = findings_for(
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                    ctx.accounts.vault.amount =
                        ctx.accounts.vault.amount.checked_sub(amount).ok_or(ErrorCode::Overflow)?;
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> { pub authority: Signer<'info> }
        "#,
        );
        assert!(f.is_empty());
    }
}
