pub mod chunker;
pub mod detectors;
pub mod llm_analyzer;
pub mod ir;
pub mod mutations;
pub mod parser;

use dike_core::analyzer::{
    AnalysisResult, Analyzer, Diagnostic, DiagnosticKind, SourceTree,
};
use dike_core::finding::Finding;

/// Full static-track analysis for an Anchor program: parse, run every
/// detector over every resolvable handler, suppress, and rank. This is the
/// single entry point the CLI and `AnchorAnalyzer` both go through, so the
/// two never drift.
pub struct AnchorAnalysis {
    pub result: AnalysisResult,
    pub handlers: usize,
    /// Findings withheld by the suppression pass, each paired with the
    /// reason it was withheld. Suppressed findings are never silently
    /// dropped (spec: they are counted into `Coverage::suppressed` and
    /// listed in a report subsection) — carrying the pair here, rather
    /// than just a count, is what keeps that possible without a second
    /// parse. `Finding` and `String` are both `dike-core`/std types, so
    /// this carries no Anchor vocabulary across the seam.
    pub suppressed: Vec<(Finding, String)>,
}

/// Parse `tree`, run every detector over every handler whose context type
/// resolves, suppress, and rank. A handler whose `context_ty` does not
/// resolve to a known `#[derive(Accounts)]` struct gets a `Skipped`
/// diagnostic and is left out of the findings entirely — partial results
/// beat no results (spec §9), so one unresolvable handler must not stop
/// analysis of the rest.
pub fn analyze_program(tree: &SourceTree) -> AnchorAnalysis {
    let parsed = parser::parse_tree(tree);
    let all_detectors = detectors::all_detectors();
    let mut findings = Vec::new();
    let mut diagnostics = parsed.diagnostics;
    let mut suppressed = Vec::new();

    for handler in &parsed.program.instructions {
        let Some(accounts) = parsed.program.accounts_for(handler) else {
            diagnostics.push(Diagnostic {
                file: Some(handler.file.clone()),
                kind: DiagnosticKind::Skipped,
                message: format!(
                    "handler `{}` references unknown context type `{}`",
                    handler.name, handler.context_ty
                ),
            });
            continue;
        };
        let raw: Vec<Finding> = all_detectors
            .iter()
            .flat_map(|d| d.run(&parsed.program, handler, accounts))
            .collect();
        let (kept, dropped) = detectors::suppression::apply(raw, handler, accounts);
        suppressed.extend(dropped.into_iter().map(|s| (s.finding, s.reason)));
        findings.extend(kept);
    }

    dike_core::merge::rank(&mut findings);

    AnchorAnalysis {
        result: AnalysisResult {
            // The static track reviews the whole tree, not a sequence of
            // units, so it reports no unit coverage (D28).
            units: None,
            findings,
            diagnostics,
            files_analyzed: parsed.files_parsed,
        },
        handlers: parsed.program.instructions.len(),
        suppressed,
    }
}

/// The static-track `Analyzer` impl. Delegates to `analyze_program` and
/// discards the handler/suppression extras — `Analyzer::analyze` returns
/// only `AnalysisResult`, so the CLI calls `analyze_program` directly when
/// it needs the coverage numbers.
pub struct AnchorAnalyzer;

impl Analyzer for AnchorAnalyzer {
    fn name(&self) -> &'static str {
        "anchor-static"
    }
    fn analyze(&self, tree: &SourceTree) -> AnalysisResult {
        analyze_program(tree).result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dike_core::analyzer::SourceFile;
    use std::path::PathBuf;

    /// Fix round 1, Item 3: nothing previously exercised the `Skipped`
    /// branch in `analyze_program` — `lib.rs` had no test module at all, and
    /// all three `end_to_end.rs` tests use the fully-resolvable vault
    /// fixture, where every handler's `Context<T>` resolves.
    ///
    /// `ghost`'s `Context<Ghost>` has no matching `#[derive(Accounts)]`
    /// struct anywhere in the tree, so it must be skipped rather than
    /// aborting the whole analysis: a `Skipped` diagnostic is emitted naming
    /// the handler and the unresolved type, and `withdraw` — the other,
    /// fully-resolvable handler — must still be analyzed and produce
    /// findings. Partial results beat no results (spec §9); this is the
    /// test of that principle.
    #[test]
    fn unresolvable_context_type_is_skipped_not_fatal() {
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile {
                path: PathBuf::from("src/lib.rs"),
                text: r#"
                    #[program]
                    pub mod vault {
                        pub fn ghost(ctx: Context<Ghost>) -> Result<()> { Ok(()) }
                        pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
                    }
                    #[derive(Accounts)]
                    pub struct Withdraw<'info> {
                        pub authority: AccountInfo<'info>,
                    }
                "#
                .into(),
            }],
        };

        let analysis = analyze_program(&tree);

        let skipped: Vec<_> = analysis
            .result
            .diagnostics
            .iter()
            .filter(|d| d.kind == DiagnosticKind::Skipped)
            .collect();
        assert_eq!(
            skipped.len(),
            1,
            "expected exactly one Skipped diagnostic: {:#?}",
            analysis.result.diagnostics
        );
        assert!(
            skipped[0].message.contains("ghost"),
            "the Skipped diagnostic must name the handler: {}",
            skipped[0].message
        );
        assert!(
            skipped[0].message.contains("Ghost"),
            "the Skipped diagnostic must name the unresolved context type: {}",
            skipped[0].message
        );

        assert!(
            analysis.result.findings.iter().any(|f| f.location.handler == "withdraw"),
            "analysis must still complete and return findings for the other, resolvable \
             handler, not stop dead on the first unresolvable one: {:#?}",
            analysis.result.findings
        );
    }
}
