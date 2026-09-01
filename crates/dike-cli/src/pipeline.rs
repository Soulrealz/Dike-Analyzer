use dike_core::analyzer::{Analyzer, SourceTree};
use dike_core::merge::merge;
use dike_core::report::{Coverage, Report, RunMetadata, TrackFindings};

/// Runs each track independently and merges only at the end. Track 2's output
/// never influences Track 1's list — the two vectors stay separate in the Report.
pub fn run(
    tree: &SourceTree,
    static_analyzer: &dyn Analyzer,
    llm_analyzer: Option<&dyn Analyzer>,
    model: Option<String>,
    corpus_hash: Option<String>,
    coverage_extra: (usize /* handlers */, usize /* suppressed */),
) -> Report {
    let s = static_analyzer.analyze(tree);
    let l = match llm_analyzer {
        Some(a) => a.analyze(tree),
        None => Default::default(),
    };

    let mut diagnostics = s.diagnostics.clone();
    diagnostics.extend(l.diagnostics.clone());

    let merged = merge(s.findings.clone(), l.findings.clone());

    Report {
        run: RunMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            model,
            corpus_hash,
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
        tracks: TrackFindings {
            static_track: s.findings,
            llm_track: l.findings,
            merged,
        },
        diagnostics,
        coverage: Coverage {
            files_total: tree.files.len(),
            files_parsed: s.files_analyzed,
            handlers: coverage_extra.0,
            loc: tree.total_loc(),
            suppressed: coverage_extra.1,
            // A track with no unit concept reports `None`, which renders as
            // zero rather than panicking.
            units_total: l.units.map(|u| u.total).unwrap_or(0),
            units_examined: l.units.map(|u| u.examined).unwrap_or(0),
        },
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use dike_core::analyzer::{AnalysisResult, SourceFile};
    use dike_core::finding::{Citation, Finding, Location, Severity, Track, VulnClass};
    use std::path::PathBuf;

    fn finding(track: Track, handler: &str) -> Finding {
        Finding {
            id: String::new(),
            class: VulnClass::new("missing-signer"),
            severity: Severity::High,
            confidence: 0.8,
            track,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line: 1,
                handler: handler.to_string(),
            },
            evidence: format!("{track:?} evidence"),
            citations: if track == Track::Llm {
                vec![Citation {
                    doc_id: "doc1".into(),
                    source_url: "https://example.com".into(),
                    title: "doc".into(),
                }]
            } else {
                vec![]
            },
        }
    }

    struct StaticStub;
    impl Analyzer for StaticStub {
        fn name(&self) -> &'static str {
            "static-stub"
        }
        fn analyze(&self, tree: &SourceTree) -> AnalysisResult {
            AnalysisResult {
                units: None,
                findings: vec![finding(Track::Static, "withdraw")],
                diagnostics: vec![],
                files_analyzed: tree.files.len(),
            }
        }
    }

    struct LlmStub;
    impl Analyzer for LlmStub {
        fn name(&self) -> &'static str {
            "llm-stub"
        }
        fn analyze(&self, tree: &SourceTree) -> AnalysisResult {
            AnalysisResult {
                units: None,
                findings: vec![finding(Track::Llm, "withdraw")],
                diagnostics: vec![],
                files_analyzed: tree.files.len(),
            }
        }
    }

    fn empty_tree() -> SourceTree {
        SourceTree { root: PathBuf::from("."), files: Vec::<SourceFile>::new() }
    }

    #[test]
    fn tracks_never_mix_except_in_merged() {
        let tree = empty_tree();
        let report = run(&tree, &StaticStub, Some(&LlmStub), None, None, (0, 0));

        assert_eq!(report.tracks.static_track.len(), 1);
        assert!(report
            .tracks
            .static_track
            .iter()
            .all(|f| f.track == Track::Static));

        assert_eq!(report.tracks.llm_track.len(), 1);
        assert!(report.tracks.llm_track.iter().all(|f| f.track == Track::Llm));

        // Same handler + class on both tracks corroborate into a single merged
        // finding: this is the only place the two tracks' evidence combines.
        assert_eq!(report.tracks.merged.len(), 1);
        assert_eq!(report.tracks.merged[0].track, Track::Corroborated);
    }
}
