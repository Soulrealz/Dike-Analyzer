//! Per-class, per-track recall and precision, plus the noise floor.
//!
//! **Recall is the primary metric** (spec §1, §8): a false positive costs an
//! auditor a minute, a false negative costs them the bug. It leads every table
//! and sits in the first numeric column.
//!
//! Every number here is derived from `CaseOutcome`s, so it inherits the
//! differential property that makes it worth reading: a finding the analyzer
//! already made on the clean program is noise, never a detection.

use super::differential::CaseOutcome;
use crate::finding::Track;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The schema `EvalSummary` serializes as. Bump it when the shape changes, so a
/// later reader can tell an old entry from a corrupted one instead of silently
/// averaging incompatible series together.
pub const SCHEMA_VERSION: u32 = 1;

/// Which view of the tool a row reports on.
///
/// Deliberately not `Track`. The three views the spec asks for are static, LLM
/// and **merged**, and `merged` is the *union*: what the tool as a whole shows
/// an auditor, so its recall is at least each single track's. `Track` has no
/// such variant — its third is `Corroborated`, the *intersection*, whose recall
/// is at most each track's. Reusing it would put the word "corroborated" in
/// `history.json` against a number meaning the opposite, which is a mistake
/// nobody would catch by reading the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricTrack {
    Static,
    Llm,
    Merged,
}

impl MetricTrack {
    /// Fixed order for every table and every history entry (invariant 5).
    pub const ALL: [MetricTrack; 3] = [MetricTrack::Static, MetricTrack::Llm, MetricTrack::Merged];

    pub fn as_str(self) -> &'static str {
        match self {
            MetricTrack::Static => "static",
            MetricTrack::Llm => "llm",
            MetricTrack::Merged => "merged",
        }
    }

    /// Whether a finding reported by `track` counts towards this view.
    /// Everything counts towards `Merged`, which is what makes it the union.
    fn covers(self, track: Track) -> bool {
        match self {
            MetricTrack::Merged => true,
            MetricTrack::Static => track == Track::Static || track == Track::Corroborated,
            MetricTrack::Llm => track == Track::Llm || track == Track::Corroborated,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassMetrics {
    pub class: String,
    pub track: MetricTrack,
    pub true_positives: usize,
    /// Cases whose injected defect was of this class — the recall denominator.
    pub total_cases: usize,
    /// Findings this view introduced on those cases that match neither the
    /// label's class nor its handler.
    pub false_positives: usize,
    /// `true_positives / total_cases`. Always defined: a row exists only
    /// because at least one case produced it.
    pub recall: f32,
    /// `true_positives / (true_positives + false_positives)`, or `None` when
    /// this view reported nothing at all on these cases. "It reported nothing"
    /// and "everything it reported was wrong" are different claims, and a
    /// `0.0` here would state the second while meaning the first.
    pub precision: Option<f32>,
}

/// Findings the analyzer reports on the clean program, which the mutation
/// neither caused nor removed (D18).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoiseFloor {
    pub track: MetricTrack,
    /// **Distinct** findings, deduplicated across cases. Every case's
    /// `persistent` list is drawn from the same clean-program run, so summing
    /// them would multiply the noise floor by the case count and report a
    /// property of the harness as a property of the analyzer.
    pub findings: usize,
    pub loc: usize,
    pub per_kloc: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalSummary {
    pub schema_version: u32,
    /// Identity of this run. `summarize` leaves it empty: the run id and the
    /// clock belong to the caller, the same way `RunMetadata::timestamp` is
    /// filled by the CLI rather than by core.
    pub run_id: String,
    pub timestamp: String,
    pub tool_version: String,
    pub model: Option<String>,
    pub corpus_hash: Option<String>,
    pub per_class: Vec<ClassMetrics>,
    pub noise: Vec<NoiseFloor>,
    /// Mutants the validity gate refused (D14). Carried so a shrinking case
    /// count is visible in the series rather than looking like improving recall.
    pub cases_rejected: usize,
}

/// Rolls a set of case outcomes up into the numbers the harness reports.
///
/// `loc` is the whole analyzed program's line count — the noise floor's
/// denominator (D18).
///
/// The run's identity (`run_id`, `timestamp`, `model`, `corpus_hash`,
/// `cases_rejected`) is left for the caller to fill: core stays free of the
/// clock, and the model and corpus are the CLI's knowledge, not this module's.
pub fn summarize(outcomes: &[CaseOutcome], loc: usize) -> EvalSummary {
    let mut per_class = Vec::new();
    let mut classes: BTreeSet<&str> = BTreeSet::new();
    for outcome in outcomes {
        classes.insert(outcome.label.class.as_str());
    }

    for class in classes {
        let cases: Vec<&CaseOutcome> = outcomes
            .iter()
            .filter(|o| o.label.class == class)
            .collect();
        for track in MetricTrack::ALL {
            let true_positives = cases
                .iter()
                .filter(|o| o.detecting_tracks.iter().any(|t| track.covers(*t)))
                .count();
            let false_positives: usize = cases
                .iter()
                .map(|o| {
                    o.false_positives()
                        .iter()
                        .filter(|f| track.covers(f.track))
                        .count()
                })
                .sum();
            let reported = true_positives + false_positives;
            per_class.push(ClassMetrics {
                class: class.to_string(),
                track,
                true_positives,
                total_cases: cases.len(),
                false_positives,
                recall: true_positives as f32 / cases.len() as f32,
                precision: (reported > 0).then(|| true_positives as f32 / reported as f32),
            });
        }
    }

    let noise = MetricTrack::ALL
        .iter()
        .map(|track| {
            // Deduplicated on the same key the differential runner compares on,
            // so "the clean program yields this finding" is counted once no
            // matter how many mutants were derived from it.
            let distinct: BTreeSet<(&str, &str)> = outcomes
                .iter()
                .flat_map(|o| o.persistent.iter())
                .filter(|f| track.covers(f.track))
                .map(|f| (f.location.handler.as_str(), f.class.as_str()))
                .collect();
            NoiseFloor {
                track: *track,
                findings: distinct.len(),
                loc,
                per_kloc: if loc == 0 {
                    0.0
                } else {
                    distinct.len() as f32 * 1000.0 / loc as f32
                },
            }
        })
        .collect();

    EvalSummary {
        schema_version: SCHEMA_VERSION,
        run_id: String::new(),
        timestamp: String::new(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        model: None,
        corpus_hash: None,
        per_class,
        noise,
        cases_rejected: 0,
    }
}

fn ratio(value: Option<f32>) -> String {
    // The project's existing rule: a missing number prints `-`, never `0.0000`
    // — "it scored zero" and "there was nothing to score" are different claims.
    match value {
        Some(v) => format!("{v:.3}"),
        None => "-".to_string(),
    }
}

/// Markdown, recall first, one row per class per track.
pub fn render_table(summary: &EvalSummary) -> String {
    let mut out = String::new();
    out.push_str("## Eval — recall is the primary metric\n\n");
    out.push_str("| Class | Track | Recall | Detected | Cases | Precision | False positives |\n");
    out.push_str("|---|---|---:|---:|---:|---:|---:|\n");

    // The rows arrive grouped by class and in `MetricTrack::ALL` order; keep
    // that rather than re-sorting, so the table matches the summary it renders.
    for m in &summary.per_class {
        out.push_str(&format!(
            "| `{}` | {} | {:.3} | {} | {} | {} | {} |\n",
            m.class,
            m.track.as_str(),
            m.recall,
            m.true_positives,
            m.total_cases,
            ratio(m.precision),
            m.false_positives,
        ));
    }
    if summary.per_class.is_empty() {
        out.push_str("| _no cases_ | | | | | | |\n");
    }

    out.push_str("\n### Noise floor\n\n");
    out.push_str(
        "Findings the analyzer reports on the clean program. The mutation caused none of \
         them, so they are counted against neither recall nor precision (D18).\n\n",
    );
    out.push_str("| Track | Findings | LOC | Per 1000 LOC |\n|---|---:|---:|---:|\n");
    for n in &summary.noise {
        out.push_str(&format!(
            "| {} | {} | {} | {:.3} |\n",
            n.track.as_str(),
            n.findings,
            n.loc,
            n.per_kloc
        ));
    }

    if summary.cases_rejected > 0 {
        out.push_str(&format!(
            "\n{} mutant{} refused by the validity gate and {} not in these numbers \
             (D14).\n",
            summary.cases_rejected,
            if summary.cases_rejected == 1 { " was" } else { "s were" },
            if summary.cases_rejected == 1 { "is" } else { "are" },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::MutationLabel;
    use crate::finding::{Finding, Location, Severity, VulnClass};
    use std::path::PathBuf;

    fn label(class: &str, handler: &str) -> MutationLabel {
        MutationLabel {
            id: "0123456789abcdef".into(),
            class: class.into(),
            severity: Severity::High,
            file: PathBuf::from("src/lib.rs"),
            line: 1,
            handler: handler.into(),
            operator: "an_operator".into(),
        }
    }

    fn finding(class: &str, handler: &str, track: Track) -> Finding {
        Finding {
            id: String::new(),
            class: VulnClass::new(class),
            severity: Severity::High,
            confidence: 0.8,
            track,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line: 1,
                handler: handler.into(),
            },
            evidence: "evidence".into(),
            citations: vec![],
        }
    }

    fn outcome(class: &str, detected: bool, tracks: Vec<Track>) -> CaseOutcome {
        let label = label(class, "withdraw");
        CaseOutcome {
            case: "a-case".into(),
            detected,
            introduced: tracks
                .iter()
                .map(|t| finding(class, "withdraw", *t))
                .collect(),
            detecting_tracks: tracks,
            persistent: vec![],
            label,
        }
    }

    fn outcome_with_persistent(class: &str, n: usize) -> CaseOutcome {
        let mut o = outcome(class, false, vec![]);
        // Distinct sites: the noise floor counts findings, and two reports of
        // the same finding on the same handler are one finding.
        o.persistent = (0..n)
            .map(|i| finding("pre-existing", &format!("handler{i}"), Track::Static))
            .collect();
        o
    }

    fn with_false_positive(mut o: CaseOutcome, track: Track) -> CaseOutcome {
        o.introduced
            .push(finding("some-other-class", "elsewhere", track));
        o
    }

    fn sample_summary(run_id: &str) -> EvalSummary {
        let mut s = summarize(
            &[
                outcome("missing-signer", true, vec![Track::Static]),
                outcome("removed-guard", true, vec![Track::Llm]),
            ],
            1000,
        );
        s.run_id = run_id.into();
        s.timestamp = "2026-09-03T00:00:00Z".into();
        s
    }

    #[test]
    fn recall_is_computed_per_class_and_per_track() {
        let outcomes = vec![
            outcome("missing-signer", true, vec![Track::Static]),
            outcome("missing-signer", true, vec![Track::Static, Track::Llm]),
            outcome("missing-signer", false, vec![]),
            outcome("removed-guard", true, vec![Track::Llm]),
        ];
        let s = summarize(&outcomes, 1000);

        let row = |class: &str, track| {
            s.per_class
                .iter()
                .find(|m| m.class == class && m.track == track)
                .unwrap()
                .clone()
        };

        let static_signer = row("missing-signer", MetricTrack::Static);
        assert_eq!(static_signer.true_positives, 2);
        assert_eq!(static_signer.total_cases, 3);
        assert!((static_signer.recall - 2.0 / 3.0).abs() < 1e-6);

        let static_guard = row("removed-guard", MetricTrack::Static);
        assert_eq!(static_guard.recall, 0.0, "Track 1 has no removed-guard detector by design");
        assert_eq!(row("removed-guard", MetricTrack::Llm).recall, 1.0);
    }

    /// The merged view is the union of the tracks, not their agreement: it is
    /// what the tool as a whole shows an auditor, so it can never do worse than
    /// either track alone.
    #[test]
    fn the_merged_view_is_the_union_of_the_tracks() {
        let outcomes = vec![
            outcome("missing-signer", true, vec![Track::Static]),
            outcome("missing-signer", true, vec![Track::Llm]),
        ];
        let s = summarize(&outcomes, 1000);
        let row = |track| {
            s.per_class
                .iter()
                .find(|m| m.track == track)
                .unwrap()
                .clone()
        };
        assert_eq!(row(MetricTrack::Static).true_positives, 1);
        assert_eq!(row(MetricTrack::Llm).true_positives, 1);
        assert_eq!(
            row(MetricTrack::Merged).true_positives,
            2,
            "merged must be the union; an intersection would report 0 here"
        );
        assert_eq!(row(MetricTrack::Merged).recall, 1.0);
    }

    #[test]
    fn noise_floor_is_per_1000_loc_of_the_whole_program() {
        let outcomes = vec![outcome_with_persistent("missing-signer", 5)];
        let s = summarize(&outcomes, 2000);
        let n = s
            .noise
            .iter()
            .find(|n| n.track == MetricTrack::Static)
            .unwrap();
        assert_eq!(n.findings, 5);
        assert!((n.per_kloc - 2.5).abs() < 1e-6);
    }

    /// Every case's `persistent` list is drawn from the same clean-program run.
    /// Summing them reports the harness's case count as if it were the
    /// analyzer's noise.
    #[test]
    fn the_noise_floor_does_not_multiply_by_the_case_count() {
        let one = summarize(&[outcome_with_persistent("missing-signer", 5)], 1000);
        let many = summarize(
            &[
                outcome_with_persistent("missing-signer", 5),
                outcome_with_persistent("missing-signer", 5),
                outcome_with_persistent("removed-guard", 5),
            ],
            1000,
        );
        let floor = |s: &EvalSummary| {
            s.noise
                .iter()
                .find(|n| n.track == MetricTrack::Static)
                .unwrap()
                .findings
        };
        assert_eq!(floor(&one), 5);
        assert_eq!(floor(&many), 5, "the noise floor scaled with the case count");
    }

    /// Noise is not a false positive against the mutation, and a detection is
    /// not noise. Confusing the two is how a clean analyzer looks noisy and a
    /// noisy one looks precise.
    #[test]
    fn persistent_findings_are_not_counted_as_false_positives() {
        let outcomes = vec![outcome_with_persistent("missing-signer", 3)];
        let s = summarize(&outcomes, 1000);
        let row = s
            .per_class
            .iter()
            .find(|m| m.track == MetricTrack::Static)
            .unwrap();
        assert_eq!(row.false_positives, 0);
        assert_eq!(row.true_positives, 0);
    }

    #[test]
    fn precision_counts_only_the_introduced_findings_that_miss_the_label() {
        let outcomes = vec![
            with_false_positive(
                outcome("missing-signer", true, vec![Track::Static]),
                Track::Static,
            ),
            outcome("missing-signer", true, vec![Track::Static]),
        ];
        let s = summarize(&outcomes, 1000);
        let row = s
            .per_class
            .iter()
            .find(|m| m.track == MetricTrack::Static)
            .unwrap();
        assert_eq!(row.true_positives, 2);
        assert_eq!(row.false_positives, 1);
        assert!((row.precision.unwrap() - 2.0 / 3.0).abs() < 1e-6);
    }

    /// "It reported nothing" and "everything it reported was wrong" are
    /// different claims, and `0.0` states the second.
    #[test]
    fn precision_is_absent_rather_than_zero_when_a_track_reported_nothing() {
        let s = summarize(&[outcome("missing-signer", false, vec![])], 1000);
        let row = s
            .per_class
            .iter()
            .find(|m| m.track == MetricTrack::Llm)
            .unwrap();
        assert_eq!(row.true_positives, 0);
        assert_eq!(row.false_positives, 0);
        assert_eq!(row.precision, None);
        assert!(render_table(&s).contains(" - |"), "{}", render_table(&s));
    }

    #[test]
    fn the_table_leads_with_recall_and_separates_tracks() {
        let t = render_table(&sample_summary("r"));
        assert!(t.contains("Recall"));
        assert!(t.contains("static") && t.contains("llm") && t.contains("merged"));
        let header = t.lines().find(|l| l.contains("Recall")).unwrap();
        assert!(header.find("Recall").unwrap() < header.find("Precision").unwrap());
    }

    /// Byte-identical output for identical input (invariant 5).
    #[test]
    fn the_summary_row_order_does_not_follow_the_input_order() {
        let a = summarize(
            &[
                outcome("removed-guard", true, vec![Track::Llm]),
                outcome("missing-signer", true, vec![Track::Static]),
            ],
            1000,
        );
        let b = summarize(
            &[
                outcome("missing-signer", true, vec![Track::Static]),
                outcome("removed-guard", true, vec![Track::Llm]),
            ],
            1000,
        );
        assert_eq!(render_table(&a), render_table(&b));
        let order: Vec<(&str, MetricTrack)> =
            a.per_class.iter().map(|m| (m.class.as_str(), m.track)).collect();
        assert_eq!(
            order,
            vec![
                ("missing-signer", MetricTrack::Static),
                ("missing-signer", MetricTrack::Llm),
                ("missing-signer", MetricTrack::Merged),
                ("removed-guard", MetricTrack::Static),
                ("removed-guard", MetricTrack::Llm),
                ("removed-guard", MetricTrack::Merged),
            ]
        );
    }

    /// A shrinking case count must not read as improving recall.
    #[test]
    fn rejected_cases_are_reported_in_the_table() {
        let mut s = sample_summary("r");
        s.cases_rejected = 3;
        assert!(render_table(&s).contains("3 mutants were refused"), "{}", render_table(&s));
        s.cases_rejected = 1;
        assert!(render_table(&s).contains("1 mutant was refused"), "{}", render_table(&s));
    }

    #[test]
    fn summarize_leaves_the_run_identity_to_the_caller_but_fills_the_schema() {
        let s = summarize(&[outcome("missing-signer", true, vec![Track::Static])], 100);
        assert_eq!(s.schema_version, SCHEMA_VERSION);
        assert_eq!(s.tool_version, env!("CARGO_PKG_VERSION"));
        assert!(s.run_id.is_empty());
        assert!(s.timestamp.is_empty());
    }

    // ---- history -------------------------------------------------------

    use crate::eval::history::{append_history, read_history};

    #[test]
    fn history_appends_without_losing_prior_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        std::fs::write(&path, "[]").unwrap();
        append_history(&path, &sample_summary("run-1")).unwrap();
        append_history(&path, &sample_summary("run-2")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let runs: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0]["run_id"], "run-1");
        assert_eq!(runs[1]["run_id"], "run-2");
        assert_eq!(runs[0]["schema_version"], 1);
    }

    /// An interrupted append would otherwise leave a truncated array in place
    /// of the whole series, so the write goes through a rename — which must
    /// not leave its scratch file behind.
    #[test]
    fn appending_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        std::fs::write(&path, "[]").unwrap();
        append_history(&path, &sample_summary("run-1")).unwrap();
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left, vec!["history.json".to_string()], "{left:?}");
    }

    #[test]
    fn history_round_trips_through_the_typed_form() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        std::fs::write(&path, "[]").unwrap();
        let summary = sample_summary("run-1");
        append_history(&path, &summary).unwrap();
        assert_eq!(read_history(&path).unwrap(), vec![summary]);
    }

    /// Creating the file instead would erase the comparison the caller was
    /// about to make, and a typo'd path would silently start a fresh series.
    #[test]
    fn appending_to_a_missing_history_is_an_error_not_a_fresh_series() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let err = append_history(&path, &sample_summary("run-1")).unwrap_err();
        assert!(format!("{err}").contains("does not exist"), "{err}");
        assert!(!path.exists());
    }

    #[test]
    fn a_history_file_that_is_not_an_array_is_refused_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        std::fs::write(&path, "{\"not\": \"an array\"}").unwrap();
        assert!(append_history(&path, &sample_summary("run-1")).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"not\": \"an array\"}");
    }

    /// The repository's own series must stay readable: a schema change that
    /// broke it would be found here rather than on the next eval run.
    #[test]
    fn the_committed_history_file_parses() {
        let path = std::path::Path::new("../../benchmarks/history.json");
        read_history(path).unwrap();
    }
}
