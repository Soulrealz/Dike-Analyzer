//! Differential evaluation: what did the mutation cause?
//!
//! The mechanism that makes every other number in the harness trustworthy
//! (spec §8). It sidesteps the question "is the base program actually clean?",
//! which is unanswerable and would otherwise poison every precision figure: a
//! finding that the analyzer reported on the *original* too was not caused by
//! the injected defect, whatever it says, and neither a hit nor a miss can be
//! read from it.
//!
//! - **True positive** — present in the mutant run, absent in the original run,
//!   matching the label's handler and class.
//! - **Noise floor** — present in both runs. Reported separately, per 1000 LOC
//!   (D18), and never counted as a false positive against the mutation.
//! - **False positive** — introduced by the mutation but matching neither the
//!   label's class nor its handler.

use super::{case_name, MutationLabel};
use crate::finding::{Finding, Track};
use std::collections::BTreeSet;

/// What one mutant's pair of runs showed.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseOutcome {
    /// The case directory's name, so an outcome can be traced back to the tree
    /// it came from without carrying a path.
    pub case: String,
    pub label: MutationLabel,
    /// The injected defect was reported, by at least one track, and was not
    /// already being reported before the mutation.
    pub detected: bool,
    /// Which tracks reported it, deduplicated and in a fixed order. Empty
    /// exactly when `detected` is false.
    pub detecting_tracks: Vec<Track>,
    /// Every finding the mutation introduced, the true positive included.
    /// `false_positives` is the subset that matches neither half of the label.
    pub introduced: Vec<Finding>,
    /// Findings the analyzer reported on both runs — the noise floor. Not
    /// attributable to the mutation in either direction.
    pub persistent: Vec<Finding>,
}

impl CaseOutcome {
    /// Introduced findings that do not match the label: the mutation caused
    /// them, and they are not the defect it injected.
    pub fn false_positives(&self) -> Vec<&Finding> {
        self.introduced
            .iter()
            .filter(|f| !matches_label(f, &self.label))
            .collect()
    }
}

/// The identity of a finding for differential purposes: the handler it sits in
/// and the class it reports.
///
/// Deliberately *not* `Finding::merge_key`, which is `(handler_id, class)` and
/// so includes the file path. The original and the mutant are two copies of one
/// program in two different directories, so their paths never agree — keying on
/// them would make every mutant finding look introduced, every persistent
/// finding invisible, and every label unmatched. The label's own path is the
/// third variant of the same problem: it names the repository fixture, not
/// either copy.
///
/// Dropping the file is safe because a handler name identifies an instruction
/// uniquely within a program — the analyzer's own unit of comparison (D5) — and
/// two handlers of the same name in one program are not a thing the target
/// language permits.
fn diff_key(finding: &Finding) -> (&str, &str) {
    (finding.location.handler.as_str(), finding.class.as_str())
}

fn matches_label(finding: &Finding, label: &MutationLabel) -> bool {
    diff_key(finding) == (label.handler.as_str(), label.class.as_str())
}

/// Fixed order for `detecting_tracks`, so two runs that found the same thing
/// produce byte-identical output (invariant 5). `Track` is deliberately not
/// `Ord` — there is no natural ranking between the tracks — so the order is
/// stated here rather than derived.
fn track_order(track: Track) -> u8 {
    match track {
        Track::Static => 0,
        Track::Llm => 1,
        Track::Corroborated => 2,
    }
}

/// Compares one analyzer run over the clean program against one over the
/// mutant.
///
/// Both lists are the **unmerged** per-track findings, concatenated. Merging
/// first would collapse a static and an LLM finding on the same handler and
/// class into a single corroborated one and destroy the per-track attribution
/// the two-track design exists to produce — and the harness must be able to say
/// that Track 1 caught something Track 2 missed.
pub fn diff_runs(original: &[Finding], mutant: &[Finding], label: &MutationLabel) -> CaseOutcome {
    let before: BTreeSet<(&str, &str)> = original.iter().map(diff_key).collect();

    let mut introduced = Vec::new();
    let mut persistent = Vec::new();
    for finding in mutant {
        if before.contains(&diff_key(finding)) {
            persistent.push(finding.clone());
        } else {
            introduced.push(finding.clone());
        }
    }

    let mut tracks: Vec<Track> = introduced
        .iter()
        .filter(|f| matches_label(f, label))
        .map(|f| f.track)
        .collect();
    tracks.sort_by_key(|t| track_order(*t));
    tracks.dedup();

    CaseOutcome {
        case: case_name(label),
        label: label.clone(),
        detected: !tracks.is_empty(),
        detecting_tracks: tracks,
        introduced,
        persistent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Location, Severity, VulnClass};
    use std::path::PathBuf;

    fn label(class: &str, handler: &str) -> MutationLabel {
        MutationLabel {
            id: "0123456789abcdef".into(),
            class: class.into(),
            severity: Severity::Critical,
            file: PathBuf::from("fixtures/vault/src/lib.rs"),
            line: 12,
            handler: handler.into(),
            operator: "signer_to_account_info".into(),
        }
    }

    fn f(class: &str, handler: &str, track: Track) -> Finding {
        Finding {
            id: String::new(),
            class: VulnClass::new(class),
            severity: Severity::Critical,
            confidence: 0.9,
            track,
            location: Location {
                file: PathBuf::from("out/cases/c1/src/lib.rs"),
                line: 12,
                handler: handler.into(),
            },
            evidence: format!("{track:?} evidence"),
            citations: vec![],
        }
    }

    #[test]
    fn a_finding_that_appears_only_in_the_mutant_at_the_label_site_is_a_true_positive() {
        let label = label("missing-signer", "withdraw");
        let original = vec![];
        let mutant = vec![f("missing-signer", "withdraw", Track::Static)];
        let o = diff_runs(&original, &mutant, &label);
        assert!(o.detected);
        assert_eq!(o.detecting_tracks, vec![Track::Static]);
        assert!(o.false_positives().is_empty());
    }

    #[test]
    fn a_finding_present_in_both_runs_is_noise_not_a_detection() {
        let label = label("missing-signer", "withdraw");
        let pre_existing = vec![f("missing-signer", "withdraw", Track::Static)];
        let o = diff_runs(&pre_existing, &pre_existing, &label);
        assert!(!o.detected, "it was already there; the mutation did not cause it");
        assert_eq!(o.persistent.len(), 1);
        assert!(o.introduced.is_empty());
        assert!(o.detecting_tracks.is_empty());
    }

    #[test]
    fn matching_is_handler_granular_not_line_exact() {
        let label = MutationLabel { line: 42, ..label("missing-signer", "withdraw") };
        let mut found = f("missing-signer", "withdraw", Track::Static);
        found.location.line = 7;
        assert!(diff_runs(&[], &[found], &label).detected);
    }

    /// The original, the mutant and the label all name different files by
    /// construction — two copies of one program plus the repository fixture the
    /// operator read. A key that included the path would make every finding
    /// look introduced and every label unmatched.
    #[test]
    fn matching_ignores_the_file_because_the_two_runs_are_different_copies() {
        let label = label("missing-signer", "withdraw");
        let mut before = f("missing-signer", "deposit", Track::Static);
        before.location.file = PathBuf::from("out/original/src/lib.rs");
        let mut after = f("missing-signer", "deposit", Track::Static);
        after.location.file = PathBuf::from("out/cases/c1/src/lib.rs");
        let hit = f("missing-signer", "withdraw", Track::Static);

        let o = diff_runs(&[before], &[after, hit], &label);
        assert!(o.detected, "the label site was not matched across the copies");
        assert_eq!(o.persistent.len(), 1, "the pre-existing finding read as introduced");
        assert_eq!(o.introduced.len(), 1);
    }

    #[test]
    fn the_right_class_in_the_wrong_handler_is_not_a_detection() {
        let label = label("missing-signer", "withdraw");
        let found = f("missing-signer", "deposit", Track::Static);
        let o = diff_runs(&[], &[found], &label);
        assert!(!o.detected);
        assert_eq!(o.introduced.len(), 1);
        assert_eq!(o.false_positives().len(), 1);
    }

    #[test]
    fn the_wrong_class_in_the_right_handler_is_not_a_detection() {
        let label = label("missing-signer", "withdraw");
        let found = f("unchecked-arithmetic", "withdraw", Track::Static);
        let o = diff_runs(&[], &[found], &label);
        assert!(!o.detected);
        assert_eq!(o.false_positives().len(), 1);
    }

    #[test]
    fn both_tracks_detecting_is_recorded_per_track() {
        let label = label("missing-signer", "withdraw");
        let mutant = vec![
            f("missing-signer", "withdraw", Track::Static),
            f("missing-signer", "withdraw", Track::Llm),
        ];
        let o = diff_runs(&[], &mutant, &label);
        assert_eq!(o.detecting_tracks.len(), 2);
        assert!(o.false_positives().is_empty());
    }

    /// One track reporting the same defect twice is one track, not two — the
    /// per-track breakdown would otherwise read as corroboration that never
    /// happened.
    #[test]
    fn a_track_that_reports_twice_is_listed_once() {
        let label = label("missing-signer", "withdraw");
        let mut second = f("missing-signer", "withdraw", Track::Static);
        second.evidence = "a second detector said so too".into();
        let mutant = vec![f("missing-signer", "withdraw", Track::Static), second];
        let o = diff_runs(&[], &mutant, &label);
        assert_eq!(o.detecting_tracks, vec![Track::Static]);
    }

    /// Byte-identical output for identical input (invariant 5): the track list
    /// must not inherit the order the findings happened to arrive in.
    #[test]
    fn detecting_tracks_order_does_not_follow_the_input_order() {
        let label = label("missing-signer", "withdraw");
        let static_first = vec![
            f("missing-signer", "withdraw", Track::Static),
            f("missing-signer", "withdraw", Track::Llm),
        ];
        let llm_first = vec![
            f("missing-signer", "withdraw", Track::Llm),
            f("missing-signer", "withdraw", Track::Static),
        ];
        assert_eq!(
            diff_runs(&[], &static_first, &label).detecting_tracks,
            diff_runs(&[], &llm_first, &label).detecting_tracks
        );
        assert_eq!(
            diff_runs(&[], &static_first, &label).detecting_tracks,
            vec![Track::Static, Track::Llm]
        );
    }

    /// A pre-existing finding somewhere else must not mask the detection.
    #[test]
    fn noise_in_another_handler_does_not_suppress_a_detection() {
        let label = label("missing-signer", "withdraw");
        let noise = f("unchecked-arithmetic", "deposit", Track::Static);
        let before = vec![noise.clone()];
        let after = vec![noise, f("missing-signer", "withdraw", Track::Static)];
        let o = diff_runs(&before, &after, &label);
        assert!(o.detected);
        assert_eq!(o.persistent.len(), 1);
        assert_eq!(o.introduced.len(), 1);
    }

    /// The outcome has to name the directory it came from, or a per-case
    /// breakdown cannot be traced back to a tree an auditor can open.
    #[test]
    fn the_outcome_names_the_case_directory() {
        let label = label("missing-signer", "withdraw");
        let o = diff_runs(&[], &[], &label);
        assert_eq!(o.case, case_name(&label));
        assert_eq!(o.case, "signer_to_account_info-0123456789abcdef");
    }
}
