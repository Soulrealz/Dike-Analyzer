//! Scoring the real holdout: published defects in programs this tool has never
//! been tuned against.
//!
//! The mutation harness ([`super::differential`]) answers "did this change help
//! against defects we injected ourselves?" This answers the different and
//! harder question of whether the tool finds defects somebody else found first,
//! in code written without it in mind.
//!
//! Two things separate it from the differential harness:
//!
//! 1. **Recall only.** The case list is what was *published*, never everything
//!    that is wrong with the program. A finding outside the list may be a false
//!    positive or may be an unpublished defect, and nothing here can tell the
//!    two apart, so no precision number is computed. Reporting one would be
//!    inventing a denominator.
//! 2. **A case is never scored twice.** Spec §8: the set is touched once, at
//!    the end. Everything here is therefore built to make a *partial* run
//!    visible rather than to paper over it — a case whose source could not be
//!    obtained is [`HoldoutOutcome::Unavailable`], which is excluded from the
//!    denominator instead of being counted as a miss.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};

/// Bumped when the shape of a recorded run changes, so an old entry is never
/// silently compared against a new one.
pub const HOLDOUT_SCHEMA_VERSION: u32 = 1;

/// One published defect, reduced to what the scorer compares against.
///
/// Deliberately not the manifest type: the manifest also carries the
/// repository, the commit and the disclosure URL, which locate the code and
/// support the claim but take no part in deciding a hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldoutTarget {
    pub id: String,
    /// The unit findings are compared at (D5).
    pub handler: String,
    /// Compared against `VulnClass::as_str` exactly. A case labelled with a
    /// class the tool does not speak can only ever miss, which is the honest
    /// result: the tool would not have reported it to an auditor either.
    pub class: String,
}

/// What happened to one case.
///
/// `Absorbed` is a hit and is recorded separately rather than folded into
/// `Direct`, because the two are different claims about the tool. `Direct`
/// says an auditor reading the row would have been pointed at this handler.
/// `Absorbed` says they would have been pointed at a different handler, with
/// this one named in the row's evidence as reachable from the same defect. Both
/// are finds; only one puts the handler at the top of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HoldoutOutcome {
    Direct,
    Absorbed {
        /// The handler the surviving row was reported under.
        reported_on: String,
    },
    Missed,
    /// The program was never analyzed, so this case says nothing about recall.
    Unavailable {
        reason: String,
    },
}

impl HoldoutOutcome {
    pub fn is_hit(&self) -> bool {
        matches!(self, HoldoutOutcome::Direct | HoldoutOutcome::Absorbed { .. })
    }
    /// Whether this case contributes to the recall denominator.
    pub fn was_scored(&self) -> bool {
        !matches!(self, HoldoutOutcome::Unavailable { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldoutCaseResult {
    pub id: String,
    pub class: String,
    pub handler: String,
    #[serde(flatten)]
    pub outcome: HoldoutOutcome,
}

/// Per-class recall over the scored cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldoutClassMetrics {
    pub class: String,
    pub cases: usize,
    pub hits: usize,
    pub recall: f32,
}

/// One scored pass over the whole set. Serialized into `runs.json`, which is
/// the record that the single permitted run has been spent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldoutSummary {
    pub schema_version: u32,
    pub cases_total: usize,
    /// Cases that contributed to recall. Less than `cases_total` means a
    /// partial run, and `recall` describes only this subset.
    pub cases_scored: usize,
    pub unavailable: usize,
    pub hits: usize,
    pub direct: usize,
    pub absorbed: usize,
    /// `hits / cases_scored`. `None` when nothing was scored: 0/0 is not 0.0,
    /// and rendering it as 0.000 would read as total failure.
    pub recall: Option<f32>,
    pub per_class: Vec<HoldoutClassMetrics>,
    pub results: Vec<HoldoutCaseResult>,
}

impl HoldoutSummary {
    /// A run that scored every case. A partial run is still worth recording,
    /// but it must never be quoted as the holdout number.
    pub fn is_complete(&self) -> bool {
        self.unavailable == 0 && self.cases_total > 0
    }
}

/// Decide one case against the findings reported for its program.
///
/// A hit is `class` equality plus a handler match, where "handler match" is the
/// case's handler being either the handler the row was reported under or one of
/// the handlers that row absorbed. That second arm is what reconciles the
/// subject collapse with per-handler comparison: the collapse folds one defect
/// seen from many handlers into a single row, so without it a defect the tool
/// genuinely found would score as a miss whenever a different handler happened
/// to sort first.
///
/// The case's file path takes no part in this. In a program whose handlers all
/// delegate to another module, `Location::file` is the handler's file rather
/// than the declaration's, so requiring the paths to agree would fail cases the
/// tool actually found.
///
/// Deterministic (Rule 5): `Direct` wins over `Absorbed` regardless of the
/// order findings arrive in, and the reported handler is the lowest matching
/// one rather than the first seen.
pub fn score_case(target: &HoldoutTarget, findings: &[Finding]) -> HoldoutOutcome {
    let same_class = || findings.iter().filter(|f| f.class.as_str() == target.class);

    if same_class().any(|f| f.location.handler == target.handler) {
        return HoldoutOutcome::Direct;
    }
    let mut absorbing: Vec<&str> = same_class()
        .filter(|f| f.absorbed_handlers.iter().any(|h| h == &target.handler))
        .map(|f| f.location.handler.as_str())
        .collect();
    absorbing.sort_unstable();
    match absorbing.first() {
        Some(handler) => HoldoutOutcome::Absorbed {
            reported_on: (*handler).to_string(),
        },
        None => HoldoutOutcome::Missed,
    }
}

/// Aggregate scored cases into the run that gets recorded.
///
/// Grouping is by class in sorted order, not in the order cases appear, so two
/// runs over the same set render identically (Rule 5).
pub fn summarize_holdout(results: Vec<HoldoutCaseResult>) -> HoldoutSummary {
    let cases_total = results.len();
    let scored: Vec<&HoldoutCaseResult> = results.iter().filter(|r| r.outcome.was_scored()).collect();
    let hits = scored.iter().filter(|r| r.outcome.is_hit()).count();
    let direct = scored
        .iter()
        .filter(|r| matches!(r.outcome, HoldoutOutcome::Direct))
        .count();

    let mut classes: Vec<String> = scored.iter().map(|r| r.class.clone()).collect();
    classes.sort();
    classes.dedup();
    let per_class = classes
        .into_iter()
        .map(|class| {
            let of_class: Vec<&&HoldoutCaseResult> =
                scored.iter().filter(|r| r.class == class).collect();
            let cases = of_class.len();
            let hits = of_class.iter().filter(|r| r.outcome.is_hit()).count();
            HoldoutClassMetrics {
                class,
                cases,
                hits,
                recall: hits as f32 / cases as f32,
            }
        })
        .collect();

    HoldoutSummary {
        schema_version: HOLDOUT_SCHEMA_VERSION,
        cases_total,
        cases_scored: scored.len(),
        unavailable: cases_total - scored.len(),
        hits,
        direct,
        absorbed: hits - direct,
        recall: if scored.is_empty() {
            None
        } else {
            Some(hits as f32 / scored.len() as f32)
        },
        per_class,
        results,
    }
}

/// The human-readable result. Every line it prints is derived from the summary,
/// so a number in the table and a number in `runs.json` cannot disagree.
pub fn render_holdout_table(summary: &HoldoutSummary) -> String {
    let mut out = String::new();
    out.push_str("| Case | Class | Outcome | Reported on |\n");
    out.push_str("|---|---|---|---|\n");
    for r in &summary.results {
        let (outcome, reported) = match &r.outcome {
            HoldoutOutcome::Direct => ("hit".to_string(), r.handler.clone()),
            HoldoutOutcome::Absorbed { reported_on } => {
                ("hit (absorbed)".to_string(), reported_on.clone())
            }
            HoldoutOutcome::Missed => ("miss".to_string(), "-".to_string()),
            HoldoutOutcome::Unavailable { reason } => {
                (format!("not scored: {reason}"), "-".to_string())
            }
        };
        out.push_str(&format!("| `{}` | `{}` | {} | {} |\n", r.id, r.class, outcome, reported));
    }

    out.push_str("\n| Class | Recall | Hits | Cases |\n");
    out.push_str("|---|---:|---:|---:|\n");
    for c in &summary.per_class {
        out.push_str(&format!(
            "| `{}` | {:.3} | {} | {} |\n",
            c.class, c.recall, c.hits, c.cases
        ));
    }

    match summary.recall {
        Some(r) => out.push_str(&format!(
            "\nRecall {:.3} ({}/{} scored; {} direct, {} absorbed).\n",
            r, summary.hits, summary.cases_scored, summary.direct, summary.absorbed
        )),
        None => out.push_str("\nNothing was scored, so there is no recall number.\n"),
    }
    if summary.unavailable > 0 {
        out.push_str(&format!(
            "PARTIAL RUN: {} of {} case(s) were never analyzed and are excluded from \
             the denominator above. This is not the holdout number.\n",
            summary.unavailable, summary.cases_total
        ));
    }
    // The missing denominator, stated where the numbers are read. The case list
    // is what was published, not everything wrong with these programs, so a
    // finding outside it cannot be called a false positive.
    out.push_str(
        "No precision number: the cases are published findings, not a complete list of \
         each program's defects.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Location, Severity, Track, VulnClass};
    use std::path::PathBuf;

    fn finding(class: &str, handler: &str, absorbed: &[&str]) -> Finding {
        Finding {
            id: format!("{class}-{handler}"),
            class: VulnClass::new(class),
            severity: Severity::High,
            confidence: 0.7,
            track: Track::Static,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                handler: handler.to_string(),
            },
            evidence: "evidence".into(),
            citations: vec![],
            subject: Some("config.admin".into()),
            absorbed_handlers: absorbed.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn target(handler: &str, class: &str) -> HoldoutTarget {
        HoldoutTarget {
            id: format!("case-{handler}"),
            handler: handler.into(),
            class: class.into(),
        }
    }

    fn result(id: &str, class: &str, outcome: HoldoutOutcome) -> HoldoutCaseResult {
        HoldoutCaseResult {
            id: id.into(),
            class: class.into(),
            handler: "h".into(),
            outcome,
        }
    }

    #[test]
    fn a_finding_on_the_cases_own_handler_is_a_direct_hit() {
        let fs = vec![finding("missing-signer", "withdraw", &[])];
        assert_eq!(
            score_case(&target("withdraw", "missing-signer"), &fs),
            HoldoutOutcome::Direct
        );
    }

    /// The whole reason `absorbed_handlers` exists. Verified against
    /// `woofi-create-wooracle-unbound-admin`: the defect is found, but the
    /// collapse reports it under `set_oracle_maximum_age` with the case's
    /// handler among 17 absorbed. Scoring that as a miss would be scoring the
    /// report layout rather than the detector.
    #[test]
    fn a_finding_that_absorbed_the_cases_handler_is_a_hit() {
        let fs = vec![finding(
            "missing-authority-binding",
            "set_oracle_maximum_age",
            &["create_pool", "create_wooracle"],
        )];
        assert_eq!(
            score_case(&target("create_wooracle", "missing-authority-binding"), &fs),
            HoldoutOutcome::Absorbed {
                reported_on: "set_oracle_maximum_age".into()
            }
        );
    }

    /// Right handler, wrong class is a miss: an auditor told "unchecked
    /// arithmetic here" has not been told about the missing signer.
    #[test]
    fn the_class_must_match_too() {
        let fs = vec![finding("unchecked-arithmetic", "withdraw", &["deposit"])];
        assert_eq!(
            score_case(&target("withdraw", "missing-signer"), &fs),
            HoldoutOutcome::Missed
        );
        assert_eq!(
            score_case(&target("deposit", "missing-signer"), &fs),
            HoldoutOutcome::Missed
        );
    }

    #[test]
    fn a_handler_nothing_reported_is_a_miss() {
        let fs = vec![finding("missing-signer", "deposit", &["initialize"])];
        assert_eq!(
            score_case(&target("withdraw", "missing-signer"), &fs),
            HoldoutOutcome::Missed
        );
        assert_eq!(score_case(&target("withdraw", "missing-signer"), &[]), HoldoutOutcome::Missed);
    }

    /// Order independence (Rule 5): the same finding set in either order must
    /// produce the same outcome, and a direct hit must win over an absorbed one.
    #[test]
    fn a_direct_hit_beats_an_absorbed_one_in_either_order() {
        let direct = finding("missing-signer", "withdraw", &[]);
        let absorbing = finding("missing-signer", "admin_set", &["withdraw"]);
        let t = target("withdraw", "missing-signer");
        assert_eq!(score_case(&t, &[direct.clone(), absorbing.clone()]), HoldoutOutcome::Direct);
        assert_eq!(score_case(&t, &[absorbing, direct]), HoldoutOutcome::Direct);
    }

    /// Two rows could each absorb the handler. Picking whichever came first
    /// would make the recorded run depend on iteration order.
    #[test]
    fn the_reported_handler_is_chosen_deterministically() {
        let a = finding("missing-signer", "zulu", &["withdraw"]);
        let b = finding("missing-signer", "alpha", &["withdraw"]);
        let t = target("withdraw", "missing-signer");
        let expected = HoldoutOutcome::Absorbed { reported_on: "alpha".into() };
        assert_eq!(score_case(&t, &[a.clone(), b.clone()]), expected);
        assert_eq!(score_case(&t, &[b, a]), expected);
    }

    /// An unavailable case is not evidence of anything, so counting it as a
    /// miss would understate recall with a number that describes the network.
    #[test]
    fn unavailable_cases_are_excluded_from_the_denominator() {
        let s = summarize_holdout(vec![
            result("a", "missing-signer", HoldoutOutcome::Direct),
            result("b", "missing-signer", HoldoutOutcome::Missed),
            result(
                "c",
                "missing-signer",
                HoldoutOutcome::Unavailable { reason: "no checkout".into() },
            ),
        ]);
        assert_eq!(s.cases_total, 3);
        assert_eq!(s.cases_scored, 2);
        assert_eq!(s.unavailable, 1);
        assert_eq!(s.recall, Some(0.5));
        assert!(!s.is_complete(), "a run with an unavailable case is not the holdout number");
        assert_eq!(s.per_class.len(), 1);
        assert_eq!(s.per_class[0].cases, 2, "the unavailable case is out of the class row too");
    }

    /// 0/0 is not 0.000. A run that scored nothing must not render as a run
    /// where the tool found nothing.
    #[test]
    fn a_run_that_scored_nothing_has_no_recall_number() {
        let s = summarize_holdout(vec![result(
            "a",
            "missing-signer",
            HoldoutOutcome::Unavailable { reason: "no checkout".into() },
        )]);
        assert_eq!(s.recall, None);
        let table = render_holdout_table(&s);
        assert!(table.contains("no recall number"), "{table}");
        assert!(!table.contains("0.000"), "{table}");
    }

    #[test]
    fn absorbed_hits_are_counted_as_hits_and_reported_separately() {
        let s = summarize_holdout(vec![
            result("a", "missing-signer", HoldoutOutcome::Direct),
            result(
                "b",
                "missing-owner-check",
                HoldoutOutcome::Absorbed { reported_on: "other".into() },
            ),
        ]);
        assert_eq!(s.hits, 2);
        assert_eq!(s.direct, 1);
        assert_eq!(s.absorbed, 1);
        assert_eq!(s.recall, Some(1.0));
        let table = render_holdout_table(&s);
        assert!(table.contains("hit (absorbed)"), "{table}");
        assert!(table.contains("1 direct, 1 absorbed"), "{table}");
    }

    /// The caveat that the numbers have no denominator for precision must be
    /// where the numbers are, not in a document downstream can drop.
    #[test]
    fn the_table_states_why_there_is_no_precision_number() {
        let s = summarize_holdout(vec![result("a", "missing-signer", HoldoutOutcome::Direct)]);
        assert!(render_holdout_table(&s).contains("No precision number"));
    }

    #[test]
    fn a_partial_run_says_so_where_the_number_is_printed() {
        let s = summarize_holdout(vec![
            result("a", "missing-signer", HoldoutOutcome::Direct),
            result(
                "b",
                "missing-signer",
                HoldoutOutcome::Unavailable { reason: "clone refused".into() },
            ),
        ]);
        let table = render_holdout_table(&s);
        assert!(table.contains("PARTIAL RUN"), "{table}");
        assert!(table.contains("clone refused"), "the reason must survive: {table}");
    }

    /// The per-class rows are sorted by class, so two runs over the same set
    /// render the same table whatever order the cases arrive in (Rule 5). The
    /// per-case rows deliberately keep the caller's order: they are the
    /// manifest read back, and sorting them would make a case harder to find.
    #[test]
    fn class_rows_are_ordered_independently_of_case_order() {
        let a = result("a", "zulu-class", HoldoutOutcome::Direct);
        let b = result("b", "alpha-class", HoldoutOutcome::Missed);
        let one = summarize_holdout(vec![a.clone(), b.clone()]);
        let two = summarize_holdout(vec![b, a]);
        assert_eq!(one.per_class, two.per_class);
        let names: Vec<&str> = one.per_class.iter().map(|c| c.class.as_str()).collect();
        assert_eq!(names, vec!["alpha-class", "zulu-class"], "sorted, not insertion order");

        // And the rendered class table follows the same order.
        let table = render_holdout_table(&one);
        let alpha = table.find("| `alpha-class` | 0.000").expect("{table}");
        let zulu = table.find("| `zulu-class` | 1.000").expect("{table}");
        assert!(alpha < zulu, "{table}");
    }
}
