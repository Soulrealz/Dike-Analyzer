use crate::finding::{Finding, Track, VulnClass};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Model-reported confidence, clamped, down-weighted on a lone citation.
pub fn track2_confidence(raw: f32, citation_count: usize) -> f32 {
    let clamped = raw.clamp(0.10, 0.90);
    if citation_count == 1 {
        clamped * 0.8
    } else {
        clamped
    }
}

/// Sorted, deduplicated union. Sorted rather than insertion-ordered because a
/// `Finding` must be byte-identical across runs (Rule 5).
fn union_of_handlers(a: &[String], b: &[String]) -> Vec<String> {
    let mut out: Vec<String> = a.iter().chain(b).cloned().collect();
    out.sort();
    out.dedup();
    out
}

/// Noisy-OR. Two independent tracks agreeing is genuinely stronger evidence
/// than either alone, which is why this must exceed both inputs.
pub fn corroborate(a: &Finding, b: &Finding) -> Finding {
    let confidence = (1.0 - (1.0 - a.confidence) * (1.0 - b.confidence)).min(0.98);
    let mut citations = a.citations.clone();
    citations.extend(b.citations.iter().cloned());
    Finding {
        id: String::new(),
        class: a.class.clone(),
        severity: a.severity.max(b.severity),
        confidence,
        track: Track::Corroborated,
        // Static analyzer's location is precise; LLM's is approximate. Always prefer static.
        location: a.location.clone(),
        evidence: format!("{}\n\n---\n\n{}", a.evidence, b.evidence),
        citations,
        subject: a.subject.clone().or_else(|| b.subject.clone()),
        // Either side may have absorbed handlers before corroboration; the
        // defect is reachable from the union of them.
        absorbed_handlers: union_of_handlers(&a.absorbed_handlers, &b.absorbed_handlers),
    }
}

/// Collapse findings that are the same defect seen from several handlers.
///
/// Track 1 detectors run once per handler, so a config account whose stored
/// authority nothing binds is reported once per instruction that takes it.
/// Measured 2026-09-06 over 28k LOC of real programs: 49 findings came from
/// 19 distinct `(class, subject)` sites, one of them appearing 19 times. An
/// auditor has one thing to fix there, not nineteen.
///
/// Aggregation, never deletion (Rule 3): the surviving row names every other
/// handler the same defect appears in, so nothing an auditor could act on is
/// lost — only the repetition is.
///
/// Findings with no `subject` (Track 2) are never collapsed: without an
/// account-level anchor there is nothing to prove two rows are the same
/// defect rather than two defects in one file.
///
/// Deterministic (Rule 5): grouping is a `BTreeMap`, and the surviving row is
/// the lowest `(line, handler)` in the group rather than whichever happened
/// to be produced first.
pub fn collapse_by_subject(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups: BTreeMap<(String, VulnClass, PathBuf), Vec<Finding>> = BTreeMap::new();
    let mut ungrouped: Vec<Finding> = Vec::new();

    for f in findings {
        match &f.subject {
            Some(subject) => groups
                .entry((subject.clone(), f.class.clone(), f.location.file.clone()))
                .or_default()
                .push(f),
            None => ungrouped.push(f),
        }
    }

    let mut out = ungrouped;
    for (_, mut group) in groups {
        group.sort_by(|a, b| {
            a.location.line.cmp(&b.location.line).then(a.location.handler.cmp(&b.location.handler))
        });
        let mut survivor = group.remove(0);
        if !group.is_empty() {
            let others: Vec<String> = group.into_iter().map(|f| f.location.handler).collect();
            // The prose is rendered from the structured list, so the two can
            // never disagree: the scorer reads the field, the auditor reads
            // the sentence, and both come from the same source.
            survivor.absorbed_handlers = union_of_handlers(&survivor.absorbed_handlers, &others);
            survivor.absorbed_handlers.retain(|h| h != &survivor.location.handler);
            survivor.evidence = format!(
                "{}\n\nThe same defect is reachable from {} other handler(s): {}.",
                survivor.evidence,
                survivor.absorbed_handlers.len(),
                survivor.absorbed_handlers.join(", ")
            );
        }
        out.push(survivor);
    }
    out
}

/// Dedupe on (handler_id, class), never on the span, then rank. Corroborated findings surface
/// first because their confidence exceeds either contributing track's.
pub fn merge(static_findings: Vec<Finding>, llm_findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_key: BTreeMap<(String, VulnClass), Finding> = BTreeMap::new();

    for f in static_findings.into_iter().chain(llm_findings) {
        match by_key.remove(&f.merge_key()) {
            None => {
                by_key.insert(f.merge_key(), f);
            }
            Some(existing) => {
                let combined = if existing.track == f.track {
                    // Same track reported it twice: keep the stronger, concatenate evidence.
                    // Do not inflate confidence — use the stronger value only.
                    // Tie-break on evidence string for order-independence (byte-identical across runs).
                    let (survivor, discarded) = match f.rank_score().partial_cmp(&existing.rank_score()) {
                        Some(std::cmp::Ordering::Greater) => (f, existing),
                        Some(std::cmp::Ordering::Less) => (existing, f),
                        _ => if f.evidence <= existing.evidence { (f, existing) } else { (existing, f) },
                    };
                    let mut merged = survivor;
                    merged.id = String::new();
                    merged.evidence = format!("{}\n\n---\n\n{}", merged.evidence, discarded.evidence);
                    merged.absorbed_handlers =
                        union_of_handlers(&merged.absorbed_handlers, &discarded.absorbed_handlers);
                    merged
                } else if existing.track == Track::Corroborated || f.track == Track::Corroborated {
                    // One is already corroborated: take max(confidence), do not re-apply noisy-OR.
                    let confidence = existing.confidence.max(f.confidence);
                    let mut citations = existing.citations.clone();
                    citations.extend(f.citations.iter().cloned());
                    Finding {
                        id: String::new(),
                        class: existing.class.clone(),
                        severity: existing.severity.max(f.severity),
                        confidence,
                        track: Track::Corroborated,
                        location: existing.location.clone(),
                        evidence: format!("{}\n\n---\n\n{}", existing.evidence, f.evidence),
                        citations,
                        subject: existing.subject.clone().or_else(|| f.subject.clone()),
                        absorbed_handlers: union_of_handlers(
                            &existing.absorbed_handlers,
                            &f.absorbed_handlers,
                        ),
                    }
                } else {
                    corroborate(&existing, &f)
                };
                by_key.insert(combined.merge_key(), combined);
            }
        }
    }

    let mut out: Vec<Finding> = by_key.into_values().collect();
    rank(&mut out);
    out
}

/// Total order (f32 is not Ord). Ties break deterministically so report diffs are clean.
pub fn rank(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.rank_score()
            .partial_cmp(&a.rank_score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.severity.cmp(&a.severity))
            .then(a.location.handler_id().cmp(&b.location.handler_id()))
            .then(a.class.cmp(&b.class))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Location, Severity, Track, VulnClass};
    use std::path::PathBuf;

    fn subject_finding(subject: &str, class: &str, handler: &str, line: u32) -> Finding {
        Finding {
            id: format!("{handler}-{subject}"),
            class: VulnClass::new(class),
            severity: Severity::High,
            confidence: 0.7,
            track: Track::Static,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line,
                handler: handler.to_string(),
            },
            evidence: format!("{subject} is unbound"),
            citations: vec![],
            subject: Some(subject.to_string()),
            absorbed_handlers: Vec::new(),
        }
    }

    /// The measured case: one config account's unbound authority reported
    /// once per instruction that takes the config.
    #[test]
    fn one_defect_seen_from_many_handlers_collapses_to_one_row() {
        let fs = vec![
            subject_finding("config.admin", "missing-authority-binding", "claim", 40),
            subject_finding("config.admin", "missing-authority-binding", "place_bet", 12),
            subject_finding("config.admin", "missing-authority-binding", "refund", 88),
        ];
        let out = collapse_by_subject(fs);
        assert_eq!(out.len(), 1, "three handlers, one defect: {out:#?}");
        assert_eq!(out[0].location.handler, "place_bet", "lowest line survives, deterministically");
    }

    /// Aggregation, not deletion: an auditor must still learn every handler
    /// the defect is reachable from, or collapsing would be hiding findings.
    #[test]
    fn the_surviving_row_names_the_handlers_it_absorbed() {
        let fs = vec![
            subject_finding("config.admin", "missing-authority-binding", "claim", 40),
            subject_finding("config.admin", "missing-authority-binding", "refund", 88),
        ];
        let out = collapse_by_subject(fs);
        // `claim` is at the lower line, so it survives and `refund` is the
        // one absorbed — the row must name what it swallowed, not itself.
        assert_eq!(out[0].location.handler, "claim");
        assert!(
            out[0].evidence.contains("refund"),
            "absorbed handler must be named: {}",
            out[0].evidence
        );
        assert!(out[0].evidence.contains("1 other handler"), "{}", out[0].evidence);
    }

    /// The holdout compares per handler while this collapses per subject,
    /// so a case whose handler was absorbed must still be findable. Prose in
    /// `evidence` cannot carry that: the scorer would be parsing English, and
    /// rewording the sentence would turn every hit into a silent miss.
    #[test]
    fn absorbed_handlers_are_listed_structurally_not_only_in_prose() {
        let fs = vec![
            subject_finding("config.admin", "missing-authority-binding", "claim", 40),
            subject_finding("config.admin", "missing-authority-binding", "place_bet", 12),
            subject_finding("config.admin", "missing-authority-binding", "refund", 88),
        ];
        let out = collapse_by_subject(fs);
        assert_eq!(out.len(), 1);
        // `place_bet` is the lowest line, so it survives and does not list itself.
        assert_eq!(out[0].location.handler, "place_bet");
        assert_eq!(
            out[0].absorbed_handlers,
            vec!["claim".to_string(), "refund".to_string()],
            "sorted, and the survivor is not among them"
        );
    }

    /// A row that absorbed nothing must carry an empty list, or "this defect is
    /// reachable from these handlers" would be a claim about handlers that were
    /// never examined.
    #[test]
    fn a_row_that_absorbed_nothing_lists_nothing() {
        let fs = vec![subject_finding("config.admin", "missing-owner-check", "claim", 40)];
        let out = collapse_by_subject(fs);
        assert!(out[0].absorbed_handlers.is_empty(), "{:?}", out[0].absorbed_handlers);
    }

    /// Different subjects are different defects, and different classes on one
    /// subject are different defects too. Collapsing either would be a real
    /// loss of recall rather than a loss of repetition.
    #[test]
    fn different_subjects_and_classes_are_never_collapsed() {
        let fs = vec![
            subject_finding("config.admin", "missing-authority-binding", "claim", 40),
            subject_finding("config.treasury", "missing-authority-binding", "claim", 41),
            subject_finding("config.admin", "missing-owner-check", "claim", 40),
        ];
        assert_eq!(collapse_by_subject(fs).len(), 3);
    }

    /// Track 2 findings carry no subject. Two of them in one file must not be
    /// mistaken for one defect.
    #[test]
    fn findings_without_a_subject_are_left_alone() {
        let mut a = subject_finding("x", "missing-signer", "one", 1);
        let mut b = subject_finding("x", "missing-signer", "two", 2);
        a.subject = None;
        b.subject = None;
        assert_eq!(collapse_by_subject(vec![a, b]).len(), 2);
    }

    fn f(track: Track, class: &str, sev: Severity, conf: f32, handler: &str) -> Finding {
        Finding {
            id: String::new(),
            class: VulnClass::new(class),
            severity: sev,
            confidence: conf,
            track,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line: 1,
                handler: handler.to_string(),
            },
            evidence: format!("{track:?} evidence"),
            citations: vec![],
            subject: None,
            absorbed_handlers: Vec::new(),
        }
    }

    #[test]
    fn track2_confidence_is_clamped() {
        assert!((track2_confidence(2.0, 3) - 0.90).abs() < 1e-6);
        assert!((track2_confidence(0.0, 3) - 0.10).abs() < 1e-6);
    }

    #[test]
    fn track2_confidence_downweights_single_citation() {
        assert!((track2_confidence(0.5, 1) - 0.40).abs() < 1e-6);
        assert!((track2_confidence(0.5, 2) - 0.50).abs() < 1e-6);
    }

    #[test]
    fn corroboration_raises_confidence_above_either_track() {
        let a = f(Track::Static, "missing-signer", Severity::High, 0.7, "withdraw");
        let b = f(Track::Llm, "missing-signer", Severity::Critical, 0.5, "withdraw");
        let c = corroborate(&a, &b);
        assert_eq!(c.track, Track::Corroborated);
        assert_eq!(c.severity, Severity::Critical);
        assert!(c.confidence > a.confidence && c.confidence > b.confidence);
        assert!((c.confidence - 0.85).abs() < 1e-6);
        assert!(c.evidence.contains("Static") && c.evidence.contains("Llm"));
    }

    #[test]
    fn merge_dedupes_on_handler_and_class_and_ranks_corroborated_first() {
        let statics = vec![
            f(Track::Static, "missing-signer", Severity::High, 0.7, "withdraw"),
            f(Track::Static, "unchecked-arithmetic", Severity::Critical, 0.3, "deposit"),
        ];
        let llms = vec![
            f(Track::Llm, "missing-signer", Severity::High, 0.6, "withdraw"),
        ];
        let merged = merge(statics, llms);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].track, Track::Corroborated);
        assert_eq!(merged[0].class.as_str(), "missing-signer");
    }

    #[test]
    fn ranking_breaks_ties_by_handler_id() {
        let mut v = vec![
            f(Track::Static, "b-class", Severity::High, 0.5, "zeta"),
            f(Track::Static, "a-class", Severity::High, 0.5, "alpha"),
        ];
        rank(&mut v);
        assert_eq!(v[0].location.handler, "alpha");
    }

    #[test]
    fn same_track_duplicate_keeps_stronger_and_concatenates_evidence() {
        let statics = vec![
            f(Track::Static, "missing-signer", Severity::High, 0.7, "withdraw"),
            f(Track::Static, "missing-signer", Severity::High, 0.5, "withdraw"),
        ];
        let merged = merge(statics, vec![]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].track, Track::Static);
        // Stronger survives: rank_score(0.7, High) = 0.75 * 0.7 = 0.525
        //                     rank_score(0.5, High) = 0.75 * 0.5 = 0.375
        assert!((merged[0].confidence - 0.7).abs() < 1e-6);
        // Evidence concatenated but confidence not inflated beyond either input
        assert!(merged[0].evidence.contains("Static"));
        assert!(merged[0].evidence.contains("---"));
    }

    #[test]
    fn location_uses_static_line_when_merging_tracks() {
        let mut static_finding = f(Track::Static, "missing-signer", Severity::High, 0.7, "withdraw");
        static_finding.location.line = 42;

        let mut llm_finding = f(Track::Llm, "missing-signer", Severity::High, 0.6, "withdraw");
        llm_finding.location.line = 100;

        let merged = merge(vec![static_finding], vec![llm_finding]);
        assert_eq!(merged.len(), 1);
        // Static line (42) is preserved, not LLM's (100)
        assert_eq!(merged[0].location.line, 42);
    }

    #[test]
    fn same_track_duplicate_evidence_concatenates_both_accounts() {
        let mut static1 = f(Track::Static, "missing-signer", Severity::High, 0.7, "withdraw");
        static1.evidence = "authority account missing signer".to_string();

        let mut static2 = f(Track::Static, "missing-signer", Severity::High, 0.5, "withdraw");
        static2.evidence = "admin account missing signer".to_string();

        let merged = merge(vec![static1, static2], vec![]);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].evidence.contains("authority"));
        assert!(merged[0].evidence.contains("admin"));
    }

    #[test]
    fn three_findings_on_one_key_do_not_inflate_past_two_track_noisy_or() {
        let static1 = f(Track::Static, "missing-signer", Severity::High, 0.7, "withdraw");
        let static2 = f(Track::Static, "missing-signer", Severity::High, 0.6, "withdraw");
        let llm = f(Track::Llm, "missing-signer", Severity::High, 0.5, "withdraw");

        let merged = merge(vec![static1, static2], vec![llm]);
        assert_eq!(merged.len(), 1);
        // First: max(0.7, 0.6) = 0.7 (same track)
        // Then: noisy-OR(0.7, 0.5) = 1.0 - 0.3*0.5 = 0.85
        // Should not exceed 0.85, not be re-boosted by a third application
        assert!((merged[0].confidence - 0.85).abs() < 1e-6);
        assert_eq!(merged[0].track, Track::Corroborated);
    }

    #[test]
    fn merge_empty_input_vectors() {
        let merged = merge(vec![], vec![]);
        assert_eq!(merged.len(), 0);
    }

    #[test]
    fn merge_one_empty_side() {
        let statics = vec![f(Track::Static, "issue", Severity::High, 0.7, "fn1")];
        let merged = merge(statics, vec![]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].track, Track::Static);
    }

    #[test]
    fn merge_other_empty_side() {
        let llms = vec![f(Track::Llm, "issue", Severity::High, 0.7, "fn1")];
        let merged = merge(vec![], llms);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].track, Track::Llm);
    }

    #[test]
    fn ranking_breaks_ties_by_severity() {
        let mut v = vec![
            f(Track::Static, "a-class", Severity::Medium, 0.8, "handler"),
            f(Track::Static, "b-class", Severity::High, 0.8, "handler"),
        ];
        rank(&mut v);
        // Both have rank_score = 0.8 * severity_weight
        // Medium: 0.8 * 0.5 = 0.4
        // High: 0.8 * 0.75 = 0.6
        // So High should be first
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[1].severity, Severity::Medium);
    }

    #[test]
    fn same_track_duplicate_order_independence() {
        // Two same-track findings with equal rank_score but different evidence
        let mut f1 = f(Track::Static, "issue", Severity::High, 0.5, "handler");
        f1.evidence = "account-1".to_string();

        let mut f2 = f(Track::Static, "issue", Severity::High, 0.5, "handler");
        f2.evidence = "account-2".to_string();

        // Merge in one order
        let merged_order1 = merge(vec![f1.clone(), f2.clone()], vec![]);

        // Merge in reversed order
        let merged_order2 = merge(vec![f2.clone(), f1.clone()], vec![]);

        // Both should produce identical results
        assert_eq!(merged_order1.len(), 1);
        assert_eq!(merged_order2.len(), 1);
        // Evidence concatenation order must be deterministic, not input-order dependent
        assert_eq!(merged_order1[0].evidence, merged_order2[0].evidence);
        // id must be cleared consistently (not carry survivor's original id)
        assert_eq!(merged_order1[0].id, merged_order2[0].id);
        assert_eq!(merged_order1[0].id, "");
    }
}
