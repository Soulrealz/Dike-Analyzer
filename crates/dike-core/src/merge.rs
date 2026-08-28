use crate::finding::{Finding, Track, VulnClass};
use std::collections::BTreeMap;

/// D3: model-reported confidence, clamped, down-weighted on a lone citation.
pub fn track2_confidence(raw: f32, citation_count: usize) -> f32 {
    let clamped = raw.clamp(0.10, 0.90);
    if citation_count == 1 {
        clamped * 0.8
    } else {
        clamped
    }
}

/// D4: noisy-OR. Two independent tracks agreeing is genuinely stronger evidence
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
    }
}

/// Dedupe on (handler_id, class) — D5 — then rank. Corroborated findings surface
/// first because their confidence exceeds either contributing track's.
pub fn merge(static_findings: Vec<Finding>, llm_findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_key: BTreeMap<(String, VulnClass), Finding> = BTreeMap::new();

    for f in static_findings.into_iter().chain(llm_findings.into_iter()) {
        match by_key.remove(&f.merge_key()) {
            None => {
                by_key.insert(f.merge_key(), f);
            }
            Some(existing) => {
                let combined = if existing.track == f.track {
                    // Same track reported it twice: keep the stronger, concatenate evidence (RULING 5).
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
                    merged
                } else if existing.track == Track::Corroborated || f.track == Track::Corroborated {
                    // One is already corroborated: take max(confidence), do not re-apply noisy-OR (RULING 6).
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
