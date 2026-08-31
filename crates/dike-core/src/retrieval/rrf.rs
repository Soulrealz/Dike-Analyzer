//! Reciprocal rank fusion, the hit type it produces, and the grounding gate.
//!
//! Dense cosine and BM25 scores live on incomparable scales, so they are fused
//! by *rank*, not by value: `score(d) = Σ_lists 1 / (k + rank(d))` with
//! 1-based ranks and `k = 60`. Rank fusion needs no calibration and no tuning
//! constant per corpus.
//!
//! **The grounding gate (D11) never thresholds the fused score.** An RRF score
//! is rank-derived, so its magnitude carries no relevance information: the
//! first document in a list of garbage scores `1/61`, exactly what a perfect
//! match scores. Grounding therefore asks the component legs — a dense cosine
//! at or above [`DENSE_GROUNDING_THRESHOLD`], or any non-zero BM25 score.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::retrieval::document::Document;

/// The `k` in the RRF denominator (spec §7).
pub const RRF_K: f32 = 60.0;

/// A dense cosine at or above this counts as evidence for grounding (D11).
pub const DENSE_GROUNDING_THRESHOLD: f32 = 0.35;

/// One retrieved document with its fused score and whichever component scores
/// it earned. `None` means the leg did not return this document — or, for
/// `dense_score`, that the dense leg did not run at all.
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalHit {
    pub document: Document,
    pub rrf_score: f32,
    pub dense_score: Option<f32>,
    pub bm25_score: Option<f32>,
}

/// Fuse ranked ID lists by reciprocal rank, best first.
///
/// Accumulation is through a `BTreeMap` and the sort carries an explicit
/// ascending-ID tie-break, so the output depends only on the contents of the
/// lists and never on their iteration or input order (Rule 5).
pub fn rrf(ranked_lists: &[Vec<String>], k: f32) -> Vec<(String, f32)> {
    let mut scores: BTreeMap<String, f32> = BTreeMap::new();
    for list in ranked_lists {
        for (i, id) in list.iter().enumerate() {
            let rank = (i + 1) as f32; // 1-based: the first document scores 1/(k+1).
            *scores.entry(id.clone()).or_insert(0.0) += 1.0 / (k + rank);
        }
    }
    let mut fused: Vec<(String, f32)> = scores.into_iter().collect();
    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    fused
}

/// Is there real retrieval evidence behind these hits?
///
/// True iff any hit carries a dense cosine at or above
/// [`DENSE_GROUNDING_THRESHOLD`], or any hit carries a BM25 score above zero.
/// Deliberately *not* a function of `rrf_score` — see the module docs.
pub fn is_grounded(hits: &[RetrievalHit]) -> bool {
    hits.iter().any(|h| {
        h.dense_score
            .is_some_and(|s| s >= DENSE_GROUNDING_THRESHOLD)
            || h.bm25_score.is_some_and(|s| s > 0.0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(id: &str, rrf: f32, dense: Option<f32>, bm25: Option<f32>) -> RetrievalHit {
        RetrievalHit {
            document: Document {
                id: id.into(),
                source_url: "u".into(),
                title: "t".into(),
                text: "x".into(),
                class_tags: vec![],
            },
            rrf_score: rrf,
            dense_score: dense,
            bm25_score: bm25,
        }
    }

    #[test]
    fn rrf_ranks_a_document_appearing_in_both_lists_above_a_list_leader() {
        // The plan's fixture for this test put `c` at rank 3 of one list and
        // rank 1 of the other, which makes `c` a both-lists document too:
        // 1/63 + 1/61 = 0.032266 edges out `b`'s 2/62 = 0.032258, so the
        // assertion contradicted correct RRF arithmetic. The fixture below
        // keeps the property the test is named for -- only `b` appears in
        // both lists -- and `b` must therefore outrank both list leaders.
        let dense = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let sparse = vec!["z".to_string(), "b".to_string(), "y".to_string()];
        let fused = rrf(&[dense, sparse], RRF_K);
        assert_eq!(fused[0].0, "b", "2nd in both beats 1st in one");
        assert!(fused[0].1 > fused[1].1);
    }

    #[test]
    fn rrf_uses_one_based_ranks() {
        let fused = rrf(&[vec!["a".to_string()]], RRF_K);
        assert!(
            (fused[0].1 - 1.0 / 61.0).abs() < 1e-6,
            "rank 1 scores 1/(60+1), got {}",
            fused[0].1
        );
    }

    #[test]
    fn rrf_output_is_sorted_descending() {
        let fused = rrf(&[vec!["a".into(), "b".into()], vec!["b".into()]], RRF_K);
        assert!(fused[0].1 >= fused[1].1);
    }

    #[test]
    fn rrf_ties_break_deterministically_by_id() {
        let a = rrf(&[vec!["y".to_string(), "x".to_string()]], RRF_K);
        let b = rrf(&[vec!["y".to_string(), "x".to_string()]], RRF_K);
        assert_eq!(a, b);
        let swapped = rrf(&[vec!["x".to_string()], vec!["y".to_string()]], RRF_K);
        assert_eq!(
            swapped[0].0, "x",
            "equal scores order by id, not by input order"
        );
        let other_way = rrf(&[vec!["y".to_string()], vec!["x".to_string()]], RRF_K);
        assert_eq!(swapped, other_way, "input order cannot change the output");
    }

    #[test]
    fn rrf_of_no_lists_is_empty() {
        assert!(rrf(&[], RRF_K).is_empty());
        assert!(rrf(&[vec![]], RRF_K).is_empty());
    }

    #[test]
    fn rrf_sums_a_documents_contribution_from_every_list() {
        // One document, top of both lists: 2/(60+1). Without accumulation
        // this would read 1/61 and a both-lists document would never
        // outrank a single-list leader.
        let fused = rrf(&[vec!["a".to_string()], vec!["a".to_string()]], RRF_K);
        assert_eq!(fused.len(), 1, "the same id is one row, not two");
        assert!((fused[0].1 - 2.0 / 61.0).abs() < 1e-6, "got {}", fused[0].1);
    }

    #[test]
    fn rrf_k_damps_the_gap_between_adjacent_ranks() {
        // The k in the denominator is what makes rank 1 and rank 2 close
        // rather than 2:1. A k of 0 would make fusion behave like a
        // winner-take-all vote.
        let damped = rrf(&[vec!["a".into(), "b".into()]], RRF_K);
        let undamped = rrf(&[vec!["a".into(), "b".into()]], 0.0);
        assert!(damped[0].1 / damped[1].1 < 1.05);
        assert!(undamped[0].1 / undamped[1].1 > 1.9);
    }

    #[test]
    fn grounding_requires_a_real_signal_not_a_fused_rank() {
        assert!(
            !is_grounded(&[hit("a", 0.9, Some(0.10), None)]),
            "a high RRF score alone is not evidence"
        );
        assert!(is_grounded(&[hit("a", 0.01, Some(0.40), None)]));
        assert!(is_grounded(&[hit("a", 0.01, None, Some(2.5))]));
        assert!(
            !is_grounded(&[hit("a", 0.99, None, Some(0.0))]),
            "a zero BM25 score is no signal"
        );
        assert!(!is_grounded(&[]));
    }

    #[test]
    fn grounding_is_inclusive_at_the_dense_threshold() {
        // The gate is `>=`, and the boundary is the one value most likely to
        // be flipped by a later "tidy-up".
        assert!(is_grounded(&[hit("a", 0.01, Some(DENSE_GROUNDING_THRESHOLD), None)]));
        assert!(!is_grounded(&[hit(
            "a",
            0.01,
            Some(DENSE_GROUNDING_THRESHOLD - 0.01),
            None
        )]));
    }

    #[test]
    fn grounding_fires_if_any_hit_qualifies_not_only_the_first() {
        let hits = vec![
            hit("a", 0.9, Some(0.10), None),
            hit("b", 0.1, Some(0.90), None),
        ];
        assert!(is_grounded(&hits));
    }
}
