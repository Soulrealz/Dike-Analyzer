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
//! match scores. Grounding therefore asks the component legs.
//!
//! **Which leg it asks was recalibrated against the real corpus on
//! 2026-08-31**, and the original spec rule ("dense >= 0.35 OR any non-zero
//! BM25") turned out to accept everything. Measured over 358 documents with
//! BGE-small-en v1.5, best score per query:
//!
//! | | dense | BM25 |
//! |---|---|---|
//! | 6 off-topic queries | 0.417 – **0.566** | 2.6 – **16.0** |
//! | 9 on-topic queries | **0.664** – 0.816 | **2.6** – 22.5 |
//!
//! Two conclusions, both load-bearing:
//!
//! - **Dense separates cleanly, but not at 0.35.** These embeddings sit on a
//!   compressed cosine scale where unrelated text scores ~0.5, so the spec's
//!   threshold was below the floor of the distribution and could never
//!   discriminate. [`DENSE_GROUNDING_THRESHOLD`] is now 0.62, which clears
//!   the off-topic maximum by 0.054 and sits 0.044 under the on-topic
//!   minimum. That minimum is an identifier query (`try_borrow_mut_data`),
//!   which is the case dense retrieval handles worst — hence the deliberately
//!   asymmetric margins.
//! - **BM25 cannot stand alone as evidence.** Its ranges overlap almost
//!   completely: an off-topic query reached 16.0 while a genuinely relevant
//!   exact-identifier query scored 2.6. No threshold separates them, so BM25
//!   grounds only when the dense leg did not run at all — a degraded,
//!   sparse-only run, where weaker evidence is accepted deliberately rather
//!   than reporting a corpus hit as no evidence.
//!
//! These are pinned constants (Rule 5): re-tuning one silently invalidates
//! every eval comparison across time. Recalibrating for a different embedding
//! model means re-running the measurement above, not nudging the number.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::retrieval::document::Document;

/// The `k` in the RRF denominator (spec §7).
pub const RRF_K: f32 = 60.0;

/// A dense cosine at or above this counts as evidence for grounding (D11).
///
/// Calibrated against the real corpus with BGE-small-en v1.5 — see the module
/// docs for the measurement and why 0.35 (the spec's value) accepted
/// everything. Model-specific: changing the embedding model invalidates it.
pub const DENSE_GROUNDING_THRESHOLD: f32 = 0.62;

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
/// When the dense leg ran, grounding is a dense question only: any hit at or
/// above [`DENSE_GROUNDING_THRESHOLD`]. A strong BM25 score does *not* rescue
/// a query the embeddings rejected, because BM25 scores an off-topic query as
/// highly as a relevant one (module docs).
///
/// When the dense leg did not run — the embedder was unavailable, so every
/// hit came from BM25 alone — any non-zero BM25 score grounds. That is
/// deliberately weaker evidence: the alternative is reporting a degraded run
/// as ungrounded, which would blame the corpus for an availability failure
/// (invariant 11). A caller that needs to tell the two apart has the
/// per-hit `dense_score`.
///
/// Deliberately *not* a function of `rrf_score` — see the module docs.
pub fn is_grounded(hits: &[RetrievalHit]) -> bool {
    let dense_leg_ran = hits.iter().any(|h| h.dense_score.is_some());
    if dense_leg_ran {
        hits.iter()
            .any(|h| h.dense_score.is_some_and(|s| s >= DENSE_GROUNDING_THRESHOLD))
    } else {
        hits.iter().any(|h| h.bm25_score.is_some_and(|s| s > 0.0))
    }
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
        assert!(is_grounded(&[hit("a", 0.01, Some(0.70), None)]));
        assert!(
            is_grounded(&[hit("a", 0.01, None, Some(2.5))]),
            "sparse-only: BM25 is the only evidence there can be"
        );
        assert!(
            !is_grounded(&[hit("a", 0.99, None, Some(0.0))]),
            "a zero BM25 score is no signal"
        );
        assert!(!is_grounded(&[]));
    }

    #[test]
    fn a_strong_bm25_does_not_rescue_a_query_the_embeddings_rejected() {
        // The calibration finding of 2026-08-31: an off-topic query scored
        // BM25 16.0 while a genuinely relevant identifier query scored 2.6,
        // so BM25 carries no standalone evidence when the dense leg ran.
        // Under the previous "dense >= 0.35 OR any non-zero BM25" rule this
        // was grounded, and so was every nonsense query.
        let hits = vec![hit("a", 0.03, Some(0.52), Some(16.0))];
        assert!(!is_grounded(&hits), "off-topic dense with a loud BM25");
    }

    #[test]
    fn a_sparse_only_run_still_grounds_on_bm25_alone() {
        // Invariant 11: an unavailable embedder is an availability failure,
        // not a corpus failure. Reporting it as ungrounded would blame the
        // corpus. Every hit lacking a dense score is what "the dense leg
        // did not run" looks like.
        let hits = vec![hit("a", 0.03, None, Some(2.6)), hit("b", 0.02, None, Some(1.1))];
        assert!(is_grounded(&hits));
    }

    #[test]
    fn one_hit_missing_from_the_dense_leg_does_not_make_the_run_sparse_only() {
        // A hit BM25 returned and the dense leg did not still has
        // `dense_score: None`, but the dense leg *did* run — so the strict
        // dense rule must stay in force. Reading "any hit has no dense
        // score" as "sparse-only" would silently restore the old
        // everything-is-grounded behaviour whenever the legs disagree.
        let hits = vec![
            hit("a", 0.03, Some(0.52), Some(1.0)),
            hit("b", 0.02, None, Some(16.0)),
        ];
        assert!(!is_grounded(&hits));
    }

    #[test]
    fn the_dense_threshold_sits_inside_the_measured_envelope() {
        // Pins the calibration itself, not just the code that reads it.
        // These two numbers are the measurement recorded in the module
        // docs: the highest dense score any off-topic query achieved, and
        // the lowest any on-topic query achieved, over the real 358-document
        // corpus with BGE-small-en v1.5. A retune that leaves this envelope
        // is a decision that needs re-measuring, not a nudge.
        // `black_box` keeps these comparisons out of clippy's
        // constant-assertion lint: both sides really are constants, which
        // is the point — the test pins the relationship between the tuned
        // threshold and the measurement it was tuned against.
        let threshold = std::hint::black_box(DENSE_GROUNDING_THRESHOLD);
        let measured_off_topic_max = std::hint::black_box(0.5660_f32);
        let measured_on_topic_min = std::hint::black_box(0.6636_f32);
        assert!(
            threshold > measured_off_topic_max,
            "the threshold would accept off-topic retrieval"
        );
        assert!(
            threshold < measured_on_topic_min,
            "the threshold would reject a real identifier query"
        );
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
