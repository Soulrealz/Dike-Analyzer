//! The retrieval seam Track 2 consumes, and its hybrid implementation.
//!
//! Track 2 holds a `Box<dyn Retrieve>`, never a concrete retriever (D19), so
//! it can be exercised against a stub with nothing running.
//!
//! [`HybridRetriever`] runs a sparse leg (BM25) and a dense leg (embeddings)
//! and fuses their rankings with [`rrf`]. Two behaviours are load-bearing:
//!
//! - **An unavailable embedder degrades to sparse-only, it does not fail.**
//!   Retrieval that returns nothing when the model server is down would make
//!   Track 2 look like a recall failure instead of an availability failure,
//!   and the eval harness would record it as one.
//! - **A model/dimension mismatch is *not* a degradation.** It propagates as
//!   an error carrying the re-index message. A stale index that answers
//!   confidently is worse than an error.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;

use crate::retrieval::bm25::Bm25Index;
use crate::retrieval::dense::Embedder;
use crate::retrieval::document::{corpus_hash, Document};
use crate::retrieval::rrf::{rrf, RetrievalHit, RRF_K};
use crate::retrieval::store::{StoreError, VectorStore};

/// Each leg over-fetches this multiple of `top_k` so fusion has material to
/// work with. Fusing two `top_k`-length lists mostly returns their union.
const OVERFETCH: usize = 4;

/// How many documents are embedded per request to the embedder.
const EMBED_BATCH: usize = 32;

/// The retrieval seam. Track 2 depends on this trait, not on a retriever.
pub trait Retrieve {
    fn search(&self, query: &str, top_k: usize) -> anyhow::Result<Vec<RetrievalHit>>;
    /// The hash of the corpus these results came from, for the run metadata.
    fn corpus_hash(&self) -> String;
    /// A human-readable description of the retrieval configuration.
    fn describe(&self) -> String;
}

/// Sparse (BM25) and dense (embeddings) retrieval fused by reciprocal rank.
pub struct HybridRetriever {
    bm25: Bm25Index,
    store: VectorStore,
    embedder: Box<dyn Embedder>,
    docs: BTreeMap<String, Document>,
    corpus_hash: String,
}

fn bm25_dir(index_dir: &Path) -> std::path::PathBuf {
    index_dir.join("bm25")
}

fn store_path(index_dir: &Path) -> std::path::PathBuf {
    index_dir.join("vectors.db")
}

impl HybridRetriever {
    /// Build both indexes at `index_dir` from `docs`.
    ///
    /// If the embedder is unavailable the sparse index is still built and the
    /// retriever is returned: a corpus that is searchable by BM25 alone beats
    /// no corpus at all.
    pub fn build(
        index_dir: &Path,
        docs: &[Document],
        embedder: Box<dyn Embedder>,
    ) -> anyhow::Result<HybridRetriever> {
        std::fs::create_dir_all(index_dir)
            .with_context(|| format!("creating index directory {}", index_dir.display()))?;
        let bm25 = Bm25Index::build(docs, &bm25_dir(index_dir))?;
        let store = VectorStore::open(&store_path(index_dir))
            .with_context(|| format!("opening the vector store in {}", index_dir.display()))?;

        match embed_documents(embedder.as_ref(), docs) {
            Ok(Some((dim, rows))) => {
                store.init(&embedder.model_name(), dim)?;
                store.upsert(&rows)?;
            }
            // Nothing to embed: leave the store uninitialised rather than
            // recording a dimension we never saw.
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "embedder unavailable; building a sparse-only index"
                );
            }
        }

        Ok(Self {
            bm25,
            store,
            embedder,
            docs: by_id(docs.to_vec()),
            corpus_hash: corpus_hash(docs),
        })
    }

    /// Open indexes previously built at `index_dir`.
    ///
    /// `docs` must be the same corpus the index was built from — it is what
    /// hydrates the hits, and it is what the corpus hash is computed over.
    pub fn open(
        index_dir: &Path,
        docs: Vec<Document>,
        embedder: Box<dyn Embedder>,
    ) -> anyhow::Result<HybridRetriever> {
        let bm25 = Bm25Index::open(&bm25_dir(index_dir))?;
        let store = VectorStore::open(&store_path(index_dir))
            .with_context(|| format!("opening the vector store in {}", index_dir.display()))?;
        let corpus_hash = corpus_hash(&docs);
        Ok(Self {
            bm25,
            store,
            embedder,
            docs: by_id(docs),
            corpus_hash,
        })
    }

    /// The dense leg: `None` when it could not run at all.
    ///
    /// A [`StoreError::ModelMismatch`] is returned as an error rather than
    /// swallowed — see the module docs.
    fn dense_leg(&self, query: &str, k: usize) -> anyhow::Result<Option<Vec<(String, f32)>>> {
        if self.store.meta()?.is_none() {
            // No vectors were ever indexed (a sparse-only build).
            return Ok(None);
        }
        let embedded = match self.embedder.embed(&[query.to_string()]) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "embedder unavailable; retrieving with BM25 only");
                return Ok(None);
            }
        };
        let Some(vector) = embedded.into_iter().next() else {
            tracing::warn!("embedder returned no vector for the query; retrieving with BM25 only");
            return Ok(None);
        };
        match self.store.search(&vector, k) {
            Ok(hits) => Ok(Some(hits)),
            Err(e @ StoreError::ModelMismatch { .. }) => Err(e.into()),
            Err(e) => Err(e.into()),
        }
    }
}

fn by_id(docs: Vec<Document>) -> BTreeMap<String, Document> {
    docs.into_iter().map(|d| (d.id.clone(), d)).collect()
}

/// Embed every document, returning `(dim, rows)`, or `None` for an empty
/// corpus. An embedding whose width disagrees with the first one is an error:
/// a store holds one dimension, and mixing them makes every later cosine
/// meaningless.
#[allow(clippy::type_complexity)]
fn embed_documents(
    embedder: &dyn Embedder,
    docs: &[Document],
) -> anyhow::Result<Option<(usize, Vec<(String, Vec<f32>)>)>> {
    if docs.is_empty() {
        return Ok(None);
    }
    let mut rows: Vec<(String, Vec<f32>)> = Vec::with_capacity(docs.len());
    let mut dim: Option<usize> = None;
    for batch in docs.chunks(EMBED_BATCH) {
        let texts: Vec<String> = batch.iter().map(|d| d.text.clone()).collect();
        let vectors = embedder.embed(&texts)?;
        anyhow::ensure!(
            vectors.len() == batch.len(),
            "embedder returned {} vectors for {} documents",
            vectors.len(),
            batch.len()
        );
        for (doc, vector) in batch.iter().zip(vectors) {
            match dim {
                None => dim = Some(vector.len()),
                Some(d) => anyhow::ensure!(
                    d == vector.len(),
                    "embedder returned {} dimensions for {} after {d} for earlier documents",
                    vector.len(),
                    doc.id
                ),
            }
            rows.push((doc.id.clone(), vector));
        }
    }
    match dim {
        Some(d) if d > 0 => Ok(Some((d, rows))),
        _ => anyhow::bail!("embedder returned zero-width vectors"),
    }
}

impl Retrieve for HybridRetriever {
    fn search(&self, query: &str, top_k: usize) -> anyhow::Result<Vec<RetrievalHit>> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let wide = top_k * OVERFETCH;
        let dense = self.dense_leg(query, wide)?;
        let sparse = self.bm25.search(query, wide)?;

        let mut lists: Vec<Vec<String>> = Vec::new();
        if let Some(d) = &dense {
            lists.push(d.iter().map(|(id, _)| id.clone()).collect());
        }
        lists.push(sparse.iter().map(|(id, _)| id.clone()).collect());

        let dense_scores: BTreeMap<&str, f32> = dense
            .iter()
            .flatten()
            .map(|(id, s)| (id.as_str(), *s))
            .collect();
        let sparse_scores: BTreeMap<&str, f32> =
            sparse.iter().map(|(id, s)| (id.as_str(), *s)).collect();

        let mut hits = Vec::new();
        for (id, score) in rrf(&lists, RRF_K) {
            // A fused id with no document behind it means the index and the
            // corpus have drifted apart; skip it rather than inventing text.
            let Some(document) = self.docs.get(&id) else {
                tracing::warn!(doc_id = %id, "retrieved an id absent from the corpus; skipping");
                continue;
            };
            hits.push(RetrievalHit {
                document: document.clone(),
                rrf_score: score,
                dense_score: dense_scores.get(id.as_str()).copied(),
                bm25_score: sparse_scores.get(id.as_str()).copied(),
            });
            if hits.len() == top_k {
                break;
            }
        }
        Ok(hits)
    }

    fn corpus_hash(&self) -> String {
        self.corpus_hash.clone()
    }

    fn describe(&self) -> String {
        format!(
            "hybrid BM25 + dense ({}), {} documents",
            self.embedder.model_name(),
            self.docs.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpError;

    fn doc(id: &str, text: &str) -> Document {
        Document {
            id: id.into(),
            source_url: "https://example.invalid/report".into(),
            title: format!("doc {id}"),
            text: text.into(),
            class_tags: vec![],
        }
    }

    /// A deterministic bag-of-words hashing embedder. It needs no network and
    /// no model, and unlike a one-hot stub it produces cosines that actually
    /// track word overlap, so a dense-leg ordering assertion means something.
    struct StubEmbedder {
        dim: usize,
    }

    impl StubEmbedder {
        fn hashing() -> Self {
            Self { dim: 32 }
        }
    }

    impl Embedder for StubEmbedder {
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, HttpError> {
            Ok(texts
                .iter()
                .map(|t| {
                    let mut v = vec![0.0f32; self.dim];
                    for word in t.split(|c: char| !c.is_alphanumeric() && c != '_') {
                        if word.is_empty() {
                            continue;
                        }
                        let bucket = word
                            .to_lowercase()
                            .bytes()
                            .fold(7u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
                        v[(bucket as usize) % self.dim] += 1.0;
                    }
                    v
                })
                .collect())
        }

        fn model_name(&self) -> String {
            "stub-hashing-32".to_string()
        }
    }

    /// Stands in for "Ollama is not running".
    struct DeadEmbedder;

    impl Embedder for DeadEmbedder {
        fn embed(&self, _texts: &[String]) -> Result<Vec<Vec<f32>>, HttpError> {
            Err(HttpError::Unavailable("connection refused".into()))
        }
        fn model_name(&self) -> String {
            "dead".to_string()
        }
    }

    #[test]
    fn hybrid_search_returns_hits_carrying_both_component_scores() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![
            doc(
                "d1",
                "The withdraw path calls close_account without checking the destination.",
            ),
            doc("d2", "Overflow in the deposit path wraps the stored balance."),
        ];
        let r =
            HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        let hits = r.search("close_account", 5).unwrap();
        assert!(!hits.is_empty());
        assert!(
            hits.iter().any(|h| h.bm25_score.is_some()),
            "sparse leg ran"
        );
        assert!(
            hits.iter().any(|h| h.dense_score.is_some()),
            "dense leg ran"
        );
        assert!(hits.iter().all(|h| h.rrf_score > 0.0));
    }

    #[test]
    fn hybrid_search_degrades_to_sparse_when_the_embedder_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "The withdraw path calls close_account.")];
        let r = HybridRetriever::build(dir.path(), &docs, Box::new(DeadEmbedder)).unwrap();
        let hits = r.search("close_account", 5).unwrap();
        assert!(!hits.is_empty(), "a dead embedder must not zero out retrieval");
        assert!(hits.iter().all(|h| h.dense_score.is_none()));
    }

    #[test]
    fn an_embedder_that_dies_after_the_index_was_built_still_retrieves() {
        // The build-time and query-time failures are different code paths:
        // this one has a populated store and a live `meta`, and must still
        // fall back rather than propagate.
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "The withdraw path calls close_account.")];
        HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        let r = HybridRetriever::open(dir.path(), docs, Box::new(DeadEmbedder)).unwrap();
        let hits = r.search("close_account", 5).unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.dense_score.is_none()));
    }

    #[test]
    fn a_model_mismatch_is_an_error_not_a_silent_degradation() {
        // Index with a 32-wide stub, then query with a 8-wide one: a stale
        // index answering confidently is worse than an error.
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "The withdraw path calls close_account.")];
        HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        let r = HybridRetriever::open(dir.path(), docs, Box::new(StubEmbedder { dim: 8 })).unwrap();
        let err = r.search("close_account", 5).unwrap_err();
        assert!(
            err.to_string().contains("re-index"),
            "the error must tell the user what to do: {err}"
        );
    }

    #[test]
    fn hybrid_search_respects_top_k() {
        let dir = tempfile::tempdir().unwrap();
        let docs: Vec<_> = (0..8)
            .map(|i| doc(&format!("d{i}"), "missing owner validation"))
            .collect();
        let r =
            HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        assert!(r.search("owner", 3).unwrap().len() <= 3);
    }

    #[test]
    fn a_top_k_of_zero_returns_nothing_rather_than_everything() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "missing owner validation")];
        let r =
            HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        assert!(r.search("owner", 0).unwrap().is_empty());
    }

    #[test]
    fn corpus_hash_is_reported_from_the_indexed_documents() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "text")];
        let r =
            HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        assert_eq!(r.corpus_hash(), corpus_hash(&docs));
    }

    #[test]
    fn search_is_deterministic_across_repeated_runs() {
        // Rule 5. Both legs and the fusion feed a ranked list that reaches a
        // Finding's citations.
        let dir = tempfile::tempdir().unwrap();
        let docs: Vec<_> = (0..6)
            .map(|i| doc(&format!("d{i}"), "missing owner validation on the vault"))
            .collect();
        let r =
            HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        let first: Vec<String> = r
            .search("owner validation", 5)
            .unwrap()
            .into_iter()
            .map(|h| h.document.id)
            .collect();
        for _ in 0..3 {
            let again: Vec<String> = r
                .search("owner validation", 5)
                .unwrap()
                .into_iter()
                .map(|h| h.document.id)
                .collect();
            assert_eq!(first, again);
        }
    }

    #[test]
    fn hits_are_hydrated_with_the_real_document_not_a_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "The withdraw path calls close_account.")];
        let r =
            HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        let hits = r.search("close_account", 5).unwrap();
        assert_eq!(hits[0].document.text, docs[0].text);
        assert_eq!(hits[0].document.source_url, docs[0].source_url);
    }

    #[test]
    fn searching_an_empty_corpus_returns_nothing_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let r = HybridRetriever::build(dir.path(), &[], Box::new(StubEmbedder::hashing())).unwrap();
        assert!(r.search("close_account", 5).unwrap().is_empty());
    }

    #[test]
    fn describe_names_the_embedding_model_that_is_actually_configured() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "text")];
        let r =
            HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::hashing())).unwrap();
        assert!(r.describe().contains("stub-hashing-32"), "{}", r.describe());
    }
}
