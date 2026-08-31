//! Dense vector store: one sqlite file, vectors as little-endian `f32` BLOBs,
//! cosine similarity computed in Rust over every row.
//!
//! **Deviation (D25).** The design doc names `sqlite-vec`. This uses plain
//! `rusqlite` with a linear scan instead. Every requirement the doc actually
//! states still holds: one file, no server, index reproducible from the fetch
//! step. At v1 corpus size (hundreds of chunks) a linear scan is
//! sub-millisecond, and the [`VectorStore`] interface hides the choice, so
//! adopting the extension later is a one-file change.
//!
//! **Dimension safety (D26).** The `meta` table records the `(model, dim)` the
//! index was built with. A query whose dimension disagrees is a refusal
//! ([`StoreError::ModelMismatch`]), never a cosine score computed across
//! mismatched dimensions -- a number that looks fine and means nothing.

use std::cmp::Ordering;
use std::path::Path;

/// Errors from a [`VectorStore`] operation.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sql(String),
    #[error(
        "index was built with model {built_with} (dim {built_dim}) but the query is \
         model {got} (dim {got_dim}) -- re-index the corpus"
    )]
    ModelMismatch {
        built_with: String,
        built_dim: usize,
        got: String,
        got_dim: usize,
    },
}

fn sql(e: rusqlite::Error) -> StoreError {
    StoreError::Sql(e.to_string())
}

/// A sqlite-backed store of `(doc_id, vector)` rows.
pub struct VectorStore {
    conn: rusqlite::Connection,
}

impl VectorStore {
    /// Open (creating if absent) the store at `path` and ensure the schema.
    pub fn open(path: &Path) -> Result<VectorStore, StoreError> {
        let conn = rusqlite::Connection::open(path).map_err(sql)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS vectors (doc_id TEXT PRIMARY KEY, vec BLOB NOT NULL);",
        )
        .map_err(sql)?;
        Ok(Self { conn })
    }

    /// Record the model and dimension this index is built with.
    ///
    /// If either differs from what is already stored, the existing vectors are
    /// deleted first: vectors from another model are not comparable with the
    /// new one, and keeping them would make later searches quietly wrong.
    pub fn init(&self, model: &str, dim: usize) -> Result<(), StoreError> {
        if let Some((old_model, old_dim)) = self.meta()? {
            if old_model != model || old_dim != dim {
                self.conn
                    .execute("DELETE FROM vectors", [])
                    .map_err(sql)?;
            }
        }
        self.conn
            .execute(
                "INSERT INTO meta (k, v) VALUES ('model', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                [model],
            )
            .map_err(sql)?;
        self.conn
            .execute(
                "INSERT INTO meta (k, v) VALUES ('dim', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                [dim.to_string()],
            )
            .map_err(sql)?;
        Ok(())
    }

    /// The `(model, dim)` this index was built with, or `None` before `init`.
    pub fn meta(&self) -> Result<Option<(String, usize)>, StoreError> {
        let model: Option<String> = self.meta_value("model")?;
        let dim: Option<String> = self.meta_value("dim")?;
        match (model, dim) {
            (Some(m), Some(d)) => {
                let d = d
                    .parse::<usize>()
                    .map_err(|e| StoreError::Sql(format!("corrupt dim in meta: {e}")))?;
                Ok(Some((m, d)))
            }
            _ => Ok(None),
        }
    }

    fn meta_value(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row("SELECT v FROM meta WHERE k = ?1", [key], |r| r.get(0))
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(sql(other)),
            })
    }

    /// Insert or replace vectors by `doc_id`.
    pub fn upsert(&self, rows: &[(String, Vec<f32>)]) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction().map_err(sql)?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO vectors (doc_id, vec) VALUES (?1, ?2)
                     ON CONFLICT(doc_id) DO UPDATE SET vec = excluded.vec",
                )
                .map_err(sql)?;
            for (id, v) in rows {
                stmt.execute(rusqlite::params![id, encode(v)]).map_err(sql)?;
            }
        }
        tx.commit().map_err(sql)?;
        Ok(())
    }

    /// The `k` nearest rows to `q` by cosine similarity, best first.
    ///
    /// Ties break on `doc_id` so the ordering is deterministic (Rule 5).
    pub fn search(&self, q: &[f32], k: usize) -> Result<Vec<(String, f32)>, StoreError> {
        self.check_dimension(q)?;
        let mut stmt = self
            .conn
            .prepare("SELECT doc_id, vec FROM vectors")
            .map_err(sql)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sql)?;
        let mut scored = Vec::new();
        for row in rows {
            let (id, blob) = row.map_err(sql)?;
            let v = decode(&blob);
            scored.push((id, cosine(q, &v)));
        }
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        scored.truncate(k);
        Ok(scored)
    }

    /// Cosine scores for specific `doc_id`s, for ids the store actually has.
    ///
    /// [`Self::search`] only reports its own top `k`, so a document that
    /// reached the final result through the sparse leg would otherwise carry
    /// no dense score at all — indistinguishable from a run where the dense
    /// leg never happened. That ambiguity is not cosmetic: the grounding gate
    /// reads it.
    pub fn scores_for(&self, q: &[f32], ids: &[String]) -> Result<Vec<(String, f32)>, StoreError> {
        self.check_dimension(q)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut stmt = self
            .conn
            .prepare("SELECT vec FROM vectors WHERE doc_id = ?1")
            .map_err(sql)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let blob: Option<Vec<u8>> = stmt
                .query_row([id], |r| r.get::<_, Vec<u8>>(0))
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(sql(other)),
                })?;
            if let Some(blob) = blob {
                out.push((id.clone(), cosine(q, &decode(&blob))));
            }
        }
        Ok(out)
    }

    /// Refuse a query whose width disagrees with what the index was built
    /// with. Shared by `search` and `scores_for` so the two can never drift.
    fn check_dimension(&self, q: &[f32]) -> Result<(), StoreError> {
        if let Some((model, dim)) = self.meta()? {
            if dim != q.len() {
                return Err(StoreError::ModelMismatch {
                    built_with: model.clone(),
                    built_dim: dim,
                    got: model,
                    got_dim: q.len(),
                });
            }
        }
        Ok(())
    }

    /// How many vectors the store holds.
    pub fn len(&self) -> Result<usize, StoreError> {
        self.conn
            .query_row("SELECT COUNT(*) FROM vectors", [], |r| {
                r.get::<_, i64>(0).map(|n| n as usize)
            })
            .map_err(sql)
    }

    /// Whether the store holds no vectors.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }
}

fn encode(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

fn decode(b: &[u8]) -> Vec<f32> {
    b.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Cosine similarity, guarding a zero norm to `0.0` rather than `NaN`.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &tempfile::TempDir) -> VectorStore {
        VectorStore::open(&dir.path().join("v.db")).unwrap()
    }

    #[test]
    fn store_round_trips_and_ranks_by_cosine() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        store
            .upsert(&[("a".into(), vec![1.0, 0.0]), ("b".into(), vec![0.0, 1.0])])
            .unwrap();
        let hits = store.search(&[0.9, 0.1], 2).unwrap();
        assert_eq!(hits[0].0, "a");
        assert!(hits[0].1 > hits[1].1);
    }

    #[test]
    fn cosine_ignores_magnitude() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        store
            .upsert(&[
                ("a".into(), vec![1.0, 0.0]),
                ("big".into(), vec![100.0, 0.0]),
            ])
            .unwrap();
        let hits = store.search(&[1.0, 0.0], 2).unwrap();
        assert!(
            (hits[0].1 - hits[1].1).abs() < 1e-5,
            "parallel vectors score equally"
        );
    }

    #[test]
    fn upsert_replaces_rather_than_duplicating() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        store.upsert(&[("a".into(), vec![1.0, 0.0])]).unwrap();
        store.upsert(&[("a".into(), vec![0.0, 1.0])]).unwrap();
        assert_eq!(store.len().unwrap(), 1);
        let hits = store.search(&[0.0, 1.0], 5).unwrap();
        assert!(hits[0].1 > 0.99, "the second vector won");
    }

    #[test]
    fn a_dimension_mismatch_is_a_refusal_not_a_wrong_answer() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("embed-model-v1", 384).unwrap();
        let err = store.search(&[1.0, 0.0], 5).unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::ModelMismatch {
                    built_dim: 384,
                    got_dim: 2,
                    ..
                }
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn meta_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        VectorStore::open(&path).unwrap().init("m1", 7).unwrap();
        let reopened = VectorStore::open(&path).unwrap();
        assert_eq!(reopened.meta().unwrap(), Some(("m1".to_string(), 7)));
    }

    #[test]
    fn re_initing_with_a_different_model_clears_the_vectors() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m1", 2).unwrap();
        store.upsert(&[("a".into(), vec![1.0, 0.0])]).unwrap();
        store.init("m2", 2).unwrap();
        assert_eq!(
            store.len().unwrap(),
            0,
            "vectors from another model are meaningless"
        );
    }

    #[test]
    fn re_initing_with_the_same_model_keeps_the_vectors() {
        // The complement of the test above: `init` is called on every index
        // run, so if it cleared unconditionally an incremental re-index would
        // silently throw the corpus away.
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m1", 2).unwrap();
        store.upsert(&[("a".into(), vec![1.0, 0.0])]).unwrap();
        store.init("m1", 2).unwrap();
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn searching_an_empty_store_returns_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        assert!(store.search(&[1.0, 0.0], 5).unwrap().is_empty());
    }

    #[test]
    fn a_zero_vector_does_not_produce_nan_scores() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        store.upsert(&[("z".into(), vec![0.0, 0.0])]).unwrap();
        let hits = store.search(&[1.0, 0.0], 5).unwrap();
        assert!(hits.iter().all(|h| h.1.is_finite()), "division by a zero norm");
    }

    #[test]
    fn equal_scores_break_ties_on_doc_id_deterministically() {
        // Rule 5: no HashMap-ish ordering may reach a ranked result. Three
        // parallel vectors all score 1.0; without the tie-break the order
        // would be whatever sqlite happened to return.
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        store
            .upsert(&[
                ("c".into(), vec![2.0, 0.0]),
                ("a".into(), vec![1.0, 0.0]),
                ("b".into(), vec![3.0, 0.0]),
            ])
            .unwrap();
        let ids: Vec<String> = store
            .search(&[1.0, 0.0], 3)
            .unwrap()
            .into_iter()
            .map(|h| h.0)
            .collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn scores_for_returns_a_score_per_known_id_and_skips_unknown_ones() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        store
            .upsert(&[("a".into(), vec![1.0, 0.0]), ("b".into(), vec![0.0, 1.0])])
            .unwrap();
        let out = store
            .scores_for(&[1.0, 0.0], &["a".to_string(), "gone".to_string()])
            .unwrap();
        assert_eq!(out.len(), 1, "an id the store does not have is skipped");
        assert_eq!(out[0].0, "a");
        assert!((out[0].1 - 1.0).abs() < 1e-5);
    }

    #[test]
    fn scores_for_agrees_with_search_on_the_same_vectors() {
        // Two ways of computing the same cosine must not drift apart.
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        store
            .upsert(&[("a".into(), vec![1.0, 0.5]), ("b".into(), vec![0.2, 1.0])])
            .unwrap();
        let q = [0.9, 0.1];
        let searched = store.search(&q, 5).unwrap();
        let scored = store
            .scores_for(&q, &["a".to_string(), "b".to_string()])
            .unwrap();
        for (id, s) in scored {
            let expected = searched.iter().find(|h| h.0 == id).unwrap().1;
            assert!((s - expected).abs() < 1e-6, "{id}: {s} vs {expected}");
        }
    }

    #[test]
    fn scores_for_refuses_a_dimension_mismatch_exactly_as_search_does() {
        // The two entry points share `check_dimension` precisely so a stale
        // index cannot be scored through the back door.
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("embed-model-v1", 384).unwrap();
        let err = store.scores_for(&[1.0, 0.0], &["a".to_string()]).unwrap_err();
        assert!(matches!(err, StoreError::ModelMismatch { .. }), "got: {err:?}");
    }

    #[test]
    fn k_truncates_the_result() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        store.init("m", 2).unwrap();
        store
            .upsert(&[("a".into(), vec![1.0, 0.0]), ("b".into(), vec![0.0, 1.0])])
            .unwrap();
        assert_eq!(store.search(&[1.0, 0.0], 1).unwrap().len(), 1);
    }

    #[test]
    fn vectors_survive_reopen_with_their_values_intact() {
        // The BLOB encoding is only correct if it round-trips through the
        // file, not merely through one connection's cache.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        {
            let store = VectorStore::open(&path).unwrap();
            store.init("m", 3).unwrap();
            store
                .upsert(&[("a".into(), vec![0.0, 1.0, 0.0])])
                .unwrap();
        }
        let reopened = VectorStore::open(&path).unwrap();
        let hits = reopened.search(&[0.0, 1.0, 0.0], 1).unwrap();
        assert_eq!(hits[0].0, "a");
        assert!((hits[0].1 - 1.0).abs() < 1e-5, "got: {}", hits[0].1);
    }
}
