//! Dense embeddings via a local Ollama server.
//!
//! The trait exists so the rest of retrieval never names a provider, and so
//! tests can substitute a deterministic embedder without a model running.
//!
//! **Model names are configuration, never constants (D26).** `OllamaEmbedder`
//! takes its host and model as parameters; the defaults live in the CLI. This
//! is the single swap point for another embedding model.
//!
//! Errors are [`HttpError`] unchanged from [`HttpClient`] (D24) -- a second
//! error type here would mean two places deciding what "the server isn't
//! running" looks like.

use std::time::Duration;

use crate::http::{HttpClient, HttpError};

/// Turns text into vectors. One implementation per provider.
pub trait Embedder {
    /// Embed every input, returning one vector per input in the same order.
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, HttpError>;
    /// The model name, recorded alongside the index so a later query can
    /// refuse to search vectors built by a different model.
    fn model_name(&self) -> String;
}

/// An [`Embedder`] backed by a local Ollama server.
pub struct OllamaEmbedder {
    pub host: String,
    pub model: String,
    http: HttpClient,
}

impl OllamaEmbedder {
    pub fn new(host: impl Into<String>, model: impl Into<String>) -> Result<Self, HttpError> {
        Ok(Self {
            host: host.into().trim_end_matches('/').to_string(),
            model: model.into(),
            http: HttpClient::new(Duration::from_secs(120))?,
        })
    }
}

impl Embedder for OllamaEmbedder {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, HttpError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let body = serde_json::json!({ "model": self.model, "input": texts });
        let resp = match self.http.post_json(&format!("{}/api/embed", self.host), &body) {
            Ok(v) => v,
            // Older Ollama builds expose only the single-input
            // `/api/embeddings` and answer `/api/embed` with 404. Fall back to
            // one request per text rather than failing the whole run; a
            // transport-level failure is still returned unchanged.
            Err(HttpError::Status(404)) => return self.embed_one_by_one(texts),
            Err(e) => return Err(e),
        };
        parse_embeddings(&resp, texts.len())
    }

    fn model_name(&self) -> String {
        self.model.clone()
    }
}

impl OllamaEmbedder {
    fn embed_one_by_one(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, HttpError> {
        let mut out = Vec::with_capacity(texts.len());
        for t in texts {
            let body = serde_json::json!({ "model": self.model, "prompt": t });
            let resp = self
                .http
                .post_json(&format!("{}/api/embeddings", self.host), &body)?;
            let v = resp
                .get("embedding")
                .and_then(as_vec_f32)
                .ok_or_else(|| {
                    HttpError::Transport("no `embedding` array in the response".to_string())
                })?;
            out.push(v);
        }
        Ok(out)
    }
}

/// Read `response["embeddings"]` as one vector per input.
///
/// A short or malformed body is a transport error, not a silently truncated
/// batch: callers zip these with chunk IDs, and a misalignment there would
/// attach every vector to the wrong document.
fn parse_embeddings(resp: &serde_json::Value, expected: usize) -> Result<Vec<Vec<f32>>, HttpError> {
    let rows = resp
        .get("embeddings")
        .and_then(|e| e.as_array())
        .ok_or_else(|| HttpError::Transport("no `embeddings` array in the response".to_string()))?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let v = as_vec_f32(row)
            .ok_or_else(|| HttpError::Transport("a non-numeric embedding row".to_string()))?;
        out.push(v);
    }
    if out.len() != expected {
        return Err(HttpError::Transport(format!(
            "expected {expected} embeddings, got {}",
            out.len()
        )));
    }
    Ok(out)
}

fn as_vec_f32(v: &serde_json::Value) -> Option<Vec<f32>> {
    v.as_array()?
        .iter()
        .map(|x| x.as_f64().map(|f| f as f32))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dead_ollama_is_unavailable_not_a_panic() {
        let e = OllamaEmbedder::new("http://127.0.0.1:1", "nope").unwrap();
        let err = e.embed(&["hello".to_string()]).unwrap_err();
        assert!(matches!(
            err,
            HttpError::Unavailable(_) | HttpError::Transport(_) | HttpError::Timeout
        ));
    }

    #[test]
    fn a_trailing_slash_in_the_host_does_not_double_up_the_path() {
        let e = OllamaEmbedder::new("http://localhost:11434/", "m").unwrap();
        assert_eq!(e.host, "http://localhost:11434");
    }

    #[test]
    fn embedding_nothing_makes_no_request() {
        // The host is a dead port: if this reached the network it would error.
        let e = OllamaEmbedder::new("http://127.0.0.1:1", "m").unwrap();
        assert!(e.embed(&[]).unwrap().is_empty());
    }

    #[test]
    fn model_name_is_what_was_configured_not_a_constant() {
        let e = OllamaEmbedder::new("http://localhost:11434", "some-other-model").unwrap();
        assert_eq!(e.model_name(), "some-other-model");
    }

    #[test]
    fn a_well_formed_batch_response_parses_in_order() {
        let resp = serde_json::json!({ "embeddings": [[1.0, 2.0], [3.0, 4.5]] });
        let v = parse_embeddings(&resp, 2).unwrap();
        assert_eq!(v, vec![vec![1.0, 2.0], vec![3.0, 4.5]]);
    }

    #[test]
    fn a_short_batch_is_an_error_not_a_misaligned_zip() {
        // Two inputs, one embedding back. Accepting this would attach the
        // vector for input 0 to whatever chunk the caller zips it against.
        let resp = serde_json::json!({ "embeddings": [[1.0, 2.0]] });
        let err = parse_embeddings(&resp, 2).unwrap_err();
        assert!(matches!(err, HttpError::Transport(_)), "got: {err:?}");
    }

    #[test]
    fn an_ollama_error_body_is_an_error_not_an_empty_vector() {
        let resp = serde_json::json!({ "error": "model \"m\" not found" });
        let err = parse_embeddings(&resp, 1).unwrap_err();
        assert!(matches!(err, HttpError::Transport(_)), "got: {err:?}");
    }

    #[test]
    fn a_non_numeric_row_is_rejected() {
        let resp = serde_json::json!({ "embeddings": [["a", "b"]] });
        let err = parse_embeddings(&resp, 1).unwrap_err();
        assert!(matches!(err, HttpError::Transport(_)), "got: {err:?}");
    }

    #[test]
    #[ignore = "needs a running Ollama with the embedding model pulled"]
    fn live_embedder_returns_a_consistent_dimension() {
        let e = OllamaEmbedder::new("http://localhost:11434", "bge-small-en-v1.5").unwrap();
        let v = e
            .embed(&[
                "a missing authorization check".into(),
                "unchecked arithmetic".into(),
            ])
            .unwrap();
        assert_eq!(v.len(), 2);
        // Consistency, not 384: hard-coding a dimension bakes one model
        // choice into a test that has no business knowing it (D26).
        assert_eq!(v[0].len(), v[1].len(), "all rows share one dimension");
        assert!(v[0].len() >= 128, "a real embedding, not an error body");
    }
}
