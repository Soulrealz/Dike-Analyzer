//! Ollama backend: a local model server, no credentials.

use crate::http::HttpClient;
use crate::llm::{map_http_err, LlmClient, LlmError, LlmRequest};

/// Hard ceiling on generated tokens.
///
/// A JSON array of findings never needs anywhere near this much. The cap
/// exists for the failure mode measured on 2026-09-01: one handler
/// repeatedly consumed the entire 120-second budget and was dropped, while
/// an identically shaped prompt answered in 7 seconds — a runaway
/// generation, not a slow one. Truncation turns that into a schema
/// violation, which costs one retry and then a logged drop, instead of
/// stalling the whole unit for two minutes.
const MAX_OUTPUT_TOKENS: u32 = 1024;

pub struct OllamaClient {
    pub host: String,
    pub model: String,
    http: HttpClient,
}

impl OllamaClient {
    pub fn new(host: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError> {
        Ok(Self {
            host: host.into().trim_end_matches('/').to_string(),
            model: model.into(),
            // The client-level timeout is a backstop only; every request
            // carries its own, because a generation call's ceiling belongs
            // to the caller.
            http: HttpClient::new(super::DEFAULT_TIMEOUT).map_err(map_http_err)?,
        })
    }
}

impl OllamaClient {
    /// The request body, separated from the call so its shape is testable
    /// without a server.
    fn request_body(&self, req: &LlmRequest) -> serde_json::Value {
        serde_json::json!({
            "model": self.model,
            "system": req.system,
            "prompt": req.user,
            "stream": false,
            "options": {
                "temperature": req.temperature,
                "num_predict": MAX_OUTPUT_TOKENS,
            },
        })
    }
}

impl LlmClient for OllamaClient {
    fn name(&self) -> String {
        format!("ollama/{}", self.model)
    }

    fn complete(&self, req: &LlmRequest) -> Result<String, LlmError> {
        let body = self.request_body(req);
        let resp = self
            .http
            .post_json_with(
                &format!("{}/api/generate", self.host),
                &body,
                &[],
                Some(req.timeout),
            )
            .map_err(map_http_err)?;
        resp.get("response")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                // An error body is JSON too, so "no `response` field" is the
                // only reliable signal that this is not a completion.
                LlmError::Transport("no `response` field in the reply".to_string())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> LlmRequest {
        LlmRequest {
            system: "s".into(),
            user: "u".into(),
            temperature: 0.0,
            timeout: std::time::Duration::from_millis(500),
        }
    }

    #[test]
    fn a_dead_endpoint_is_unavailable_not_a_panic() {
        let c = OllamaClient::new("http://127.0.0.1:1", "nope").unwrap();
        let err = c.complete(&req()).unwrap_err();
        assert!(
            matches!(
                err,
                LlmError::Unavailable(_) | LlmError::Transport(_) | LlmError::Timeout
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn client_name_identifies_the_model_for_the_report() {
        let c = OllamaClient::new("http://127.0.0.1:1", "qwen2.5-coder:14b").unwrap();
        assert!(
            c.name().contains("qwen2.5-coder:14b"),
            "RunMetadata::model comes from here; a bare backend name is not reproducible"
        );
        assert!(c.name().starts_with("ollama/"), "got: {}", c.name());
    }

    #[test]
    fn the_request_caps_generated_tokens() {
        // Pins the runaway-generation guard: without `num_predict`, a model
        // that starts repeating consumes the entire per-unit timeout and the
        // handler is dropped from the run.
        let c = OllamaClient::new("http://127.0.0.1:1", "m").unwrap();
        let body = c.request_body(&LlmRequest::new("s", "u"));
        assert_eq!(body["options"]["num_predict"], MAX_OUTPUT_TOKENS);
        assert_eq!(body["stream"], false, "a streamed reply would not parse");
    }

    #[test]
    fn a_trailing_slash_in_the_host_does_not_double_up_the_path() {
        let c = OllamaClient::new("http://localhost:11434/", "m").unwrap();
        assert_eq!(c.host, "http://localhost:11434");
    }

    #[test]
    fn the_trait_is_object_safe() {
        // Not trivial: the pipeline stores a `Box<dyn LlmClient>`, and a
        // generic method added to the trait later would break that with an
        // error far from its cause.
        let c: Box<dyn LlmClient> = Box::new(OllamaClient::new("http://127.0.0.1:1", "m").unwrap());
        assert!(!c.name().is_empty());
    }

    #[test]
    #[ignore = "needs a running Ollama with the generation model pulled"]
    fn live_ollama_returns_text() {
        let c = OllamaClient::new("http://localhost:11434", "qwen2.5-coder:14b").unwrap();
        let out = c
            .complete(&LlmRequest {
                system: "You reply with exactly one word.".into(),
                user: "Say OK.".into(),
                temperature: 0.0,
                timeout: std::time::Duration::from_secs(120),
            })
            .unwrap();
        assert!(!out.trim().is_empty());
    }
}
