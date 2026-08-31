//! Gemini backend: a hosted model, authenticated with an API key.
//!
//! **Secret handling is a hard rule here.** The key is read from the
//! environment at construction, held in memory for the process's lifetime,
//! and sent in the `x-goog-api-key` header — never in the URL, because URLs
//! reach logs, proxies and error messages. It is never persisted, never
//! logged, and never included in an error: the failure message for a missing
//! key says only that it is missing.

use crate::http::HttpClient;
use crate::llm::{map_http_err, LlmClient, LlmError, LlmRequest};

const API_ROOT: &str = "https://generativelanguage.googleapis.com/v1beta/models";
const KEY_VAR: &str = "GEMINI_API_KEY";

pub struct GeminiClient {
    pub model: String,
    api_key: String,
    http: HttpClient,
}

impl GeminiClient {
    /// Build a client from `GEMINI_API_KEY`.
    ///
    /// A missing or blank key is [`LlmError::Refused`] whose message names
    /// the variable and nothing else.
    pub fn from_env(model: impl Into<String>) -> Result<Self, LlmError> {
        let api_key = std::env::var(KEY_VAR).unwrap_or_default();
        if api_key.trim().is_empty() {
            return Err(LlmError::Refused(format!("{KEY_VAR} is not set")));
        }
        Ok(Self {
            model: model.into(),
            api_key,
            http: HttpClient::new(super::DEFAULT_TIMEOUT).map_err(map_http_err)?,
        })
    }
}

/// Redacting `Debug`, written by hand rather than derived.
///
/// A derived one would print the key into any `{:?}`, `unwrap` panic,
/// `assert!` message or `tracing` field that ever touched this struct — the
/// exact way secrets leak into logs.
impl std::fmt::Debug for GeminiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeminiClient")
            .field("model", &self.model)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl LlmClient for GeminiClient {
    fn name(&self) -> String {
        format!("gemini/{}", self.model)
    }

    fn complete(&self, req: &LlmRequest) -> Result<String, LlmError> {
        let body = serde_json::json!({
            "system_instruction": { "parts": [{ "text": req.system }] },
            "contents": [{ "parts": [{ "text": req.user }] }],
            "generationConfig": { "temperature": req.temperature },
        });
        let resp = self
            .http
            .post_json_with(
                &format!("{API_ROOT}/{}:generateContent", self.model),
                &body,
                // In the header, never the URL.
                &[("x-goog-api-key", self.api_key.as_str())],
                Some(req.timeout),
            )
            .map_err(map_http_err)?;
        extract_text(&resp)
    }
}

/// Pull the completion text out of a Gemini response.
///
/// A response with no candidate is not an empty completion: it is what a
/// safety block or a malformed request looks like, and returning `""` would
/// let that reach a report as a model that had nothing to say.
fn extract_text(resp: &serde_json::Value) -> Result<String, LlmError> {
    resp.get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .and_then(|p| p.first())
        .and_then(|p| p.get("text"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| LlmError::Transport("no candidate text in the reply".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `std::env` is process-global and the test harness is threaded, so the
    /// two tests that touch `GEMINI_API_KEY` must not overlap.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn a_missing_gemini_key_is_refused_without_echoing_anything() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore = std::env::var(KEY_VAR).ok();
        std::env::remove_var(KEY_VAR);

        let err = GeminiClient::from_env("gemini-2.0-flash").unwrap_err();

        if let Some(v) = restore {
            std::env::set_var(KEY_VAR, v);
        }
        match err {
            LlmError::Refused(m) => {
                assert!(m.contains(KEY_VAR), "the message must name the variable: {m}");
                assert!(
                    !m.to_lowercase().contains("aiza"),
                    "never echo key material"
                );
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn a_blank_key_is_refused_rather_than_sent() {
        // An empty or whitespace `GEMINI_API_KEY` is a misconfiguration, not
        // a credential. Sending it would produce a confusing 401 from the
        // API instead of an actionable message here.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore = std::env::var(KEY_VAR).ok();
        std::env::set_var(KEY_VAR, "   ");

        let err = GeminiClient::from_env("gemini-2.0-flash").unwrap_err();

        match restore {
            Some(v) => std::env::set_var(KEY_VAR, v),
            None => std::env::remove_var(KEY_VAR),
        }
        assert!(matches!(err, LlmError::Refused(_)), "got: {err:?}");
    }

    #[test]
    fn the_api_key_never_appears_in_the_request_url() {
        // The URL is the one part of a request that reliably reaches logs
        // and error messages, which is why the key travels in a header.
        let url = format!("{API_ROOT}/gemini-2.0-flash:generateContent");
        assert!(!url.contains("key"), "got: {url}");
        assert!(url.starts_with("https://"), "got: {url}");
    }

    #[test]
    fn a_well_formed_response_yields_its_text() {
        let resp = serde_json::json!({
            "candidates": [{ "content": { "parts": [{ "text": "hello" }] } }]
        });
        assert_eq!(extract_text(&resp).unwrap(), "hello");
    }

    #[test]
    fn a_blocked_or_empty_response_is_an_error_not_an_empty_completion() {
        // A safety block returns candidates without text; treating that as
        // "" would put a silent non-answer into a report.
        let blocked = serde_json::json!({ "promptFeedback": { "blockReason": "SAFETY" } });
        assert!(matches!(
            extract_text(&blocked),
            Err(LlmError::Transport(_))
        ));
        let empty = serde_json::json!({ "candidates": [] });
        assert!(matches!(extract_text(&empty), Err(LlmError::Transport(_))));
    }

    #[test]
    fn debug_output_redacts_the_api_key() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore = std::env::var(KEY_VAR).ok();
        std::env::set_var(KEY_VAR, "AIzaSyTOTALLYNOTAREALKEY");

        let c = GeminiClient::from_env("gemini-2.0-flash").unwrap();
        let printed = format!("{c:?}");

        match restore {
            Some(v) => std::env::set_var(KEY_VAR, v),
            None => std::env::remove_var(KEY_VAR),
        }
        assert!(
            !printed.contains("AIzaSyTOTALLYNOTAREALKEY"),
            "the key reached a Debug string: {printed}"
        );
        assert!(printed.contains("<redacted>"), "got: {printed}");
        assert!(printed.contains("gemini-2.0-flash"), "got: {printed}");
    }

    #[test]
    fn client_name_identifies_the_model() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let restore = std::env::var(KEY_VAR).ok();
        std::env::set_var(KEY_VAR, "not-a-real-key");

        let c = GeminiClient::from_env("gemini-2.0-flash").unwrap();
        let name = c.name();

        match restore {
            Some(v) => std::env::set_var(KEY_VAR, v),
            None => std::env::remove_var(KEY_VAR),
        }
        assert_eq!(name, "gemini/gemini-2.0-flash");
    }
}
