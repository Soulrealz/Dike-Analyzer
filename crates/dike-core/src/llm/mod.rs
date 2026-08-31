//! The LLM seam: one request shape, one error type, one trait, two backends.
//!
//! Track 2 holds a `Box<dyn LlmClient>` and never names a backend, so the
//! model is a runtime choice and a test can substitute a stub with nothing
//! running.
//!
//! **The model is a parameter, never a constant.** The default generation
//! model lives in the CLI; swapping it — for a different local build, say —
//! must be a `--model` string and no code change.
//!
//! **Errors mirror [`crate::http::HttpError`] but are not it.** The
//! distinction that matters downstream is [`LlmError::Unavailable`]: it is
//! what the pipeline turns into a degraded run — Track 1 results plus a
//! diagnostic — rather than a failure.

pub mod gemini;
pub mod ollama;

use std::time::Duration;

pub use gemini::GeminiClient;
pub use ollama::OllamaClient;

use crate::http::HttpError;

/// The default per-request timeout (spec §9). A pathological handler must
/// not hang a run, and the ceiling belongs on the request rather than on the
/// shared client, whose other callers need seconds, not minutes.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// One completion request.
///
/// `temperature` defaults to `0.0` via [`LlmRequest::new`]. Track 2 is not
/// deterministic even so — a local model's sampling and batching still vary —
/// but there is no reason to add avoidable variance to an eval loop.
#[derive(Debug, Clone)]
pub struct LlmRequest {
    pub system: String,
    pub user: String,
    pub temperature: f32,
    pub timeout: Duration,
}

impl LlmRequest {
    pub fn new(system: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            system: system.into(),
            user: user.into(),
            temperature: 0.0,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Errors from an [`LlmClient`] call.
#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    /// The backend could not be reached. Load-bearing: the pipeline turns
    /// this into a degraded run, not a failed one.
    #[error("model backend unavailable: {0}")]
    Unavailable(String),
    #[error("model request timed out")]
    Timeout,
    #[error("transport error: {0}")]
    Transport(String),
    /// The backend was reached and declined — bad credentials, a missing
    /// key, a rejected request. Never carries credential material.
    #[error("refused: {0}")]
    Refused(String),
}

/// Map an HTTP-layer error to the LLM vocabulary.
///
/// 401 and 403 become [`LlmError::Refused`] because retrying or degrading is
/// the wrong response to "your credentials are wrong" — that needs a human.
/// Everything else that is not a connection or timeout failure is transport.
fn map_http_err(e: HttpError) -> LlmError {
    match e {
        HttpError::Unavailable(m) => LlmError::Unavailable(m),
        HttpError::Timeout => LlmError::Timeout,
        HttpError::Status(code @ (401 | 403)) => {
            LlmError::Refused(format!("backend rejected the request (status {code})"))
        }
        HttpError::Status(code) => LlmError::Transport(format!("http status {code}")),
        HttpError::Transport(m) => LlmError::Transport(m),
    }
}

/// A text-completion backend.
///
/// Object-safe on purpose: the pipeline stores a `Box<dyn LlmClient>`. Adding
/// a generic method here would break that at a call site far from the cause.
pub trait LlmClient {
    /// Backend and model, e.g. `ollama/qwen2.5-coder:14b`. This is what a
    /// report records, so it must identify the exact model — a bare backend
    /// name is not reproducible.
    fn name(&self) -> String;
    fn complete(&self, req: &LlmRequest) -> Result<String, LlmError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_401_is_refused_and_a_500_is_transport() {
        // Retrying or degrading is the wrong response to bad credentials.
        assert!(matches!(
            map_http_err(HttpError::Status(401)),
            LlmError::Refused(_)
        ));
        match map_http_err(HttpError::Status(403)) {
            // Pins the code in the message: an earlier draft hard-coded 401
            // into the format string, so a 403 reported itself as a 401.
            LlmError::Refused(m) => assert!(m.contains("403"), "got: {m}"),
            other => panic!("expected Refused, got {other:?}"),
        }
        assert!(matches!(
            map_http_err(HttpError::Status(500)),
            LlmError::Transport(_)
        ));
    }

    #[test]
    fn an_unreachable_backend_maps_to_unavailable_not_transport() {
        // The pipeline branches on `Unavailable` to degrade instead of
        // failing; mapping it to `Transport` would turn "the model isn't
        // running" into a hard error.
        assert!(matches!(
            map_http_err(HttpError::Unavailable("refused".into())),
            LlmError::Unavailable(_)
        ));
        assert!(matches!(map_http_err(HttpError::Timeout), LlmError::Timeout));
    }

    #[test]
    fn a_request_defaults_to_zero_temperature_and_the_spec_timeout() {
        let r = LlmRequest::new("s", "u");
        assert_eq!(r.temperature, 0.0);
        assert_eq!(r.timeout, DEFAULT_TIMEOUT);
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(120));
    }
}
