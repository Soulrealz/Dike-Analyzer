//! The single HTTP surface for the whole project (D24). The embedder
//! (retrieval) and the LLM client both go through [`HttpClient`], so the
//! timeout policy and the connection-refused-to-[`HttpError::Unavailable`]
//! mapping are written exactly once, here.

use std::time::Duration;

/// Errors from an [`HttpClient`] call.
///
/// `Unavailable` is load-bearing: it is what a caller later turns into a
/// degraded-not-failed run, so a connection refusal must map here and not
/// to `Transport`.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("service unavailable: {0}")]
    Unavailable(String),
    #[error("request timed out")]
    Timeout,
    #[error("http status {0}")]
    Status(u16),
    #[error("transport error: {0}")]
    Transport(String),
}

/// The one HTTP client type used anywhere in this codebase.
pub struct HttpClient {
    client: reqwest::blocking::Client,
}

impl HttpClient {
    pub fn new(timeout: Duration) -> Result<Self, HttpError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .user_agent("dike/0.1 (+security triage; contact via repository)")
            .build()
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        Ok(Self { client })
    }

    pub fn get_bytes(&self, url: &str) -> Result<Vec<u8>, HttpError> {
        let resp = self.client.get(url).send().map_err(map_reqwest_err)?;
        let resp = check_status(resp)?;
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| HttpError::Transport(e.to_string()))
    }

    pub fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, HttpError> {
        self.post_json_with(url, body, &[], None)
    }

    /// `post_json` with per-request headers and an optional per-request
    /// timeout that overrides the client's default.
    ///
    /// Both exist for the LLM clients: a generation call needs minutes where
    /// a corpus fetch needs seconds (spec §9's pathological handler), and one
    /// backend authenticates with a header. Adding them here rather than
    /// letting those clients build their own `reqwest` requests is what keeps
    /// the connection-refused-to-[`HttpError::Unavailable`] mapping in one
    /// place (D24).
    ///
    /// Header values may be secrets. They are attached to the request and
    /// never logged, never echoed into an error, and never stored.
    pub fn post_json_with(
        &self,
        url: &str,
        body: &serde_json::Value,
        headers: &[(&str, &str)],
        timeout: Option<Duration>,
    ) -> Result<serde_json::Value, HttpError> {
        let mut req = self.client.post(url).json(body);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        if let Some(timeout) = timeout {
            req = req.timeout(timeout);
        }
        let resp = req.send().map_err(map_reqwest_err)?;
        let resp = check_status(resp)?;
        resp.json::<serde_json::Value>()
            .map_err(|e| HttpError::Transport(e.to_string()))
    }
}

fn map_reqwest_err(err: reqwest::Error) -> HttpError {
    if err.is_timeout() {
        HttpError::Timeout
    } else if err.is_connect() {
        HttpError::Unavailable(err.to_string())
    } else {
        HttpError::Transport(err.to_string())
    }
}

fn check_status(
    resp: reqwest::blocking::Response,
) -> Result<reqwest::blocking::Response, HttpError> {
    if resp.status().is_success() {
        Ok(resp)
    } else {
        Err(HttpError::Status(resp.status().as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dead_endpoint_is_unavailable_not_a_panic() {
        let c = HttpClient::new(std::time::Duration::from_millis(500)).unwrap();
        let err = c.get_bytes("http://127.0.0.1:1/x").unwrap_err();
        // Assert `Unavailable` exactly, not `Unavailable(_) | Transport(_)`.
        // The looser form would still pass if `map_reqwest_err` regressed
        // to mapping connection refusals to `Transport`, which is exactly
        // the failure mode the module docstring calls load-bearing: Task 22
        // branches on `Unavailable` specifically to turn "Ollama isn't
        // running" into a degraded run instead of a hard failure. Connecting
        // to 127.0.0.1:1 (a port nothing listens on) reliably yields
        // `is_connect() == true` in this environment, so `Unavailable` is
        // the one variant this test should accept.
        assert!(matches!(err, HttpError::Unavailable(_)), "got: {err:?}");
    }
}
