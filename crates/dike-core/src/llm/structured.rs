//! Structured output: parse the model's reply, retry once on a schema
//! violation, and drop any finding whose citations it invented.
//!
//! Three mechanisms, all from the spec:
//!
//! 1. **One retry, with the violation fed back** (§9). Never a third attempt,
//!    never a crash — a unit that fails twice is dropped and logged.
//! 2. **Tolerant parsing.** A 14B model wraps JSON in commentary and code
//!    fences constantly. Failing on that throws away good findings, so the
//!    parser strips fences and, if prose surrounds the array, extracts from
//!    the first `[` to the last `]`.
//! 3. **Citation validation (D12).** A citation naming a document that was
//!    never offered is deleted; a finding left with none is dropped. This is
//!    what turns grounding from a claim into a filter — without it, "cite
//!    your sources" is a request the model can decline silently.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use crate::finding::{Citation, Finding, Location, Severity, Track, VulnClass};
use crate::llm::{LlmClient, LlmError, LlmRequest};
use crate::merge::track2_confidence;
use crate::retrieval::rrf::RetrievalHit;

/// A finding exactly as the model reported it — untrusted until validated.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RawLlmFinding {
    pub class: String,
    pub severity: String,
    pub confidence: f32,
    pub handler: String,
    /// Optional: a model that cannot place a finding on a line says so
    /// rather than inventing one.
    #[serde(default)]
    pub line: Option<u32>,
    pub evidence: String,
    #[serde(default)]
    pub citations: Vec<String>,
}

/// The reply did not match the schema. The message is fed back to the model
/// on the single retry, so it must describe what was wrong.
#[derive(Debug, Clone, PartialEq)]
pub struct SchemaViolation(pub String);

/// Parse a model reply into findings, tolerating fences and surrounding prose.
pub fn parse_findings(raw: &str) -> Result<Vec<RawLlmFinding>, SchemaViolation> {
    let candidate = extract_json_array(raw)
        .ok_or_else(|| SchemaViolation("no JSON array found in the response".to_string()))?;
    serde_json::from_str::<Vec<RawLlmFinding>>(&candidate)
        .map_err(|e| SchemaViolation(format!("JSON did not match the schema: {e}")))
}

/// Find the JSON array in a reply.
///
/// Fences are stripped first, then the span from the first `[` to the last
/// `]` is taken. Taking the *last* `]` rather than the first matters: a
/// finding's own `citations` array closes before the outer one does, so
/// stopping at the first close would truncate every multi-finding reply.
fn extract_json_array(raw: &str) -> Option<String> {
    let without_fences = strip_code_fences(raw);
    let start = without_fences.find('[')?;
    let end = without_fences.rfind(']')?;
    if end < start {
        return None;
    }
    Some(without_fences[start..=end].to_string())
}

/// Remove ```` ``` ```` fences, keeping their contents.
fn strip_code_fences(raw: &str) -> String {
    raw.lines()
        .filter(|l| !l.trim_start().starts_with("```"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The instruction appended to the retry prompt.
fn retry_suffix(violation: &SchemaViolation) -> String {
    format!(
        "\n\nYour previous response was rejected: {}. Return only a JSON array \
         matching the schema, with no prose and no code fences.",
        violation.0
    )
}

/// Complete `req` and parse the reply, retrying once on a schema violation.
///
/// A transport failure propagates. Flattening it into `Ok(vec![])` would make
/// "the model reviewed this and found nothing" indistinguishable from "the
/// model is not running", and the report would claim coverage it never had.
pub fn complete_structured(
    client: &dyn LlmClient,
    req: &LlmRequest,
) -> Result<Vec<RawLlmFinding>, LlmError> {
    let first = client.complete(req)?;
    let violation = match parse_findings(&first) {
        Ok(findings) => return Ok(findings),
        Err(v) => v,
    };
    tracing::warn!(violation = %violation.0, "model reply failed the schema; retrying once");

    let mut retry = req.clone();
    retry.user.push_str(&retry_suffix(&violation));
    let second = client.complete(&retry)?;
    match parse_findings(&second) {
        Ok(findings) => Ok(findings),
        Err(v) => {
            // Drop and log. A third attempt would spend another 120-second
            // budget on a model that has now failed the same schema twice.
            tracing::warn!(
                violation = %v.0,
                "model reply failed the schema twice; dropping this unit"
            );
            Ok(Vec::new())
        }
    }
}

/// Turn a reported finding into a real one, or drop it.
///
/// Citations naming documents that were never offered are deleted (D12), and
/// a finding with no surviving citation returns `None`. `file` is a parameter
/// because a `RawLlmFinding` carries no path and a `Location` needs one (D27).
pub fn validate_citations(
    f: RawLlmFinding,
    offered: &[RetrievalHit],
    file: &Path,
) -> Option<Finding> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let citations: Vec<Citation> = f
        .citations
        .iter()
        // A duplicate must not inflate confidence: `track2_confidence`
        // reads the count, so citing one document twice would otherwise
        // buy the same up-weighting as citing two.
        .filter(|id| seen.insert(id.as_str()))
        .filter_map(|id| offered.iter().find(|h| &h.document.id == id))
        .map(|hit| Citation {
            doc_id: hit.document.id.clone(),
            source_url: hit.document.source_url.clone(),
            title: hit.document.title.clone(),
        })
        .collect();

    if citations.is_empty() {
        return None;
    }

    let location = Location {
        file: file.to_path_buf(),
        line: f.line.unwrap_or(0),
        handler: f.handler.clone(),
    };
    // Same shape as the static track's ids (`detectors::finding_at`), so the
    // two tracks' ids are recognisable as the same kind of thing.
    let id = {
        let seed = format!("{}|{}|{}", location.handler_id(), f.class, location.line);
        blake3::hash(seed.as_bytes()).to_hex()[..16].to_string()
    };

    Some(Finding {
        id,
        class: VulnClass::new(f.class),
        severity: parse_severity(&f.severity),
        confidence: track2_confidence(f.confidence, citations.len()),
        track: Track::Llm,
        location,
        evidence: f.evidence,
        citations,
    })
}

/// Parse a severity, case-insensitively, defaulting to `Medium`.
///
/// An unrecognised label is a reporting quirk, not a reason to lose the
/// finding — and defaulting to the middle avoids both burying it and
/// promoting it (Rule 3).
fn parse_severity(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" | "informational" => Severity::Info,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retrieval::document::Document;
    use std::cell::RefCell;
    use std::path::PathBuf;

    fn hit_with_id(id: &str) -> RetrievalHit {
        RetrievalHit {
            document: Document {
                id: id.to_string(),
                source_url: format!("https://example.invalid/{id}"),
                title: format!("document {id}"),
                text: "text".into(),
                class_tags: vec![],
            },
            rrf_score: 0.03,
            dense_score: Some(1.0),
            bm25_score: Some(1.0),
        }
    }

    fn raw_finding(citations: Vec<String>) -> RawLlmFinding {
        RawLlmFinding {
            class: "missing-owner-check".into(),
            severity: "high".into(),
            confidence: 0.8,
            handler: "withdraw".into(),
            line: Some(12),
            evidence: "e".into(),
            citations,
        }
    }

    fn file() -> PathBuf {
        "src/lib.rs".into()
    }

    fn sample_request() -> LlmRequest {
        LlmRequest::new("system prompt", "review this unit")
    }

    const VALID_JSON: &str = r#"[{"class":"c","severity":"low","confidence":0.5,
        "handler":"h","line":3,"evidence":"e","citations":["d1"]}]"#;

    /// Records every request and replies from a scripted list, repeating the
    /// last reply once the script runs out.
    #[derive(Default)]
    struct ScriptedClient {
        replies: Vec<String>,
        seen: RefCell<Vec<LlmRequest>>,
    }

    impl ScriptedClient {
        fn new(replies: &[&str]) -> Self {
            Self {
                replies: replies.iter().map(|s| s.to_string()).collect(),
                seen: RefCell::new(Vec::new()),
            }
        }
        fn calls(&self) -> usize {
            self.seen.borrow().len()
        }
        fn requests(&self) -> Vec<LlmRequest> {
            self.seen.borrow().clone()
        }
    }

    impl LlmClient for ScriptedClient {
        fn name(&self) -> String {
            "scripted/test".to_string()
        }
        fn complete(&self, req: &LlmRequest) -> Result<String, LlmError> {
            let n = self.seen.borrow().len();
            self.seen.borrow_mut().push(req.clone());
            let idx = n.min(self.replies.len().saturating_sub(1));
            Ok(self.replies.get(idx).cloned().unwrap_or_default())
        }
    }

    struct DeadClient;

    impl LlmClient for DeadClient {
        fn name(&self) -> String {
            "dead/test".to_string()
        }
        fn complete(&self, _req: &LlmRequest) -> Result<String, LlmError> {
            Err(LlmError::Unavailable("connection refused".into()))
        }
    }

    /// The prompt shape Task 22 will use, kept free of domain vocabulary so
    /// the seam gate stays happy (this crate must name no chain or framework).
    const LIVE_SYSTEM: &str = "You review code for security defects. Reply with ONLY a JSON \
         array. Each element must have exactly these fields: class (string), severity \
         (one of critical, high, medium, low, info), confidence (number between 0 and 1), \
         handler (string), line (integer or null), evidence (string), citations (array of \
         the document ids you used). Cite only ids from the provided documents. If you \
         find nothing, reply with [].";

    const LIVE_USER: &str = "Documents:\n[d1] A privileged operation must verify that the \
         caller signed the transaction before mutating stored balances.\n\nCode under \
         review, function `withdraw`:\n  fn withdraw(ctx: Ctx, amount: u64) {\n      let s \
         = &mut ctx.state;\n      s.balance = s.balance - amount;\n  }\n\nThe caller is \
         never checked. Report findings as JSON.";

    #[test]
    #[ignore = "needs a running local model"]
    fn live_model_output_survives_the_parser() {
        // The mechanism this exercises is tolerant parsing: a 14B model
        // wraps JSON in commentary and fences constantly, and this is the
        // only way to find out whether the parser copes with what THIS
        // model actually emits rather than what a fixture says it emits.
        let client = crate::llm::OllamaClient::new("http://localhost:11434", "qwen2.5-coder:14b")
            .unwrap();
        let mut req = LlmRequest::new(LIVE_SYSTEM, LIVE_USER);
        req.timeout = std::time::Duration::from_secs(180);

        let raw = client.complete(&req).unwrap();
        println!("--- raw model reply ---\n{raw}\n--- end ---");

        let parsed = parse_findings(&raw).expect("the parser must cope with real model output");
        println!("parsed {} finding(s)", parsed.len());
        for f in &parsed {
            println!("  class={} severity={} citations={:?}", f.class, f.severity, f.citations);
        }
    }

    #[test]
    #[ignore = "needs a running local model"]
    fn live_end_to_end_produces_a_validated_finding() {
        // Parsing is not the point on its own — the point is whether a real
        // reply survives citation validation and becomes a Finding.
        let client = crate::llm::OllamaClient::new("http://localhost:11434", "qwen2.5-coder:14b")
            .unwrap();
        let mut req = LlmRequest::new(LIVE_SYSTEM, LIVE_USER);
        req.timeout = std::time::Duration::from_secs(180);

        let offered = vec![hit_with_id("d1")];
        let raws = complete_structured(&client, &req).unwrap();
        let kept: Vec<Finding> = raws
            .into_iter()
            .filter_map(|r| validate_citations(r, &offered, &file()))
            .collect();
        println!("{} finding(s) survived citation validation", kept.len());
        for f in &kept {
            println!(
                "  {} [{:?}] confidence={:.2} citations={:?}",
                f.class.as_str(),
                f.severity,
                f.confidence,
                f.citations.iter().map(|c| &c.doc_id).collect::<Vec<_>>()
            );
        }
    }

    // --- parsing ---------------------------------------------------------

    #[test]
    fn parses_json_wrapped_in_prose_and_fences() {
        let raw = "Here is what I found:\n```json\n[{\"class\":\"missing-signer\",\
                   \"severity\":\"critical\",\"confidence\":0.8,\"handler\":\"withdraw\",\
                   \"line\":12,\"evidence\":\"e\",\"citations\":[\"d1\"]}]\n```\nHope that helps!";
        let parsed = parse_findings(raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].class, "missing-signer");
    }

    #[test]
    fn parses_a_bare_array_with_no_decoration() {
        assert_eq!(parse_findings("[]").unwrap().len(), 0);
    }

    #[test]
    fn empty_array_is_a_valid_response_not_a_violation() {
        assert!(parse_findings("Nothing found.\n[]\n").is_ok());
    }

    #[test]
    fn a_null_line_parses_as_none() {
        let raw = "[{\"class\":\"c\",\"severity\":\"low\",\"confidence\":0.1,\
                   \"handler\":\"h\",\"line\":null,\"evidence\":\"e\",\"citations\":[]}]";
        assert!(parse_findings(raw).unwrap()[0].line.is_none());
    }

    #[test]
    fn a_missing_optional_field_does_not_reject_the_whole_array() {
        let raw = "[{\"class\":\"c\",\"severity\":\"low\",\"confidence\":0.1,\
                   \"handler\":\"h\",\"evidence\":\"e\",\"citations\":[]}]";
        assert!(parse_findings(raw).is_ok(), "`line` is optional; #[serde(default)]");
    }

    #[test]
    fn rejects_non_json_with_a_violation_message() {
        let err = parse_findings("I could not find anything of note.").unwrap_err();
        assert!(!err.0.is_empty(), "the message is fed back to the model on retry");
    }

    #[test]
    fn rejects_a_json_object_that_is_not_an_array() {
        assert!(parse_findings("{\"class\":\"c\"}").is_err());
    }

    #[test]
    fn several_findings_survive_their_own_nested_arrays() {
        // Extraction runs to the LAST `]`, not the first: each finding's
        // `citations` array closes before the outer one does, so stopping at
        // the first close would truncate every multi-finding reply into
        // invalid JSON.
        let raw = r#"Findings:
[{"class":"a","severity":"low","confidence":0.2,"handler":"h","evidence":"e","citations":["d1"]},
 {"class":"b","severity":"high","confidence":0.7,"handler":"h","evidence":"e","citations":["d2","d3"]}]
That is all."#;
        let parsed = parse_findings(raw).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].citations.len(), 2);
    }

    #[test]
    fn a_truncated_reply_is_a_violation_not_a_partial_finding() {
        // A model that runs out of tokens mid-array must not yield a
        // half-parsed finding whose fields are whatever survived.
        let raw = r#"[{"class":"a","severity":"low","confidence":0.2,"handler":"#;
        assert!(parse_findings(raw).is_err());
    }

    // --- citation validation ---------------------------------------------

    #[test]
    fn hallucinated_citations_are_stripped_and_uncited_findings_dropped() {
        let offered = vec![hit_with_id("d1"), hit_with_id("d2")];
        let mut f = raw_finding(vec!["d1".into(), "d99".into()]);
        let kept = validate_citations(f.clone(), &offered, &file()).unwrap();
        assert_eq!(kept.citations.len(), 1);
        assert_eq!(kept.citations[0].doc_id, "d1");

        f.citations = vec!["d99".into()];
        assert!(
            validate_citations(f.clone(), &offered, &file()).is_none(),
            "no valid citation, no finding"
        );
        f.citations = vec![];
        assert!(validate_citations(f, &offered, &file()).is_none());
    }

    #[test]
    fn a_kept_finding_carries_a_complete_location() {
        let offered = vec![hit_with_id("d1")];
        let f = validate_citations(raw_finding(vec!["d1".into()]), &offered, &file()).unwrap();
        assert_eq!(f.location.file, file(), "D27: the file comes from the caller");
        assert_eq!(f.location.handler, "withdraw");
        assert_eq!(f.location.line, 12);
        assert_eq!(f.track, Track::Llm);
    }

    #[test]
    fn citations_carry_the_document_url_and_title_for_the_report() {
        let offered = vec![hit_with_id("d1")];
        let f = validate_citations(raw_finding(vec!["d1".into()]), &offered, &file()).unwrap();
        assert!(!f.citations[0].source_url.is_empty());
        assert!(!f.citations[0].title.is_empty());
    }

    #[test]
    fn single_citation_findings_are_down_weighted() {
        let offered = vec![hit_with_id("d1"), hit_with_id("d2")];
        let one = validate_citations(raw_finding(vec!["d1".into()]), &offered, &file()).unwrap();
        let two = validate_citations(
            raw_finding(vec!["d1".into(), "d2".into()]),
            &offered,
            &file(),
        )
        .unwrap();
        assert!(one.confidence < two.confidence);
    }

    #[test]
    fn an_unrecognized_severity_defaults_to_medium() {
        let offered = vec![hit_with_id("d1")];
        let mut f = raw_finding(vec!["d1".into()]);
        f.severity = "spicy".into();
        assert_eq!(
            validate_citations(f, &offered, &file()).unwrap().severity,
            Severity::Medium
        );
    }

    #[test]
    fn severity_parsing_is_case_insensitive() {
        let offered = vec![hit_with_id("d1")];
        let mut f = raw_finding(vec!["d1".into()]);
        f.severity = "CRITICAL".into();
        assert_eq!(
            validate_citations(f, &offered, &file()).unwrap().severity,
            Severity::Critical
        );
    }

    #[test]
    fn a_duplicate_citation_is_counted_once() {
        let offered = vec![hit_with_id("d1"), hit_with_id("d2")];
        let dup = validate_citations(
            raw_finding(vec!["d1".into(), "d1".into()]),
            &offered,
            &file(),
        )
        .unwrap();
        assert_eq!(dup.citations.len(), 1, "duplicates must not inflate confidence");
    }

    #[test]
    fn a_duplicate_citation_does_not_buy_the_two_citation_confidence() {
        // The consequence of the test above, asserted where it actually
        // matters: `track2_confidence` reads the count.
        let offered = vec![hit_with_id("d1"), hit_with_id("d2")];
        let dup = validate_citations(
            raw_finding(vec!["d1".into(), "d1".into()]),
            &offered,
            &file(),
        )
        .unwrap();
        let one = validate_citations(raw_finding(vec!["d1".into()]), &offered, &file()).unwrap();
        assert!((dup.confidence - one.confidence).abs() < 1e-6);
    }

    #[test]
    fn a_missing_line_becomes_zero_rather_than_dropping_the_finding() {
        // Invariant 9 says a *static* finding never points at line 0; a
        // model that will not guess a line is reporting honestly, and
        // dropping the finding for it would lose a real one (Rule 3).
        let offered = vec![hit_with_id("d1")];
        let mut f = raw_finding(vec!["d1".into()]);
        f.line = None;
        let kept = validate_citations(f, &offered, &file()).unwrap();
        assert_eq!(kept.location.line, 0);
    }

    #[test]
    fn confidence_is_clamped_into_the_track_2_band() {
        let offered = vec![hit_with_id("d1"), hit_with_id("d2")];
        let mut f = raw_finding(vec!["d1".into(), "d2".into()]);
        f.confidence = 5.0;
        let high = validate_citations(f.clone(), &offered, &file()).unwrap();
        assert!(high.confidence <= 0.90, "got {}", high.confidence);
        f.confidence = -1.0;
        let low = validate_citations(f, &offered, &file()).unwrap();
        assert!(low.confidence >= 0.10, "got {}", low.confidence);
    }

    #[test]
    fn two_findings_in_one_handler_get_different_ids() {
        let offered = vec![hit_with_id("d1")];
        let mut a = raw_finding(vec!["d1".into()]);
        a.class = "class-one".into();
        let mut b = raw_finding(vec!["d1".into()]);
        b.class = "class-two".into();
        let fa = validate_citations(a, &offered, &file()).unwrap();
        let fb = validate_citations(b, &offered, &file()).unwrap();
        assert_ne!(fa.id, fb.id);
        assert_eq!(fa.id.len(), 16, "same shape as the static track's ids");
    }

    // --- retry -----------------------------------------------------------

    #[test]
    fn a_first_violation_is_retried_once_and_the_retry_is_used() {
        let client = ScriptedClient::new(&["I did not find anything.", VALID_JSON]);
        let out = complete_structured(&client, &sample_request()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(client.calls(), 2, "exactly one retry");
    }

    #[test]
    fn a_valid_first_reply_is_not_retried() {
        let client = ScriptedClient::new(&[VALID_JSON]);
        complete_structured(&client, &sample_request()).unwrap();
        assert_eq!(client.calls(), 1, "a good reply must not cost a second call");
    }

    #[test]
    fn the_retry_prompt_carries_the_violation_back_to_the_model() {
        let client = ScriptedClient::new(&["prose only", "still prose"]);
        let _ = complete_structured(&client, &sample_request());
        let requests = client.requests();
        let second = &requests[1];
        assert!(
            second.user.contains("was rejected"),
            "the model is told what was wrong: {}",
            second.user
        );
        assert!(
            second.user.contains(&requests[0].user),
            "the original task survives the retry"
        );
    }

    #[test]
    fn the_retry_keeps_the_system_prompt_and_the_timeout() {
        // The retry is the same request with an appended note, not a fresh
        // one: losing the system prompt would change what is being asked.
        let client = ScriptedClient::new(&["prose only", VALID_JSON]);
        let _ = complete_structured(&client, &sample_request());
        let requests = client.requests();
        assert_eq!(requests[1].system, requests[0].system);
        assert_eq!(requests[1].timeout, requests[0].timeout);
        assert_eq!(requests[1].temperature, requests[0].temperature);
    }

    #[test]
    fn a_second_schema_violation_drops_the_unit_without_erroring() {
        let client = ScriptedClient::new(&["prose only", "still prose"]);
        let out = complete_structured(&client, &sample_request());
        assert!(
            matches!(out, Ok(ref v) if v.is_empty()),
            "drop and log, never crash"
        );
        assert_eq!(client.calls(), 2, "never a third attempt");
    }

    #[test]
    fn a_transport_error_propagates_rather_than_being_swallowed_as_empty() {
        let client = DeadClient;
        assert!(matches!(
            complete_structured(&client, &sample_request()),
            Err(LlmError::Unavailable(_) | LlmError::Transport(_))
        ));
    }

    #[test]
    fn a_transport_error_on_the_retry_also_propagates() {
        // The first call succeeded but failed the schema, and the model went
        // away before the second. Reporting that as "found nothing" would
        // claim coverage the run never had.
        struct FailSecond {
            calls: RefCell<usize>,
        }
        impl LlmClient for FailSecond {
            fn name(&self) -> String {
                "failsecond/test".to_string()
            }
            fn complete(&self, _req: &LlmRequest) -> Result<String, LlmError> {
                let mut c = self.calls.borrow_mut();
                *c += 1;
                if *c == 1 {
                    Ok("prose only".to_string())
                } else {
                    Err(LlmError::Timeout)
                }
            }
        }
        let client = FailSecond {
            calls: RefCell::new(0),
        };
        assert!(matches!(
            complete_structured(&client, &sample_request()),
            Err(LlmError::Timeout)
        ));
    }
}
