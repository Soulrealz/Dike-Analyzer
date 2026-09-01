//! Track 2 assembled: chunk, retrieve, ask, validate.
//!
//! Per unit: derive the query, retrieve, check grounding, prompt the model,
//! parse, validate citations, emit. Two properties are load-bearing and each
//! has a test that cannot be satisfied by reading the prompt file:
//!
//! - **The prompt never contains Track 1's findings (D29).** Not as context,
//!   not as hints, not as a "check these" list. If Track 2 is told what the
//!   static track found, corroboration is circular and every eval number
//!   built on it is self-congratulatory.
//! - **The prompt never tells the model to skip what Track 1 covers (D30).**
//!   That instruction would suppress exactly the overlap `merge_key`
//!   collision detection exists to find, making `Track::Corroborated`
//!   unreachable. Two independent methods agreeing is the strongest signal
//!   this tool can produce.
//!
//! An unavailable model stops the track, emits one `TrackSkipped`
//! diagnostic, and returns what was collected: degraded, not failed.

use dike_core::analyzer::{
    AnalysisResult, Analyzer, Diagnostic, DiagnosticKind, SourceTree, UnitCoverage,
};
use dike_core::finding::Finding;
use dike_core::llm::structured::{complete_structured, validate_citations};
use dike_core::llm::{LlmClient, LlmError, LlmRequest};
use dike_core::retrieval::rrf::{is_grounded, RetrievalHit};
use dike_core::retrieval::retriever::Retrieve;

use crate::chunker::{chunk, HandlerUnit};
use crate::parser::parse_tree;

/// The system prompt. Loaded at compile time so a deployed binary can never
/// disagree with the repository about what was asked.
const SYSTEM_PROMPT: &str = include_str!("../prompts/track2.md");

/// Retrieval-grounded review of one handler at a time.
pub struct LlmAnalyzer {
    pub client: Box<dyn LlmClient>,
    /// A trait, not a concrete retriever (D19), so this is testable with a
    /// stub and no model or corpus.
    pub retriever: Box<dyn Retrieve>,
    pub top_k: usize,
}

impl LlmAnalyzer {
    pub fn new(client: Box<dyn LlmClient>, retriever: Box<dyn Retrieve>, top_k: usize) -> Self {
        Self {
            client,
            retriever,
            top_k,
        }
    }
}

/// Render the retrieved documents and the unit into the user prompt.
///
/// Every document is labelled `[doc_id: <id>]`. Citations are only checkable
/// if the model can see the ids it is meant to cite.
fn build_user_prompt(unit: &HandlerUnit, hits: &[RetrievalHit]) -> String {
    let mut out = String::new();
    out.push_str("## Reference documents\n\n");
    for hit in hits {
        out.push_str(&format!(
            "[doc_id: {}] {}\n{}\n\n",
            hit.document.id, hit.document.title, hit.document.text
        ));
    }
    out.push_str("## Code under review\n\n");
    out.push_str(&format!("Instruction handler: {}\n\n", unit.handler_name));
    out.push_str("```rust\n");
    out.push_str(&unit.source);
    out.push_str("\n```\n");
    out
}

impl Analyzer for LlmAnalyzer {
    fn name(&self) -> &'static str {
        "llm"
    }

    fn analyze(&self, tree: &SourceTree) -> AnalysisResult {
        let parsed = parse_tree(tree);
        let units = chunk(&parsed.program, tree);

        let mut findings: Vec<Finding> = Vec::new();
        let mut diagnostics: Vec<Diagnostic> = Vec::new();
        let mut examined = 0usize;

        for unit in &units {
            let hits = match self.retriever.search(&unit.query, self.top_k) {
                Ok(h) => h,
                Err(e) => {
                    // Retrieval failing for one unit is not the whole track
                    // failing: the next unit's query may well succeed.
                    diagnostics.push(Diagnostic {
                        file: Some(unit.file.clone()),
                        kind: DiagnosticKind::Skipped,
                        message: format!(
                            "retrieval failed for handler `{}`: {e:#}",
                            unit.handler_name
                        ),
                    });
                    continue;
                }
            };

            // The grounding gate is a filter, not a hint: an ungrounded unit
            // is not reviewed at all, so nothing the model might invent
            // about it can reach a report.
            if !is_grounded(&hits) {
                continue;
            }

            let mut req = LlmRequest::new(SYSTEM_PROMPT, build_user_prompt(unit, &hits));
            req.temperature = 0.0;

            let raws = match complete_structured(self.client.as_ref(), &req) {
                Ok(r) => r,
                Err(LlmError::Unavailable(msg)) => {
                    // Stop the whole track. Continuing would issue one
                    // failing request per unit and produce one diagnostic
                    // per unit for a single cause.
                    diagnostics.push(Diagnostic {
                        file: None,
                        kind: DiagnosticKind::TrackSkipped,
                        message: format!(
                            "LLM track stopped after {examined} unit(s): model unavailable: {msg}"
                        ),
                    });
                    return AnalysisResult {
                        findings,
                        diagnostics,
                        files_analyzed: parsed.files_parsed,
                        units: Some(UnitCoverage {
                            total: units.len(),
                            examined,
                        }),
                    };
                }
                Err(e) => {
                    diagnostics.push(Diagnostic {
                        file: Some(unit.file.clone()),
                        kind: DiagnosticKind::Skipped,
                        message: format!("handler `{}` was not reviewed: {e}", unit.handler_name),
                    });
                    continue;
                }
            };

            examined += 1;

            for raw in raws {
                // A finding naming a handler this program does not have
                // cannot be located, cited or corroborated — and the model
                // does occasionally answer about a helper it saw in the
                // unit's context rather than the handler under review.
                let Some(handler) = parsed.program.handler(&raw.handler) else {
                    diagnostics.push(Diagnostic {
                        file: Some(unit.file.clone()),
                        kind: DiagnosticKind::Skipped,
                        message: format!(
                            "discarded a finding naming unknown handler `{}`",
                            raw.handler
                        ),
                    });
                    continue;
                };
                // A finding pointing at line 0 destroys trust in every other
                // line number in the report, so an absent line falls back to
                // the handler's own (the rule Task 10 applies to attr_line).
                let mut raw = raw;
                if raw.line.unwrap_or(0) == 0 {
                    raw.line = Some(handler.line);
                }
                if let Some(f) = validate_citations(raw, &hits, &handler.file) {
                    findings.push(f);
                }
            }
        }

        AnalysisResult {
            findings,
            diagnostics,
            files_analyzed: parsed.files_parsed,
            units: Some(UnitCoverage {
                total: units.len(),
                examined,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dike_core::analyzer::SourceFile;
    use dike_core::finding::{Finding, Location, Severity, Track, VulnClass};
    use dike_core::retrieval::document::Document;
    use std::cell::RefCell;
    use std::path::PathBuf;

    const SRC: &str = r#"
#[program]
pub mod vault {
    use super::*;
    pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.amount = v.amount - amount;
        Ok(())
    }
}
#[account]
pub struct Vault { pub admin: Pubkey, pub amount: u64 }
#[derive(Accounts)]
pub struct W<'info> {
    pub authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
"#;

    fn fixture_tree() -> SourceTree {
        SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile {
                path: PathBuf::from("lib.rs"),
                text: SRC.to_string(),
            }],
        }
    }

    fn doc(id: &str) -> Document {
        Document {
            id: id.to_string(),
            source_url: format!("https://example.invalid/{id}"),
            title: format!("document {id}"),
            text: "Reference text about validating accounts.".to_string(),
            class_tags: vec![],
        }
    }

    struct StubRetriever {
        dense: f32,
        bm25: f32,
    }

    impl StubRetriever {
        fn grounded() -> Self {
            Self {
                dense: 0.9,
                bm25: 5.0,
            }
        }
        fn ungrounded() -> Self {
            Self {
                dense: 0.1,
                bm25: 0.0,
            }
        }
    }

    impl Retrieve for StubRetriever {
        fn search(&self, _query: &str, _top_k: usize) -> anyhow::Result<Vec<RetrievalHit>> {
            Ok(["d1", "d2"]
                .into_iter()
                .map(|id| RetrievalHit {
                    document: doc(id),
                    rrf_score: 0.03,
                    dense_score: Some(self.dense),
                    bm25_score: Some(self.bm25),
                })
                .collect())
        }
        fn corpus_hash(&self) -> String {
            "stub-hash".to_string()
        }
        fn describe(&self) -> String {
            "stub retriever".to_string()
        }
    }

    fn one_finding_json(handler: &str) -> String {
        format!(
            r#"[{{"class":"missing-owner-check","severity":"high","confidence":0.8,
                "handler":"{handler}","line":6,"evidence":"e","citations":["d1","d2"]}}]"#
        )
    }

    #[derive(Clone, Default)]
    struct RecordingClient {
        reply: String,
        seen: std::rc::Rc<RefCell<Vec<LlmRequest>>>,
    }

    impl RecordingClient {
        fn with(reply: String) -> Self {
            Self {
                reply,
                seen: Default::default(),
            }
        }
        fn requests(&self) -> Vec<LlmRequest> {
            self.seen.borrow().clone()
        }
    }

    impl LlmClient for RecordingClient {
        fn name(&self) -> String {
            "recording/test".to_string()
        }
        fn complete(&self, req: &LlmRequest) -> Result<String, LlmError> {
            self.seen.borrow_mut().push(req.clone());
            Ok(self.reply.clone())
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

    fn analyzer(client: impl LlmClient + 'static, retriever: StubRetriever) -> LlmAnalyzer {
        LlmAnalyzer::new(Box::new(client), Box::new(retriever), 5)
    }

    fn static_finding(handler: &str, class: &str) -> Finding {
        Finding {
            id: "s1".into(),
            class: VulnClass::new(class),
            severity: Severity::High,
            confidence: 0.7,
            track: Track::Static,
            location: Location {
                file: PathBuf::from("lib.rs"),
                line: 6,
                handler: handler.to_string(),
            },
            evidence: "static evidence".into(),
            citations: vec![],
        }
    }

    #[test]
    fn track2_findings_are_tagged_llm_and_carry_citations() {
        let result = analyzer(
            RecordingClient::with(one_finding_json("withdraw")),
            StubRetriever::grounded(),
        )
        .analyze(&fixture_tree());
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().all(|f| f.track == Track::Llm));
        assert!(result.findings.iter().all(|f| !f.citations.is_empty()));
    }

    #[test]
    fn emits_no_findings_for_ungrounded_units() {
        let result = analyzer(
            RecordingClient::with(one_finding_json("withdraw")),
            StubRetriever::ungrounded(),
        )
        .analyze(&fixture_tree());
        assert!(
            result.findings.is_empty(),
            "the grounding gate is a filter, not a hint"
        );
    }

    #[test]
    fn an_ungrounded_unit_is_never_sent_to_the_model_at_all() {
        // Not just "produces no findings": the request must not be issued,
        // or an ungrounded unit still costs a full generation timeout.
        let client = RecordingClient::with(one_finding_json("withdraw"));
        let _ = LlmAnalyzer::new(
            Box::new(client.clone()),
            Box::new(StubRetriever::ungrounded()),
            5,
        )
        .analyze(&fixture_tree());
        assert!(client.requests().is_empty());
    }

    #[test]
    fn an_ungrounded_unit_is_counted_but_not_examined() {
        let result = analyzer(
            RecordingClient::with(one_finding_json("withdraw")),
            StubRetriever::ungrounded(),
        )
        .analyze(&fixture_tree());
        let u = result.units.expect("Track 2 reports unit coverage");
        assert!(u.total > 0);
        assert_eq!(
            u.examined, 0,
            "a thin report must be distinguishable from a broken one"
        );
    }

    #[test]
    fn the_model_never_sees_track_1_findings() {
        let client = RecordingClient::with(one_finding_json("withdraw"));
        let _ = LlmAnalyzer::new(
            Box::new(client.clone()),
            Box::new(StubRetriever::grounded()),
            5,
        )
        .analyze(&fixture_tree());
        for req in client.requests() {
            let all = format!("{} {}", req.system, req.user);
            assert!(!all.contains("Track 1"), "D29: no static results in the prompt");
            assert!(!all.contains("static_track"));
            assert!(
                !all.contains("missing-signer at line"),
                "no rendered Track 1 finding may leak into the prompt"
            );
        }
    }

    #[test]
    fn the_prompt_does_not_tell_the_model_to_skip_what_track_1_covers() {
        // D30. That instruction would suppress exactly the overlap
        // `merge_key` collision detection exists to find, making
        // `Track::Corroborated` unreachable.
        // Phrase-level, not word-level: an earlier version of this test
        // banned the bare word "already" and fired on a rule that said the
        // opposite ("do not assume anything has already been checked"),
        // which is an instruction *against* skipping. What D30 forbids is
        // telling the model that something else covers a class.
        let lowered = SYSTEM_PROMPT.to_lowercase();
        for phrase in [
            "already covered",
            "already reported",
            "already detected",
            "already found",
            "static analysis",
            "static analyzer",
            "another tool",
            "do not report",
            "skip ",
            "omit ",
        ] {
            assert!(
                !lowered.contains(phrase),
                "D30: the prompt must not steer the model away from any class — found {phrase:?}"
            );
        }
    }

    #[test]
    fn the_prompt_states_the_class_vocabulary_so_findings_can_be_matched() {
        // Found live in Task 21: left free, the model answers with labels of
        // its own invention. `Finding::merge_key` is `(handler_id, class)`,
        // so a Track 2 finding can only corroborate a Track 1 one when the
        // class strings match exactly.
        for class in [
            crate::detectors::MISSING_SIGNER,
            crate::detectors::MISSING_OWNER_CHECK,
            crate::detectors::MISSING_AUTHORITY_BINDING,
            crate::detectors::PDA_VALIDATION_GAP,
            crate::detectors::UNCHECKED_ARITHMETIC,
        ] {
            assert!(
                SYSTEM_PROMPT.contains(class),
                "the prompt must name `{class}`"
            );
        }
    }

    #[test]
    fn the_prompt_labels_every_offered_document_with_its_doc_id() {
        let client = RecordingClient::with(one_finding_json("withdraw"));
        let _ = LlmAnalyzer::new(
            Box::new(client.clone()),
            Box::new(StubRetriever::grounded()),
            5,
        )
        .analyze(&fixture_tree());
        let user = &client.requests()[0].user;
        assert!(
            user.contains("[doc_id: d1]"),
            "citations are only checkable if ids are shown"
        );
        assert!(user.contains("[doc_id: d2]"));
    }

    #[test]
    fn the_prompt_carries_the_code_under_review() {
        let client = RecordingClient::with(one_finding_json("withdraw"));
        let _ = LlmAnalyzer::new(
            Box::new(client.clone()),
            Box::new(StubRetriever::grounded()),
            5,
        )
        .analyze(&fixture_tree());
        let user = &client.requests()[0].user;
        assert!(user.contains("pub fn withdraw"), "{user}");
        assert!(user.contains("pub struct W"), "the accounts struct too");
    }

    #[test]
    fn an_unavailable_model_degrades_rather_than_failing() {
        let result = analyzer(DeadClient, StubRetriever::grounded()).analyze(&fixture_tree());
        assert!(result.findings.is_empty());
        assert!(result
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::TrackSkipped));
    }

    #[test]
    fn an_unavailable_model_emits_exactly_one_diagnostic_not_one_per_unit() {
        let result = analyzer(DeadClient, StubRetriever::grounded()).analyze(&fixture_tree());
        assert_eq!(
            result
                .diagnostics
                .iter()
                .filter(|d| d.kind == DiagnosticKind::TrackSkipped)
                .count(),
            1
        );
    }

    #[test]
    fn an_unavailable_model_still_reports_unit_coverage() {
        // The number a reader needs to tell "reviewed nothing" from "found
        // nothing" is exactly the one a bailing-out path is likeliest to
        // forget to fill in.
        let result = analyzer(DeadClient, StubRetriever::grounded()).analyze(&fixture_tree());
        let u = result.units.expect("unit coverage survives a degraded run");
        assert!(u.total > 0);
        assert_eq!(u.examined, 0);
    }

    #[test]
    fn llm_findings_locate_to_a_real_handler_so_corroboration_can_fire() {
        let result = analyzer(
            RecordingClient::with(one_finding_json("withdraw")),
            StubRetriever::grounded(),
        )
        .analyze(&fixture_tree());
        assert!(result
            .findings
            .iter()
            .all(|f| f.location.handler == "withdraw"));
    }

    #[test]
    fn a_finding_naming_an_unknown_handler_is_discarded() {
        let result = analyzer(
            RecordingClient::with(one_finding_json("does_not_exist")),
            StubRetriever::grounded(),
        )
        .analyze(&fixture_tree());
        assert!(
            result.findings.is_empty(),
            "an unmappable handler cannot be located, cited, or corroborated"
        );
        assert!(result
            .diagnostics
            .iter()
            .any(|d| d.message.contains("does_not_exist")));
    }

    #[test]
    fn a_finding_with_no_line_falls_back_to_the_handlers_own_line() {
        let json = r#"[{"class":"missing-owner-check","severity":"high","confidence":0.8,
            "handler":"withdraw","line":null,"evidence":"e","citations":["d1"]}]"#;
        let result = analyzer(
            RecordingClient::with(json.to_string()),
            StubRetriever::grounded(),
        )
        .analyze(&fixture_tree());
        assert_eq!(result.findings.len(), 1);
        assert!(
            result.findings[0].location.line > 0,
            "a finding pointing at line 0 destroys trust in every other line"
        );
    }

    #[test]
    fn a_matching_static_finding_corroborates_through_merge() {
        let llm = analyzer(
            RecordingClient::with(one_finding_json("withdraw")),
            StubRetriever::grounded(),
        )
        .analyze(&fixture_tree())
        .findings;
        let stat = vec![static_finding("withdraw", "missing-owner-check")];
        let merged = dike_core::merge::merge(stat, llm);
        assert!(
            merged.iter().any(|f| f.track == Track::Corroborated),
            "D30: overlap between tracks is the product, not waste"
        );
    }

    #[test]
    fn a_model_reply_of_nothing_is_an_examined_unit_not_a_skipped_one() {
        let result = analyzer(
            RecordingClient::with("[]".to_string()),
            StubRetriever::grounded(),
        )
        .analyze(&fixture_tree());
        assert!(result.findings.is_empty());
        let u = result.units.unwrap();
        assert_eq!(u.examined, u.total, "the model did review these units");
    }
}
