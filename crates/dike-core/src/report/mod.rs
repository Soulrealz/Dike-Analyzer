mod json;
mod markdown;

use crate::analyzer::Diagnostic;
use crate::finding::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    pub tool_version: String,
    pub model: Option<String>,
    pub corpus_hash: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub files_total: usize,
    pub files_parsed: usize,
    /// Count of handlers *discovered* while parsing, not the count actually
    /// analyzed. A handler whose `Context<T>` type does not resolve to a
    /// known `#[derive(Accounts)]` struct is skipped rather than analyzed,
    /// but it is still counted here — hiding it from this number would
    /// understate how much of the program was found at all. Each skipped
    /// handler is reported individually in the diagnostics section (as a
    /// `Skipped` diagnostic), so nothing here is silent; this field is
    /// deliberately just "handlers found", and the report label reflects
    /// that rather than claiming they were all analyzed.
    pub handlers: usize,
    pub loc: usize,
    /// Findings withheld by the imperative-check suppression pass (D15).
    pub suppressed: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrackFindings {
    pub static_track: Vec<Finding>,
    pub llm_track: Vec<Finding>,
    pub merged: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub run: RunMetadata,
    pub tracks: TrackFindings,
    pub diagnostics: Vec<Diagnostic>,
    pub coverage: Coverage,
}

impl Report {
    pub fn render_markdown(&self) -> String {
        markdown::render(self)
    }
    pub fn render_json(&self) -> serde_json::Result<String> {
        json::render(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::DiagnosticKind;
    use crate::finding::{Location, Severity, Track, VulnClass};
    use std::path::PathBuf;

    fn sample_report() -> Report {
        let f = Finding {
            id: "abc123".into(),
            class: VulnClass::new("missing-signer"),
            severity: Severity::High,
            confidence: 0.9,
            track: Track::Static,
            location: Location { file: PathBuf::from("src/lib.rs"), line: 42, handler: "withdraw".into() },
            evidence: "`authority` account has no signer constraint".into(),
            citations: vec![],
        };
        Report {
            run: RunMetadata {
                tool_version: "0.1.0".into(),
                model: None,
                corpus_hash: None,
                timestamp: "2026-08-27T00:00:00Z".into(),
            },
            tracks: TrackFindings { static_track: vec![f.clone()], llm_track: vec![], merged: vec![f] },
            diagnostics: vec![Diagnostic {
                file: Some(PathBuf::from("src/broken.rs")),
                kind: DiagnosticKind::ParseFailure,
                message: "expected `}`".into(),
            }],
            coverage: Coverage { files_total: 2, files_parsed: 1, handlers: 3, loc: 250, suppressed: 1 },
        }
    }

    #[test]
    fn markdown_reports_each_track_separately() {
        let md = sample_report().render_markdown();
        assert!(md.contains("## Track 1 — Static"));
        assert!(md.contains("## Track 2 — LLM"));
        assert!(md.contains("## Merged"));
        assert!(md.contains("withdraw"));
    }

    #[test]
    fn markdown_lists_unparsed_files_in_coverage() {
        let md = sample_report().render_markdown();
        assert!(md.contains("## Coverage"));
        assert!(md.contains("src/broken.rs"));
        assert!(md.contains("1/2"));
    }

    #[test]
    fn markdown_records_run_provenance() {
        let md = sample_report().render_markdown();
        assert!(md.contains("0.1.0"));
        assert!(md.contains("2026-08-27T00:00:00Z"));
        // model and corpus_hash are None in the fixture; they must render as `none`,
        // not be silently omitted or panic on unwrap.
        assert!(md.contains("Model: `none`"));
        assert!(md.contains("Corpus hash: `none`"));
    }

    #[test]
    fn json_round_trips() {
        let json = sample_report().render_json().unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tracks.merged.len(), 1);
        assert_eq!(back.coverage.suppressed, 1);
    }

    #[test]
    fn markdown_escapes_pipes_and_newlines_in_evidence_table_cells() {
        let mut r = sample_report();
        r.tracks.static_track[0].evidence = "line one | has a pipe\nand a newline".into();
        let md = r.render_markdown();
        // The escaped pipe and the literal `\n` marker must appear on a single line
        // within the table row; the raw newline must not have split the row in two.
        assert!(md.contains("line one \\| has a pipe and a newline"));
        assert!(!md.contains("line one | has a pipe\nand a newline"));
    }
}
