use super::{Report, TrackFindings};
use crate::analyzer::DiagnosticKind;
use crate::finding::Finding;

pub fn render(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Dike Report\n\n");
    out.push_str(&format!(
        "- Tool version: `{}`\n- Model: `{}`\n- Corpus hash: `{}`\n- Run at: `{}`\n\n",
        report.run.tool_version,
        report.run.model.as_deref().unwrap_or("none"),
        report.run.corpus_hash.as_deref().unwrap_or("none"),
        report.run.timestamp,
    ));
    out.push_str("> Triage output. This report says where to look; it never says a program is safe.\n\n");

    let TrackFindings { static_track, llm_track, merged } = &report.tracks;
    section(&mut out, "## Track 1 — Static (deterministic)", static_track);
    section(&mut out, "## Track 2 — LLM (retrieval-grounded)", llm_track);
    section(&mut out, "## Merged (triage order)", merged);

    out.push_str("## Coverage\n\n");
    out.push_str(&format!(
        "- Files parsed: {}/{}\n- Handlers found: {}\n- Lines of code: {}\n- Findings suppressed by imperative checks: {}\n\n",
        report.coverage.files_parsed,
        report.coverage.files_total,
        report.coverage.handlers,
        report.coverage.loc,
        report.coverage.suppressed,
    ));
    if !report.diagnostics.is_empty() {
        out.push_str("### Diagnostics\n\n");
        for d in &report.diagnostics {
            let file = d.file.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
            let kind = match d.kind {
                DiagnosticKind::ParseFailure => "parse failure",
                DiagnosticKind::Skipped => "skipped",
                DiagnosticKind::Ambiguity => "ambiguous symbol",
                DiagnosticKind::TrackSkipped => "track skipped",
            };
            out.push_str(&format!("- **{kind}** `{file}` — {}\n", d.message));
        }
        out.push('\n');
    }
    out
}

fn section(out: &mut String, title: &str, findings: &[Finding]) {
    out.push_str(title);
    out.push_str("\n\n");
    if findings.is_empty() {
        out.push_str("_No findings._\n\n");
        return;
    }
    out.push_str("| Severity | Conf | Class | Location | Evidence |\n");
    out.push_str("|---|---|---|---|---|\n");
    for f in findings {
        out.push_str(&format!(
            "| {:?} | {:.2} | `{}` | `{}:{}` ({}) | {} |\n",
            f.severity,
            f.confidence,
            f.class.as_str(),
            f.location.file.display(),
            f.location.line,
            f.location.handler,
            f.evidence.replace('\n', " ").replace('|', "\\|"),
        ));
    }
    out.push('\n');
    for f in findings.iter().filter(|f| !f.citations.is_empty()) {
        out.push_str(&format!("- `{}` cites: ", f.class.as_str()));
        let cites: Vec<String> = f
            .citations
            .iter()
            .map(|c| format!("[{}]({})", c.title, c.source_url))
            .collect();
        out.push_str(&cites.join(", "));
        out.push('\n');
    }
    out.push('\n');
}
