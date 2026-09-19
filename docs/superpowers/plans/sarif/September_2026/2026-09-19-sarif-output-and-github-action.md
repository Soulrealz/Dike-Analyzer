# SARIF Output and GitHub Action Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit SARIF 2.1.0 from `dike analyze` and ship a composite GitHub Action that uploads it to code scanning, so dike's findings appear as pull-request annotations.

**Architecture:** A third renderer (`report/sarif.rs`) joins `markdown.rs` and `json.rs` in `dike-core`. Core defines a domain-agnostic `RuleDoc`; `dike-lang-anchor` fills a six-entry catalog; `dike-cli` hands the catalog to the renderer, remaining the only place the two worlds meet. An `action.yml` at the repository root builds dike from the consumer's checked-out copy of the action and uploads the result.

**Tech Stack:** Rust 2021, `serde_json` (already a workspace dependency — **no new dependencies are added by this plan**), `clap` derive, GitHub composite actions, `github/codeql-action/upload-sarif@v3`.

**Spec:** [`docs/superpowers/specs/sarif/September_2026/2026-09-19-sarif-design.md`](../../../specs/sarif/September_2026/2026-09-19-sarif-design.md)

## Global Constraints

These come from `CLAUDE.md` and apply to **every task below without exception**.

- **Rule 2 — the seam.** `crates/dike-core/tests/seam.rs` fails the build if any non-comment line under `crates/dike-core/src` contains any of: `anchor`, `solana`, `Signer<`, `AccountInfo`, `UncheckedAccount`, `has_one`, `invoke_signed`, `pubkey`, `Pubkey`, `spl_`. **It walks `src`, so `#[cfg(test)] mod tests` inside `sarif.rs` is covered too** — test fixtures and string literals in core must use neutral vocabulary. Class-name strings like `missing-signer` are fine; evidence prose mentioning `UncheckedAccount` is not.
- **Rule 4 — exit 0 is a feature.** No `--fail-on` flag, no exit-code change. `invocations[0].executionSuccessful` is `true` whenever the tool ran.
- **Rule 5 — determinism.** No clock, no randomness, no `HashMap` iteration order anywhere in this code path. `RunMetadata.timestamp` is **not** emitted into SARIF.
- **Rule 6 — tests must be able to fail.** Every test below names the change that breaks it. Write the test, run it, confirm it fails, then implement.
- **Rule 7 — verify before claiming.** The four gates:
  ```
  cargo test --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test -p dike-core --test seam
  cargo run -p dike-cli -- analyze tests/fixtures/programs/vault   # exit 0, zero findings
  ```
  Clippy is deny-by-default; `redundant_comparisons`, `ptr_arg`, `bool_assert_comparison`, `useless_format`, `question_mark`, `derivable_impls` and `cloned_ref_to_slice_refs` have each broken this build before.
- **Rule 9 — the user owns git.** **Do not run `git` commands.** Every task's final step says "Propose the commit"; write the message out for the user and stop. The `git commit` blocks in this plan are text to hand to the user, not commands to execute.
- **House style.** There is deliberately no `cargo fmt` gate. Match the surrounding hand-formatting; do not reformat neighboring code.
- **Pinned constants.** The severity → `level` / `security-severity` map is pinned in the same sense as the per-detector confidences. It is set once, in Task 2, and not revisited.
- **Repository URL:** `https://github.com/Soulrealz/Dike-Analyzer`.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `crates/dike-core/src/report/sarif.rs` | create | `RuleDoc`, the SARIF 2.1.0 renderer, and its tests |
| `crates/dike-core/src/report/mod.rs` | modify | declare `pub mod sarif;`, re-export `RuleDoc`, add `Report::render_sarif` |
| `crates/dike-core/src/lib.rs` | modify | re-export `RuleDoc` alongside `Report` |
| `crates/dike-lang-anchor/src/rules.rs` | create | the six-entry Anchor rule catalog + completeness test |
| `crates/dike-lang-anchor/src/lib.rs` | modify | `pub mod rules;` |
| `crates/dike-cli/src/config.rs` | modify | `Format::Sarif`, `RunConfig::base_dir` |
| `crates/dike-cli/src/main.rs` | modify | `--base-dir` argument, pass it through |
| `crates/dike-cli/src/commands/analyze.rs` | modify | render SARIF with the catalog |
| `crates/dike-cli/tests/analyze_sarif.rs` | create | CLI integration test over `leaky_vault` |
| `action.yml` | create | the composite action |
| `.github/workflows/ci.yml` | modify | the `action-smoke` job |
| `README.md` | modify | consumer workflow, permissions, protection-rule note |
| `docs/PROJECT_CONTEXT.md` | modify | Rule 1 |
| `learning/part-04-report.md`, `learning/part-10-cli.md` | modify | Rule 10 |

Task order is dependency order. Tasks 1–5 build the renderer incrementally in one file, each adding one testable behavior; 6 is the catalog; 7 is the CLI; 8 is packaging; 9 is documentation.

---

### Task 1: The SARIF skeleton — `RuleDoc`, an empty document, determinism

**Files:**
- Create: `crates/dike-core/src/report/sarif.rs`
- Modify: `crates/dike-core/src/report/mod.rs`
- Modify: `crates/dike-core/src/lib.rs`

**Interfaces:**
- Consumes: `crate::report::Report`, `crate::analyzer::Diagnostic`, `crate::finding::{Finding, Severity}`.
- Produces:
  - `pub struct RuleDoc { pub id: String, pub short_description: String, pub full_description: String, pub help_uri: Option<String>, pub tags: Vec<String> }`
  - `pub fn render(report: &Report, rules: &[RuleDoc], base: &std::path::Path) -> serde_json::Result<String>` (module-private to `report`, reached through the method below)
  - `impl Report { pub fn render_sarif(&self, rules: &[RuleDoc], base: &std::path::Path) -> serde_json::Result<String> }`

- [ ] **Step 1: Write the failing tests**

Append to `crates/dike-core/src/report/sarif.rs` (create the file with just this test module for now; the `use super::*;` will not resolve until Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::empty_report;
    use std::path::Path;

    #[test]
    fn empty_run_is_a_valid_document_with_empty_arrays() {
        let out = render(&empty_report(), &[], Path::new("/repo")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].as_str().unwrap().contains("sarif"));
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "dike");
        assert_eq!(v["runs"][0]["tool"]["driver"]["version"], "0.1.0");
        // Empty, not null and not absent: a consumer that indexes these must
        // not have to special-case a clean run.
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn no_clock_derived_field_appears_anywhere() {
        // `empty_report`'s timestamp is a recognisable sentinel. Rule 5: two
        // runs over identical input must be byte-identical, and a timestamp
        // in a CI artifact makes every run look changed.
        let out = render(&empty_report(), &[], Path::new("/repo")).unwrap();
        assert!(!out.contains("2026-08-27T00:00:00Z"));
        assert!(!out.contains("startTimeUtc"));
        assert!(!out.contains("endTimeUtc"));
    }

    #[test]
    fn rendering_twice_is_byte_identical() {
        let r = empty_report();
        assert_eq!(
            render(&r, &[], Path::new("/repo")).unwrap(),
            render(&r, &[], Path::new("/repo")).unwrap()
        );
    }
}
```

This needs a shared fixture. Add to `crates/dike-core/src/report/mod.rs`, **outside** the existing `#[cfg(test)] mod tests`:

```rust
/// Report fixtures shared by the renderer test modules. `sarif.rs` and
/// `mod.rs` both build reports to render; duplicating the constructor in
/// each meant a field added to `Report` had to be added in two places.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::{Coverage, Report, RunMetadata, TrackFindings};
    use crate::analyzer::Diagnostic;
    use crate::finding::{Finding, Location, Severity, Track, VulnClass};
    use std::path::PathBuf;

    pub(crate) fn empty_report() -> Report {
        Report {
            run: RunMetadata {
                tool_version: "0.1.0".into(),
                model: None,
                corpus_hash: None,
                timestamp: "2026-08-27T00:00:00Z".into(),
            },
            tracks: TrackFindings::default(),
            diagnostics: Vec::new(),
            coverage: Coverage::default(),
        }
    }

    /// A finding with every optional field populated, so a renderer that
    /// drops one is caught. `file` is deliberately under `/repo`.
    pub(crate) fn finding(class: &str, sev: Severity, line: u32, handler: &str) -> Finding {
        Finding {
            id: format!("id-{class}-{handler}"),
            class: VulnClass::new(class),
            severity: sev,
            confidence: 0.9,
            track: Track::Static,
            location: Location {
                file: PathBuf::from("/repo/programs/demo/src/lib.rs"),
                line,
                handler: handler.to_string(),
            },
            evidence: "the declared account is not constrained".into(),
            citations: Vec::new(),
            subject: Some("authority".into()),
            absorbed_handlers: vec!["deposit".into()],
        }
    }

    pub(crate) fn report_with(findings: Vec<Finding>, diagnostics: Vec<Diagnostic>) -> Report {
        let mut r = empty_report();
        r.tracks.merged = findings;
        r.diagnostics = diagnostics;
        r
    }
}
```

> Note the evidence string: `the declared account is not constrained`. It says nothing the seam test bans. Do not paste a real detector's evidence here — every one of them names `UncheckedAccount`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: FAIL — the file is not declared as a module yet, so this is a compile error (`failed to resolve: use of undeclared crate or module`). That is the expected failure for this step.

- [ ] **Step 3: Write the minimal implementation**

Prepend to `crates/dike-core/src/report/sarif.rs`, above the test module:

```rust
use super::Report;
use serde_json::{json, Value};
use std::path::Path;

const SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/Soulrealz/Dike-Analyzer";

/// Documentation for one vulnerability class, for consumers that want a rule
/// catalog rather than bare class names.
///
/// Core defines the shape and never the contents: class vocabularies are
/// language-specific and live in the language crates (CLAUDE.md Rule 2). The
/// renderer below therefore hard-codes no class name, no per-class severity
/// and no help URL — every one of those arrives here from the caller.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleDoc {
    pub id: String,
    pub short_description: String,
    pub full_description: String,
    pub help_uri: Option<String>,
    pub tags: Vec<String>,
}

/// Render the report as SARIF 2.1.0.
///
/// `base` is stripped from every emitted path so the URIs are repository-root
/// relative, which is what a code-scanning upload resolves against.
///
/// Deliberately emits no timestamp of any kind: this document is a CI
/// artifact that gets diffed and cached, and a clock in it would make every
/// run look changed (Rule 5).
pub fn render(report: &Report, rules: &[RuleDoc], base: &Path) -> serde_json::Result<String> {
    let results: Vec<Value> = Vec::new();
    let emitted: Vec<Value> = Vec::new();
    let _ = (rules, base);

    let doc = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "dike",
                    "version": report.run.tool_version,
                    "informationUri": INFORMATION_URI,
                    "rules": emitted,
                }
            },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&doc)
}
```

In `crates/dike-core/src/report/mod.rs`, add the module declaration next to the others and the re-export and method:

```rust
mod json;
mod markdown;
mod sarif;

pub use sarif::RuleDoc;
```

and inside `impl Report`, after `render_json`:

```rust
    /// SARIF 2.1.0, for code-scanning upload. `rules` documents the class
    /// vocabulary — core does not know it — and `base` is stripped from
    /// emitted paths so they resolve against a repository root.
    pub fn render_sarif(&self, rules: &[RuleDoc], base: &std::path::Path) -> serde_json::Result<String> {
        sarif::render(self, rules, base)
    }
```

In `crates/dike-core/src/lib.rs`, extend the existing report re-export line:

```rust
pub use report::{Coverage, Report, RuleDoc, RunMetadata, TrackFindings};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: PASS, 3 tests.

Then: `cargo test -p dike-core --test seam` — expected PASS. Run it now rather than at the end; a seam violation introduced here is cheapest to find here.

Then: `cargo clippy --workspace --all-targets -- -D warnings`. The `let _ = (rules, base);` line exists precisely to keep this green while the parameters are unused; it disappears in Task 3.

- [ ] **Step 5: Propose the commit** (do not run it — Rule 9)

```
add a SARIF 2.1.0 skeleton and the RuleDoc shape

RuleDoc lets a caller document the class vocabulary without core learning
what the classes are. The document carries no timestamp: it is a CI artifact
that gets diffed, and a clock in it makes every run look changed.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

### Task 2: Results — the severity map, fingerprints, and properties

**Files:**
- Modify: `crates/dike-core/src/report/sarif.rs`

**Interfaces:**
- Consumes: `RuleDoc` and `render` from Task 1; `tests_support::{report_with, finding}` from Task 1.
- Produces: `fn level_and_security_severity(sev: Severity) -> (&'static str, &'static str)` (private). One `results[]` entry per finding in `report.tracks.merged`, in merged order.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `sarif.rs`:

```rust
    use crate::finding::{Severity, Track};
    use crate::report::tests_support::{finding, report_with};

    fn results(report: &crate::report::Report) -> Vec<serde_json::Value> {
        let out = render(report, &[], Path::new("/repo")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        v["runs"][0]["results"].as_array().unwrap().clone()
    }

    #[test]
    fn severity_maps_to_level_and_security_severity() {
        // Pinned. Changing any row changes every consumer's alert triage at
        // once, in the same way the per-detector confidences do.
        let cases = [
            (Severity::Critical, "error", "9.0"),
            (Severity::High, "error", "7.0"),
            (Severity::Medium, "warning", "5.0"),
            (Severity::Low, "note", "3.0"),
            (Severity::Info, "note", "1.0"),
        ];
        for (sev, level, sec) in cases {
            let r = report_with(vec![finding("some-class", sev, 10, "withdraw")], vec![]);
            let got = results(&r);
            assert_eq!(got[0]["level"], level, "level for {sev:?}");
            // A string, not a number: a numeric value here is silently ignored.
            assert_eq!(got[0]["properties"]["security-severity"], sec, "security-severity for {sev:?}");
        }
    }

    #[test]
    fn results_follow_merged_order_and_carry_the_evidence() {
        let r = report_with(
            vec![
                finding("class-a", Severity::Critical, 10, "withdraw"),
                finding("class-b", Severity::Low, 20, "deposit"),
            ],
            vec![],
        );
        let got = results(&r);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0]["ruleId"], "class-a");
        assert_eq!(got[1]["ruleId"], "class-b");
        assert_eq!(got[0]["message"]["text"], "the declared account is not constrained");
        assert_eq!(got[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 10);
    }

    #[test]
    fn a_result_carries_the_finding_id_as_a_partial_fingerprint() {
        let r = report_with(vec![finding("some-class", Severity::High, 10, "withdraw")], vec![]);
        let got = results(&r);
        assert_eq!(got[0]["partialFingerprints"]["dikeFindingId/v1"], "id-some-class-withdraw");
    }

    #[test]
    fn the_fingerprint_does_not_move_when_the_line_moves() {
        // The whole point. `finding.id` is blake3(handler|class|key) with no
        // line and no path in it, so an alert survives a refactor instead of
        // being closed and reopened — and a dismissal survives with it.
        let a = report_with(vec![finding("some-class", Severity::High, 10, "withdraw")], vec![]);
        let b = report_with(vec![finding("some-class", Severity::High, 999, "withdraw")], vec![]);
        assert_eq!(
            results(&a)[0]["partialFingerprints"],
            results(&b)[0]["partialFingerprints"]
        );
        assert_ne!(
            results(&a)[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            results(&b)[0]["locations"][0]["physicalLocation"]["region"]["startLine"]
        );
    }

    #[test]
    fn properties_carry_the_track_severity_confidence_subject_and_absorbed_handlers() {
        let r = report_with(vec![finding("some-class", Severity::Critical, 10, "withdraw")], vec![]);
        let p = results(&r)[0]["properties"].clone();
        assert_eq!(p["dikeTrack"], "static");
        assert_eq!(p["dikeSeverity"], "critical");
        // Exact, deliberately. `json!(some_f32)` widens to f64 and emits
        // 0.8999999761581421 for the confidence the JSON report renders as
        // 0.9 — measured, not guessed. This assertion is what catches it.
        assert_eq!(p["dikeConfidence"], 0.9);
        assert_eq!(p["dikeSubject"], "authority");
        assert_eq!(p["dikeAbsorbedHandlers"][0], "deposit");
    }

    #[test]
    fn an_absent_subject_and_empty_absorbed_handlers_are_omitted_not_null() {
        let mut f = finding("some-class", Severity::High, 10, "withdraw");
        f.subject = None;
        f.absorbed_handlers.clear();
        let r = report_with(vec![f], vec![]);
        let p = results(&r)[0]["properties"].clone();
        assert!(p.get("dikeSubject").is_none());
        assert!(p.get("dikeAbsorbedHandlers").is_none());
    }

    #[test]
    fn a_corroborated_finding_reports_its_track() {
        let mut f = finding("some-class", Severity::Critical, 10, "withdraw");
        f.track = Track::Corroborated;
        let r = report_with(vec![f], vec![]);
        assert_eq!(results(&r)[0]["properties"]["dikeTrack"], "corroborated");
    }

    #[test]
    fn citations_become_related_locations() {
        let mut f = finding("some-class", Severity::High, 10, "withdraw");
        f.citations = vec![crate::finding::Citation {
            doc_id: "doc-1".into(),
            source_url: "https://example.invalid/guide".into(),
            title: "A guide".into(),
        }];
        let r = report_with(vec![f], vec![]);
        let rel = results(&r)[0]["relatedLocations"].clone();
        assert_eq!(rel[0]["message"]["text"], "A guide");
        assert_eq!(
            rel[0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://example.invalid/guide"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: FAIL — `results` is always empty, so every assertion indexing `got[0]` panics with an index-out-of-bounds or a `null` comparison mismatch.

- [ ] **Step 3: Write the implementation**

Replace the `let results: Vec<Value> = Vec::new();` line in `render` and add the helpers:

```rust
/// Pinned, in the same sense as the per-detector confidences: consumers triage
/// against these, so a change moves every alert at once.
///
/// This map can fail a pull request's check. GitHub fails the code-scanning
/// check at `error` or at a security severity of 7.0 and above, unless the
/// repository owner raises the threshold. Capping everything below that would
/// mean reporting a critical as a medium — a false statement about severity,
/// made to work around a UI default. Rule 4 governs *dike's* exit code, which
/// stays 0 unconditionally; what a consumer's CI does with an alert is the
/// consumer's setting to change, and the README names it.
fn level_and_security_severity(sev: Severity) -> (&'static str, &'static str) {
    match sev {
        Severity::Critical => ("error", "9.0"),
        Severity::High => ("error", "7.0"),
        Severity::Medium => ("warning", "5.0"),
        Severity::Low => ("note", "3.0"),
        Severity::Info => ("note", "1.0"),
    }
}

fn severity_name(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn track_name(track: Track) -> &'static str {
    match track {
        Track::Static => "static",
        Track::Llm => "llm",
        Track::Corroborated => "corroborated",
    }
}

/// A confidence as a number that reads the way the JSON report's does.
///
/// `json!(some_f32)` widens to `f64` and prints `0.8999999761581421` for a
/// confidence of `0.9`, because the widening happens before the formatter
/// ever sees an `f32`. The JSON renderer serializes the `f32` directly and
/// gets `0.9`. Round-tripping through `f32`'s own shortest representation
/// reproduces that, so the two reports quote the same number.
fn confidence_value(confidence: f32) -> Value {
    match confidence.to_string().parse::<f64>() {
        Ok(f) => json!(f),
        // Unreachable — `f32::to_string` always round-trips — but a report
        // must never panic on a number (Rule 4).
        Err(_) => json!(confidence),
    }
}

fn result_for(finding: &Finding, base: &Path) -> Value {
    let (level, security_severity) = level_and_security_severity(finding.severity);

    let mut properties = serde_json::Map::new();
    properties.insert("dikeTrack".into(), json!(track_name(finding.track)));
    properties.insert("dikeSeverity".into(), json!(severity_name(finding.severity)));
    properties.insert("dikeConfidence".into(), confidence_value(finding.confidence));
    properties.insert("security-severity".into(), json!(security_severity));
    if let Some(subject) = &finding.subject {
        properties.insert("dikeSubject".into(), json!(subject));
    }
    if !finding.absorbed_handlers.is_empty() {
        properties.insert("dikeAbsorbedHandlers".into(), json!(finding.absorbed_handlers));
    }

    let mut result = json!({
        "ruleId": finding.class.as_str(),
        "level": level,
        "message": { "text": finding.evidence },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri_for(&finding.location.file, base) },
                // `startLine` only. Dike records a line, never a column, and
                // inventing one would claim a span precision the IR does not
                // have. A consumer annotates the whole line instead.
                "region": { "startLine": finding.location.line }
            }
        }],
        "partialFingerprints": { "dikeFindingId/v1": finding.id },
        "properties": Value::Object(properties),
    });

    if !finding.citations.is_empty() {
        let related: Vec<Value> = finding
            .citations
            .iter()
            .map(|c| {
                json!({
                    "physicalLocation": { "artifactLocation": { "uri": c.source_url } },
                    "message": { "text": c.title }
                })
            })
            .collect();
        result["relatedLocations"] = Value::Array(related);
    }
    result
}
```

`uri_for` does not exist yet. For this task only, add a temporary definition; Task 4 replaces its body:

```rust
fn uri_for(path: &Path, _base: &Path) -> String {
    path.to_string_lossy().into_owned()
}
```

In `render`, build the results and drop the now-used `base` from the discard line:

```rust
    let results: Vec<Value> =
        report.tracks.merged.iter().map(|f| result_for(f, base)).collect();
    let emitted: Vec<Value> = Vec::new();
    let _ = rules;
```

Extend the imports at the top of the file:

```rust
use crate::finding::{Finding, Severity, Track};
```

> `tracks.merged` and not the per-track arrays: merged is the report's answer, and a corroborated finding is one row there rather than two. The originating track survives in `properties.dikeTrack`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: PASS, 11 tests.

Run: `cargo test -p dike-core --test seam` — expected PASS.
Run: `cargo clippy --workspace --all-targets -- -D warnings` — expected clean.

- [ ] **Step 5: Propose the commit** (do not run it)

```
render one SARIF result per merged finding, fingerprinted by finding id

partialFingerprints carries finding.id, which has no line and no path in it,
so an alert survives a refactor rather than being closed and reopened — and a
dismissal survives with it. The severity map is pinned: it can fail a
consumer's PR check, and the README names the setting that governs that.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

### Task 3: The rules array — referenced only, deduplicated, catalog order

**Files:**
- Modify: `crates/dike-core/src/report/sarif.rs`

**Interfaces:**
- Consumes: `RuleDoc`, `result_for` from Tasks 1–2.
- Produces: `fn emit_rules(report: &Report, rules: &[RuleDoc]) -> (Vec<Value>, Vec<Option<usize>>)` (private) — the rule objects to emit, plus the `ruleIndex` for each merged finding in order, `None` when the class has no catalog entry.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
    fn doc(id: &str, uri: Option<&str>) -> RuleDoc {
        RuleDoc {
            id: id.into(),
            short_description: format!("short for {id}"),
            full_description: format!("full for {id}"),
            help_uri: uri.map(|u| u.to_string()),
            tags: vec!["security".into()],
        }
    }

    fn rendered(report: &crate::report::Report, rules: &[RuleDoc]) -> serde_json::Value {
        serde_json::from_str(&render(report, rules, Path::new("/repo")).unwrap()).unwrap()
    }

    #[test]
    fn only_referenced_rules_are_emitted() {
        // Emitting the whole catalog would advertise classes this run never
        // examined, which reads as "checked and clean".
        let catalog = [doc("class-a", None), doc("class-b", None), doc("class-c", None)];
        let r = report_with(vec![finding("class-b", Severity::High, 10, "withdraw")], vec![]);
        let v = rendered(&r, &catalog);
        let emitted = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0]["id"], "class-b");
    }

    #[test]
    fn emitted_rules_follow_catalog_order_not_finding_order() {
        let catalog = [doc("class-a", None), doc("class-b", None)];
        let r = report_with(
            vec![
                finding("class-b", Severity::High, 10, "withdraw"),
                finding("class-a", Severity::High, 20, "deposit"),
            ],
            vec![],
        );
        let v = rendered(&r, &catalog);
        let emitted = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(emitted[0]["id"], "class-a");
        assert_eq!(emitted[1]["id"], "class-b");
    }

    #[test]
    fn two_results_of_one_class_share_a_rule_index() {
        // This is the `leaky_vault` shape: seven results, five rules.
        let catalog = [doc("class-a", None)];
        let r = report_with(
            vec![
                finding("class-a", Severity::High, 10, "withdraw"),
                finding("class-a", Severity::High, 20, "deposit"),
            ],
            vec![],
        );
        let v = rendered(&r, &catalog);
        assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(v["runs"][0]["results"][0]["ruleIndex"], 0);
        assert_eq!(v["runs"][0]["results"][1]["ruleIndex"], 0);
    }

    #[test]
    fn a_rule_renders_its_descriptions_help_and_tags() {
        let catalog = [doc("class-a", Some("https://example.invalid/a"))];
        let r = report_with(vec![finding("class-a", Severity::High, 10, "withdraw")], vec![]);
        let rule = rendered(&r, &catalog)["runs"][0]["tool"]["driver"]["rules"][0].clone();
        assert_eq!(rule["id"], "class-a");
        assert_eq!(rule["name"], "class-a");
        assert_eq!(rule["shortDescription"]["text"], "short for class-a");
        assert_eq!(rule["fullDescription"]["text"], "full for class-a");
        // `help` and `fullDescription` land in different panes of the alert
        // view; omitting either leaves one of them blank.
        assert_eq!(rule["help"]["text"], "full for class-a");
        assert_eq!(rule["helpUri"], "https://example.invalid/a");
        assert_eq!(rule["properties"]["tags"][0], "security");
    }

    #[test]
    fn a_rule_without_a_help_uri_omits_the_key_rather_than_emitting_null() {
        let catalog = [doc("class-a", None)];
        let r = report_with(vec![finding("class-a", Severity::High, 10, "withdraw")], vec![]);
        let rule = rendered(&r, &catalog)["runs"][0]["tool"]["driver"]["rules"][0].clone();
        assert!(rule.get("helpUri").is_none());
    }

    #[test]
    fn a_class_with_no_catalog_entry_still_reports_with_a_rule_id_and_no_index() {
        // Track 2 can name a class the catalog does not carry. Dropping the
        // result would be a silent false negative, which Rule 3 forbids;
        // SARIF permits a ruleId with no ruleIndex.
        let catalog = [doc("class-a", None)];
        let r = report_with(vec![finding("unlisted-class", Severity::High, 10, "withdraw")], vec![]);
        let v = rendered(&r, &catalog);
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "unlisted-class");
        assert!(v["runs"][0]["results"][0].get("ruleIndex").is_none());
        assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 0);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: FAIL — `rules` is still discarded and `emitted` is hard-coded empty, so every rule assertion indexes `null`.

- [ ] **Step 3: Write the implementation**

Add to `sarif.rs`:

```rust
/// The rules to emit, and each merged finding's index into them.
///
/// Only classes a result actually references are emitted, in catalog order
/// rather than finding order — `ruleIndex` is positional, so the order has to
/// be decided once, here, and both halves derived from the same decision.
fn emit_rules(report: &Report, rules: &[RuleDoc]) -> (Vec<Value>, Vec<Option<usize>>) {
    let mut keep: Vec<&RuleDoc> = Vec::new();
    for rule in rules {
        if report.tracks.merged.iter().any(|f| f.class.as_str() == rule.id) {
            keep.push(rule);
        }
    }

    let indices = report
        .tracks
        .merged
        .iter()
        .map(|f| keep.iter().position(|r| r.id == f.class.as_str()))
        .collect();

    let emitted = keep
        .into_iter()
        .map(|rule| {
            let mut obj = json!({
                "id": rule.id,
                "name": rule.id,
                "shortDescription": { "text": rule.short_description },
                "fullDescription": { "text": rule.full_description },
                "help": { "text": rule.full_description },
                "properties": { "tags": rule.tags },
            });
            // Omitted, never `null`: a null helpUri renders as a dead link.
            if let Some(uri) = &rule.help_uri {
                obj["helpUri"] = json!(uri);
            }
            obj
        })
        .collect();

    (emitted, indices)
}
```

Change `result_for` to take the index and set it:

```rust
fn result_for(finding: &Finding, rule_index: Option<usize>, base: &Path) -> Value {
```

and just before `if !finding.citations.is_empty()`:

```rust
    if let Some(i) = rule_index {
        result["ruleIndex"] = json!(i);
    }
```

In `render`, replace the results/emitted block:

```rust
    let (emitted, indices) = emit_rules(report, rules);
    let results: Vec<Value> = report
        .tracks
        .merged
        .iter()
        .zip(indices)
        .map(|(f, i)| result_for(f, i, base))
        .collect();
```

and delete the `let _ = rules;` line.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: PASS, 17 tests.

Run: `cargo clippy --workspace --all-targets -- -D warnings`. Watch for `needless_range_loop` and `ptr_arg` here; `emit_rules` takes `&[RuleDoc]`, which is correct, not `&Vec<RuleDoc>`.

- [ ] **Step 5: Propose the commit** (do not run it)

```
emit only the rules a run actually referenced, in catalog order

Emitting the whole catalog would advertise classes the run never examined,
which reads as "checked and clean". A class with no catalog entry still
reports, with a ruleId and no ruleIndex: dropping it would be a silent false
negative.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

### Task 4: Path relativization

**Files:**
- Modify: `crates/dike-core/src/report/sarif.rs`

**Interfaces:**
- Consumes: the temporary `uri_for` from Task 2.
- Produces: `fn uri_for(path: &Path, base: &Path) -> String` (private), final form.

**Why this exists:** `SourceTree::load` stores `entry.path()` verbatim, so `finding.location.file` is the path as the user typed it. `dike analyze /home/me/vault` yields an absolute path; a code-scanning upload resolves URIs against the repository root and **silently drops** results it cannot map to a checked-out file. Without this task the SARIF uploads successfully and annotates nothing.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
    #[test]
    fn an_absolute_path_under_the_base_is_relativized() {
        let r = report_with(vec![finding("class-a", Severity::High, 10, "withdraw")], vec![]);
        let v = rendered(&r, &[]);
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "programs/demo/src/lib.rs"
        );
    }

    #[test]
    fn a_relative_path_is_left_alone() {
        let mut f = finding("class-a", Severity::High, 10, "withdraw");
        f.location.file = std::path::PathBuf::from("programs/demo/src/lib.rs");
        let r = report_with(vec![f], vec![]);
        let v = rendered(&r, &[]);
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "programs/demo/src/lib.rs"
        );
    }

    #[test]
    fn a_path_outside_the_base_is_emitted_unchanged_rather_than_mangled() {
        // Better a URI the consumer cannot resolve than a plausible-looking
        // relative path pointing at a file that is not the one we analyzed.
        let mut f = finding("class-a", Severity::High, 10, "withdraw");
        f.location.file = std::path::PathBuf::from("/elsewhere/src/lib.rs");
        let r = report_with(vec![f], vec![]);
        let v = rendered(&r, &[]);
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "/elsewhere/src/lib.rs"
        );
    }

    #[test]
    fn separators_are_normalized_to_forward_slashes() {
        // SARIF `uri` is a URI reference, not a native path.
        let out = uri_for(Path::new(r"C:\repo\src\lib.rs"), Path::new("/nowhere"));
        assert!(!out.contains('\\'), "got {out}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: FAIL — `an_absolute_path_under_the_base_is_relativized` gets `/repo/programs/demo/src/lib.rs`, and `separators_are_normalized_to_forward_slashes` gets the backslashes back.

- [ ] **Step 3: Write the implementation**

Replace the temporary `uri_for` with:

```rust
/// A SARIF `uri` for a path: relative to `base` when it is under it, and
/// always forward-slashed.
///
/// Three cases, all real. An absolute path under the base is the one the
/// action produces when a caller passes an absolute directory. A relative
/// path is what `dike analyze programs/vault` produces, and it is already
/// correct. A path outside the base is left exactly as it is — emitting a
/// mangled relative path would point a reviewer at a file that is not the one
/// analyzed, which is worse than a URI the consumer simply cannot resolve.
fn uri_for(path: &Path, base: &Path) -> String {
    match path.strip_prefix(base) {
        Ok(rel) => rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
        Err(_) => path.to_string_lossy().replace('\\', "/"),
    }
}
```

> `components()` on the stripped remainder never yields a root component, so the join cannot produce a leading `//`. The `Err` branch handles both the relative and the outside-the-base cases, which is why it does the separator normalization rather than the `Ok` branch.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: PASS, 21 tests.

- [ ] **Step 5: Propose the commit** (do not run it)

```
relativize SARIF paths against a base directory

A code-scanning upload resolves URIs against the repository root and silently
drops results it cannot map to a checked-out file, so an absolute path
produces a SARIF that uploads cleanly and annotates nothing. A path outside
the base is emitted unchanged rather than mangled into a plausible-looking
relative path pointing somewhere else.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

### Task 5: Diagnostics become tool-execution notifications

**Files:**
- Modify: `crates/dike-core/src/report/sarif.rs`

**Interfaces:**
- Consumes: `crate::analyzer::{Diagnostic, DiagnosticKind}`, `uri_for` from Task 4.
- Produces: `runs[0].invocations[0]` with `executionSuccessful: true` and `toolExecutionNotifications`.

**Why this exists:** a run that failed to parse half the program is otherwise indistinguishable in the Security tab from a run that found the program clean. That is exactly the failure Rule 3 exists to prevent.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:

```rust
    use crate::analyzer::{Diagnostic, DiagnosticKind};

    fn diag(kind: DiagnosticKind, file: Option<&str>) -> Diagnostic {
        Diagnostic {
            file: file.map(std::path::PathBuf::from),
            kind,
            message: "something was skipped".into(),
        }
    }

    #[test]
    fn diagnostics_become_tool_execution_notifications() {
        let r = report_with(
            vec![],
            vec![diag(DiagnosticKind::ParseFailure, Some("/repo/programs/demo/src/bad.rs"))],
        );
        let v = rendered(&r, &[]);
        let n = v["runs"][0]["invocations"][0]["toolExecutionNotifications"][0].clone();
        assert_eq!(n["message"]["text"], "something was skipped");
        assert_eq!(n["level"], "warning");
        assert_eq!(
            n["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "programs/demo/src/bad.rs"
        );
    }

    #[test]
    fn notification_levels_distinguish_a_dropped_file_from_a_note() {
        // A parse failure means a file was not analyzed at all; an ambiguity
        // means it was, with a tie broken. Flattening them hides the first.
        for (kind, level) in [
            (DiagnosticKind::ParseFailure, "warning"),
            (DiagnosticKind::Skipped, "warning"),
            (DiagnosticKind::Ambiguity, "note"),
            (DiagnosticKind::TrackSkipped, "note"),
        ] {
            let r = report_with(vec![], vec![diag(kind, None)]);
            let v = rendered(&r, &[]);
            assert_eq!(
                v["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["level"],
                level,
                "level for {kind:?}"
            );
        }
    }

    #[test]
    fn a_diagnostic_without_a_file_omits_locations() {
        let r = report_with(vec![], vec![diag(DiagnosticKind::TrackSkipped, None)]);
        let v = rendered(&r, &[]);
        let n = v["runs"][0]["invocations"][0]["toolExecutionNotifications"][0].clone();
        assert!(n.get("locations").is_none());
    }

    #[test]
    fn execution_is_successful_even_with_critical_findings() {
        // Rule 4: findings never mean the tool failed.
        let r = report_with(vec![finding("class-a", Severity::Critical, 10, "withdraw")], vec![]);
        let v = rendered(&r, &[]);
        assert_eq!(v["runs"][0]["invocations"][0]["executionSuccessful"], true);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: FAIL — there is no `invocations` key, so every assertion compares against `null`.

- [ ] **Step 3: Write the implementation**

Add to `sarif.rs`:

```rust
fn notification_for(diagnostic: &Diagnostic, base: &Path) -> Value {
    // A parse failure or a skip means code was not analyzed; an ambiguity or
    // a skipped track means it was, with something noted. Flattening the two
    // would hide the first, which is the one that makes a clean report a lie.
    let level = match diagnostic.kind {
        DiagnosticKind::ParseFailure | DiagnosticKind::Skipped => "warning",
        DiagnosticKind::Ambiguity | DiagnosticKind::TrackSkipped => "note",
    };
    let mut notification = json!({
        "level": level,
        "message": { "text": diagnostic.message },
    });
    if let Some(file) = &diagnostic.file {
        notification["locations"] = json!([{
            "physicalLocation": { "artifactLocation": { "uri": uri_for(file, base) } }
        }]);
    }
    notification
}
```

Extend the imports:

```rust
use crate::analyzer::{Diagnostic, DiagnosticKind};
```

In `render`, build the notifications and add the `invocations` key to the run object:

```rust
    let notifications: Vec<Value> =
        report.diagnostics.iter().map(|d| notification_for(d, base)).collect();
```

```rust
            "results": results,
            "invocations": [{
                // Always true when the tool ran. Findings are not failures
                // (Rule 4) and a diagnostic is a degraded run, not a failed one.
                "executionSuccessful": true,
                "toolExecutionNotifications": notifications,
            }],
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-core --lib report::sarif`
Expected: PASS, 25 tests.

Run all four gates now — this is the last task that touches core's renderer:
```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p dike-core --test seam
cargo run -p dike-cli -- analyze tests/fixtures/programs/vault
```
Expected: all green; the last prints a report with zero findings and exits 0.

- [ ] **Step 5: Propose the commit** (do not run it)

```
carry diagnostics into SARIF as tool-execution notifications

A run that failed to parse half the program was otherwise indistinguishable
from a run that found it clean. executionSuccessful stays true regardless of
findings: Rule 4.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

### Task 6: The Anchor rule catalog

**Files:**
- Create: `crates/dike-lang-anchor/src/rules.rs`
- Modify: `crates/dike-lang-anchor/src/lib.rs`

**Interfaces:**
- Consumes: `dike_core::report::RuleDoc`; the class constants in `crate::detectors` (`MISSING_SIGNER`, `MISSING_OWNER_CHECK`, `MISSING_AUTHORITY_BINDING`, `PDA_VALIDATION_GAP`, `UNCHECKED_ARITHMETIC`, `REMOVED_GUARD`); `crate::detectors::all_detectors()`.
- Produces: `pub fn catalog() -> Vec<RuleDoc>` — six entries, in `all_detectors()` order.

- [ ] **Step 1: Write the failing test**

Create `crates/dike-lang-anchor/src/rules.rs` with only this for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::all_detectors;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_covers_exactly_the_detector_vocabulary() {
        // Both directions. A seventh detector with no entry fails this; a
        // stale entry left behind after removing a detector fails it too.
        let documented: BTreeSet<String> = catalog().into_iter().map(|r| r.id).collect();
        let detected: BTreeSet<String> =
            all_detectors().iter().map(|d| d.class().to_string()).collect();
        assert_eq!(documented, detected);
    }

    #[test]
    fn every_entry_is_populated_and_ordered_like_the_detectors() {
        let cat = catalog();
        let detected: Vec<String> =
            all_detectors().iter().map(|d| d.class().to_string()).collect();
        let documented: Vec<String> = cat.iter().map(|r| r.id.clone()).collect();
        assert_eq!(documented, detected, "catalog order must match all_detectors()");
        for rule in &cat {
            assert!(!rule.short_description.is_empty(), "{} has no short description", rule.id);
            assert!(!rule.full_description.is_empty(), "{} has no full description", rule.id);
            assert!(rule.help_uri.is_some(), "{} has no help uri", rule.id);
            assert!(rule.tags.contains(&"security".to_string()), "{} is not tagged", rule.id);
        }
    }
}
```

Add to `crates/dike-lang-anchor/src/lib.rs`, with the other module declarations:

```rust
pub mod rules;
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-lang-anchor --lib rules`
Expected: FAIL — compile error, `cannot find function catalog in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `crates/dike-lang-anchor/src/rules.rs`:

```rust
//! Documentation for the Anchor vulnerability vocabulary.
//!
//! `dike-core` defines the `RuleDoc` shape and deliberately knows none of
//! these classes (CLAUDE.md Rule 2); this is where the domain words live. The
//! wording is drawn from the detectors' own evidence strings, so a reader who
//! sees an annotation and then reads the detector finds the same explanation
//! twice rather than two that have drifted apart.
//!
//! Every `help_uri` below is already a source in `corpus/sources.toml`: the
//! catalog cites what the retriever cites.

use crate::detectors::{
    MISSING_AUTHORITY_BINDING, MISSING_OWNER_CHECK, MISSING_SIGNER, PDA_VALIDATION_GAP,
    REMOVED_GUARD, UNCHECKED_ARITHMETIC,
};
use dike_core::report::RuleDoc;

const SEALEVEL: &str = "https://github.com/coral-xyz/sealevel-attacks/tree/master/programs";

fn rule(id: &str, short: &str, full: &str, help_uri: &str) -> RuleDoc {
    RuleDoc {
        id: id.to_string(),
        short_description: short.to_string(),
        full_description: full.to_string(),
        help_uri: Some(help_uri.to_string()),
        tags: vec!["security".into(), "solana".into(), "anchor".into(), id.to_string()],
    }
}

/// The six documented classes, in `detectors::all_detectors()` order.
///
/// The order is load-bearing: `RuleDoc`s are emitted in catalog order and
/// `ruleIndex` is positional, so reordering this list reorders every
/// consumer's rule array.
pub fn catalog() -> Vec<RuleDoc> {
    vec![
        rule(
            MISSING_SIGNER,
            "A privileged account is not required to sign",
            "An account the program treats as privileged is declared without a `Signer<'info>` type, a `signer` constraint, or an `address =` pin. Nothing requires the transaction to be signed by it, so any caller may pass an arbitrary account in its place and act with its authority.",
            &format!("{SEALEVEL}/0-signer-authorization"),
        ),
        rule(
            MISSING_OWNER_CHECK,
            "An account's owning program is never checked",
            "The account is declared as a raw wrapper, for which Anchor performs neither an owner check nor a discriminator check. Nothing else (`address =`, `owner =`, `seeds`, or a manual `constraint = ...` pinning its identity) constrains it either, so an attacker may substitute an account of the right shape owned by a program they control.",
            &format!("{SEALEVEL}/2-owner-checks"),
        ),
        rule(
            MISSING_AUTHORITY_BINDING,
            "A signer is never bound to the account it claims authority over",
            "A handler takes both a state account and an authority, but nothing ties the two together — no `has_one`, no `constraint = ...` comparing them, no seed derivation over the authority. The signature proves who sent the transaction and not what they are entitled to touch, so any valid signer may operate on anyone's account.",
            &format!("{SEALEVEL}/1-account-data-matching"),
        ),
        rule(
            PDA_VALIDATION_GAP,
            "A derived address is validated inconsistently across handlers",
            "The same account type is derived with `seeds` in one accounts struct and accepted without derivation in another. The handler that skips the derivation accepts any account of that type, which makes the constraint the other handlers enforce reachable around rather than through.",
            &format!("{SEALEVEL}/7-bump-seed-canonicalization"),
        ),
        rule(
            UNCHECKED_ARITHMETIC,
            "Arithmetic on account state can wrap",
            "A handler performs arithmetic on persisted balances or counters using operators that wrap in release builds rather than the checked, saturating or `require!`-guarded forms. An attacker who can drive a value past a boundary changes state the program believes is impossible.",
            "https://neodyme.io/en/blog/solana_common_pitfalls/",
        ),
        rule(
            REMOVED_GUARD,
            "A guard the surrounding code implies is absent",
            "A constraint that the rest of the program's shape implies should be present is missing from this declaration — a field its siblings bind, or an authority-shaped account nothing pins. Reported at lower confidence than the classes above: the evidence is the surrounding code's own pattern rather than a structural rule.",
            "https://www.anchor-lang.com/docs/references/account-constraints",
        ),
    ]
}
```

> These strings contain `anchor` and `solana`. That is correct **here** — the seam test walks `crates/dike-core/src` only, and domain vocabulary belongs in this crate (Rule 2). Do not move any of this into core.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-lang-anchor --lib rules`
Expected: PASS, 2 tests.

Run: `cargo test -p dike-core --test seam` — expected PASS. This confirms the catalog's domain words did not leak into core.

Run: `cargo clippy --workspace --all-targets -- -D warnings`. `useless_format` is on the deny list and has broken this build before — the `format!("{SEALEVEL}/0-signer-authorization")` calls do interpolate, so they are fine, but a bare `format!("literal")` anywhere would fail.

- [ ] **Step 5: Propose the commit** (do not run it)

```
document the Anchor vulnerability vocabulary as a rule catalog

Six RuleDocs in dike-lang-anchor, where the domain words belong. The wording
comes from the detectors' own evidence strings so an annotation and the
detector behind it say the same thing, and a test asserts the catalog and
all_detectors() cover exactly the same class set in both directions.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

### Task 7: CLI wiring — `--format sarif` and `--base-dir`

**Files:**
- Modify: `crates/dike-cli/src/config.rs`
- Modify: `crates/dike-cli/src/main.rs`
- Modify: `crates/dike-cli/src/commands/analyze.rs`
- Create: `crates/dike-cli/tests/analyze_sarif.rs`

**Interfaces:**
- Consumes: `dike_lang_anchor::rules::catalog()` (Task 6), `Report::render_sarif` (Task 1).
- Produces: `Format::Sarif`, `RunConfig::base_dir: std::path::PathBuf`.

- [ ] **Step 1: Write the failing test**

Create `crates/dike-cli/tests/analyze_sarif.rs`:

```rust
//! `dike analyze --format sarif` over the vulnerable fixture.
//!
//! The fixture is deliberately the one with findings: a smoke test over a
//! clean program passes against a renderer that emits an empty document.

use std::collections::BTreeSet;
use std::process::Command;

fn sarif_for(fixture: &str) -> serde_json::Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let out = Command::new(env!("CARGO_BIN_EXE_dike"))
        .current_dir(&root)
        .args(["analyze", fixture, "--format", "sarif"])
        .output()
        .expect("running dike");
    assert!(out.status.success(), "dike exited {:?}", out.status);
    serde_json::from_slice(&out.stdout).expect("stdout is not JSON")
}

#[test]
fn the_vulnerable_fixture_renders_seven_results_across_five_rules() {
    // Verified 2026-09-19. Seven results, five distinct classes: the case
    // that catches a renderer emitting one rule per result.
    let v = sarif_for("tests/fixtures/programs/leaky_vault");
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 7, "results: {results:#?}");

    let classes: BTreeSet<&str> =
        results.iter().map(|r| r["ruleId"].as_str().unwrap()).collect();
    assert_eq!(
        classes,
        BTreeSet::from([
            "missing-signer",
            "missing-owner-check",
            "missing-authority-binding",
            "pda-validation-gap",
            "unchecked-arithmetic",
        ])
    );
    assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 5);
}

#[test]
fn paths_are_repository_relative_so_a_consumer_can_resolve_them() {
    let v = sarif_for("tests/fixtures/programs/leaky_vault");
    let uri = v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .unwrap();
    assert_eq!(uri, "tests/fixtures/programs/leaky_vault/src/lib.rs");
    assert!(!uri.starts_with('/'), "an absolute uri resolves against nothing");
}

#[test]
fn the_clean_fixture_renders_a_valid_document_with_no_results() {
    let v = sarif_for("tests/fixtures/programs/vault");
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    assert_eq!(v["runs"][0]["invocations"][0]["executionSuccessful"], true);
}
```

`serde_json` is already a direct dependency of `dike-cli` (verified 2026-09-19 in `crates/dike-cli/Cargo.toml`), and a `[dependencies]` entry is visible to integration tests. Nothing to add.

The binary is named `dike`, not `dike-cli` — `crates/dike-cli/Cargo.toml` carries an explicit `[[bin]] name = "dike"` — so the environment variable is `CARGO_BIN_EXE_dike`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-cli --test analyze_sarif`
Expected: FAIL — `error: invalid value 'sarif' for '--format <FORMAT>'`, surfacing as a non-success exit status in `sarif_for`.

- [ ] **Step 3: Write the implementation**

In `crates/dike-cli/src/config.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Md,
    Json,
    Sarif,
}
```

and add to `RunConfig`:

```rust
    /// Stripped from emitted paths so they resolve against a repository root.
    /// SARIF only; accepted for every format because a flag whose validity
    /// depends on another flag is worse than one that is simply inert.
    pub base_dir: std::path::PathBuf,
```

In `crates/dike-cli/src/main.rs`, add to the `Analyze` variant after `out`:

```rust
        /// Strip this prefix from paths in SARIF output. Defaults to the
        /// current directory, which is what a CI checkout root is.
        #[arg(long)]
        base_dir: Option<std::path::PathBuf>,
```

and where the `Analyze` arm builds its `RunConfig`, add:

```rust
            base_dir: base_dir.unwrap_or(std::env::current_dir()?),
```

> Find the existing `Command::Analyze { .. }` match arm and extend both its destructuring pattern and the `RunConfig` literal. If the arm's body does not already return a `Result` in a `?`-friendly context, use `std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))` instead — an unreadable working directory should degrade to "no stripping", never fail the run (Rule 4).

In `crates/dike-cli/src/commands/analyze.rs`, replace the render match:

```rust
    let rendered = match cfg.format {
        Format::Md => report.render_markdown(),
        Format::Json => report.render_json()?,
        // The CLI is the one place core and the Anchor crate meet (Rule 2):
        // core defines RuleDoc and knows no class, the Anchor crate fills the
        // catalog and knows no SARIF, and this line introduces them.
        Format::Sarif => report.render_sarif(&dike_lang_anchor::rules::catalog(), &cfg.base_dir)?,
    };
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-cli --test analyze_sarif`
Expected: PASS, 3 tests.

Then all four gates:
```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p dike-core --test seam
cargo run -p dike-cli -- analyze tests/fixtures/programs/vault
```

Then look at the real output before believing any of it (Rule 7):
```
cargo run -p dike-cli -- analyze tests/fixtures/programs/leaky_vault --format sarif | head -60
```
Expected: `$schema`, `version: "2.1.0"`, a `rules` array of five, and repository-relative URIs.

- [ ] **Step 5: Propose the commit** (do not run it)

```
add --format sarif and --base-dir to dike analyze

The CLI hands dike-lang-anchor's catalog to dike-core's renderer, which is the
one place the two worlds are allowed to meet. --base-dir defaults to the
working directory, which is a CI checkout root.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

### Task 8: The composite action and its CI smoke test

**Files:**
- Create: `action.yml`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `dike analyze --format sarif --out` (Task 7).
- Produces: an action with inputs `path`, `sarif-file`, `category`, `upload`, and output `sarif-file`.

- [ ] **Step 1: Write `action.yml`**

```yaml
name: Dike — Solana Anchor security triage
description: >-
  Run dike over an Anchor program and upload the findings to code scanning.
  Triage, not a gate: dike always exits 0, and findings never fail the run.
author: Soulrealz

branding:
  icon: shield
  color: purple

inputs:
  path:
    description: Program directory to analyze, relative to the workspace root.
    required: true
  sarif-file:
    description: Where to write the SARIF document.
    required: false
    default: dike.sarif
  category:
    description: >-
      Code-scanning category. Keeps dike's alerts from colliding with another
      tool's, and lets one repository run dike over several programs.
    required: false
    default: dike
  upload:
    description: >-
      Upload the SARIF to code scanning. Set to "false" to write the file and
      stop — the path is available as the `sarif-file` output.
    required: false
    default: "true"

outputs:
  sarif-file:
    description: Path to the written SARIF document.
    value: ${{ inputs.sarif-file }}

runs:
  using: composite
  steps:
    - uses: dtolnay/rust-toolchain@stable

    # Keyed on the action's own checkout, not the caller's workspace: what is
    # being built is dike, which lives here.
    - uses: Swatinem/rust-cache@v2
      with:
        workspaces: ${{ github.action_path }}

    - name: Build dike
      shell: bash
      run: cargo install --path "${{ github.action_path }}/crates/dike-cli" --locked

    # Runs from the workspace root, so `--base-dir` stays at its default and
    # the emitted URIs are workspace-relative — which is what a code-scanning
    # upload resolves against.
    - name: Analyze
      shell: bash
      run: dike analyze "${{ inputs.path }}" --format sarif --out "${{ inputs.sarif-file }}"

    - name: Upload to code scanning
      if: inputs.upload == 'true'
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: ${{ inputs.sarif-file }}
        category: ${{ inputs.category }}
```

> `cargo install --path "${{ github.action_path }}/..."` and not `--git`: `github.action_path` is the consumer's already-checked-out copy of this action at whatever ref they pinned in `uses:`. Building from it means the binary is exactly the version they asked for, there is no `ref` input to keep in sync with the `uses:` line, and nothing is fetched over the network. `--locked` makes it build against the committed `Cargo.lock`.

- [ ] **Step 2: Add the CI job**

In `.github/workflows/ci.yml`, after the `check` job:

```yaml
  # The action, end to end, against a fixture that actually has findings —
  # a smoke test over a clean program passes against a renderer that emits an
  # empty document.
  #
  # `upload: false` deliberately. `leaky_vault` is vulnerable on purpose;
  # uploading its SARIF would file permanent code-scanning alerts against this
  # repository for a fixture nobody intends to fix, and every contributor
  # would have to learn to ignore them. The cost is that the upload step is
  # not exercised here — it is a four-line `uses:` of a Microsoft-maintained
  # action, and the README's consumer example covers it.
  action-smoke:
    runs-on: ubuntu-latest
    needs: check
    steps:
      - uses: actions/checkout@v4
      - uses: Swatinem/rust-cache@v2

      - name: Run the action
        uses: ./
        with:
          path: tests/fixtures/programs/leaky_vault
          sarif-file: dike.sarif
          upload: false

      - name: The SARIF is well formed and reports the fixture's classes
        run: |
          set -euo pipefail
          python3 - <<'EOF'
          import json, sys
          doc = json.load(open("dike.sarif"))
          assert doc["version"] == "2.1.0", doc.get("version")
          assert "sarif" in doc["$schema"]
          run = doc["runs"][0]
          assert run["invocations"][0]["executionSuccessful"] is True
          ids = {r["ruleId"] for r in run["results"]}
          expected = {
              "missing-signer",
              "missing-owner-check",
              "missing-authority-binding",
              "pda-validation-gap",
              "unchecked-arithmetic",
          }
          assert ids == expected, f"got {sorted(ids)}"
          assert len(run["results"]) == 7, len(run["results"])
          assert len(run["tool"]["driver"]["rules"]) == 5
          for r in run["results"]:
              uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
              assert not uri.startswith("/"), uri
          print(f"ok: {len(run['results'])} results, {len(run['tool']['driver']['rules'])} rules")
          EOF
```

- [ ] **Step 3: Verify what can be verified locally**

The action cannot run outside GitHub. Verify the two things that can be checked here:

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('action.yml')); yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"
```
Expected: `yaml ok`. If `pyyaml` is unavailable, skip this and say so rather than claiming it passed.

Then reproduce what the action's Analyze step does, from the repository root:

```bash
cargo run -p dike-cli -- analyze tests/fixtures/programs/leaky_vault --format sarif --out /tmp/dike-smoke.sarif
python3 - <<'EOF'
import json
doc = json.load(open("/tmp/dike-smoke.sarif"))
run = doc["runs"][0]
print(len(run["results"]), "results;", len(run["tool"]["driver"]["rules"]), "rules")
print(sorted({r["ruleId"] for r in run["results"]}))
EOF
```
Expected: `7 results; 5 rules` and the five class names. This is the CI assertion, run locally against the same binary the action installs.

- [ ] **Step 4: Record what was not verified**

State plainly in the handoff that the upload step and `Swatinem/rust-cache` keyed on `github.action_path` are **unexercised** until the first real run on GitHub. Do not describe the action as "tested".

- [ ] **Step 5: Propose the commit** (do not run it)

```
add a composite action that runs dike and uploads SARIF

Builds from the consumer's checked-out copy of the action rather than
--git, so the binary is exactly the ref they pinned and nothing is fetched.
CI exercises the action against the vulnerable fixture with upload disabled:
uploading it would file permanent alerts against this repo for a fixture
nobody intends to fix.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

### Task 9: Documentation — Rules 1 and 10

**Files:**
- Modify: `docs/PROJECT_CONTEXT.md`
- Modify: `README.md`
- Modify: `learning/part-04-report.md`
- Modify: `learning/part-10-cli.md`

This is not optional cleanup. Rule 1 requires `PROJECT_CONTEXT.md` to change in the same commit as a new module, subcommand flag or major structural addition; Rule 10 requires a lesson to change when the source it teaches does.

- [ ] **Step 1: Update `docs/PROJECT_CONTEXT.md`**

Four edits:

1. In the folder-structure block, under `dike-core/src/report/`, note the third renderer:
   `Markdown + JSON + SARIF renderers, Coverage, RunMetadata`
2. Under `dike-lang-anchor/src/`, add:
   `├── rules.rs        RuleDoc catalog: the six classes, documented for SARIF consumers`
3. At the top level of the folder-structure block, add:
   `├── action.yml      The composite GitHub Action: build, analyze, upload SARIF`
4. In the `main.rs` line, extend the `analyze` description to mention `--format sarif` and `--base-dir`; in the `.github/workflows/ci.yml` line, add the `action-smoke` job.

Then add to **"Quirks & constraint-driven decisions"**:

```markdown
### SARIF severity is mapped faithfully, and that can fail someone's PR check

GitHub fails a pull request's code-scanning check for alerts at `level: error`
or `security-severity` at or above 7.0, unless the repository owner raises the
threshold in Settings → Code security → Code scanning → "Protection rules".
Dike maps `Critical`/`High` to `error` at 9.0/7.0, so on default settings a
dike alert can block a merge.

The alternative was capping every severity below the threshold so a dike run
could never gate anything. That was rejected: it would mean reporting a
critical missing-signer as a medium — a false statement about severity, made
to work around a UI default in someone else's product.

**Rule 4 is not in tension with this.** Rule 4 governs dike's exit code, which
is 0 unconditionally, findings or not. What a consumer's CI does with an
uploaded alert is the consumer's setting, and the README names it.

The map is pinned in the same sense as the per-detector confidences: consumers
triage against it, so a change moves every alert at once.
```

and:

```markdown
### SARIF carries no timestamp, though the JSON report does

`RunMetadata.timestamp` is rendered by the JSON and Markdown reporters and
deliberately omitted from SARIF. A SARIF document is a CI artifact that gets
diffed, cached and compared between runs; a clock in it makes every run look
changed and defeats Rule 5's byte-identical guarantee for the one output most
likely to be diffed.
```

- [ ] **Step 2: Update `README.md`**

Add a section:

````markdown
## In CI

```yaml
name: Security triage
on: [pull_request]

jobs:
  dike:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required, or the upload fails
    steps:
      - uses: actions/checkout@v4
      - uses: Soulrealz/Dike-Analyzer@master
        with:
          path: programs/my-program
```

Findings appear as pull-request annotations and in the Security tab.

Three things worth knowing before you wire this up:

- **`security-events: write` is required.** Without it the upload fails with a
  permissions error that does not explain itself.
- **The first run builds dike from source** and takes several minutes.
  `Swatinem/rust-cache` is inside the action, so later runs are fast.
- **A dike alert can fail the check.** GitHub fails a pull request's
  code-scanning check at `level: error` or `security-severity` ≥ 7.0, and dike
  maps Critical and High there because that is what they are. Dike itself
  always exits 0 — it is triage, not a gate — so if you want the check to stay
  green, raise the threshold in Settings → Code security → Code scanning →
  "Protection rules". We would rather tell you that than understate a critical.

To write the file without uploading it:

```yaml
      - uses: Soulrealz/Dike-Analyzer@master
        with:
          path: programs/my-program
          upload: false
```

Or locally:

```
dike analyze programs/my-program --format sarif --out dike.sarif
```
````

- [ ] **Step 3: Update `learning/part-04-report.md`**

The lesson tours `report/{mod,markdown,json}.rs` and now has a third sibling. Add a section covering, in the lesson's existing voice:

- **`serde_json::json!` as a shape-first alternative to a serde struct.** The other two renderers derive their output from the `Report` type; SARIF's shape is someone else's specification, so it is built as a `Value` tree instead. Worth naming the tradeoff: no compile-time check that the document is well-formed, which is why the tests assert structure rather than trusting the type system.
- **`Option` in output: omitted versus `null`.** `help_uri: None` must produce no key at all, because a `null` helpUri renders as a dead link in the consumer's UI. Show the `if let Some(uri) = ... { obj["helpUri"] = ... }` idiom and contrast it with `#[serde(skip_serializing_if)]`.
- **Dependency injection across an architectural boundary.** `render_sarif` takes `&[RuleDoc]` precisely so core never learns the class vocabulary — the same seam Lesson 02 introduces, seen from the output end.
- **`Path::strip_prefix` returns a `Result`, not an `Option`,** and the `Err` branch is a real case here, not an error: it means "this path is not under the base", which is answered by leaving the path alone.
- Update the lesson's header table row to read `report/{mod,markdown,json,sarif}.rs`.

Update the matching row in `learning/README.md`'s index table.

- [ ] **Step 4: Update `learning/part-10-cli.md`**

The lesson traces `dike analyze` from argument to rendered report; both ends changed. Add:

- The third `Format` variant and why adding one is a three-line change in three files — the payoff of the renderer living behind a method on `Report`.
- `#[arg(long)] base_dir: Option<PathBuf>` with a **runtime** default (`std::env::current_dir()`), which clap's `default_value` cannot express because it is not a compile-time constant. This is the first flag in the CLI that needs that, so it is worth the paragraph.
- The `Format::Sarif` arm as the clearest one-line illustration of the whole seam: `report.render_sarif(&dike_lang_anchor::rules::catalog(), &cfg.base_dir)` is core's renderer, the Anchor crate's vocabulary, and the CLI as the only place the two are allowed to meet.

- [ ] **Step 5: Run the gates one final time and propose the commit**

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p dike-core --test seam
cargo run -p dike-cli -- analyze tests/fixtures/programs/vault
cargo run -p dike-cli -- analyze tests/fixtures/programs/escrow
```

Read the output of each before claiming anything passes. Grep for `FAILED` explicitly or read the tail — a grep for `test result: ok` has reported a green build over a failing test in this repo before.

Proposed commit (do not run it):

```
document SARIF output and the action

PROJECT_CONTEXT gains the new modules, flags and CI job, plus two quirks: why
severity is mapped faithfully even though it can gate a consumer's PR, and why
SARIF alone carries no timestamp. Lessons 04 and 10 tour files this changed.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KNgD4jV6fiFALMLutasbpf
```

---

## Verification summary

At the end of Task 9, every one of these must have been run and its output read:

| Command | Expected |
|---|---|
| `cargo test --workspace` | all pass; the workspace total rises from 533 by roughly 30 |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p dike-core --test seam` | green — the one gate this work could plausibly break |
| `cargo run -p dike-cli -- analyze tests/fixtures/programs/vault` | exit 0, zero findings |
| `cargo run -p dike-cli -- analyze tests/fixtures/programs/escrow` | exit 0, zero findings |
| `cargo run -p dike-cli -- analyze tests/fixtures/programs/leaky_vault --format sarif` | 7 results, 5 rules, relative URIs |

**Known unverifiable:** the action's upload step and its cache configuration cannot be exercised outside GitHub. Say so in the handoff rather than describing the action as tested.

**CI's clippy is ahead of the local one.** A green local clippy is not evidence CI is green.
