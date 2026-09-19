use super::Report;
use crate::analyzer::{Diagnostic, DiagnosticKind};
use crate::finding::{Finding, Severity, Track};
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
    // `strip_prefix("")` trivially succeeds for every path, which would let
    // an absolute path's root component survive into `components()` and
    // double the leading slash. An empty base carries no stripping intent, so
    // it takes the same path as a base that does not match at all.
    if base.as_os_str().is_empty() {
        return path.to_string_lossy().replace('\\', "/");
    }
    match path.strip_prefix(base) {
        Ok(rel) => rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
        Err(_) => path.to_string_lossy().replace('\\', "/"),
    }
}

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
            // GitHub reads `security-severity` from a *rule's* `properties`,
            // not a result's, to drive the Security tab and the >=7.0 check
            // threshold (the per-result copy in `result_for` is an opaque
            // property bag GitHub does not act on). Derived from the run's
            // own findings rather than a catalog field on `RuleDoc`: a
            // catalog-supplied value would duplicate the per-detector
            // severity constants Rule 5 pins, and could drift from them.
            // `keep` only holds rules with at least one referencing finding
            // (see the filter above), so `max()` is always defined.
            let max_severity = report
                .tracks
                .merged
                .iter()
                .filter(|f| f.class.as_str() == rule.id)
                .map(|f| f.severity)
                .max()
                .expect("a kept rule always has at least one referencing finding");
            let (_, security_severity) = level_and_security_severity(max_severity);

            let mut obj = json!({
                "id": rule.id,
                "name": rule.id,
                "shortDescription": { "text": rule.short_description },
                "fullDescription": { "text": rule.full_description },
                "help": { "text": rule.full_description },
                "properties": { "tags": rule.tags, "security-severity": security_severity },
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

/// One result per finding in `tracks.merged`.
///
/// Two things a consumer relies on are each conditionally omitted rather than
/// emitted with a value that lies:
///
/// - `partialFingerprints` is present only when `finding.id` is non-empty. A
///   finding built by `merge::corroborate` or the same-track branch of
///   `merge::merge` carries `id: String::new()` (never recomputed here — see
///   `merge.rs`), and two such findings sharing the empty string would fold
///   into *one* GitHub alert, silently dropping the other (a false negative,
///   which CLAUDE.md Rule 3 forbids). Omitting the key lets GitHub fall back
///   to its own source-hash fingerprinting instead: degraded, but correct.
///   This means the claim "every result gets a stable fingerprint because
///   `finding.id` carries no line and no path" is false for a finding merged
///   from multiple sources — it carries no id and therefore no fingerprint at
///   all. Known gap; see `docs/PROJECT_CONTEXT.md`.
/// - `region` is present only when `finding.location.line >= 1`. Track 2 can
///   report a finding with no line (`llm::structured::to_finding` uses
///   `f.line.unwrap_or(0)`), and SARIF 2.1.0 requires `region.startLine >= 1`.
///   `github/codeql-action/upload-sarif` validates the whole document against
///   the schema before ingesting anything, so a single line-less finding
///   emitted as `startLine: 0` would reject the *entire* run. The line is
///   never clamped to 1 — that would point a reviewer at code that is not
///   where the finding is.
fn result_for(finding: &Finding, rule_index: Option<usize>, base: &Path) -> Value {
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

    let mut physical_location = json!({
        "artifactLocation": { "uri": uri_for(&finding.location.file, base) },
    });
    // `startLine` only, and only when it is a valid SARIF line (>= 1). Dike
    // records a line, never a column, and inventing one would claim a span
    // precision the IR does not have. A consumer annotates the whole line
    // instead, or (with no `region` at all) the whole file.
    if finding.location.line >= 1 {
        physical_location["region"] = json!({ "startLine": finding.location.line });
    }

    let mut result = json!({
        "ruleId": finding.class.as_str(),
        "level": level,
        "message": { "text": finding.evidence },
        "locations": [{ "physicalLocation": physical_location }],
        "properties": Value::Object(properties),
    });

    // Omitted, never emitted with an empty string: see the doc comment above.
    if !finding.id.is_empty() {
        result["partialFingerprints"] = json!({ "dikeFindingId/v1": finding.id });
    }

    if let Some(i) = rule_index {
        result["ruleIndex"] = json!(i);
    }

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

/// Render the report as SARIF 2.1.0.
///
/// `base` is stripped from every emitted path so the URIs are repository-root
/// relative, which is what a code-scanning upload resolves against.
///
/// Deliberately emits no timestamp of any kind: this document is a CI
/// artifact that gets diffed and cached, and a clock in it would make every
/// run look changed (Rule 5).
pub fn render(report: &Report, rules: &[RuleDoc], base: &Path) -> serde_json::Result<String> {
    let (emitted, indices) = emit_rules(report, rules);
    let results: Vec<Value> = report
        .tracks
        .merged
        .iter()
        .zip(indices)
        .map(|(f, i)| result_for(f, i, base))
        .collect();

    let notifications: Vec<Value> =
        report.diagnostics.iter().map(|d| notification_for(d, base)).collect();

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
            "invocations": [{
                // Always true when the tool ran. Findings are not failures
                // (Rule 4) and a diagnostic is a degraded run, not a failed one.
                "executionSuccessful": true,
                "toolExecutionNotifications": notifications,
            }],
        }]
    });
    serde_json::to_string_pretty(&doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, Track};
    use crate::report::tests_support::{empty_report, finding, report_with};
    use std::path::Path;

    fn results(report: &crate::report::Report) -> Vec<serde_json::Value> {
        let out = render(report, &[], Path::new("/repo")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        v["runs"][0]["results"].as_array().unwrap().clone()
    }

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
        // A populous report — several findings (one with citations, one
        // without), several diagnostics, and a multi-entry catalog — so that
        // reintroducing a `HashMap` over findings, rules, or citations, or a
        // clock anywhere in `result_for`/`notification_for`, would show up as
        // a difference between the two renders. Rendering `empty_report()`
        // twice, as this test used to, cannot fail for that reason: there is
        // nothing in it to reorder (CLAUDE.md Rule 6 — "a stability test
        // comparing two empty vectors").
        let catalog = [doc("class-a", Some("https://example.invalid/a")), doc("class-b", None)];
        let mut f1 = finding("class-a", Severity::Critical, 10, "withdraw");
        f1.citations = vec![crate::finding::Citation {
            doc_id: "doc-1".into(),
            source_url: "https://example.invalid/guide".into(),
            title: "A guide".into(),
        }];
        let f2 = finding("class-b", Severity::Low, 20, "deposit");
        let r = report_with(
            vec![f1, f2],
            vec![
                diag(DiagnosticKind::ParseFailure, Some("/repo/programs/demo/src/bad.rs")),
                diag(DiagnosticKind::Ambiguity, None),
            ],
        );
        assert_eq!(
            render(&r, &catalog, Path::new("/repo")).unwrap(),
            render(&r, &catalog, Path::new("/repo")).unwrap()
        );
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

    // A renderer-side check that `finding.id` moving with the line would show
    // up here was removed: both fixtures built their id from the literal
    // `format!("id-{class}-{handler}")` in `tests_support::finding`, which
    // never included the line, so the assertion could not have failed for the
    // reason its name claimed (CLAUDE.md Rule 6). The real assertion — that
    // `finding_at` itself produces the same id for two different lines — now
    // lives in `dike_lang_anchor::detectors::tests::finding_at_is_stable_when_only_the_line_moves`,
    // where the id is actually computed.
    //
    // Note a real exception to the property this used to (mis)claim
    // universally: `llm::structured::to_finding` seeds a Track 2 id with
    // `location.line`, so a Track 2 finding's id genuinely does move when its
    // line does. See the spec's fingerprint section.

    #[test]
    fn an_empty_finding_id_omits_partial_fingerprints_rather_than_a_blank_one() {
        // Reachable on a Track-1-only run: `merge::corroborate` and
        // `merge::merge` set `id: String::new()` on a combined finding (see
        // `merge.rs`), and two such findings share the empty string — GitHub
        // would then treat them as one alert, silently dropping the other.
        // Omitting the key entirely makes GitHub fall back to its own
        // source-hash fingerprinting instead: degraded, but collision-free.
        let mut f = finding("some-class", Severity::High, 10, "withdraw");
        f.id = String::new();
        let r = report_with(vec![f], vec![]);
        let got = results(&r);
        assert!(got[0].get("partialFingerprints").is_none());
    }

    #[test]
    fn a_line_of_zero_omits_the_region_but_keeps_the_artifact_location() {
        // Track 2 can report a finding with no line
        // (`llm::structured::to_finding` uses `f.line.unwrap_or(0)`), and
        // SARIF 2.1.0 requires `region.startLine >= 1`. Emitting 0 makes
        // `github/codeql-action/upload-sarif` reject the *entire* document,
        // discarding every other finding in the run — so it must be omitted,
        // never clamped to 1, which would point a reviewer at the wrong line.
        let mut f = finding("some-class", Severity::High, 10, "withdraw");
        f.location.line = 0;
        let r = report_with(vec![f], vec![]);
        let got = results(&r);
        let physical = &got[0]["locations"][0]["physicalLocation"];
        assert!(physical.get("region").is_none());
        assert_eq!(physical["artifactLocation"]["uri"], "programs/demo/src/lib.rs");
    }

    #[test]
    fn a_rules_security_severity_reflects_the_highest_severity_finding_referencing_it() {
        // GitHub reads `security-severity` from `runs[].tool.driver.rules[].properties`,
        // not from `results[].properties`, to drive the Security tab and the
        // >=7.0 check threshold. Derived from the run's own findings rather
        // than a catalog field, so it can never drift from the pinned
        // per-detector severities.
        let catalog = [doc("some-class", None)];
        let r = report_with(
            vec![
                finding("some-class", Severity::Low, 10, "withdraw"),
                finding("some-class", Severity::Critical, 20, "deposit"),
            ],
            vec![],
        );
        let v = rendered(&r, &catalog);
        let rule = v["runs"][0]["tool"]["driver"]["rules"][0].clone();
        assert_eq!(rule["properties"]["security-severity"], "9.0");
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
        // This is the `leaky_vault` shape: more results than rules.
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
    fn an_empty_base_does_not_double_the_leading_separator() {
        // `strip_prefix("")` trivially succeeds for any path, so an absolute
        // path's root component survived into `components()` and produced
        // "//repo/src/lib.rs" — malformed, and silently unresolvable by a
        // SARIF consumer. An empty base must behave like a non-matching base:
        // the path is emitted unchanged.
        let out = uri_for(Path::new("/repo/src/lib.rs"), Path::new(""));
        assert_eq!(out, "/repo/src/lib.rs");
        assert!(!out.starts_with("//"), "got {out}");
    }

    #[test]
    fn separators_are_normalized_to_forward_slashes() {
        // SARIF `uri` is a URI reference, not a native path.
        let out = uri_for(Path::new(r"C:\repo\src\lib.rs"), Path::new("/nowhere"));
        assert!(!out.contains('\\'), "got {out}");
    }

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
}
