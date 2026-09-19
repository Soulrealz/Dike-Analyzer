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
fn the_vulnerable_fixture_renders_eight_results_across_six_rules() {
    // Verified 2026-09-19. Eight results, six distinct classes: the case that
    // catches a renderer emitting one rule per result.
    //
    // 7/5 -> 8/6 on 2026-09-19, when `removed-guard` gained a rule for an
    // account that moves value, is named after state the handler writes, and
    // is unpinned. `vault_token` is that account in BOTH `deposit` and
    // `withdraw`; `collapse_by_subject` folds the two handlers into one row,
    // which is why this is 8 and not 9.
    let v = sarif_for("tests/fixtures/programs/leaky_vault");
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 8, "results: {results:#?}");

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
            "removed-guard",
        ])
    );
    assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 6);
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
