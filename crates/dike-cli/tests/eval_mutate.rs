//! End-to-end checks on `dike eval mutate`'s output layout.
//!
//! The differential runner reads this directory structure, so its shape is an
//! interface, not an implementation detail.

use std::path::Path;
use std::process::Command;

const FIXTURE: &str = "../../tests/fixtures/programs/vault";

fn run(out: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dike"))
        .args(["eval", "mutate", FIXTURE, "--out"])
        .arg(out)
        .args(extra)
        .output()
        .expect("running dike")
}

#[test]
fn mutate_writes_a_case_directory_per_mutant_and_a_manifest() {
    let out = tempfile::tempdir().unwrap();
    let output = run(out.path(), &["--no-compile-check"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let manifest = std::fs::read_to_string(out.path().join("cases.json")).unwrap();
    let cases: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let cases = cases.as_array().unwrap();
    assert!(cases.len() >= 12, "only {} cases", cases.len());

    let dirs: Vec<_> = std::fs::read_dir(out.path().join("cases"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(dirs.len(), cases.len(), "manifest and case directories disagree");

    for case in cases {
        let dir = Path::new(case["mutant"].as_str().unwrap());
        assert!(dir.join("label.json").is_file(), "{}", dir.display());
        assert!(dir.join("src/lib.rs").is_file());
        // The validity gate needs the manifest, so the copy must carry it.
        assert!(dir.join("Cargo.toml").is_file());
        assert!(Path::new(case["original"].as_str().unwrap()).join("src/lib.rs").is_file());
    }
    assert!(out.path().join("original/src/lib.rs").is_file());
}

/// `--no-compile-check` must not leave behind a record that reads as "checked,
/// nothing rejected" — that is the one claim it cannot make.
#[test]
fn skipping_the_gate_writes_no_rejection_record() {
    let out = tempfile::tempdir().unwrap();
    let first = run(out.path(), &["--no-compile-check"]);
    assert!(first.status.success());
    assert!(!out.path().join("rejected.json").exists());
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("SKIPPED"),
        "{}",
        String::from_utf8_lossy(&first.stdout)
    );
}

/// Mutating a directory with no mutation site in it must not produce an empty
/// case set — an eval run over zero cases scores as perfect recall.
#[test]
fn a_program_with_no_mutation_site_is_an_error_not_an_empty_case_set() {
    let empty = tempfile::tempdir().unwrap();
    std::fs::write(empty.path().join("lib.rs"), "pub fn nothing() {}\n").unwrap();
    let out = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dike"))
        .args(["eval", "mutate"])
        .arg(empty.path())
        .arg("--out")
        .arg(out.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("nothing to score"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The real gate against a real dependency tree. Ignored by default: it builds
/// the fixture's whole dependency graph, which needs the network on a cold
/// machine (CLAUDE.md Rule 8). Run it from the eval target.
#[test]
#[ignore = "builds the fixture's dependency tree; opt in explicitly"]
fn the_gate_accepts_every_mutant_of_the_clean_fixture() {
    let out = tempfile::tempdir().unwrap();
    let output = run(out.path(), &[]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let rejected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.path().join("rejected.json")).unwrap())
            .unwrap();
    // A non-empty list means an operator emits code that does not compile.
    // Fix the operator; never disable the gate.
    assert_eq!(rejected.as_array().unwrap().len(), 0, "{rejected}");
}
