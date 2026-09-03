//! `dike eval run` end to end, in the mode CI uses: Track 1 only, no model, no
//! network.
//!
//! These are the tests that read the harness's own output as a number rather
//! than as a shape. When one of them changes, a detector changed.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs a static eval into a throwaway history file and returns
/// `(stdout, the recorded summary)`.
fn run_static_eval(dir: &Path, extra: &[&str]) -> (String, dike_core::eval::EvalSummary) {
    let history = dir.join("history.json");
    std::fs::write(&history, "[]").unwrap();
    let work = dir.join("work");

    let output = Command::new(env!("CARGO_BIN_EXE_dike"))
        .args(["eval", "run", "tests/fixtures/programs/vault", "--track", "static", "--out"])
        .arg(&history)
        .arg("--work-dir")
        .arg(&work)
        .args(extra)
        .current_dir(repo_root())
        .output()
        .expect("running dike");
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let runs = dike_core::eval::read_history(&history).unwrap();
    assert_eq!(runs.len(), 1, "the run was not recorded");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        runs.into_iter().next().unwrap(),
    )
}

#[test]
fn static_eval_runs_end_to_end_without_a_model_and_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let (stdout, summary) = run_static_eval(dir.path(), &["--no-compile-check"]);

    assert!(stdout.contains("Recall"));
    assert!(stdout.contains("missing-signer"));
    assert!(stdout.contains("Noise floor"));
    assert!(!summary.run_id.is_empty() && !summary.timestamp.is_empty());
    // Track 1 needs no model and no corpus, and must not claim either.
    assert_eq!(summary.model, None);
    assert_eq!(summary.corpus_hash, None);
}

/// Four of the five Track 1 classes have a mutation operator whose injected
/// defect the detector is built to see. Anything below 1.0 here is a detector
/// regression, not a model result.
#[test]
fn static_eval_detects_every_class_with_a_reachable_detector() {
    let dir = tempfile::tempdir().unwrap();
    let (_, summary) = run_static_eval(dir.path(), &["--no-compile-check"]);

    for class in [
        "missing-signer",
        "missing-owner-check",
        "missing-authority-binding",
        "unchecked-arithmetic",
    ] {
        let m = summary
            .per_class
            .iter()
            .find(|m| m.class == class && m.track == dike_core::eval::MetricTrack::Static)
            .unwrap_or_else(|| panic!("no static row for {class}"));
        assert_eq!(m.recall, 1.0, "{class} recall dropped to {}", m.recall);
        assert_eq!(
            m.precision,
            Some(1.0),
            "{class} precision dropped to {:?}",
            m.precision
        );
    }
}

/// **This test pins a known defect, and it is meant to fail when the defect is
/// fixed.**
///
/// `PdaValidationGapDetector` fires only on `has_seeds() != has_bump()` — an
/// inconsistent pair. That condition cannot occur in a program Anchor will
/// compile: verified on 2026-09-03 against `anchor-lang` 0.30, `seeds` without
/// `bump` is rejected at compile time with "bump must be provided with seeds".
/// So the detector cannot fire on any real program, and `strip_seeds_bump`,
/// which removes a whole PDA constraint, injects a defect Track 1 cannot see.
///
/// Nothing is silently excluded to keep the numbers pretty: the class stays in
/// the table at 0.000. When somebody teaches the detector what a missing PDA
/// constraint looks like, this test goes red and the expectation above moves
/// here.
#[test]
fn pda_validation_gap_is_not_yet_detectable_and_this_test_is_the_reminder() {
    let dir = tempfile::tempdir().unwrap();
    let (_, summary) = run_static_eval(dir.path(), &["--no-compile-check"]);

    let m = summary
        .per_class
        .iter()
        .find(|m| m.class == "pda-validation-gap" && m.track == dike_core::eval::MetricTrack::Static)
        .expect("pda-validation-gap must stay in the table, at whatever it scores");
    assert!(m.total_cases > 0, "the operator stopped producing cases");
    assert_eq!(
        m.recall, 0.0,
        "pda-validation-gap now scores {}; if the detector was fixed, move it into \
         static_eval_detects_every_class_with_a_reachable_detector and delete this test",
        m.recall
    );
}

/// The clean fixture is the mutation source; a non-zero noise floor on it means
/// a detector started firing on correct code.
#[test]
fn the_clean_fixture_has_no_noise_floor() {
    let dir = tempfile::tempdir().unwrap();
    let (_, summary) = run_static_eval(dir.path(), &["--no-compile-check"]);
    let noise = summary
        .noise
        .iter()
        .find(|n| n.track == dike_core::eval::MetricTrack::Static)
        .unwrap();
    assert_eq!(noise.findings, 0, "the clean fixture now yields findings");
    assert_eq!(noise.loc, 162);
}

/// The caveat is printed by the command so a summary downstream cannot drop it.
#[test]
fn the_holdout_command_leads_with_the_memorization_caveat() {
    let output = Command::new(env!("CARGO_BIN_EXE_dike"))
        .args(["eval", "holdout"])
        .current_dir(repo_root())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("CAVEAT"), "{stdout}");
    assert!(stdout.contains("pretraining data"));
    // The scaffold ships empty on purpose: an invented commit hash would look
    // exactly like a real case and produce a real-looking number.
    assert!(stdout.contains("holds no cases"), "{stdout}");
}

/// The same run with the validity gate on. Ignored by default: it builds the
/// fixture's dependency tree, which needs the network on a cold machine
/// (CLAUDE.md Rule 8). This is what `just eval-static` runs.
#[test]
#[ignore = "builds the fixture's dependency tree; opt in explicitly"]
fn static_eval_with_the_validity_gate_rejects_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (_, summary) = run_static_eval(dir.path(), &[]);
    assert_eq!(summary.cases_rejected, 0);
}

/// The differential mechanism itself, exercised against a program that is
/// broken before anything is injected.
///
/// `leaky_vault` is the vulnerable fixture: Track 1 reports findings on it
/// already. Mutating it is not how the harness is meant to be used — a mutation
/// applied to already-broken code cannot be attributed — which is exactly what
/// makes it the test. Those pre-existing findings must land in the noise floor
/// and must not be credited as detections, so classes whose sites were already
/// being reported score *below* what they reach on the clean fixture.
///
/// Without this, nothing pins that the clean run happens at all: on the clean
/// fixture the original produces no findings, so skipping that run entirely
/// changes not one number in the table.
#[test]
fn findings_that_pre_date_the_mutation_are_noise_and_earn_no_credit() {
    let dir = tempfile::tempdir().unwrap();
    let history = dir.path().join("history.json");
    std::fs::write(&history, "[]").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dike"))
        .args(["eval", "run", "tests/fixtures/programs/leaky_vault", "--track", "static", "--out"])
        .arg(&history)
        .arg("--work-dir")
        .arg(dir.path().join("work"))
        .arg("--no-compile-check")
        .current_dir(repo_root())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let summary = dike_core::eval::read_history(&history).unwrap().remove(0);

    let noise = summary
        .noise
        .iter()
        .find(|n| n.track == dike_core::eval::MetricTrack::Static)
        .unwrap();
    assert!(
        noise.findings > 0,
        "the vulnerable fixture reported no pre-existing findings, so the original \
         run either did not happen or found nothing it should have"
    );

    // `missing-owner-check` has sites the analyzer already reports on. Crediting
    // those would put recall at 1.000, the same as on the clean fixture.
    let owner = summary
        .per_class
        .iter()
        .find(|m| {
            m.class == "missing-owner-check" && m.track == dike_core::eval::MetricTrack::Static
        })
        .unwrap();
    assert!(owner.total_cases > owner.true_positives, "{owner:?}");
    assert!(
        owner.recall < 1.0,
        "a finding that pre-dates the mutation was credited to it"
    );
}

/// Recording a run whose requested track never started would write zeros into
/// the series that read exactly like a detector regression.
#[test]
fn a_track_that_cannot_be_built_fails_the_run_rather_than_recording_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let history = dir.path().join("history.json");
    std::fs::write(&history, "[]").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dike"))
        .args(["eval", "run", "tests/fixtures/programs/vault", "--track", "llm", "--out"])
        .arg(&history)
        .arg("--work-dir")
        .arg(dir.path().join("work"))
        .arg("--index-dir")
        // Track 2 needs a corpus index; this one does not exist.
        .arg(dir.path().join("no-such-index"))
        .arg("--no-compile-check")
        .current_dir(repo_root())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(
        std::fs::read_to_string(&history).unwrap().trim(),
        "[]",
        "a run was recorded despite the track never starting"
    );
}
