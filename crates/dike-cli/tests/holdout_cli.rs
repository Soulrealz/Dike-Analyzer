//! `dike eval holdout --score` end to end, offline.
//!
//! The real set is scored once, ever, so the scoring path cannot be
//! exercised by running it. These tests build a checkout by hand from a fixture
//! program and point the command at it with `--offline`, which reaches every
//! step except the fetch: derive the program root, analyze, score each case,
//! render, record, and refuse a second pass.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// A checkout the way `ensure_checkout` expects to find one: the case's path
/// resolves, a manifest sits above it, and the marker records the commit.
///
/// The sources are `leaky_vault`, which is a deliberately vulnerable fixture —
/// so the expected outcomes below are known from the fixture rather than from
/// whatever the detectors happen to do today.
fn build_checkout(dir: &Path, id: &str) {
    let program = dir.join(format!("{id}-{}", &COMMIT[..12])).join("programs/vault");
    std::fs::create_dir_all(program.join("src")).unwrap();
    std::fs::write(
        program.join("Cargo.toml"),
        "[package]\nname = \"vault\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    let src = repo_root().join("tests/fixtures/programs/leaky_vault/src");
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), program.join("src").join(entry.file_name())).unwrap();
    }
    let marker = dir.join(format!("{id}-{}", &COMMIT[..12])).join(".dike-checkout");
    std::fs::write(marker, COMMIT).unwrap();
}

fn case(id: &str, handler: &str, class: &str) -> String {
    format!(
        "[[case]]\nid = \"{id}\"\nrepo = \"https://example.invalid/org/repo\"\n\
         commit = \"{COMMIT}\"\npath = \"programs/vault/src/lib.rs\"\n\
         handler = \"{handler}\"\nclass = \"{class}\"\nseverity = \"high\"\n\
         source = \"https://example.invalid/disclosure\"\n\n"
    )
}

fn score(dir: &Path, cases: &str, extra: &[&str]) -> (bool, String, String) {
    let cases_path = dir.join("cases.toml");
    std::fs::write(&cases_path, cases).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dike"))
        .args(["eval", "holdout", "--score", "--offline"])
        .arg("--checkout-dir")
        .arg(dir.join("checkouts"))
        .args(extra)
        .arg("--cases")
        .arg(&cases_path)
        .arg("--runs")
        .arg(dir.join("runs.json"))
        .current_dir(repo_root())
        .output()
        .expect("running dike");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// The three outcomes in one run: a defect the fixture has, a defect it does
/// not, and a case whose code was never obtained.
#[test]
fn scoring_separates_hits_misses_and_cases_that_were_never_analyzed() {
    let dir = tempfile::tempdir().unwrap();
    build_checkout(&dir.path().join("checkouts"), "hit");
    build_checkout(&dir.path().join("checkouts"), "miss");
    let cases = format!(
        "{}{}{}",
        case("hit", "withdraw", "missing-signer"),
        // `removed-guard` is Track-2-only by design, and this scorer runs
        // Track 1, so it is a miss whatever the code says. Using a Track 1
        // class here would tie the test to what the detectors happen to find
        // in the fixture today.
        case("miss", "withdraw", "removed-guard"),
        case("absent", "withdraw", "missing-signer"),
    );

    let (ok, stdout, stderr) = score(dir.path(), &cases, &[]);
    assert!(ok, "stderr:\n{stderr}");

    assert!(stdout.starts_with("CAVEAT"), "{stdout}");
    assert!(stdout.contains("| `hit` | `missing-signer` | hit |"), "{stdout}");
    assert!(stdout.contains("| `miss` | `removed-guard` | miss |"), "{stdout}");
    assert!(stdout.contains("not scored: no checkout"), "{stdout}");
    // One hit out of the two that were analyzed. The unavailable case is out
    // of the denominator, so this is 1/2 rather than 1/3.
    assert!(stdout.contains("Recall 0.500 (1/2 scored"), "{stdout}");
    assert!(stdout.contains("PARTIAL RUN"), "{stdout}");
    assert!(stdout.contains("No precision number"), "{stdout}");

    let runs: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("runs.json")).unwrap())
            .unwrap();
    assert_eq!(runs.as_array().unwrap().len(), 1, "the run was not recorded");
    assert_eq!(runs[0]["cases_scored"], 2);
    assert_eq!(runs[0]["hits"], 1);
    assert_eq!(runs[0]["unavailable"], 1);
    assert_eq!(runs[0]["tracks"][0], "static");
}

/// The guard that makes the number mean something. A second pass would be
/// iterating against the test set, whatever the intent.
#[test]
fn a_second_scored_run_is_refused_and_records_nothing_more() {
    let dir = tempfile::tempdir().unwrap();
    build_checkout(&dir.path().join("checkouts"), "hit");
    let cases = case("hit", "withdraw", "missing-signer");

    let (ok, _, stderr) = score(dir.path(), &cases, &[]);
    assert!(ok, "stderr:\n{stderr}");
    let after_first = std::fs::read_to_string(dir.path().join("runs.json")).unwrap();

    let (ok, _, stderr) = score(dir.path(), &cases, &[]);
    assert!(!ok, "a second scored run was allowed");
    assert!(stderr.contains("already been scored"), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("runs.json")).unwrap(),
        after_first,
        "the refused run still wrote to the record"
    );
}

/// `--force` is the deliberate override, and it must leave the earlier entry
/// in place: `runs.json` is the evidence that the first run happened.
#[test]
fn force_appends_rather_than_replacing_the_earlier_run() {
    let dir = tempfile::tempdir().unwrap();
    build_checkout(&dir.path().join("checkouts"), "hit");
    let cases = case("hit", "withdraw", "missing-signer");

    assert!(score(dir.path(), &cases, &[]).0);
    let (ok, _, stderr) = score(dir.path(), &cases, &["--force"]);
    assert!(ok, "stderr:\n{stderr}");

    let runs: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("runs.json")).unwrap())
            .unwrap();
    assert_eq!(runs.as_array().unwrap().len(), 2, "the first run was overwritten");
}

/// A case whose handler is absorbed into another row must score as a hit. This
/// is the blocker the subject collapse created, exercised through the real
/// pipeline rather than against a hand-built finding: two handlers over one
/// accounts struct share a single unbound authority, the collapse folds them
/// into one row, and the case names the handler that did not survive.
#[test]
fn a_case_whose_handler_was_absorbed_by_the_collapse_still_scores_as_a_hit() {
    let dir = tempfile::tempdir().unwrap();
    let checkouts = dir.path().join("checkouts");
    build_checkout(&checkouts, "absorbed");

    // Inserted *above* `set_fee`, so the collapse's lowest-line rule makes the
    // new handler the survivor and `set_fee` — the handler the case names —
    // the absorbed one. Same context type, so it is the same defect.
    let lib = checkouts
        .join(format!("absorbed-{}", &COMMIT[..12]))
        .join("programs/vault/src/lib.rs");
    let text = std::fs::read_to_string(&lib).unwrap();
    assert!(text.contains("    pub fn set_fee("), "the fixture changed shape");
    let text = text.replace(
        "    pub fn set_fee(",
        "    pub fn adjust_fee(ctx: Context<SetFee>, fee: u64) -> Result<()> {\n\
         \x20       let vault = &mut ctx.accounts.vault;\n\
         \x20       vault.amount = fee;\n\
         \x20       Ok(())\n\
         \x20   }\n\n\
         \x20   pub fn set_fee(",
    );
    std::fs::write(&lib, text).unwrap();

    let (ok, stdout, stderr) = score(
        dir.path(),
        &case("absorbed", "set_fee", "missing-authority-binding"),
        &[],
    );
    assert!(ok, "stderr:\n{stderr}\nstdout:\n{stdout}");
    assert!(
        stdout.contains("hit (absorbed) | adjust_fee"),
        "the defect is found under the surviving handler; scoring it a miss \
         would be scoring the report layout:\n{stdout}"
    );
    assert!(stdout.contains("Recall 1.000"), "{stdout}");
}
