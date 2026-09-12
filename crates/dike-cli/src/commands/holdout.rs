//! `dike eval holdout` — the single scored run against published defects.
//!
//! Split from `eval.rs` because it is a different kind of harness. The
//! differential harness owns its inputs: it makes the mutants, so it can rerun
//! whenever it likes. This one reads code somebody else wrote at a commit
//! somebody else published, and spec §8 permits exactly one scored pass over
//! the set. Almost everything below exists to keep that pass from being spent
//! by accident.
//!
//! Three things are deliberately separate:
//!
//! - Listing the cases is the default and touches nothing. Scoring requires
//!   `--score`, because a command whose bare form spends the one run is a
//!   command that spends it during a demo.
//! - Fetching is the only part that needs the network (Rule 8). `--offline`
//!   runs the whole path against checkouts already on disk, which is how the
//!   scoring path is tested without a fetch.
//! - A run that scored nothing is not recorded, so an offline dry run leaves
//!   the single permitted pass unspent.

use anyhow::Context;
use dike_core::analyzer::SourceTree;
use dike_core::eval::holdout::{
    render_holdout_table, score_case, summarize_holdout, HoldoutCaseResult, HoldoutOutcome,
    HoldoutSummary, HoldoutTarget,
};
use dike_core::finding::Finding;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const HOLDOUT_CASES: &str = "benchmarks/holdout/cases.toml";
pub const HOLDOUT_RUNS: &str = "benchmarks/holdout/runs.json";
/// Default location for checked-out programs. Gitignored: these are other
/// people's repositories at other people's commits, and vendoring them here
/// would redistribute code this project has no licence to redistribute.
pub const HOLDOUT_CHECKOUTS: &str = "benchmarks/holdout/checkouts";
/// Written into a checkout once it is at the recorded commit. Its presence is
/// what makes a second run skip the fetch, and its contents say which commit
/// the directory holds, so a half-finished clone is never mistaken for a good
/// one.
const CHECKOUT_MARKER: &str = ".dike-checkout";

/// The caveat that must travel with every holdout number.
///
/// Printed by the command rather than written in a document, because a footnote
/// in a document is something a summary downstream can drop and a line in the
/// output is not (spec §8).
pub const MEMORIZATION_CAVEAT: &str = "\
CAVEAT — read this before quoting any number below.
These are published findings in well-known programs. They are plausibly in the
generation model's pretraining data, so a Track 2 hit here may be recall of the
program or recitation of the disclosure, and nothing in the result distinguishes
the two. Track 1 is unaffected: it has no pretraining. Quote holdout numbers
only alongside this caveat.";

#[derive(Debug, Clone, serde::Deserialize)]
pub struct HoldoutCase {
    pub id: String,
    pub repo: String,
    pub commit: String,
    pub path: String,
    pub handler: String,
    pub class: String,
    pub severity: String,
    pub source: String,
}

impl HoldoutCase {
    fn target(&self) -> HoldoutTarget {
        HoldoutTarget {
            id: self.id.clone(),
            handler: self.handler.clone(),
            class: self.class.clone(),
        }
    }

    /// Directory name for this case's checkout. Carries the commit so that
    /// editing a case's commit produces a new directory rather than silently
    /// scoring the old code.
    fn checkout_name(&self) -> String {
        format!("{}-{}", self.id, &self.commit[..self.commit.len().min(12)])
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct HoldoutFile {
    #[serde(default)]
    case: Vec<HoldoutCase>,
}

/// One recorded pass, appended to `runs.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HoldoutRun {
    pub run_id: String,
    pub tool_version: String,
    /// Which tracks produced the findings. Recorded because a Track 1 number
    /// and a Track 1 + Track 2 number are not comparable, and the holdout
    /// cannot be rerun to settle which one an old entry was.
    pub tracks: Vec<String>,
    #[serde(flatten)]
    pub summary: HoldoutSummary,
}

pub struct HoldoutOptions {
    pub score: bool,
    pub force: bool,
    pub offline: bool,
    pub checkout_dir: PathBuf,
    pub cases_path: PathBuf,
    pub runs_path: PathBuf,
}

impl Default for HoldoutOptions {
    fn default() -> Self {
        Self {
            score: false,
            force: false,
            offline: false,
            checkout_dir: PathBuf::from(HOLDOUT_CHECKOUTS),
            cases_path: PathBuf::from(HOLDOUT_CASES),
            runs_path: PathBuf::from(HOLDOUT_RUNS),
        }
    }
}

pub fn holdout(opts: HoldoutOptions) -> anyhow::Result<()> {
    // First, before anything that could fail or be skimmed past.
    println!("{MEMORIZATION_CAVEAT}\n");

    let text = std::fs::read_to_string(&opts.cases_path)
        .with_context(|| format!("reading {}", opts.cases_path.display()))?;
    let parsed: HoldoutFile = toml::from_str(&text)
        .with_context(|| format!("parsing {}", opts.cases_path.display()))?;

    if parsed.case.is_empty() {
        println!(
            "{} holds no cases. Populate it from disclosures you have read, with commit \
             hashes you have resolved. Target size is 15–30 cases; see the schema in the file.",
            opts.cases_path.display()
        );
        return Ok(());
    }

    println!("{} holdout case(s):\n", parsed.case.len());
    for case in &parsed.case {
        println!("  {} [{} / {}]", case.id, case.class, case.severity);
        println!(
            "    {} @ {} — {}::{}",
            case.repo,
            &case.commit[..case.commit.len().min(12)],
            case.path,
            case.handler
        );
        println!("    disclosure: {}", case.source);
    }
    println!();

    if !opts.score {
        println!(
            "Listing only. Nothing was scored and no run was recorded. Pass --score to \
             spend the one scored run this set permits (spec §8); add --offline to score \
             only the programs already checked out under {}.",
            opts.checkout_dir.display()
        );
        return Ok(());
    }

    // Spec §8: the holdout is touched once. A second run means the numbers were
    // read, something was changed, and the numbers were read again — which is
    // tuning on the test set, whatever the intent was.
    let prior = read_runs(&opts.runs_path)?;
    if !prior.is_empty() && !opts.force {
        anyhow::bail!(
            "the holdout has already been scored ({} run(s) recorded in {}). \
             Iterating against it is tuning on the test set, and the number stops \
             meaning anything. Pass --force only if you have decided to retire this \
             holdout and are reporting it as such",
            prior.len(),
            opts.runs_path.display()
        );
    }

    if let Some(warning) = unreachable_class_warning(&parsed.case) {
        println!("{warning}\n");
    }

    let results = score_all(&parsed.case, &opts);
    let summary = summarize_holdout(results);
    println!("{}", render_holdout_table(&summary));

    // A run that scored nothing is not a measurement of the tool, so recording
    // it would spend the single permitted pass on the state of the network.
    if summary.cases_scored == 0 {
        println!(
            "Nothing was scored, so no run was recorded and the single scored run is \
             still unspent."
        );
        return Ok(());
    }

    let run = HoldoutRun {
        run_id: chrono::Utc::now().to_rfc3339(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        // Track 1 only. Track 2 over the holdout needs a model and an indexed
        // corpus, and running it here would spend the one pass on a path no
        // test covers.
        tracks: vec!["static".to_string()],
        summary,
    };
    append_run(&opts.runs_path, run)?;
    println!(
        "Recorded in {}. That was the scored run this set permits.",
        opts.runs_path.display()
    );
    Ok(())
}

/// Say so, before the run is spent, when the set contains cases no detector in
/// the track being run can report.
///
/// Measured 2026-09-12 against the six populated cases: four are
/// `removed-guard`, which is Track-2-only by design (D16) because the absence
/// of an arbitrary expression is not a structural signal. A Track 1 pass over
/// this set therefore misses those four before it reads a line of code, and
/// the resulting recall would describe the class vocabulary rather than the
/// detectors. Warned rather than refused: a deliberate Track 1 number over the
/// cases Track 1 can reach is a legitimate thing to want, as long as nobody
/// quotes it as the tool's holdout recall.
fn unreachable_class_warning(cases: &[HoldoutCase]) -> Option<String> {
    let reachable: Vec<&str> = dike_lang_anchor::detectors::all_detectors()
        .iter()
        .map(|d| d.class())
        .collect();
    let mut unreachable: Vec<&str> = cases
        .iter()
        .map(|c| c.class.as_str())
        .filter(|c| !reachable.contains(c))
        .collect();
    unreachable.sort_unstable();
    unreachable.dedup();
    if unreachable.is_empty() {
        return None;
    }
    let affected = cases
        .iter()
        .filter(|c| unreachable.contains(&c.class.as_str()))
        .count();
    Some(format!(
        "WARNING: {} of {} case(s) are classes no Track 1 detector reports ({}). \
         They can only be scored as misses here, so the recall below is a Track 1 \
         number over a set Track 1 cannot fully reach.",
        affected,
        cases.len(),
        unreachable.join(", ")
    ))
}

/// Check out what is missing, analyze each program once, and score every case
/// against it.
///
/// Programs are analyzed per checkout rather than per case, so two cases in the
/// same repository at the same commit cost one analysis. The map is a
/// `BTreeMap` so the work happens in a fixed order (Rule 5).
fn score_all(cases: &[HoldoutCase], opts: &HoldoutOptions) -> Vec<HoldoutCaseResult> {
    let mut analyzed: BTreeMap<PathBuf, Result<Vec<Finding>, String>> = BTreeMap::new();
    let mut results = Vec::with_capacity(cases.len());

    for case in cases {
        let outcome = match ensure_checkout(case, &opts.checkout_dir, opts.offline) {
            Err(reason) => HoldoutOutcome::Unavailable { reason },
            Ok(checkout) => match program_root(&checkout, &case.path) {
                Err(reason) => HoldoutOutcome::Unavailable { reason },
                Ok(root) => {
                    let findings = analyzed
                        .entry(root.clone())
                        .or_insert_with(|| analyze_at(&root));
                    match findings {
                        Err(reason) => HoldoutOutcome::Unavailable { reason: reason.clone() },
                        Ok(findings) => score_case(&case.target(), findings),
                    }
                }
            },
        };
        results.push(HoldoutCaseResult {
            id: case.id.clone(),
            class: case.class.clone(),
            handler: case.handler.clone(),
            outcome,
        });
    }
    results
}

fn analyze_at(root: &Path) -> Result<Vec<Finding>, String> {
    let tree = SourceTree::load(root).map_err(|e| format!("reading {}: {e}", root.display()))?;
    let analysis = dike_lang_anchor::analyze_program(&tree);
    // A program that parsed into no handlers was not analyzed in any meaningful
    // sense, and scoring its cases as misses would report a parser limit as a
    // detector limit.
    if analysis.handlers == 0 {
        return Err(format!("{} parsed into 0 handlers", root.display()));
    }
    Ok(analysis.result.findings)
}

/// The program directory to analyze, derived from the case's file path.
///
/// A case records the file the finding sits in (`programs/x/src/lib.rs`); the
/// analyzer takes a directory. The nearest ancestor with a `Cargo.toml` is that
/// directory, so a repository of many programs is narrowed to the one the case
/// is about rather than analyzed whole.
fn program_root(checkout: &Path, case_path: &str) -> Result<PathBuf, String> {
    let full = checkout.join(case_path);
    if !full.exists() {
        return Err(format!(
            "{case_path} does not exist in the checkout; the case's path or commit is wrong"
        ));
    }
    let mut dir = full.parent();
    while let Some(candidate) = dir {
        if !candidate.starts_with(checkout) {
            break;
        }
        if candidate.join("Cargo.toml").is_file() {
            return Ok(candidate.to_path_buf());
        }
        dir = candidate.parent();
    }
    Err(format!("no Cargo.toml above {case_path} inside the checkout"))
}

/// Make the case's code available on disk, fetching it only if it is not there.
///
/// The marker file records the commit, so an interrupted clone leaves a
/// directory that is retried rather than scored.
fn ensure_checkout(case: &HoldoutCase, dir: &Path, offline: bool) -> Result<PathBuf, String> {
    let target = dir.join(case.checkout_name());
    let marker = target.join(CHECKOUT_MARKER);
    if marker.is_file() {
        let recorded = std::fs::read_to_string(&marker).unwrap_or_default();
        if recorded.trim() == case.commit {
            return Ok(target);
        }
        return Err(format!(
            "{} holds {} but the case records {}",
            target.display(),
            recorded.trim(),
            case.commit
        ));
    }
    if offline {
        return Err(format!(
            "no checkout at {} (offline: no fetch attempted)",
            target.display()
        ));
    }
    fetch_checkout(case, &target)?;
    std::fs::write(&marker, &case.commit)
        .map_err(|e| format!("writing {}: {e}", marker.display()))?;
    Ok(target)
}

/// Clone the repository and check out the exact commit the case records.
///
/// Blob-filtered and without an initial checkout, because the case needs one
/// commit's worth of source and these repositories carry years of history.
/// A partial clone is removed rather than left behind: a directory holding some
/// other commit is worse than no directory.
fn fetch_checkout(case: &HoldoutCase, target: &Path) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    if target.exists() {
        std::fs::remove_dir_all(target)
            .map_err(|e| format!("clearing {}: {e}", target.display()))?;
    }
    eprintln!("dike: fetching {} at {}", case.repo, &case.commit[..case.commit.len().min(12)]);

    let clone = run_git(
        Path::new("."),
        &["clone", "--filter=blob:none", "--no-checkout", "--quiet", &case.repo],
        Some(target),
    );
    if let Err(e) = clone {
        let _ = std::fs::remove_dir_all(target);
        return Err(e);
    }
    if let Err(e) = run_git(target, &["checkout", "--quiet", &case.commit], None) {
        let _ = std::fs::remove_dir_all(target);
        return Err(e);
    }
    Ok(())
}

fn run_git(cwd: &Path, args: &[&str], extra: Option<&Path>) -> Result<(), String> {
    let mut command = std::process::Command::new("git");
    command.current_dir(cwd).args(args);
    if let Some(path) = extra {
        command.arg(path);
    }
    let output = command.output().map_err(|e| format!("running git: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "git {} failed: {}",
        args.first().copied().unwrap_or("?"),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn read_runs(path: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => Ok(Vec::new()),
        Ok(t) => serde_json::from_str(&t).with_context(|| format!("parsing {}", path.display())),
        Err(_) => Ok(Vec::new()),
    }
}

/// Append rather than overwrite: the file is the record that the run was spent,
/// and a `--force` rerun must not erase the entry that says so.
fn append_run(path: &Path, run: HoldoutRun) -> anyhow::Result<()> {
    let mut runs = read_runs(path)?;
    runs.push(serde_json::to_value(&run)?);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&runs)?))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(id: &str, path: &str) -> HoldoutCase {
        HoldoutCase {
            id: id.into(),
            repo: "https://example.invalid/org/repo".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            path: path.into(),
            handler: "withdraw".into(),
            class: "missing-signer".into(),
            severity: "critical".into(),
            source: "https://example.invalid/disclosure".into(),
        }
    }

    /// A checkout already on disk at the recorded commit must be used as is.
    /// Without this the scoring path could not be exercised without a fetch.
    #[test]
    fn an_existing_checkout_at_the_recorded_commit_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let c = case("a", "programs/x/src/lib.rs");
        let target = dir.path().join(c.checkout_name());
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join(CHECKOUT_MARKER), &c.commit).unwrap();

        assert_eq!(ensure_checkout(&c, dir.path(), true), Ok(target));
    }

    /// Offline with nothing on disk is `Unavailable`, never a miss: the case
    /// says nothing about the detectors, and counting it would understate
    /// recall with a number describing the network.
    #[test]
    fn offline_with_no_checkout_is_unavailable_rather_than_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let err = ensure_checkout(&case("a", "programs/x/src/lib.rs"), dir.path(), true)
            .unwrap_err();
        assert!(err.contains("offline"), "{err}");
    }

    /// A directory left over from a different commit must not be scored. The
    /// findings would be real and the attribution would be wrong.
    #[test]
    fn a_checkout_at_the_wrong_commit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let c = case("a", "programs/x/src/lib.rs");
        let target = dir.path().join(c.checkout_name());
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join(CHECKOUT_MARKER), "deadbeefdeadbeef").unwrap();

        let err = ensure_checkout(&c, dir.path(), true).unwrap_err();
        assert!(err.contains("deadbeef") && err.contains(&c.commit), "{err}");
    }

    /// A half-finished clone has no marker, so it is retried rather than
    /// scored as if it were the recorded commit.
    #[test]
    fn a_checkout_without_a_marker_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let c = case("a", "programs/x/src/lib.rs");
        std::fs::create_dir_all(dir.path().join(c.checkout_name()).join("src")).unwrap();

        assert!(ensure_checkout(&c, dir.path(), true).is_err());
    }

    #[test]
    fn the_program_root_is_the_nearest_crate_above_the_case_path() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("programs/x");
        std::fs::create_dir_all(program.join("src")).unwrap();
        std::fs::write(program.join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
        std::fs::write(program.join("src/lib.rs"), "// code\n").unwrap();
        // A workspace manifest at the root must not win over the program's own.
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\n").unwrap();

        assert_eq!(program_root(dir.path(), "programs/x/src/lib.rs"), Ok(program));
    }

    /// A case whose path does not resolve is a defect in the case, and saying
    /// so beats analyzing the whole repository and reporting a miss.
    #[test]
    fn a_case_path_that_does_not_exist_is_reported_as_such() {
        let dir = tempfile::tempdir().unwrap();
        let err = program_root(dir.path(), "programs/x/src/lib.rs").unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn a_checkout_with_no_manifest_above_the_case_path_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("programs/x/src")).unwrap();
        std::fs::write(dir.path().join("programs/x/src/lib.rs"), "// code\n").unwrap();

        let err = program_root(dir.path(), "programs/x/src/lib.rs").unwrap_err();
        assert!(err.contains("no Cargo.toml"), "{err}");
    }

    /// The run-once guard is the only thing standing between the set and being
    /// tuned against. `runs.json` holding an entry must stop a second pass.
    #[test]
    fn a_second_scored_run_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("runs.json");
        std::fs::write(&runs, "[{\"run_id\":\"earlier\"}]").unwrap();
        let cases = dir.path().join("cases.toml");
        std::fs::write(
            &cases,
            "[[case]]\nid=\"a\"\nrepo=\"r\"\ncommit=\"0123456789abcdef\"\npath=\"p\"\n\
             handler=\"h\"\nclass=\"c\"\nseverity=\"high\"\nsource=\"s\"\n",
        )
        .unwrap();

        let err = holdout(HoldoutOptions {
            score: true,
            offline: true,
            cases_path: cases,
            runs_path: runs,
            checkout_dir: dir.path().join("checkouts"),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("already been scored"), "{err:#}");
    }

    /// An offline pass that reached no code must leave the single permitted
    /// run unspent, or checking that the plumbing works would consume the
    /// measurement it exists to protect.
    #[test]
    fn a_run_that_scored_nothing_is_not_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("runs.json");
        let cases = dir.path().join("cases.toml");
        std::fs::write(
            &cases,
            "[[case]]\nid=\"a\"\nrepo=\"r\"\ncommit=\"0123456789abcdef\"\npath=\"p\"\n\
             handler=\"h\"\nclass=\"c\"\nseverity=\"high\"\nsource=\"s\"\n",
        )
        .unwrap();

        holdout(HoldoutOptions {
            score: true,
            offline: true,
            cases_path: cases,
            runs_path: runs.clone(),
            checkout_dir: dir.path().join("checkouts"),
            ..Default::default()
        })
        .unwrap();

        assert!(!runs.exists(), "an unscored run was recorded and spent the one pass");
    }

    /// The one run must not be spent discovering that most of the set was
    /// unreachable by construction. Four of the six populated cases are
    /// `removed-guard`, which is Track-2-only by design (D16).
    #[test]
    fn a_class_no_detector_reports_is_called_out_before_the_run_is_spent() {
        let mut reachable = case("a", "programs/x/src/lib.rs");
        reachable.class = "missing-signer".into();
        let mut unreachable = case("b", "programs/x/src/lib.rs");
        unreachable.class = "removed-guard".into();

        assert_eq!(unreachable_class_warning(&[reachable.clone()]), None);
        let warning = unreachable_class_warning(&[reachable, unreachable]).expect("warned");
        assert!(warning.contains("1 of 2"), "{warning}");
        assert!(warning.contains("removed-guard"), "{warning}");
    }

    /// Listing must not touch `runs.json` at all. `dike eval holdout` with no
    /// flags is the form most likely to be run by someone exploring the tool.
    #[test]
    fn listing_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("runs.json");
        let cases = dir.path().join("cases.toml");
        std::fs::write(
            &cases,
            "[[case]]\nid=\"a\"\nrepo=\"r\"\ncommit=\"0123456789abcdef\"\npath=\"p\"\n\
             handler=\"h\"\nclass=\"c\"\nseverity=\"high\"\nsource=\"s\"\n",
        )
        .unwrap();

        holdout(HoldoutOptions {
            score: false,
            cases_path: cases,
            runs_path: runs.clone(),
            checkout_dir: dir.path().join("checkouts"),
            ..Default::default()
        })
        .unwrap();

        assert!(!runs.exists());
    }
}
