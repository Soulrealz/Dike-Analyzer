//! `dike eval` — build the mutant corpus the differential harness scores against.

use crate::config::RunConfig;
use anyhow::Context;
use dike_core::analyzer::{Analyzer, SourceTree};
use dike_core::eval::{
    append_history, compile_gate, diff_runs, materialize, reject, render_table, summarize, EvalCase,
    RejectedMutant, CASES_FILE, ORIGINAL_DIR, REJECTED_FILE,
};
use dike_lang_anchor::mutations::all_operators;
use std::path::{Path, PathBuf};

/// Cargo build artifacts, shared by every case.
///
/// Each case is a copy of the same crate with the same dependency graph, so one
/// target directory builds those dependencies once rather than once per mutant.
/// It sits beside the cases rather than inside them, so `SourceTree::load` — and
/// the copy `materialize` makes — never see it.
const SHARED_TARGET: &str = ".cargo-target";

pub fn mutate(program: PathBuf, out: PathBuf, no_compile_check: bool) -> anyhow::Result<()> {
    let tree = SourceTree::load(&program)
        .with_context(|| format!("reading {}", program.display()))?;
    let parsed = dike_lang_anchor::parser::parse_tree(&tree);

    let operators = all_operators();
    let mutants: Vec<_> = operators
        .iter()
        .flat_map(|op| op.apply(&parsed.program, &tree))
        .collect();
    if mutants.is_empty() {
        anyhow::bail!(
            "no operator found a site in {}; there is nothing to score",
            program.display()
        );
    }

    let cases = materialize(&program, mutants, &out)
        .with_context(|| format!("materializing into {}", out.display()))?;

    let (kept, rejected) = if no_compile_check {
        (cases, Vec::new())
    } else {
        run_gate(&out, cases)?
    };

    write_json(&out.join(CASES_FILE), &kept)?;
    if no_compile_check {
        // Absence is the record that the gate did not run — the same way an
        // absent `corpus/cache/` is this project's evidence that no fetch has
        // happened. An empty `rejected.json` would claim every case was
        // checked and passed.
        let path = out.join(REJECTED_FILE);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
    } else {
        write_json(&out.join(REJECTED_FILE), &rejected)?;
    }

    report(&out, &kept, &rejected, no_compile_check);
    Ok(())
}

fn run_gate(
    out: &Path,
    cases: Vec<EvalCase>,
) -> anyhow::Result<(Vec<EvalCase>, Vec<RejectedMutant>)> {
    let target = out.join(SHARED_TARGET);
    let mut kept = Vec::new();
    let mut rejected = Vec::new();
    for case in cases {
        match compile_gate(&case.mutant, Some(&target)) {
            Ok(()) => kept.push(case),
            Err(reason) => {
                eprintln!("dike: rejected {} — {}", case.name, first_line(&reason));
                rejected.push(
                    reject(out, &case, reason)
                        .with_context(|| format!("recording rejection of {}", case.name))?,
                );
            }
        }
    }
    Ok((kept, rejected))
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("(no output)")
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))
}

fn report(out: &Path, kept: &[EvalCase], rejected: &[RejectedMutant], skipped: bool) {
    use std::collections::BTreeMap;
    let mut per_operator: BTreeMap<&str, usize> = BTreeMap::new();
    for case in kept {
        *per_operator.entry(case.label.operator.as_str()).or_default() += 1;
    }
    println!("{} cases in {}", kept.len(), out.display());
    for (operator, n) in per_operator {
        println!("  {operator:<24} {n}");
    }
    if skipped {
        println!(
            "validity gate SKIPPED (--no-compile-check): {} cases are unverified, and \
             a finding on a case that no longer compiles inflates recall (D14)",
            kept.len()
        );
    } else if rejected.is_empty() {
        println!("validity gate: all cases compile");
    } else {
        // A non-empty list means an operator emits broken code. Fix the
        // operator; never disable the gate.
        println!("validity gate REJECTED {} cases — see {}", rejected.len(), out.join(REJECTED_FILE).display());
        for r in rejected {
            println!("  {} ({})", r.name, r.label.class);
        }
    }
}

// ---------------------------------------------------------------------------
// `dike eval run`
// ---------------------------------------------------------------------------

/// Which analyzer tracks actually execute.
///
/// Note what is *not* here: `merged`. Merged is a reporting view — the union of
/// the tracks, always present in the table — not something that can be run on
/// its own. The CLI accepts `--track merged` as a spelling of `all` and says so,
/// rather than silently doing something the word does not mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TrackSelection {
    /// Track 1 only. No model, no corpus, no network — the mode CI runs.
    Static,
    /// Track 2 only.
    Llm,
    /// Both tracks.
    All,
    /// Accepted spelling of `all`; merged is a view, not a track.
    Merged,
}

impl TrackSelection {
    fn runs_static(self) -> bool {
        !matches!(self, TrackSelection::Llm)
    }
    fn runs_llm(self) -> bool {
        !matches!(self, TrackSelection::Static)
    }
    fn as_str(self) -> &'static str {
        match self {
            TrackSelection::Static => "static",
            TrackSelection::Llm => "llm",
            TrackSelection::All | TrackSelection::Merged => "all",
        }
    }
}

pub struct EvalRunConfig {
    pub programs: Vec<PathBuf>,
    pub track: TrackSelection,
    /// The history series to append to.
    pub out: PathBuf,
    /// Where mutant trees are materialized. Kept rather than made a temporary
    /// directory, because a rejected mutant and a missed detection are both
    /// things you want to open afterwards.
    pub work_dir: PathBuf,
    pub no_compile_check: bool,
    pub run_id: Option<String>,
    /// Only consulted when Track 2 runs.
    pub llm: RunConfig,
}

pub fn run(cfg: EvalRunConfig) -> anyhow::Result<()> {
    if cfg.track == TrackSelection::Merged {
        eprintln!(
            "dike: `--track merged` runs both tracks; merged is a view of the results, \
             not a track. Reporting it as `all`."
        );
    }

    // Built once and reused across every case: it holds a model client and an
    // open corpus index, and rebuilding them per mutant would dominate the run.
    let llm = if cfg.track.runs_llm() {
        let analyzer = crate::commands::analyze::build_llm_analyzer(&cfg.llm);
        if analyzer.is_none() {
            anyhow::bail!(
                "Track 2 was requested but could not be built; see the reason above. \
                 Recording a run with an absent track would put a zero in the series \
                 that reads as a detector regression"
            );
        }
        analyzer
    } else {
        None
    };
    let llm_ref = llm.as_ref().map(|a| a as &dyn Analyzer);

    let mut outcomes = Vec::new();
    let mut loc = 0usize;
    let mut rejected_total = 0usize;

    for program in &cfg.programs {
        let tree = SourceTree::load(program)
            .with_context(|| format!("reading {}", program.display()))?;
        loc += tree.total_loc();

        let name = program
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "program".to_string());
        let out_dir = cfg.work_dir.join(&name);

        let parsed = dike_lang_anchor::parser::parse_tree(&tree);
        let mutants: Vec<_> = all_operators()
            .iter()
            .flat_map(|op| op.apply(&parsed.program, &tree))
            .collect();
        if mutants.is_empty() {
            anyhow::bail!(
                "no operator found a site in {}; there is nothing to score",
                program.display()
            );
        }
        let cases = materialize(program, mutants, &out_dir)
            .with_context(|| format!("materializing into {}", out_dir.display()))?;
        let (cases, rejected) = if cfg.no_compile_check {
            (cases, Vec::new())
        } else {
            run_gate(&out_dir, cases)?
        };
        rejected_total += rejected.len();
        write_json(&out_dir.join(CASES_FILE), &cases)?;
        if !cfg.no_compile_check {
            write_json(&out_dir.join(REJECTED_FILE), &rejected)?;
        }

        // Analyzed once and reused: the clean run is identical for every mutant
        // of this program, and it is otherwise the single largest cost in the
        // loop — with Track 2 on, it is a full model pass per case.
        let original_tree = SourceTree::load(&out_dir.join(ORIGINAL_DIR))?;
        let original = findings_for(&original_tree, cfg.track, llm_ref);

        for case in &cases {
            let mutant_tree = SourceTree::load(&case.mutant)
                .with_context(|| format!("reading {}", case.mutant.display()))?;
            let mutant = findings_for(&mutant_tree, cfg.track, llm_ref);
            outcomes.push(diff_runs(&original, &mutant, &case.label));
        }
    }

    let mut summary = summarize(&outcomes, loc);
    summary.cases_rejected = rejected_total;
    summary.timestamp = chrono::Utc::now().to_rfc3339();
    summary.run_id = cfg
        .run_id
        .unwrap_or_else(|| format!("{}-{}", summary.timestamp, cfg.track.as_str()));
    if let Some(analyzer) = &llm {
        summary.model = Some(analyzer.client.name());
        summary.corpus_hash = Some(analyzer.retriever.corpus_hash());
    }

    println!("{}", render_table(&summary));
    append_history(&cfg.out, &summary)
        .with_context(|| format!("recording the run in {}", cfg.out.display()))?;
    println!("Recorded as `{}` in {}.", summary.run_id, cfg.out.display());
    Ok(())
}

/// The **unmerged** per-track findings, concatenated. `diff_runs` needs them
/// separate: merging first collapses a static and an LLM hit on the same
/// handler and class into one corroborated finding and destroys exactly the
/// per-track attribution the harness reports.
fn findings_for(
    tree: &SourceTree,
    track: TrackSelection,
    llm: Option<&dyn Analyzer>,
) -> Vec<dike_core::Finding> {
    let mut findings = Vec::new();
    if track.runs_static() {
        findings.extend(dike_lang_anchor::analyze_program(tree).result.findings);
    }
    if let Some(analyzer) = llm {
        findings.extend(analyzer.analyze(tree).findings);
    }
    findings
}

// ---------------------------------------------------------------------------
// `dike eval holdout`
// ---------------------------------------------------------------------------

pub const HOLDOUT_CASES: &str = "benchmarks/holdout/cases.toml";
pub const HOLDOUT_RUNS: &str = "benchmarks/holdout/runs.json";

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

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct HoldoutFile {
    #[serde(default)]
    case: Vec<HoldoutCase>,
}

pub fn holdout(force: bool) -> anyhow::Result<()> {
    // First, before anything that could fail or be skimmed past.
    println!("{MEMORIZATION_CAVEAT}\n");

    let cases_path = Path::new(HOLDOUT_CASES);
    let text = std::fs::read_to_string(cases_path)
        .with_context(|| format!("reading {}", cases_path.display()))?;
    let parsed: HoldoutFile = toml::from_str(&text)
        .with_context(|| format!("parsing {}", cases_path.display()))?;

    let runs_path = Path::new(HOLDOUT_RUNS);
    let prior: Vec<serde_json::Value> = match std::fs::read_to_string(runs_path) {
        Ok(t) => serde_json::from_str(&t)
            .with_context(|| format!("parsing {}", runs_path.display()))?,
        Err(_) => Vec::new(),
    };
    // Spec §8: the holdout is touched once. A second run means the numbers were
    // read, something was changed, and the numbers were read again — which is
    // tuning on the test set, whatever the intent was.
    if !prior.is_empty() && !force {
        anyhow::bail!(
            "the holdout has already been scored ({} run(s) recorded in {}). \
             Iterating against it is tuning on the test set, and the number stops \
             meaning anything. Pass --force only if you have decided to retire this \
             holdout and are reporting it as such",
            prior.len(),
            runs_path.display()
        );
    }

    if parsed.case.is_empty() {
        println!(
            "{} holds no cases. It is a scaffold: populate it from disclosures you \
             have read, with commit hashes you have resolved. Target size is 15–30 \
             cases; see the schema in the file.",
            cases_path.display()
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
    println!(
        "\nScoring these requires fetching each repository at its recorded commit, \
         which this command does not do. Nothing has been scored, and no run has \
         been recorded."
    );
    Ok(())
}
