//! `dike eval` — build the mutant corpus the differential harness scores against.

use anyhow::Context;
use dike_core::analyzer::SourceTree;
use dike_core::eval::{
    compile_gate, materialize, reject, EvalCase, RejectedMutant, CASES_FILE, REJECTED_FILE,
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
