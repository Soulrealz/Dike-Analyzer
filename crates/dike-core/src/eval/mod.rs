//! Ground truth for the differential eval harness.
//!
//! A `MutationLabel` is what a mutation operator *claims* it injected into an
//! otherwise-clean program: a class string, a severity, and a source location.
//! The harness compares it against what an analyzer actually reported.
//!
//! It lives in `dike-core` rather than in a language crate because the harness
//! consumes it and `dike-core` can never depend on a language crate. Nothing
//! here names a language: the class is a free string, exactly as `VulnClass`
//! is, for the same reason (D6).

use crate::finding::Severity;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// One injected defect, labelled by the operator that made the edit.
///
/// The label is emitted at the edit site, never inferred afterwards, so ground
/// truth is exact rather than guessed (spec §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationLabel {
    /// Stable across runs for the same operator and site — the harness keys
    /// history on it, so it must not move when unrelated mutants appear.
    pub id: String,
    /// The class an analyzer is expected to report. Compared against
    /// `VulnClass::as_str`.
    pub class: String,
    pub severity: Severity,
    pub file: PathBuf,
    /// The line the operator rewrote, 1-based. Never 0 (invariant 9).
    pub line: u32,
    /// The enclosing instruction handler — the unit at which findings are
    /// compared (D5).
    pub handler: String,
    /// The operator's `name()`. Carried so a per-operator recall breakdown
    /// needs no second pass over the mutation engine.
    pub operator: String,
}

impl MutationLabel {
    /// The same key `Location::handler_id` produces, so a label and a finding
    /// can be matched without either side knowing the other's type.
    pub fn handler_id(&self) -> String {
        format!("{}::{}", self.file.display(), self.handler)
    }
}

/// One clean program plus one injected defect.
///
/// `files` carries only the files the operator actually rewrote, as
/// `(path, full new text)`; `materialize` copies the clean tree and overwrites
/// exactly these, so a mutant stays small regardless of program size.
///
/// It lives beside `MutationLabel` rather than in the language crate that
/// produces it for the same reason `MutationLabel` does: `materialize` consumes
/// it, and nothing about "a rewritten file plus its ground truth" is
/// language-specific. The operators and the trait that emits them stay in the
/// language crate.
#[derive(Debug, Clone, PartialEq)]
pub struct Mutant {
    pub label: MutationLabel,
    pub files: Vec<(PathBuf, String)>,
}

/// Layout of a materialized eval set, relative to the output directory.
///
/// The accepted cases and the rejected ones live in separate subtrees so that
/// "iterate the cases" never has to consult a manifest to avoid a broken one,
/// while a rejected mutant is still there on disk to be read — a compile
/// failure is a defect in an operator, and deleting the evidence is how it
/// stays undiagnosed.
pub const ORIGINAL_DIR: &str = "original";
pub const CASES_DIR: &str = "cases";
pub const REJECTED_DIR: &str = "rejected";
pub const LABEL_FILE: &str = "label.json";
pub const CASES_FILE: &str = "cases.json";
pub const REJECTED_FILE: &str = "rejected.json";
/// Written into an output directory this tool created, and required before it
/// will clear one. Without it, `--out ~/src` would recursively delete
/// `~/src/cases` on the strength of a typo.
pub const MARKER_FILE: &str = ".dike-eval";

/// One mutant on disk, paired with the clean program it was derived from.
///
/// Both paths are self-contained copies under the output directory: the
/// differential runner compares two trees it owns, and never reads the
/// repository the mutants came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalCase {
    pub name: String,
    pub original: PathBuf,
    pub mutant: PathBuf,
    pub label: MutationLabel,
}

/// A mutant the validity gate refused, with the compiler's own account of why.
///
/// D14: a mutant that no longer compiles is not a vulnerable program, it is a
/// broken one, and a finding triggered by broken code counts as a true positive
/// under differential matching — silently inflating the one number the harness
/// exists to make trustworthy. Rejections are recorded rather than dropped so a
/// broken operator is visible instead of quietly shrinking the case count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedMutant {
    pub name: String,
    pub label: MutationLabel,
    pub reason: String,
}

/// Copies `program_root` once per mutant, overwrites the rewritten files, and
/// writes each mutant's label alongside its tree.
///
/// Programs are small, so a full copy per mutant buys a case that can be
/// analyzed, compiled and diffed in place with no bookkeeping about what was
/// patched. The clean tree is copied once, to `<out_dir>/original`.
///
/// Clears `<out_dir>`'s `original`, `cases` and `rejected` subtrees first, so a
/// second run does not inherit the first one's cases — but only in a directory
/// this tool created (see `MARKER_FILE`).
pub fn materialize(
    program_root: &Path,
    mutants: Vec<Mutant>,
    out_dir: &Path,
) -> io::Result<Vec<EvalCase>> {
    prepare_out_dir(out_dir)?;

    let original = out_dir.join(ORIGINAL_DIR);
    copy_tree(program_root, &original)?;

    let mut cases = Vec::with_capacity(mutants.len());
    for mutant in mutants {
        let name = case_name(&mutant.label);
        let dir = out_dir.join(CASES_DIR).join(&name);
        copy_tree(program_root, &dir)?;
        for (path, text) in &mutant.files {
            // The paths come from the tree that was parsed. A mismatch here
            // means the caller mutated one program and materialized another,
            // which would write the rewrite outside the case directory —
            // worth an error rather than a best guess at the intent.
            let relative = path.strip_prefix(program_root).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not inside {}", path.display(), program_root.display()),
                )
            })?;
            let target = dir.join(relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(target, text)?;
        }
        let label = serde_json::to_string_pretty(&mutant.label)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(dir.join(LABEL_FILE), label)?;
        cases.push(EvalCase {
            name,
            original: original.clone(),
            mutant: dir,
            label: mutant.label,
        });
    }
    Ok(cases)
}

/// A directory name that is unique, stable across runs, and readable enough to
/// tell which operator produced it without opening `label.json`.
pub fn case_name(label: &MutationLabel) -> String {
    format!("{}-{}", label.operator, label.id)
}

/// Moves a case out of `cases/` and into `rejected/`.
pub fn reject(out_dir: &Path, case: &EvalCase, reason: String) -> io::Result<RejectedMutant> {
    let target = out_dir.join(REJECTED_DIR).join(&case.name);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if target.exists() {
        std::fs::remove_dir_all(&target)?;
    }
    std::fs::rename(&case.mutant, &target)?;
    Ok(RejectedMutant {
        name: case.name.clone(),
        label: case.label.clone(),
        reason,
    })
}

fn prepare_out_dir(out_dir: &Path) -> io::Result<()> {
    let occupied = out_dir.exists()
        && out_dir
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
    if occupied && !out_dir.join(MARKER_FILE).exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} is not empty and was not created by this tool; refusing to clear it",
                out_dir.display()
            ),
        ));
    }
    for sub in [ORIGINAL_DIR, CASES_DIR, REJECTED_DIR] {
        let path = out_dir.join(sub);
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
    }
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join(MARKER_FILE), "")?;
    Ok(())
}

/// Recursive copy, skipping build output and dot-entries — the same filter
/// `SourceTree::load` applies, so the copy holds exactly what analysis will
/// see, plus the manifest the validity gate needs.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    if !from.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is not a directory", from.display()),
        ));
    }
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name.starts_with('.') {
            continue;
        }
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// How long a single validity check may run before it is killed and rejected.
pub const COMPILE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Runs `cargo check` over a materialized case and reports whether it builds.
///
/// This is the one place the tool shells out to `cargo`, and it runs only
/// against eval fixtures this repository controls — never against a program a
/// user asked it to analyze.
///
/// `shared_target` is a deviation from the plan's one-argument signature, and
/// it is the difference between a usable gate and an unusable one: every case
/// is a copy of the same crate with the same dependency graph, so pointing them
/// all at one `CARGO_TARGET_DIR` builds those dependencies once instead of once
/// per mutant. Pass `None` to let each case build in its own directory.
pub fn compile_gate(case_dir: &Path, shared_target: Option<&Path>) -> Result<(), String> {
    let manifest = case_dir.join("Cargo.toml");
    if !manifest.is_file() {
        return Err(format!(
            "{} has no Cargo.toml, so it cannot be checked; the validity gate needs a \
             buildable fixture crate",
            case_dir.display()
        ));
    }

    // The compiler's output goes to a file rather than a pipe: a pipe whose
    // buffer fills blocks the child, and the child is the thing being polled
    // for the timeout, so the two would deadlock on exactly the verbose
    // failures worth reading.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let log = std::env::temp_dir().join(format!("dike-check-{}-{n}.log", std::process::id()));
    let sink = std::fs::File::create(&log).map_err(|e| format!("creating {}: {e}", log.display()))?;

    let mut command = std::process::Command::new("cargo");
    command
        .arg("check")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(&manifest)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(sink));
    if let Some(target) = shared_target {
        command.env("CARGO_TARGET_DIR", target);
    }

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&log);
            return Err(format!("could not run cargo: {e}"));
        }
    };

    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() >= COMPILE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = std::fs::remove_file(&log);
                    return Err(format!(
                        "cargo check exceeded {}s",
                        COMPILE_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                let _ = std::fs::remove_file(&log);
                return Err(format!("waiting on cargo: {e}"));
            }
        }
    };

    let output = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_file(&log);
    if status.success() {
        Ok(())
    } else {
        Err(output.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Location;

    fn label(operator: &str, id: &str) -> MutationLabel {
        MutationLabel {
            id: id.into(),
            class: "missing-signer".into(),
            severity: Severity::Critical,
            file: PathBuf::from("src/lib.rs"),
            line: 3,
            handler: "withdraw".into(),
            operator: operator.into(),
        }
    }

    /// A tiny program tree, so the copy has a subdirectory to recurse into and
    /// a non-source file to carry.
    fn clean_program(root: &Path) {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"p\"\n").unwrap();
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join("target/junk"), "build output").unwrap();
    }

    fn two_mutants(root: &Path) -> Vec<Mutant> {
        vec![
            Mutant {
                label: label("op_one", "aaaa"),
                files: vec![(root.join("src/lib.rs"), "pub fn a() { /* one */ }\n".into())],
            },
            Mutant {
                label: label("op_two", "bbbb"),
                files: vec![(root.join("src/lib.rs"), "pub fn a() { /* two */ }\n".into())],
            },
        ]
    }

    #[test]
    fn materialize_writes_one_directory_per_mutant_with_a_label() {
        let src = tempfile::tempdir().unwrap();
        clean_program(src.path());
        let out = tempfile::tempdir().unwrap();

        let cases =
            materialize(src.path(), two_mutants(src.path()), out.path()).unwrap();

        assert_eq!(cases.len(), 2);
        for case in &cases {
            assert!(case.mutant.join(LABEL_FILE).exists());
            assert!(case.mutant.join("src/lib.rs").exists());
            assert!(case.original.join("src/lib.rs").exists());
            let written: MutationLabel =
                serde_json::from_str(&std::fs::read_to_string(case.mutant.join(LABEL_FILE)).unwrap())
                    .unwrap();
            assert_eq!(written, case.label);
        }
        assert_ne!(cases[0].mutant, cases[1].mutant);
    }

    /// The rewrite must land in the copy, and the copy must otherwise be the
    /// clean program — a mutant that also carried a neighbour's edit could not
    /// be attributed.
    #[test]
    fn each_case_carries_its_own_rewrite_and_nothing_else() {
        let src = tempfile::tempdir().unwrap();
        clean_program(src.path());
        let out = tempfile::tempdir().unwrap();

        let cases = materialize(src.path(), two_mutants(src.path()), out.path()).unwrap();
        let read = |p: PathBuf| std::fs::read_to_string(p).unwrap();

        assert!(read(cases[0].mutant.join("src/lib.rs")).contains("one"));
        assert!(!read(cases[0].mutant.join("src/lib.rs")).contains("two"));
        assert!(read(cases[1].mutant.join("src/lib.rs")).contains("two"));
        assert_eq!(read(cases[0].original.join("src/lib.rs")), "pub fn a() {}\n");
        // Non-source files come along; the gate needs the manifest.
        assert!(cases[0].mutant.join("Cargo.toml").is_file());
        // Build output does not.
        assert!(!cases[0].mutant.join("target").exists());
    }

    /// A second run must not inherit the first run's cases, or a case count
    /// would only ever grow and stale mutants would be scored again.
    #[test]
    fn a_second_run_replaces_the_cases_of_the_first() {
        let src = tempfile::tempdir().unwrap();
        clean_program(src.path());
        let out = tempfile::tempdir().unwrap();

        let first = materialize(src.path(), two_mutants(src.path()), out.path()).unwrap();
        let stale = first[1].mutant.clone();
        let second = materialize(
            src.path(),
            vec![two_mutants(src.path()).remove(0)],
            out.path(),
        )
        .unwrap();

        assert_eq!(second.len(), 1);
        assert!(!stale.exists(), "a case from the previous run survived");
    }

    /// Clearing a directory this tool did not create is how `--out` turns into
    /// a recursive delete of somebody's source tree.
    #[test]
    fn materialize_refuses_to_clear_a_directory_it_did_not_create() {
        let src = tempfile::tempdir().unwrap();
        clean_program(src.path());
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("someones-work.txt"), "important").unwrap();

        let err = materialize(src.path(), two_mutants(src.path()), out.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(out.path().join("someones-work.txt").exists());
    }

    /// Materializing a tree the mutants did not come from would write the
    /// rewrite outside the case directory.
    #[test]
    fn materialize_rejects_a_rewrite_from_outside_the_program() {
        let src = tempfile::tempdir().unwrap();
        clean_program(src.path());
        let out = tempfile::tempdir().unwrap();
        let stray = vec![Mutant {
            label: label("op_one", "aaaa"),
            files: vec![(PathBuf::from("/elsewhere/src/lib.rs"), "x".into())],
        }];

        let err = materialize(src.path(), stray, out.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn reject_moves_a_case_out_of_the_case_set_but_keeps_it_on_disk() {
        let src = tempfile::tempdir().unwrap();
        clean_program(src.path());
        let out = tempfile::tempdir().unwrap();
        let cases = materialize(src.path(), two_mutants(src.path()), out.path()).unwrap();

        let record = reject(out.path(), &cases[0], "it exploded".into()).unwrap();

        assert!(!cases[0].mutant.exists());
        let moved = out.path().join(REJECTED_DIR).join(&cases[0].name);
        assert!(moved.join("src/lib.rs").exists(), "the evidence was deleted");
        assert_eq!(record.reason, "it exploded");
        assert_eq!(record.label, cases[0].label);
        // The surviving case is untouched.
        assert!(cases[1].mutant.exists());
    }

    /// Names must not collide (one case would overwrite another) and must not
    /// move between runs (history is keyed on them).
    #[test]
    fn case_names_are_distinct_and_stable() {
        assert_eq!(case_name(&label("op_one", "aaaa")), "op_one-aaaa");
        assert_ne!(
            case_name(&label("op_one", "aaaa")),
            case_name(&label("op_one", "bbbb"))
        );
        assert_ne!(
            case_name(&label("op_one", "aaaa")),
            case_name(&label("op_two", "aaaa"))
        );
    }

    fn write_minimal_crate(root: &Path, body: &str) {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            // An empty `[workspace]` table detaches the crate from any
            // workspace above it in the filesystem, which is what lets a
            // fixture live inside this repository without being built by
            // `cargo test` at the root.
            "[package]\nname = \"probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n",
        )
        .unwrap();
        std::fs::write(root.join("src/main.rs"), body).unwrap();
    }

    /// D14. These two shell out to `cargo`, so they are the slowest tests in
    /// the workspace by a wide margin; the crate they build has no
    /// dependencies, so neither needs the network.
    #[test]
    fn the_compile_gate_rejects_a_syntactically_broken_mutant() {
        let dir = tempfile::tempdir().unwrap();
        write_minimal_crate(dir.path(), "fn main() { let x = ; }");
        let err = compile_gate(dir.path(), None).unwrap_err();
        assert!(!err.is_empty(), "a rejection with no reason is not a report");
    }

    #[test]
    fn the_compile_gate_accepts_a_valid_crate() {
        let dir = tempfile::tempdir().unwrap();
        write_minimal_crate(dir.path(), "fn main() {}");
        assert_eq!(compile_gate(dir.path(), None), Ok(()));
    }

    /// A case with no manifest cannot be checked. Reporting that as a pass
    /// would make the gate silently vacuous on exactly the fixture layout this
    /// repository used before Task 24.
    ///
    /// Asserts on *our* explanation, not merely on a failure: `cargo` would
    /// also fail here, and with a message that happens to name `Cargo.toml`
    /// too — so a looser assertion would pass with the check removed and would
    /// cost a process spawn per case to say something less useful.
    #[test]
    fn the_compile_gate_refuses_a_case_it_cannot_build() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn a() {}").unwrap();
        let err = compile_gate(dir.path(), None).unwrap_err();
        assert!(err.contains("buildable fixture crate"), "{err}");
    }

    /// The whole point of the type is that it lines up with a `Finding`'s
    /// location. If either side changes its key format, this goes red.
    #[test]
    fn a_label_and_a_location_agree_on_the_handler_key() {
        let label = MutationLabel {
            id: "abc".into(),
            class: "some-class".into(),
            severity: Severity::High,
            file: PathBuf::from("src/lib.rs"),
            line: 12,
            handler: "withdraw".into(),
            operator: "some_operator".into(),
        };
        let location = Location {
            file: PathBuf::from("src/lib.rs"),
            line: 99, // deliberately different: the key must not read the line
            handler: "withdraw".into(),
        };
        assert_eq!(label.handler_id(), location.handler_id());
    }
}
