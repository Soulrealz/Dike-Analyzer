# Dike Anchor Security Analyzer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `dike`, a Rust CLI that analyzes Solana Anchor programs from source alone and emits prioritized, precedent-backed security findings from two independent tracks (deterministic static detectors + a retrieval-grounded LLM pass), with a mutation-based differential eval harness proving its recall.

**Architecture:** Three crates. `dike-core` is domain-agnostic: it owns the `Finding` type, the `Analyzer` trait seam, retrieval, the LLM client, merge/ranking, reporting, and the eval harness — it knows nothing about Solana. `dike-lang-anchor` owns everything Solana-specific: the `syn`-based parser producing an IR, the constraint detectors, the LLM chunker, and the mutation catalogue. `dike-cli` owns orchestration: config, the pipeline driver, corpus fetching, and the binary. Two tracks run independently over the same program and are merged only at the end; Track 2 never feeds Track 1's metrics.

**Tech Stack:** Rust (2021 edition), `syn` 2.x + `proc-macro2` (parsing, span → line), `walkdir`, `serde`/`serde_json`, `clap` 4 (CLI), `tantivy` (BM25), `rusqlite` + `sqlite-vec` (vector store), `reqwest` blocking (Ollama + Gemini HTTP), `blake3` (content/corpus hashing), `toml`, `tracing` + `tracing-subscriber`, `insta` (snapshot tests), `tempfile` (test fixtures). Local models via Ollama: `qwen2.5-coder:14b-instruct-q4_K_M` (generation) and `bge-small-en-v1.5` (embeddings).

**Spec:** `docs/superpowers/specs/analyzer/August_2026/2026-08-27-analyzer-design.md`

## Global Constraints

- **Triage, not a gate.** `dike analyze` exits **0 even when findings exist**. Non-zero exit is reserved for tool failure (unreadable root, malformed config, internal panic). Never add a `--fail-on` flag in v1.
- **Recall is the primary metric.** Where a design choice trades precision for recall, take recall.
- **Source-only.** The analyzer must never invoke `cargo`, `anchor`, or any build tool on the *target* program. (`cargo check` is used in exactly one place — the mutation validity gate of Task 24 — and that runs against eval fixtures, not user input.)
- **Partial results beat no results.** A file that fails to parse is warned about, skipped, and listed in the report's coverage section. Never silent, never fatal.
- **Track 2 never feeds Track 1's metrics.** Every metric and every report section is emitted per-track (`static` / `llm` / `merged`) and never collapsed.
- **Every Track 2 finding must cite ≥1 retrieved document, validated against the documents actually placed in the prompt.** Uncited or hallucinated-citation findings are dropped.
- **`dike-core` contains no Solana identifiers.** Enforced by a test (Task 4, Step 6). If a Solidity port would force a change to `Finding`, `Analyzer`, or the eval harness, the boundary is wrong.
- **Total cost $0.** Local models only in the eval loop; Gemini free tier for spot checks only. Hardware ceiling: RTX 5070 12GB VRAM / 15GB system RAM — never plan a model above 14B quantized.
- **Every run records** tool version, model name+version, and corpus hash in the report.
- **Commit after every task.** Conventional commit prefixes (`feat:`, `test:`, `fix:`, `chore:`, `docs:`).

## Decisions Resolved During Planning

The spec left these under-specified. They are pinned here; treat these values as normative.

| # | Area | Decision |
|---|---|---|
| D1 | Workspace | **Three crates** — `dike-core`, `dike-lang-anchor`, `dike-cli`. Orchestration (pipeline driver, config, corpus fetch) lives in `dike-cli` so `dike-core` stays a pure library. |
| D2 | Severity weights | `Critical 1.0, High 0.75, Medium 0.5, Low 0.25, Info 0.1`. Rank score = `severity.weight() * confidence`, descending; ties broken by `(severity, handler_id, class)` for determinism. |
| D3 | Track 2 confidence | Model's raw value clamped to `[0.10, 0.90]`, then multiplied by `0.8` if exactly one citation survived validation. |
| D4 | Corroboration | Noisy-OR: `c = 1 - (1 - c1) * (1 - c2)`, capped at `0.98`. Severity = `max(s1, s2)`. Track = `Corroborated`. Evidence and citations from both are concatenated. |
| D5 | Merge key | `(handler_id, class)` where `handler_id = "<file path>::<handler name>"`. **Not** the span — Track 1 and Track 2 spans never coincide, which would silently defeat corroboration. Span is retained on `Location` for display only. |
| D6 | `VulnClass` | A `String` newtype in `dike-core`, **not** an enum. Class constants (`"missing-signer"`, …) are declared in `dike-lang-anchor`. A hardcoded enum of Solana classes in core would fail the seam test. |
| D7 | `Signer` ambiguity | `Wrapper::Signer` = the `Signer<'info>` type. `Constraint::SignerAttr` = the literal `signer` keyword inside `#[account(...)]` (legacy Anchor). They are distinct and both satisfy the missing-signer detector. |
| D8 | Wrapper coverage | The IR must handle `InterfaceAccount`, `Box<...>`, and `Option<...>`. `Box`/`Option` are unwrapped to flags (`boxed`, `optional`) on `AccountDecl`, not variants. |
| D9 | Body opacity | The parser emits a typed `HandlerBody` **summary** (calls, arithmetic ops, imperative checks, state writes) at parse time. Detectors read the summary; `syn` is used in exactly one module tree (`dike-lang-anchor::parser`). |
| D10 | Cross-file resolution | One global symbol table keyed by bare type name, built across all parsed files. Name collisions: first-seen wins, and an `Ambiguity` diagnostic is emitted. |
| D11 | Retrieval threshold | No threshold on RRF scores — they are rank-derived and have no absolute meaning. Grounding requires the best **pre-fusion dense cosine similarity ≥ 0.35** OR at least one BM25 hit with score > 0. Otherwise the unit is ungrounded and Track 2 emits nothing for it. `top_k = 5`. |
| D12 | Citation validation | The prompt carries explicit `doc_id`s. Returned citations are filtered to ids actually present in that prompt. If zero survive, the finding is dropped and a `citation_rejected` counter is incremented. |
| D13 | Mutation scope | **Six operators in v1** (signer, owner/type, has_one, constraint strip, seeds/bump, arithmetic). `state write after CPI` and `rounding flip` are deferred — they need semantically valid rewrites and have no Track 1 detector. |
| D14 | Mutant validity | Every generated mutant must pass `cargo check` in its fixture workspace. A mutant that fails is rejected, not evaluated, and logged. Prevents recall inflation from findings triggered by broken code. |
| D15 | Imperative checks | Track 1 runs a suppression pass in v1: a constraint finding whose account is referenced by a `require!`/`require_keys_eq!`/`require_eq!`/`#[access_control]` check in the same handler is **suppressed** (recorded as suppressed in the report, not emitted). This is the largest false-positive source on real code. |
| D16 | Per-track class coverage | Declared up front so the eval table is readable: Track 1 covers `missing-signer`, `missing-owner-check`, `missing-authority-binding`, `pda-validation-gap`, `unchecked-arithmetic`. `removed-guard` is **Track 2 only** — the absence of an arbitrary `constraint = ...` expression is not a detectable structural signal. |
| D17 | Corpus reproducibility | `corpus/sources.toml` stores a `sha256` per source. The fetch command verifies it and fails loudly on drift. `corpus_hash` = blake3 over the sorted list of document ids + content hashes. |
| D18 | Noise floor denominator | Findings present in **both** the original and mutated runs, normalized per 1000 physical LOC **of the whole analyzed program**, reported per track. |

## File Structure

```
Cargo.toml                                  workspace manifest, shared deps in [workspace.dependencies]
rust-toolchain.toml                         pinned stable toolchain
justfile                                    dev + eval targets (dike then anchor build; make-style)
.github/workflows/ci.yml                    fmt, clippy, test, Track-1-only eval

crates/dike-core/src/
  lib.rs                                    re-exports; module wiring
  finding.rs                                Severity, VulnClass, Track, Location, Citation, Finding
  analyzer.rs                               Analyzer trait, SourceTree, SourceFile, AnalysisResult, Diagnostic
  merge.rs                                  dedupe on (handler_id, class), corroboration, ranking
  report/mod.rs                             Report, RunMetadata, Coverage
  report/markdown.rs                        human renderer
  report/json.rs                            machine renderer (eval harness input)
  retrieval/mod.rs                          Retriever facade, RetrievalHit, top_k + grounding rule
  retrieval/document.rs                     Document type, chunk-by-finding splitter
  retrieval/bm25.rs                         tantivy index build + query
  retrieval/dense.rs                        embedding client + sqlite-vec store
  retrieval/rrf.rs                          Reciprocal Rank Fusion, k=60
  llm/mod.rs                                LlmClient trait, LlmError, per-request timeout
  llm/ollama.rs                             local backend
  llm/gemini.rs                             hosted free-tier backend
  llm/structured.rs                         schema, parse, one-retry-with-violation
  eval/mod.rs                               MutationLabel, EvalCase, EvalRunner
  eval/differential.rs                      original-vs-mutant diffing, handler+class matching
  eval/metrics.rs                           per-class/per-track recall+precision, noise floor
  eval/history.rs                           benchmarks/history.json append + schema

crates/dike-lang-anchor/src/
  lib.rs                                    AnchorAnalyzer (impl Analyzer), class constants
  ir.rs                                     Program, Handler, HandlerBody, AccountsStruct, AccountDecl, Wrapper, Constraint
  parser/mod.rs                             ingest driver, per-file tolerance, symbol table assembly
  parser/symbols.rs                         global symbol table (D10)
  parser/accounts.rs                        #[derive(Accounts)] struct → AccountsStruct
  parser/program.rs                         #[program] mod → Handler list, context type binding
  parser/body.rs                            HandlerBody summary extraction (D9)
  detectors/mod.rs                          Detector trait, registry, per-detector confidence constants
  detectors/signer.rs                       missing-signer
  detectors/owner.rs                        missing-owner-check
  detectors/authority.rs                    missing-authority-binding (has_one)
  detectors/pda.rs                          pda-validation-gap (seeds/bump)
  detectors/arithmetic.rs                   unchecked-arithmetic
  detectors/suppression.rs                  imperative-check suppression pass (D15)
  chunker.rs                                HandlerUnit + derived query construction
  mutations/mod.rs                          Mutation, MutationLabel, catalogue registry
  mutations/operators.rs                    the six v1 operators (D13)

crates/dike-cli/src/
  main.rs                                   clap dispatch
  config.rs                                 dike.toml + flag resolution
  pipeline.rs                               run both tracks, merge, render
  commands/analyze.rs                       dike analyze <path>
  commands/ir.rs                            dike ir <path>  (debug: dump IR as JSON)
  commands/corpus.rs                        dike corpus fetch | index | hash
  commands/eval.rs                          dike eval [--track static|llm|merged]

corpus/sources.toml                         URL, license note, retrieval date, sha256 (D17)
corpus/notes/                               derived original notes (committable)
benchmarks/history.json                     committed local eval results
tests/fixtures/programs/                    checked-in Anchor fixture programs
```

---

## Phase 1 — Core Contract

Deliverable: a `dike` binary that walks a directory, runs zero analyzers, and prints a valid empty report in both formats. Everything downstream plugs into the seam built here.

### Task 1: Workspace and the `Finding` type

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`
- Create: `crates/dike-core/Cargo.toml`, `crates/dike-core/src/lib.rs`, `crates/dike-core/src/finding.rs`
- Test: `crates/dike-core/src/finding.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: nothing.
- Produces: `Severity` (enum, `weight() -> f32`), `VulnClass` (newtype over `String`, `VulnClass::new(&str)`, `as_str()`), `Track` (enum `Static | Llm | Corroborated`), `Location { file: PathBuf, line: u32, handler: String, handler_id() -> String }`, `Citation { doc_id: String, source_url: String, title: String }`, `Finding { id, class, severity, confidence, track, location, evidence, citations }` with `merge_key() -> (String, VulnClass)` and `rank_score() -> f32`.

Rust unit tests live in the same file as the code under `#[cfg(test)] mod tests`. That is idiomatic and keeps private items testable — do not create a separate `tests/` file for these.

- [ ] **Step 1: Create the workspace skeleton**

`Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/dike-core", "crates/dike-lang-anchor", "crates/dike-cli"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

`.gitignore`:

```
/target
/corpus/cache
*.db
```

`crates/dike-core/Cargo.toml`:

```toml
[package]
name = "dike-core"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tracing.workspace = true
```

Create the other two member crates as empty libs for now so the workspace resolves:
`crates/dike-lang-anchor/Cargo.toml` and `crates/dike-cli/Cargo.toml` with the same
`[package]` block (names `dike-lang-anchor`, `dike-cli`), no dependencies, and a
`src/lib.rs` / `src/main.rs` containing only `fn main() {}` for the CLI.

- [ ] **Step 2: Write the failing test**

In `crates/dike-core/src/finding.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn finding(class: &str, sev: Severity, conf: f32, handler: &str) -> Finding {
        Finding {
            id: String::new(),
            class: VulnClass::new(class),
            severity: sev,
            confidence: conf,
            track: Track::Static,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                handler: handler.to_string(),
            },
            evidence: "evidence".into(),
            citations: vec![],
        }
    }

    #[test]
    fn severity_weights_are_ordered_and_pinned() {
        assert_eq!(Severity::Critical.weight(), 1.0);
        assert_eq!(Severity::High.weight(), 0.75);
        assert_eq!(Severity::Medium.weight(), 0.5);
        assert_eq!(Severity::Low.weight(), 0.25);
        assert_eq!(Severity::Info.weight(), 0.1);
        assert!(Severity::Critical > Severity::Info);
    }

    #[test]
    fn rank_score_is_severity_times_confidence() {
        let f = finding("missing-signer", Severity::High, 0.8, "withdraw");
        assert!((f.rank_score() - 0.6).abs() < 1e-6);
    }

    #[test]
    fn merge_key_is_handler_and_class_not_span() {
        let mut a = finding("missing-signer", Severity::High, 0.9, "withdraw");
        let mut b = finding("missing-signer", Severity::Medium, 0.4, "withdraw");
        b.location.line = 412; // wildly different span, same handler
        a.location.line = 10;
        assert_eq!(a.merge_key(), b.merge_key());
    }

    #[test]
    fn handler_id_joins_file_and_handler() {
        let f = finding("missing-signer", Severity::High, 0.8, "withdraw");
        assert_eq!(f.location.handler_id(), "src/lib.rs::withdraw");
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p dike-core`
Expected: FAIL — `cannot find type Severity in this scope` (nothing is implemented yet).

- [ ] **Step 4: Implement the types**

In `crates/dike-core/src/finding.rs`, above the test module:

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Intrinsic to the vulnerability class — never a statement about how sure we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Ranking weights (D2). Pinned — the eval harness compares runs across time.
    pub fn weight(self) -> f32 {
        match self {
            Severity::Critical => 1.0,
            Severity::High => 0.75,
            Severity::Medium => 0.5,
            Severity::Low => 0.25,
            Severity::Info => 0.1,
        }
    }
}

/// A vulnerability class label. Deliberately a string newtype, not an enum:
/// class vocabularies are language-specific and live in the language crates (D6).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VulnClass(String);

impl VulnClass {
    pub fn new(s: impl Into<String>) -> Self {
        VulnClass(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Track {
    Static,
    Llm,
    Corroborated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: u32,
    /// Enclosing instruction handler. The unit at which findings are compared (D5).
    pub handler: String,
}

impl Location {
    pub fn handler_id(&self) -> String {
        format!("{}::{}", self.file.display(), self.handler)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Citation {
    pub doc_id: String,
    pub source_url: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub class: VulnClass,
    pub severity: Severity,
    /// How sure this *instance* is real. Track 1: a per-detector constant.
    /// Track 2: model-reported, clamped and down-weighted (D3).
    pub confidence: f32,
    pub track: Track,
    pub location: Location,
    pub evidence: String,
    pub citations: Vec<Citation>,
}

impl Finding {
    /// Dedupe/corroboration key: handler granularity + class, never the span (D5).
    pub fn merge_key(&self) -> (String, VulnClass) {
        (self.location.handler_id(), self.class.clone())
    }

    pub fn rank_score(&self) -> f32 {
        self.severity.weight() * self.confidence
    }
}
```

`crates/dike-core/src/lib.rs`:

```rust
pub mod finding;

pub use finding::{Citation, Finding, Location, Severity, Track, VulnClass};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p dike-core`
Expected: PASS — 4 tests.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml rust-toolchain.toml .gitignore crates/
git commit -m "feat: workspace skeleton and the core Finding type"
```

---

### Task 2: The `Analyzer` seam and tolerant ingest

**Files:**
- Create: `crates/dike-core/src/analyzer.rs`
- Modify: `crates/dike-core/src/lib.rs`
- Modify: `crates/dike-core/Cargo.toml` (add `walkdir`)
- Modify: `Cargo.toml` (add `walkdir = "2"` to `[workspace.dependencies]`)

**Interfaces:**
- Consumes: `Finding` from Task 1.
- Produces: `SourceFile { path: PathBuf, text: String }`, `SourceTree { root: PathBuf, files: Vec<SourceFile> }` with `SourceTree::load(root: &Path) -> std::io::Result<SourceTree>` and `total_loc() -> usize`; `DiagnosticKind { ParseFailure, Skipped, Ambiguity, TrackSkipped }`; `Diagnostic { file: Option<PathBuf>, kind: DiagnosticKind, message: String }`; `AnalysisResult { findings: Vec<Finding>, diagnostics: Vec<Diagnostic>, files_analyzed: usize }`; `trait Analyzer { fn name(&self) -> &'static str; fn analyze(&self, tree: &SourceTree) -> AnalysisResult; }`.

`SourceTree::load` walks for `*.rs` only, skips `target/` and any hidden directory, and reads files as UTF-8 lossy so a stray byte never aborts a run.

- [ ] **Step 1: Write the failing test**

In `crates/dike-core/src/analyzer.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn load_collects_rust_files_and_skips_target_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join("src/lib.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        fs::write(root.join("src/notes.md"), "# not rust").unwrap();
        fs::write(root.join("target/debug/build.rs"), "fn c() {}").unwrap();
        fs::write(root.join(".git/hook.rs"), "fn d() {}").unwrap();

        let tree = SourceTree::load(root).unwrap();

        assert_eq!(tree.files.len(), 1);
        assert!(tree.files[0].path.ends_with("src/lib.rs"));
        assert_eq!(tree.total_loc(), 2);
    }

    #[test]
    fn load_survives_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bad.rs"), [0xff, 0xfe, b'\n']).unwrap();
        let tree = SourceTree::load(dir.path()).unwrap();
        assert_eq!(tree.files.len(), 1);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-core analyzer`
Expected: FAIL — `SourceTree` not found.

- [ ] **Step 3: Add dependencies**

Workspace `Cargo.toml` `[workspace.dependencies]`: add `walkdir = "2"` and `tempfile = "3"`.
`crates/dike-core/Cargo.toml`: add `walkdir.workspace = true` under `[dependencies]` and

```toml
[dev-dependencies]
tempfile.workspace = true
```

- [ ] **Step 4: Implement**

In `crates/dike-core/src/analyzer.rs`, above the tests:

```rust
use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct SourceTree {
    pub root: PathBuf,
    pub files: Vec<SourceFile>,
}

impl SourceTree {
    /// Read every `.rs` file under `root`. Never builds anything (Global Constraints).
    pub fn load(root: &Path) -> std::io::Result<SourceTree> {
        let mut files = Vec::new();
        let walker = walkdir::WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !(name == "target" || name.starts_with('.'))
            });
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                // An unreadable entry is a skipped file, not a failed run.
                Err(err) => {
                    tracing::warn!(%err, "skipping unreadable path");
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.path().extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let bytes = std::fs::read(entry.path())?;
            files.push(SourceFile {
                path: entry.path().to_path_buf(),
                text: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path)); // determinism
        Ok(SourceTree { root: root.to_path_buf(), files })
    }

    /// Physical lines across all analyzed files. Denominator for the noise floor (D18).
    pub fn total_loc(&self) -> usize {
        self.files.iter().map(|f| f.text.lines().count()).sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    /// A file could not be parsed; it was skipped. Reported in coverage, never silent.
    ParseFailure,
    Skipped,
    /// Two symbols share a name across files; first-seen won (D10).
    Ambiguity,
    /// A whole track did not run (e.g. LLM unavailable). Degraded, not failed.
    TrackSkipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub file: Option<PathBuf>,
    pub kind: DiagnosticKind,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<Diagnostic>,
    pub files_analyzed: usize,
}

/// The extensibility seam. A Solidity port implements this and touches nothing else.
pub trait Analyzer {
    fn name(&self) -> &'static str;
    fn analyze(&self, tree: &SourceTree) -> AnalysisResult;
}
```

Add to `lib.rs`:

```rust
pub mod analyzer;
pub use analyzer::{AnalysisResult, Analyzer, Diagnostic, DiagnosticKind, SourceFile, SourceTree};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p dike-core`
Expected: PASS — 6 tests.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/dike-core
git commit -m "feat: Analyzer seam and tolerant source ingest"
```

---

### Task 3: Merge, corroboration, and ranking

**Files:**
- Create: `crates/dike-core/src/merge.rs`
- Modify: `crates/dike-core/src/lib.rs`

**Interfaces:**
- Consumes: `Finding`, `Severity`, `Track` from Task 1.
- Produces: `pub fn track2_confidence(raw: f32, citation_count: usize) -> f32`; `pub fn corroborate(a: &Finding, b: &Finding) -> Finding`; `pub fn merge(static_findings: Vec<Finding>, llm_findings: Vec<Finding>) -> Vec<Finding>` (returns ranked); `pub fn rank(findings: &mut Vec<Finding>)`.

`merge` groups by `merge_key()`, corroborates a static/LLM pair, then ranks. Ranking is a **total order** — `f32` has no `Ord`, so sort by `rank_score` descending with ties broken by `(severity desc, handler_id, class)` to keep output byte-stable across runs.

- [ ] **Step 1: Write the failing test**

In `crates/dike-core/src/merge.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn f(track: Track, class: &str, sev: Severity, conf: f32, handler: &str) -> Finding {
        Finding {
            id: String::new(),
            class: VulnClass::new(class),
            severity: sev,
            confidence: conf,
            track,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line: 1,
                handler: handler.to_string(),
            },
            evidence: format!("{track:?} evidence"),
            citations: vec![],
        }
    }

    #[test]
    fn track2_confidence_is_clamped() {
        assert!((track2_confidence(2.0, 3) - 0.90).abs() < 1e-6);
        assert!((track2_confidence(0.0, 3) - 0.10).abs() < 1e-6);
    }

    #[test]
    fn track2_confidence_downweights_single_citation() {
        assert!((track2_confidence(0.5, 1) - 0.40).abs() < 1e-6);
        assert!((track2_confidence(0.5, 2) - 0.50).abs() < 1e-6);
    }

    #[test]
    fn corroboration_raises_confidence_above_either_track() {
        let a = f(Track::Static, "missing-signer", Severity::High, 0.7, "withdraw");
        let b = f(Track::Llm, "missing-signer", Severity::Critical, 0.5, "withdraw");
        let c = corroborate(&a, &b);
        assert_eq!(c.track, Track::Corroborated);
        assert_eq!(c.severity, Severity::Critical);
        assert!(c.confidence > 0.7 && c.confidence > 0.5);
        assert!((c.confidence - 0.85).abs() < 1e-6);
        assert!(c.evidence.contains("Static") && c.evidence.contains("Llm"));
    }

    #[test]
    fn merge_dedupes_on_handler_and_class_and_ranks_corroborated_first() {
        let statics = vec![
            f(Track::Static, "missing-signer", Severity::High, 0.7, "withdraw"),
            f(Track::Static, "unchecked-arithmetic", Severity::Critical, 0.3, "deposit"),
        ];
        let llms = vec![
            f(Track::Llm, "missing-signer", Severity::High, 0.6, "withdraw"),
        ];
        let merged = merge(statics, llms);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].track, Track::Corroborated);
        assert_eq!(merged[0].class.as_str(), "missing-signer");
    }

    #[test]
    fn ranking_is_stable_for_equal_scores() {
        let mut v = vec![
            f(Track::Static, "b-class", Severity::High, 0.5, "zeta"),
            f(Track::Static, "a-class", Severity::High, 0.5, "alpha"),
        ];
        rank(&mut v);
        assert_eq!(v[0].location.handler, "alpha");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-core merge`
Expected: FAIL — `merge` not found.

- [ ] **Step 3: Implement**

```rust
use crate::finding::{Finding, Severity, Track, VulnClass};
use std::collections::BTreeMap;

/// D3: model-reported confidence, clamped, down-weighted on a lone citation.
pub fn track2_confidence(raw: f32, citation_count: usize) -> f32 {
    let clamped = raw.clamp(0.10, 0.90);
    if citation_count == 1 {
        clamped * 0.8
    } else {
        clamped
    }
}

/// D4: noisy-OR. Two independent tracks agreeing is genuinely stronger evidence
/// than either alone, which is why this must exceed both inputs.
pub fn corroborate(a: &Finding, b: &Finding) -> Finding {
    let confidence = (1.0 - (1.0 - a.confidence) * (1.0 - b.confidence)).min(0.98);
    let mut citations = a.citations.clone();
    citations.extend(b.citations.iter().cloned());
    Finding {
        id: String::new(),
        class: a.class.clone(),
        severity: a.severity.max(b.severity),
        confidence,
        track: Track::Corroborated,
        location: a.location.clone(),
        evidence: format!("{}\n\n---\n\n{}", a.evidence, b.evidence),
        citations,
    }
}

/// Dedupe on (handler_id, class) — D5 — then rank. Corroborated findings surface
/// first because their confidence exceeds either contributing track's.
pub fn merge(static_findings: Vec<Finding>, llm_findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_key: BTreeMap<(String, VulnClass), Finding> = BTreeMap::new();

    for f in static_findings.into_iter().chain(llm_findings.into_iter()) {
        match by_key.remove(&f.merge_key()) {
            None => {
                by_key.insert(f.merge_key(), f);
            }
            Some(existing) => {
                let combined = if existing.track == f.track {
                    // Same track reported it twice: keep the stronger, do not inflate.
                    if f.rank_score() > existing.rank_score() { f } else { existing }
                } else {
                    corroborate(&existing, &f)
                };
                by_key.insert(combined.merge_key(), combined);
            }
        }
    }

    let mut out: Vec<Finding> = by_key.into_values().collect();
    rank(&mut out);
    out
}

/// Total order (f32 is not Ord). Ties break deterministically so report diffs are clean.
pub fn rank(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        b.rank_score()
            .partial_cmp(&a.rank_score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.severity.cmp(&a.severity))
            .then(a.location.handler_id().cmp(&b.location.handler_id()))
            .then(a.class.cmp(&b.class))
    });
}
```

Add `pub mod merge;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-core`
Expected: PASS — 11 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/dike-core
git commit -m "feat: merge, corroboration and deterministic ranking"
```

---

### Task 4: Report renderers and the CLI shell

**Files:**
- Create: `crates/dike-core/src/report/mod.rs`, `crates/dike-core/src/report/markdown.rs`, `crates/dike-core/src/report/json.rs`
- Create: `crates/dike-cli/src/main.rs`, `crates/dike-cli/src/config.rs`, `crates/dike-cli/src/pipeline.rs`, `crates/dike-cli/src/commands/mod.rs`, `crates/dike-cli/src/commands/analyze.rs`
- Create: `crates/dike-core/tests/seam.rs`
- Modify: `crates/dike-cli/Cargo.toml`, workspace `Cargo.toml`

**Interfaces:**
- Consumes: `Finding`, `Diagnostic`, `AnalysisResult`, `SourceTree`, `merge`.
- Produces: `RunMetadata { tool_version: String, model: Option<String>, corpus_hash: Option<String>, timestamp: String }`; `Coverage { files_total, files_parsed, handlers, loc, suppressed: usize }`; `TrackFindings { static_track: Vec<Finding>, llm_track: Vec<Finding>, merged: Vec<Finding> }`; `Report { run: RunMetadata, tracks: TrackFindings, diagnostics: Vec<Diagnostic>, coverage: Coverage }` with `render_markdown() -> String` and `render_json() -> serde_json::Result<String>`; CLI `dike analyze <PATH> [--format md|json] [--out FILE]`.

The report renders **three separate sections** — static, llm, merged — never a single collapsed list. That separation is the whole reason the eval table can be trusted.

- [ ] **Step 1: Write the failing test**

In `crates/dike-core/src/report/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Location, Severity, Track, VulnClass};
    use std::path::PathBuf;

    fn sample_report() -> Report {
        let f = Finding {
            id: "abc123".into(),
            class: VulnClass::new("missing-signer"),
            severity: Severity::High,
            confidence: 0.9,
            track: Track::Static,
            location: Location { file: PathBuf::from("src/lib.rs"), line: 42, handler: "withdraw".into() },
            evidence: "`authority` is `AccountInfo` with no signer constraint".into(),
            citations: vec![],
        };
        Report {
            run: RunMetadata {
                tool_version: "0.1.0".into(),
                model: None,
                corpus_hash: None,
                timestamp: "2026-08-27T00:00:00Z".into(),
            },
            tracks: TrackFindings { static_track: vec![f.clone()], llm_track: vec![], merged: vec![f] },
            diagnostics: vec![Diagnostic {
                file: Some(PathBuf::from("src/broken.rs")),
                kind: DiagnosticKind::ParseFailure,
                message: "expected `}`".into(),
            }],
            coverage: Coverage { files_total: 2, files_parsed: 1, handlers: 3, loc: 250, suppressed: 1 },
        }
    }

    #[test]
    fn markdown_reports_each_track_separately() {
        let md = sample_report().render_markdown();
        assert!(md.contains("## Track 1 — Static"));
        assert!(md.contains("## Track 2 — LLM"));
        assert!(md.contains("## Merged"));
        assert!(md.contains("withdraw"));
    }

    #[test]
    fn markdown_lists_unparsed_files_in_coverage() {
        let md = sample_report().render_markdown();
        assert!(md.contains("## Coverage"));
        assert!(md.contains("src/broken.rs"));
        assert!(md.contains("1/2"));
    }

    #[test]
    fn markdown_records_run_provenance() {
        let md = sample_report().render_markdown();
        assert!(md.contains("0.1.0"));
        assert!(md.contains("2026-08-27T00:00:00Z"));
    }

    #[test]
    fn json_round_trips() {
        let json = sample_report().render_json().unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tracks.merged.len(), 1);
        assert_eq!(back.coverage.suppressed, 1);
    }

    #[test]
    fn json_track2_findings_never_appear_in_track1() {
        let r = sample_report();
        assert!(r.tracks.static_track.iter().all(|f| f.track == Track::Static));
    }
}
```

In `crates/dike-core/tests/seam.rs` — the boundary test from the Global Constraints:

```rust
//! dike-core must contain no Solana/Anchor vocabulary. If this fails, the seam
//! has leaked and a Solidity port would require changing core.
use std::fs;

#[test]
fn core_contains_no_solana_identifiers() {
    let banned = [
        "anchor", "solana", "Signer<", "AccountInfo", "UncheckedAccount",
        "has_one", "invoke_signed", "pubkey", "Pubkey", "spl_",
    ];
    let mut offenders = Vec::new();
    for entry in walkdir::WalkDir::new("src") {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(entry.path()).unwrap();
        for (i, line) in text.lines().enumerate() {
            // Doc comments may reference the domain; code may not.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for word in banned {
                if line.contains(word) {
                    offenders.push(format!("{}:{}: {}", entry.path().display(), i + 1, word));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "seam leak:\n{}", offenders.join("\n"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-core`
Expected: FAIL — `Report` not found; `seam.rs` fails to compile until `walkdir` is a dev-dependency (it already is a normal dependency, which suffices).

- [ ] **Step 3: Implement the report types**

`crates/dike-core/src/report/mod.rs` (above the tests):

```rust
mod json;
mod markdown;

use crate::analyzer::{Diagnostic, DiagnosticKind};
use crate::finding::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    pub tool_version: String,
    pub model: Option<String>,
    pub corpus_hash: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub files_total: usize,
    pub files_parsed: usize,
    pub handlers: usize,
    pub loc: usize,
    /// Findings withheld by the imperative-check suppression pass (D15).
    pub suppressed: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrackFindings {
    pub static_track: Vec<Finding>,
    pub llm_track: Vec<Finding>,
    pub merged: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub run: RunMetadata,
    pub tracks: TrackFindings,
    pub diagnostics: Vec<Diagnostic>,
    pub coverage: Coverage,
}

impl Report {
    pub fn render_markdown(&self) -> String {
        markdown::render(self)
    }
    pub fn render_json(&self) -> serde_json::Result<String> {
        json::render(self)
    }
}
```

`crates/dike-core/src/report/json.rs`:

```rust
use super::Report;

pub fn render(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}
```

`crates/dike-core/src/report/markdown.rs`:

```rust
use super::{Report, TrackFindings};
use crate::analyzer::DiagnosticKind;
use crate::finding::Finding;

pub fn render(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Dike Report\n\n");
    out.push_str(&format!(
        "- Tool version: `{}`\n- Model: `{}`\n- Corpus hash: `{}`\n- Run at: `{}`\n\n",
        report.run.tool_version,
        report.run.model.as_deref().unwrap_or("none"),
        report.run.corpus_hash.as_deref().unwrap_or("none"),
        report.run.timestamp,
    ));
    out.push_str("> Triage output. This report says where to look; it never says a program is safe.\n\n");

    let TrackFindings { static_track, llm_track, merged } = &report.tracks;
    section(&mut out, "## Track 1 — Static (deterministic)", static_track);
    section(&mut out, "## Track 2 — LLM (retrieval-grounded)", llm_track);
    section(&mut out, "## Merged (triage order)", merged);

    out.push_str("## Coverage\n\n");
    out.push_str(&format!(
        "- Files parsed: {}/{}\n- Handlers analyzed: {}\n- Lines of code: {}\n- Findings suppressed by imperative checks: {}\n\n",
        report.coverage.files_parsed,
        report.coverage.files_total,
        report.coverage.handlers,
        report.coverage.loc,
        report.coverage.suppressed,
    ));
    if !report.diagnostics.is_empty() {
        out.push_str("### Diagnostics\n\n");
        for d in &report.diagnostics {
            let file = d.file.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
            let kind = match d.kind {
                DiagnosticKind::ParseFailure => "parse failure",
                DiagnosticKind::Skipped => "skipped",
                DiagnosticKind::Ambiguity => "ambiguous symbol",
                DiagnosticKind::TrackSkipped => "track skipped",
            };
            out.push_str(&format!("- **{kind}** `{file}` — {}\n", d.message));
        }
        out.push('\n');
    }
    out
}

fn section(out: &mut String, title: &str, findings: &[Finding]) {
    out.push_str(title);
    out.push_str("\n\n");
    if findings.is_empty() {
        out.push_str("_No findings._\n\n");
        return;
    }
    out.push_str("| Severity | Conf | Class | Location | Evidence |\n");
    out.push_str("|---|---|---|---|---|\n");
    for f in findings {
        out.push_str(&format!(
            "| {:?} | {:.2} | `{}` | `{}:{}` ({}) | {} |\n",
            f.severity,
            f.confidence,
            f.class.as_str(),
            f.location.file.display(),
            f.location.line,
            f.location.handler,
            f.evidence.replace('\n', " ").replace('|', "\\|"),
        ));
    }
    out.push('\n');
    for f in findings.iter().filter(|f| !f.citations.is_empty()) {
        out.push_str(&format!("- `{}` cites: ", f.class.as_str()));
        let cites: Vec<String> = f
            .citations
            .iter()
            .map(|c| format!("[{}]({})", c.title, c.source_url))
            .collect();
        out.push_str(&cites.join(", "));
        out.push('\n');
    }
    out.push('\n');
}
```

Add `pub mod report;` to `lib.rs`.

- [ ] **Step 4: Implement the CLI shell**

Workspace `Cargo.toml` `[workspace.dependencies]`: add `clap = { version = "4", features = ["derive"] }`, `anyhow = "1"`, `chrono = "0.4"`, `tracing-subscriber = "0.3"`.

`crates/dike-cli/Cargo.toml`:

```toml
[package]
name = "dike-cli"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "dike"
path = "src/main.rs"

[dependencies]
dike-core = { path = "../dike-core" }
clap.workspace = true
anyhow.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

`crates/dike-cli/src/config.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Md,
    Json,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub root: std::path::PathBuf,
    pub format: Format,
    pub out: Option<std::path::PathBuf>,
    /// Track 2 is opt-in until Phase 6 lands; the flag exists from day one so the
    /// pipeline signature never changes underneath callers.
    pub llm: bool,
}
```

`crates/dike-cli/src/pipeline.rs`:

```rust
use dike_core::analyzer::{Analyzer, SourceTree};
use dike_core::merge::merge;
use dike_core::report::{Coverage, Report, RunMetadata, TrackFindings};

/// Runs each track independently and merges only at the end. Track 2's output
/// never influences Track 1's list — the two vectors stay separate in the Report.
pub fn run(
    tree: &SourceTree,
    static_analyzer: &dyn Analyzer,
    llm_analyzer: Option<&dyn Analyzer>,
    model: Option<String>,
    corpus_hash: Option<String>,
) -> Report {
    let s = static_analyzer.analyze(tree);
    let l = match llm_analyzer {
        Some(a) => a.analyze(tree),
        None => Default::default(),
    };

    let mut diagnostics = s.diagnostics.clone();
    diagnostics.extend(l.diagnostics.clone());

    let merged = merge(s.findings.clone(), l.findings.clone());

    Report {
        run: RunMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            model,
            corpus_hash,
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
        tracks: TrackFindings {
            static_track: s.findings,
            llm_track: l.findings,
            merged,
        },
        diagnostics,
        coverage: Coverage {
            files_total: tree.files.len(),
            files_parsed: s.files_analyzed,
            handlers: 0,
            loc: tree.total_loc(),
            suppressed: 0,
        },
    }
}
```

`crates/dike-cli/src/commands/analyze.rs`:

```rust
use crate::config::{Format, RunConfig};
use anyhow::Context;
use dike_core::analyzer::{AnalysisResult, Analyzer, SourceTree};

/// Placeholder until Phase 3 wires in AnchorAnalyzer. Keeps the seam honest:
/// the pipeline only ever sees `&dyn Analyzer`.
struct NullAnalyzer;
impl Analyzer for NullAnalyzer {
    fn name(&self) -> &'static str { "null" }
    fn analyze(&self, tree: &SourceTree) -> AnalysisResult {
        AnalysisResult { files_analyzed: tree.files.len(), ..Default::default() }
    }
}

pub fn run(cfg: RunConfig) -> anyhow::Result<()> {
    let tree = SourceTree::load(&cfg.root)
        .with_context(|| format!("reading {}", cfg.root.display()))?;
    let report = crate::pipeline::run(&tree, &NullAnalyzer, None, None, None);

    let rendered = match cfg.format {
        Format::Md => report.render_markdown(),
        Format::Json => report.render_json()?,
    };
    match cfg.out {
        Some(path) => std::fs::write(&path, rendered)
            .with_context(|| format!("writing {}", path.display()))?,
        None => println!("{rendered}"),
    }
    Ok(()) // exit 0 even with findings — triage, not a gate
}
```

`crates/dike-cli/src/commands/mod.rs`:

```rust
pub mod analyze;
```

`crates/dike-cli/src/main.rs`:

```rust
mod commands;
mod config;
mod pipeline;

use clap::{Parser, Subcommand};
use config::{Format, RunConfig};

#[derive(Parser)]
#[command(name = "dike", version, about = "Security triage for Solana Anchor programs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a program directory and print a triage report.
    Analyze {
        path: std::path::PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Md)]
        format: Format,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        #[arg(long)]
        llm: bool,
    },
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Analyze { path, format, out, llm } => {
            commands::analyze::run(RunConfig { root: path, format, out, llm })
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        // Non-zero is tool failure only, never "findings exist".
        Err(err) => {
            eprintln!("dike: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 5: Run the tests and the binary**

Run: `cargo test --workspace`
Expected: PASS — all `dike-core` tests including `seam.rs`.

Run: `cargo run -p dike-cli -- analyze crates/dike-core --format md`
Expected: a Markdown report with three empty track sections and a coverage block; `echo $?` prints `0`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/
git commit -m "feat: report renderers, seam test and the dike analyze CLI shell"
```

---

## Phase 2 — Anchor IR and Parser

Deliverable: `dike ir <path>` dumps a complete IR for a real Anchor program as JSON. The IR is the contract between `dike-lang-anchor` and everything downstream — detectors, chunker, and mutation engine all read it, and **no other module parses Rust**.

### Task 5: The IR types

**Files:**
- Create: `crates/dike-lang-anchor/src/ir.rs`, `crates/dike-lang-anchor/src/lib.rs`
- Modify: `crates/dike-lang-anchor/Cargo.toml`

**Interfaces:**
- Consumes: nothing from earlier tasks (the IR is standalone and serializable).
- Produces:

```rust
pub struct Program { pub instructions: Vec<Handler>,
                     pub accounts_structs: BTreeMap<String, AccountsStruct>,
                     pub state_structs: BTreeMap<String, StateStruct> }
pub struct Handler { pub name: String, pub file: PathBuf, pub line: u32, pub end_line: u32,
                     pub args: Vec<Arg>, pub context_ty: String, pub body: HandlerBody }
pub struct Arg { pub name: String, pub ty: String }
pub struct HandlerBody { pub calls: Vec<CallSite>, pub arithmetic: Vec<ArithOp>,
                         pub checks: Vec<ImperativeCheck>, pub state_writes: Vec<StateWrite> }
pub struct CallSite { pub name: String, pub line: u32, pub is_cpi: bool }
pub struct ArithOp { pub op: String, pub line: u32, pub checked: bool }
pub enum CheckKind { Require, RequireKeysEq, RequireEq, AccessControl, ManualIf }
pub struct ImperativeCheck { pub kind: CheckKind, pub referenced_accounts: Vec<String>, pub line: u32 }
pub struct StateWrite { pub account: String, pub line: u32 }
pub struct AccountsStruct { pub name: String, pub file: PathBuf, pub decls: Vec<AccountDecl>,
                           pub line: u32, pub end_line: u32 }
pub struct AccountDecl { pub name: String, pub wrapper: Wrapper, pub boxed: bool,
                         pub optional: bool, pub constraints: Vec<Constraint>, pub line: u32 }
pub enum Wrapper { Signer, Account(String), InterfaceAccount(String), UncheckedAccount,
                   AccountInfo, Program(String), SystemAccount, Sysvar(String), Other(String) }
pub enum Constraint { Mut, Init, InitIfNeeded, Close(String), Seeds(String), Bump(Option<String>),
                      HasOne(String), Owner(String), Address(String), SignerAttr, Raw(String) }
pub struct StateStruct { pub name: String, pub fields: Vec<(String, String)>, pub file: PathBuf,
                        pub line: u32, pub end_line: u32 }
```

`line`/`end_line` are recorded on every item (from `span().start().line` and
`span().end().line`) so Task 20 can slice the original file text back out. Reconstructing
source with `quote` instead would lose comments and the `/// CHECK:` docs an auditor needs.

Plus helpers: `AccountDecl::has_constraint_kind(&self, pred) -> bool`, `AccountDecl::is_unchecked(&self) -> bool`, `Program::handler(&self, name) -> Option<&Handler>`, and `AccountsStruct::decl(&self, name) -> Option<&AccountDecl>`.

- [ ] **Step 1: Write the failing test**

In `crates/dike-lang-anchor/src/ir.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn decl(name: &str, wrapper: Wrapper, constraints: Vec<Constraint>) -> AccountDecl {
        AccountDecl { name: name.into(), wrapper, boxed: false, optional: false, constraints, line: 1 }
    }

    #[test]
    fn signer_wrapper_and_signer_attribute_are_distinct_but_both_recognized() {
        // D7: `Signer<'info>` and `#[account(signer)]` are different IR shapes.
        let typed = decl("authority", Wrapper::Signer, vec![]);
        let legacy = decl("authority", Wrapper::AccountInfo, vec![Constraint::SignerAttr]);
        assert!(typed.enforces_signer());
        assert!(legacy.enforces_signer());
        assert!(!decl("authority", Wrapper::AccountInfo, vec![]).enforces_signer());
    }

    #[test]
    fn unchecked_wrappers_are_identified() {
        assert!(decl("a", Wrapper::UncheckedAccount, vec![]).is_unchecked());
        assert!(decl("a", Wrapper::AccountInfo, vec![]).is_unchecked());
        assert!(!decl("a", Wrapper::Account("Vault".into()), vec![]).is_unchecked());
        assert!(!decl("a", Wrapper::InterfaceAccount("Mint".into()), vec![]).is_unchecked());
    }

    #[test]
    fn has_one_targets_are_readable() {
        let d = decl("vault", Wrapper::Account("Vault".into()), vec![Constraint::HasOne("admin".into())]);
        assert_eq!(d.has_one_targets(), vec!["admin".to_string()]);
    }

    #[test]
    fn program_lookups_work() {
        let mut p = Program::default();
        p.instructions.push(Handler {
            name: "withdraw".into(),
            file: PathBuf::from("src/lib.rs"),
            line: 5,
            args: vec![],
            context_ty: "Withdraw".into(),
            body: HandlerBody::default(),
        });
        assert!(p.handler("withdraw").is_some());
        assert!(p.handler("deposit").is_none());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-lang-anchor`
Expected: FAIL — module `ir` does not exist.

- [ ] **Step 3: Implement the IR**

Write the struct/enum definitions exactly as listed in **Interfaces** above, deriving
`#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]` on every type and
`Default` on `Program`, `HandlerBody`, and `AccountsStruct`. Then the helpers:

```rust
impl AccountDecl {
    /// D7: either the typed wrapper or the legacy attribute satisfies a signer check.
    pub fn enforces_signer(&self) -> bool {
        matches!(self.wrapper, Wrapper::Signer)
            || self.constraints.iter().any(|c| matches!(c, Constraint::SignerAttr))
    }

    /// Anchor performs no owner or discriminator validation on these.
    pub fn is_unchecked(&self) -> bool {
        matches!(self.wrapper, Wrapper::UncheckedAccount | Wrapper::AccountInfo)
    }

    pub fn has_one_targets(&self) -> Vec<String> {
        self.constraints
            .iter()
            .filter_map(|c| match c {
                Constraint::HasOne(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn has_seeds(&self) -> bool {
        self.constraints.iter().any(|c| matches!(c, Constraint::Seeds(_)))
    }

    pub fn has_bump(&self) -> bool {
        self.constraints.iter().any(|c| matches!(c, Constraint::Bump(_)))
    }

    pub fn is_init(&self) -> bool {
        self.constraints
            .iter()
            .any(|c| matches!(c, Constraint::Init | Constraint::InitIfNeeded))
    }

    /// Any explicit key/owner pin, which substitutes for type-based validation.
    pub fn is_address_pinned(&self) -> bool {
        self.constraints
            .iter()
            .any(|c| matches!(c, Constraint::Address(_) | Constraint::Owner(_)))
    }
}

impl Program {
    pub fn handler(&self, name: &str) -> Option<&Handler> {
        self.instructions.iter().find(|h| h.name == name)
    }
    /// The accounts struct bound to a handler's `Context<T>` type parameter.
    pub fn accounts_for(&self, handler: &Handler) -> Option<&AccountsStruct> {
        self.accounts_structs.get(&handler.context_ty)
    }
}

impl AccountsStruct {
    pub fn decl(&self, name: &str) -> Option<&AccountDecl> {
        self.decls.iter().find(|d| d.name == name)
    }
}
```

`crates/dike-lang-anchor/Cargo.toml` dependencies: `serde.workspace = true`, `serde_json.workspace = true`, `dike-core = { path = "../dike-core" }`.
`crates/dike-lang-anchor/src/lib.rs`: `pub mod ir;`

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-lang-anchor`
Expected: PASS — 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/dike-lang-anchor
git commit -m "feat: Anchor IR types"
```

---

### Task 6: Parse `#[derive(Accounts)]` structs

**Files:**
- Create: `crates/dike-lang-anchor/src/parser/mod.rs`, `crates/dike-lang-anchor/src/parser/accounts.rs`
- Modify: `crates/dike-lang-anchor/Cargo.toml` (add `syn`, `proc-macro2`), workspace `Cargo.toml`
- Modify: `crates/dike-lang-anchor/src/lib.rs`

**Interfaces:**
- Consumes: `ir::{AccountsStruct, AccountDecl, Wrapper, Constraint}`.
- Produces: `pub fn parse_accounts_struct(item: &syn::ItemStruct, file: &Path) -> AccountsStruct`; `pub(crate) fn parse_wrapper(ty: &syn::Type) -> (Wrapper, bool /*boxed*/, bool /*optional*/)`; `pub(crate) fn parse_constraints(attrs: &[syn::Attribute]) -> Vec<Constraint>`.

Two subtleties that will bite if missed. First, `Box<Account<'info, T>>` and `Option<Account<'info, T>>` must be **unwrapped recursively** to `Wrapper::Account("T")` with the corresponding flag set (D8) — a naive match sees `Box` and classifies the account as unknown, silently disabling every detector on it. Second, `#[account(...)]` contents are not valid Rust expressions as a whole; parse the attribute with `parse_nested_meta` and fall back to `Constraint::Raw(tokens.to_string())` for anything unrecognized so nothing is lost.

- [ ] **Step 1: Write the failing test**

In `crates/dike-lang-anchor/src/parser/accounts.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Constraint, Wrapper};
    use std::path::Path;

    fn parse(src: &str) -> crate::ir::AccountsStruct {
        let file: syn::File = syn::parse_str(src).unwrap();
        let item = file.items.iter().find_map(|i| match i {
            syn::Item::Struct(s) => Some(s),
            _ => None,
        }).unwrap();
        parse_accounts_struct(item, Path::new("src/lib.rs"))
    }

    #[test]
    fn parses_wrappers_including_box_and_option_and_interface() {
        let s = parse(r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub authority: Signer<'info>,
                pub vault: Box<Account<'info, Vault>>,
                pub mint: InterfaceAccount<'info, Mint>,
                pub maybe: Option<Account<'info, Config>>,
                /// CHECK: manual
                pub raw: UncheckedAccount<'info>,
                pub sys: Program<'info, System>,
            }
        "#);
        assert_eq!(s.name, "Withdraw");
        assert_eq!(s.decl("authority").unwrap().wrapper, Wrapper::Signer);
        let vault = s.decl("vault").unwrap();
        assert_eq!(vault.wrapper, Wrapper::Account("Vault".into()));
        assert!(vault.boxed);
        assert_eq!(s.decl("mint").unwrap().wrapper, Wrapper::InterfaceAccount("Mint".into()));
        let maybe = s.decl("maybe").unwrap();
        assert_eq!(maybe.wrapper, Wrapper::Account("Config".into()));
        assert!(maybe.optional);
        assert_eq!(s.decl("raw").unwrap().wrapper, Wrapper::UncheckedAccount);
        assert_eq!(s.decl("sys").unwrap().wrapper, Wrapper::Program("System".into()));
    }

    #[test]
    fn parses_constraints() {
        let s = parse(r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut, has_one = admin, seeds = [b"vault", admin.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
                #[account(init, payer = admin, space = 8 + 32)]
                pub fresh: Account<'info, Vault>,
                #[account(mut, close = admin, constraint = vault.amount > 0)]
                pub closing: Account<'info, Vault>,
                #[account(signer)]
                pub legacy: AccountInfo<'info>,
                #[account(address = crate::ID)]
                pub pinned: AccountInfo<'info>,
            }
        "#);
        let vault = s.decl("vault").unwrap();
        assert!(vault.constraints.contains(&Constraint::Mut));
        assert_eq!(vault.has_one_targets(), vec!["admin".to_string()]);
        assert!(vault.has_seeds() && vault.has_bump());
        assert!(s.decl("fresh").unwrap().is_init());
        let closing = s.decl("closing").unwrap();
        assert!(closing.constraints.iter().any(|c| matches!(c, Constraint::Close(_))));
        assert!(closing.constraints.iter().any(|c| matches!(c, Constraint::Raw(_))));
        assert!(s.decl("legacy").unwrap().enforces_signer());
        assert!(s.decl("pinned").unwrap().is_address_pinned());
    }

    #[test]
    fn records_the_declaration_line() {
        let s = parse("#[derive(Accounts)]\npub struct W<'info> {\n    pub a: Signer<'info>,\n}");
        assert_eq!(s.decl("a").unwrap().line, 3);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-lang-anchor accounts`
Expected: FAIL — `parse_accounts_struct` not found.

- [ ] **Step 3: Add dependencies**

Workspace `Cargo.toml`: `syn = { version = "2", features = ["full", "extra-traits", "visit"] }`, `proc-macro2 = { version = "1", features = ["span-locations"] }`, `quote = "1"`.

The `span-locations` feature is **required** — without it `span().start().line` always returns 0 and every finding points at line 0.

`crates/dike-lang-anchor/Cargo.toml`: add `syn.workspace = true`, `proc-macro2.workspace = true`, `quote.workspace = true`.

- [ ] **Step 4: Implement**

```rust
use crate::ir::{AccountDecl, AccountsStruct, Constraint, Wrapper};
use std::path::Path;
use syn::spanned::Spanned;

pub fn parse_accounts_struct(item: &syn::ItemStruct, file: &Path) -> AccountsStruct {
    let mut decls = Vec::new();
    if let syn::Fields::Named(named) = &item.fields {
        for field in &named.named {
            let name = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
            let (wrapper, boxed, optional) = parse_wrapper(&field.ty);
            decls.push(AccountDecl {
                name,
                wrapper,
                boxed,
                optional,
                constraints: parse_constraints(&field.attrs),
                line: field.span().start().line as u32,
            });
        }
    }
    AccountsStruct { name: item.ident.to_string(), file: file.to_path_buf(), decls }
}

/// Recursively unwraps `Box<..>` and `Option<..>` before classifying (D8).
pub(crate) fn parse_wrapper(ty: &syn::Type) -> (Wrapper, bool, bool) {
    fn outer_segment(ty: &syn::Type) -> Option<&syn::PathSegment> {
        match ty {
            syn::Type::Path(p) => p.path.segments.last(),
            syn::Type::Reference(r) => outer_segment(&r.elem),
            _ => None,
        }
    }
    fn first_type_arg(seg: &syn::PathSegment) -> Option<&syn::Type> {
        if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
            args.args.iter().find_map(|a| match a {
                syn::GenericArgument::Type(t) => Some(t),
                _ => None,
            })
        } else {
            None
        }
    }
    /// Anchor's account wrappers carry `<'info, T>`; T is the last type argument.
    fn last_type_arg_name(seg: &syn::PathSegment) -> String {
        if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
            for arg in args.args.iter().rev() {
                if let syn::GenericArgument::Type(syn::Type::Path(p)) = arg {
                    if let Some(s) = p.path.segments.last() {
                        return s.ident.to_string();
                    }
                }
            }
        }
        String::new()
    }

    let Some(seg) = outer_segment(ty) else {
        return (Wrapper::Other(String::new()), false, false);
    };
    match seg.ident.to_string().as_str() {
        "Box" => {
            let inner = first_type_arg(seg);
            let (w, _, opt) = inner.map(parse_wrapper).unwrap_or((Wrapper::Other("Box".into()), false, false));
            (w, true, opt)
        }
        "Option" => {
            let inner = first_type_arg(seg);
            let (w, boxed, _) = inner.map(parse_wrapper).unwrap_or((Wrapper::Other("Option".into()), false, false));
            (w, boxed, true)
        }
        "Signer" => (Wrapper::Signer, false, false),
        "Account" => (Wrapper::Account(last_type_arg_name(seg)), false, false),
        "InterfaceAccount" => (Wrapper::InterfaceAccount(last_type_arg_name(seg)), false, false),
        "UncheckedAccount" => (Wrapper::UncheckedAccount, false, false),
        "AccountInfo" => (Wrapper::AccountInfo, false, false),
        "Program" => (Wrapper::Program(last_type_arg_name(seg)), false, false),
        "SystemAccount" => (Wrapper::SystemAccount, false, false),
        "Sysvar" => (Wrapper::Sysvar(last_type_arg_name(seg)), false, false),
        other => (Wrapper::Other(other.to_string()), false, false),
    }
}

/// Anything unrecognized becomes `Raw` rather than being dropped — a lost
/// constraint is a false positive later.
pub(crate) fn parse_constraints(attrs: &[syn::Attribute]) -> Vec<Constraint> {
    let mut out = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("account") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            let key = meta
                .path
                .get_ident()
                .map(|i| i.to_string())
                .unwrap_or_default();
            let value = || -> String {
                meta.input
                    .fork()
                    .parse::<proc_macro2::TokenStream>()
                    .map(|t| t.to_string())
                    .unwrap_or_default()
            };
            match key.as_str() {
                "mut" => out.push(Constraint::Mut),
                "init" => out.push(Constraint::Init),
                "init_if_needed" => out.push(Constraint::InitIfNeeded),
                "signer" => out.push(Constraint::SignerAttr),
                "close" => out.push(Constraint::Close(value())),
                "seeds" => out.push(Constraint::Seeds(value())),
                "bump" => out.push(Constraint::Bump(Some(value()).filter(|v| !v.is_empty()))),
                "has_one" => {
                    // `has_one = admin` — take the identifier, ignore any trailing
                    // `@ ErrorCode::X` so the target name stays clean.
                    let raw = value();
                    let target = raw
                        .trim_start_matches('=')
                        .split('@')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    out.push(Constraint::HasOne(target));
                }
                "owner" => out.push(Constraint::Owner(value())),
                "address" => out.push(Constraint::Address(value())),
                _ => out.push(Constraint::Raw(format!("{key}{}", value()))),
            }
            // Consume the rest of this meta item so parsing continues.
            let _ = meta.input.parse::<proc_macro2::TokenStream>();
            Ok(())
        });
    }
    out
}
```

If `parse_nested_meta` proves too restrictive for bracketed values like
`seeds = [b"x", y.key().as_ref()]`, fall back to `attr.meta.to_token_stream().to_string()`
and split on top-level commas with a depth counter over `[](){}`. Choose whichever
makes the Step 1 tests pass; the tests are the contract, not the technique.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p dike-lang-anchor`
Expected: PASS — 7 tests.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/dike-lang-anchor
git commit -m "feat: parse Anchor accounts structs into the IR"
```

---

### Task 7: Parse `#[program]` handlers and build the global symbol table

**Files:**
- Create: `crates/dike-lang-anchor/src/parser/program.rs`, `crates/dike-lang-anchor/src/parser/symbols.rs`
- Modify: `crates/dike-lang-anchor/src/parser/mod.rs`

**Interfaces:**
- Consumes: Task 5 IR, Task 6 `parse_accounts_struct`, `dike_core::analyzer::{SourceTree, Diagnostic, DiagnosticKind}`.
- Produces: `pub struct ParseOutcome { pub program: Program, pub diagnostics: Vec<Diagnostic>, pub files_parsed: usize }`; `pub fn parse_tree(tree: &SourceTree) -> ParseOutcome`; `pub(crate) fn parse_handlers(module: &syn::ItemMod, file: &Path) -> Vec<Handler>`; `pub(crate) fn context_type_name(ty: &syn::Type) -> Option<String>`.

`parse_tree` is the tolerance boundary (Global Constraints): each file is parsed with `syn::parse_file`; on error it emits a `ParseFailure` diagnostic and continues. Symbols are collected across **all** files into one table keyed by bare type name (D10) — Anchor programs routinely put `#[program]`, `#[derive(Accounts)]`, and `#[account]` state in three different modules. A duplicate name keeps the first and emits an `Ambiguity` diagnostic.

- [ ] **Step 1: Write the failing test**

In `crates/dike-lang-anchor/src/parser/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use dike_core::analyzer::{DiagnosticKind, SourceFile, SourceTree};
    use std::path::PathBuf;

    fn tree(files: &[(&str, &str)]) -> SourceTree {
        SourceTree {
            root: PathBuf::from("."),
            files: files
                .iter()
                .map(|(p, t)| SourceFile { path: PathBuf::from(p), text: (*t).to_string() })
                .collect(),
        }
    }

    #[test]
    fn binds_handlers_to_accounts_structs_across_files() {
        let t = tree(&[
            ("src/lib.rs", r#"
                #[program]
                pub mod vault {
                    use super::*;
                    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> { Ok(()) }
                    pub fn deposit(ctx: Context<Deposit>) -> Result<()> { Ok(()) }
                }
            "#),
            ("src/contexts.rs", r#"
                #[derive(Accounts)]
                pub struct Withdraw<'info> { pub authority: Signer<'info> }
                #[derive(Accounts)]
                pub struct Deposit<'info> { pub payer: Signer<'info> }
            "#),
            ("src/state.rs", r#"
                #[account]
                pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            "#),
        ]);
        let out = parse_tree(&t);
        assert_eq!(out.program.instructions.len(), 2);
        let w = out.program.handler("withdraw").unwrap();
        assert_eq!(w.context_ty, "Withdraw");
        assert_eq!(w.args.len(), 1);
        assert_eq!(w.args[0].name, "amount");
        assert!(out.program.accounts_for(w).is_some());
        assert!(out.program.state_structs.contains_key("Vault"));
        assert_eq!(out.files_parsed, 3);
    }

    #[test]
    fn a_broken_file_is_skipped_not_fatal() {
        let t = tree(&[
            ("src/broken.rs", "pub fn oops( {"),
            ("src/lib.rs", r#"
                #[program]
                pub mod vault {
                    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
                }
            "#),
        ]);
        let out = parse_tree(&t);
        assert_eq!(out.program.instructions.len(), 1);
        assert_eq!(out.files_parsed, 1);
        assert!(out.diagnostics.iter().any(|d| d.kind == DiagnosticKind::ParseFailure));
    }

    #[test]
    fn duplicate_symbol_names_keep_the_first_and_warn() {
        let t = tree(&[
            ("src/a.rs", "#[derive(Accounts)]\npub struct Withdraw<'info> { pub a: Signer<'info> }"),
            ("src/b.rs", "#[derive(Accounts)]\npub struct Withdraw<'info> { pub b: Signer<'info> }"),
        ]);
        let out = parse_tree(&t);
        let s = out.program.accounts_structs.get("Withdraw").unwrap();
        assert!(s.decl("a").is_some());
        assert!(out.diagnostics.iter().any(|d| d.kind == DiagnosticKind::Ambiguity));
    }

    #[test]
    fn handlers_are_found_in_nested_modules() {
        let t = tree(&[("src/lib.rs", r#"
            pub mod outer {
                #[program]
                pub mod vault {
                    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
                }
            }
        "#)]);
        assert_eq!(parse_tree(&t).program.instructions.len(), 1);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-lang-anchor parser`
Expected: FAIL — `parse_tree` not found.

- [ ] **Step 3: Implement**

`crates/dike-lang-anchor/src/parser/symbols.rs`:

```rust
use crate::ir::{AccountsStruct, StateStruct};
use dike_core::analyzer::{Diagnostic, DiagnosticKind};
use std::collections::BTreeMap;
use std::path::Path;

/// One flat namespace keyed by bare type name (D10). Anchor context types are
/// referenced as `Context<Withdraw>` regardless of the module they live in, so
/// path-accurate resolution buys nothing here and costs a lot.
#[derive(Default)]
pub struct SymbolTable {
    pub accounts_structs: BTreeMap<String, AccountsStruct>,
    pub state_structs: BTreeMap<String, StateStruct>,
    pub diagnostics: Vec<Diagnostic>,
}

impl SymbolTable {
    pub fn insert_accounts(&mut self, s: AccountsStruct, file: &Path) {
        if let Some(existing) = self.accounts_structs.get(&s.name) {
            self.diagnostics.push(Diagnostic {
                file: Some(file.to_path_buf()),
                kind: DiagnosticKind::Ambiguity,
                message: format!(
                    "accounts struct `{}` also defined in {} — keeping the first",
                    s.name,
                    existing.file.display()
                ),
            });
            return;
        }
        self.accounts_structs.insert(s.name.clone(), s);
    }

    pub fn insert_state(&mut self, s: StateStruct, file: &Path) {
        if let Some(existing) = self.state_structs.get(&s.name) {
            self.diagnostics.push(Diagnostic {
                file: Some(file.to_path_buf()),
                kind: DiagnosticKind::Ambiguity,
                message: format!(
                    "state struct `{}` also defined in {} — keeping the first",
                    s.name,
                    existing.file.display()
                ),
            });
            return;
        }
        self.state_structs.insert(s.name.clone(), s);
    }
}
```

`crates/dike-lang-anchor/src/parser/program.rs`:

```rust
use crate::ir::{Arg, Handler, HandlerBody};
use std::path::Path;
use syn::spanned::Spanned;

/// Extracts the `T` from `Context<'info, T>` / `Context<T>`.
pub(crate) fn context_type_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != "Context" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else { return None };
    args.args.iter().rev().find_map(|a| match a {
        syn::GenericArgument::Type(syn::Type::Path(tp)) => {
            tp.path.segments.last().map(|s| s.ident.to_string())
        }
        _ => None,
    })
}

/// Every `pub fn` in a `#[program]` module whose first argument is a `Context<T>`.
pub(crate) fn parse_handlers(module: &syn::ItemMod, file: &Path) -> Vec<Handler> {
    let Some((_, items)) = &module.content else { return Vec::new() };
    let mut handlers = Vec::new();
    for item in items {
        let syn::Item::Fn(f) = item else { continue };
        let mut inputs = f.sig.inputs.iter();
        let Some(syn::FnArg::Typed(first)) = inputs.next() else { continue };
        let Some(context_ty) = context_type_name(&first.ty) else { continue };

        let args = inputs
            .filter_map(|a| match a {
                syn::FnArg::Typed(t) => Some(Arg {
                    name: match &*t.pat {
                        syn::Pat::Ident(i) => i.ident.to_string(),
                        other => quote::quote!(#other).to_string(),
                    },
                    ty: {
                        let ty = &t.ty;
                        quote::quote!(#ty).to_string()
                    },
                }),
                _ => None,
            })
            .collect();

        handlers.push(Handler {
            name: f.sig.ident.to_string(),
            file: file.to_path_buf(),
            line: f.span().start().line as u32,
            args,
            context_ty,
            // Filled in by Task 8.
            body: HandlerBody::default(),
        });
    }
    handlers
}
```

`crates/dike-lang-anchor/src/parser/mod.rs`:

```rust
pub mod accounts;
pub mod program;
pub mod symbols;

use crate::ir::{Program, StateStruct};
use dike_core::analyzer::{Diagnostic, DiagnosticKind, SourceTree};
use std::path::Path;
use symbols::SymbolTable;

pub struct ParseOutcome {
    pub program: Program,
    pub diagnostics: Vec<Diagnostic>,
    pub files_parsed: usize,
}

pub fn parse_tree(tree: &SourceTree) -> ParseOutcome {
    let mut symbols = SymbolTable::default();
    let mut handlers = Vec::new();
    let mut diagnostics = Vec::new();
    let mut files_parsed = 0;

    for file in &tree.files {
        let parsed = match syn::parse_file(&file.text) {
            Ok(p) => p,
            Err(err) => {
                // Partial results beat no results.
                diagnostics.push(Diagnostic {
                    file: Some(file.path.clone()),
                    kind: DiagnosticKind::ParseFailure,
                    message: err.to_string(),
                });
                continue;
            }
        };
        files_parsed += 1;
        visit_items(&parsed.items, &file.path, &mut symbols, &mut handlers);
    }

    diagnostics.extend(std::mem::take(&mut symbols.diagnostics));
    handlers.sort_by(|a, b| a.name.cmp(&b.name)); // determinism

    ParseOutcome {
        program: Program {
            instructions: handlers,
            accounts_structs: symbols.accounts_structs,
            state_structs: symbols.state_structs,
        },
        diagnostics,
        files_parsed,
    }
}

fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

fn derives(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("derive")
            && a.parse_nested_meta(|m| {
                if m.path.is_ident(name) {
                    Err(m.error("found"))
                } else {
                    Ok(())
                }
            })
            .is_err()
    })
}

/// Recurses into inline modules — real programs nest `#[program]` inside `pub mod`.
fn visit_items(
    items: &[syn::Item],
    file: &Path,
    symbols: &mut SymbolTable,
    handlers: &mut Vec<crate::ir::Handler>,
) {
    for item in items {
        match item {
            syn::Item::Mod(m) => {
                if has_attr(&m.attrs, "program") {
                    handlers.extend(program::parse_handlers(m, file));
                }
                if let Some((_, inner)) = &m.content {
                    visit_items(inner, file, symbols, handlers);
                }
            }
            syn::Item::Struct(s) => {
                if derives(&s.attrs, "Accounts") {
                    symbols.insert_accounts(accounts::parse_accounts_struct(s, file), file);
                } else if has_attr(&s.attrs, "account") {
                    let fields = match &s.fields {
                        syn::Fields::Named(named) => named
                            .named
                            .iter()
                            .map(|f| {
                                let ty = &f.ty;
                                (
                                    f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default(),
                                    quote::quote!(#ty).to_string(),
                                )
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    symbols.insert_state(
                        StateStruct { name: s.ident.to_string(), fields, file: file.to_path_buf() },
                        file,
                    );
                }
            }
            _ => {}
        }
    }
}
```

Add `pub mod parser;` to `crates/dike-lang-anchor/src/lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-lang-anchor`
Expected: PASS — 11 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/dike-lang-anchor
git commit -m "feat: parse program handlers with a cross-file symbol table"
```

---

### Task 8: Handler body summary and the `dike ir` command

**Files:**
- Create: `crates/dike-lang-anchor/src/parser/body.rs`, `crates/dike-cli/src/commands/ir.rs`
- Create: `tests/fixtures/programs/vault/src/lib.rs`
- Modify: `crates/dike-lang-anchor/src/parser/mod.rs`, `crates/dike-lang-anchor/src/parser/program.rs`, `crates/dike-cli/src/commands/mod.rs`, `crates/dike-cli/src/main.rs`, `crates/dike-cli/Cargo.toml`

**Interfaces:**
- Consumes: `ir::{HandlerBody, CallSite, ArithOp, ImperativeCheck, CheckKind, StateWrite}`.
- Produces: `pub fn summarize_body(f: &syn::ItemFn) -> HandlerBody`; CLI subcommand `dike ir <PATH>` printing `Program` as pretty JSON.

This is the module that satisfies D9: everything below the accounts struct that
detectors need is extracted **once**, here, into typed data. No detector ever touches
`syn`. Implement with a `syn::visit::Visit` walker over the function body.

Recognition rules:
- **CPI call**: a call whose path ends in `invoke`, `invoke_signed`, or whose receiver chain contains `CpiContext`. Set `is_cpi = true`.
- **Arithmetic**: `syn::Expr::Binary` with `Add | Sub | Mul | Div` → `checked: false`; a method call named `checked_*`, `saturating_*`, or `wrapping_*` → `checked: true`.
- **Imperative check**: macro named `require`, `require_eq`, `require_keys_eq`, `require_neq`, `require_gt`, `require_gte`; plus `#[access_control(...)]` on the fn. `referenced_accounts` = every identifier appearing in the macro tokens that also names a field of the handler's accounts struct — since the accounts struct is not in scope here, record **all** identifiers and let the suppression pass (Task 12) intersect them.
- **State write**: an assignment (`Expr::Assign`) whose left side is a field access rooted at `ctx.accounts.<name>`; record `<name>`.

- [ ] **Step 1: Write the failing test**

In `crates/dike-lang-anchor/src/parser/body.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::CheckKind;

    fn body(src: &str) -> crate::ir::HandlerBody {
        let f: syn::ItemFn = syn::parse_str(src).unwrap();
        summarize_body(&f)
    }

    #[test]
    fn detects_unchecked_and_checked_arithmetic() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                let a = ctx.accounts.vault.amount - amount;
                let c = ctx.accounts.vault.amount.checked_add(amount).unwrap();
                Ok(())
            }
        "#);
        assert!(b.arithmetic.iter().any(|a| !a.checked && a.op == "-"));
        assert!(b.arithmetic.iter().any(|a| a.checked));
    }

    #[test]
    fn detects_cpi_calls() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>) -> Result<()> {
                let cpi = CpiContext::new(ctx.accounts.token_program.to_account_info(), accs);
                token::transfer(cpi, 1)?;
                invoke_signed(&ix, &accounts, signers)?;
                Ok(())
            }
        "#);
        assert!(b.calls.iter().any(|c| c.is_cpi));
        assert!(b.calls.iter().any(|c| c.name.contains("invoke_signed")));
    }

    #[test]
    fn detects_imperative_checks_and_their_identifiers() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>) -> Result<()> {
                require_keys_eq!(ctx.accounts.vault.admin, ctx.accounts.authority.key());
                require!(amount > 0, ErrorCode::Zero);
                Ok(())
            }
        "#);
        assert_eq!(b.checks.len(), 2);
        let keys_eq = b.checks.iter().find(|c| c.kind == CheckKind::RequireKeysEq).unwrap();
        assert!(keys_eq.referenced_accounts.contains(&"authority".to_string()));
        assert!(keys_eq.referenced_accounts.contains(&"vault".to_string()));
    }

    #[test]
    fn detects_access_control_attribute() {
        let b = body(r#"
            #[access_control(only_admin(&ctx))]
            pub fn withdraw(ctx: Context<W>) -> Result<()> { Ok(()) }
        "#);
        assert!(b.checks.iter().any(|c| c.kind == CheckKind::AccessControl));
    }

    #[test]
    fn detects_state_writes_through_ctx_accounts() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>) -> Result<()> {
                ctx.accounts.vault.amount = 0;
                Ok(())
            }
        "#);
        assert_eq!(b.state_writes.len(), 1);
        assert_eq!(b.state_writes[0].account, "vault");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-lang-anchor body`
Expected: FAIL — `summarize_body` not found.

- [ ] **Step 3: Implement `summarize_body`**

Sketch (fill in the visitor arms until the Step 1 tests pass):

```rust
use crate::ir::{ArithOp, CallSite, CheckKind, HandlerBody, ImperativeCheck, StateWrite};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

#[derive(Default)]
struct BodyVisitor {
    body: HandlerBody,
}

/// Collect every identifier in a token stream. The suppression pass intersects
/// these with real account names — doing it here would need scope we don't have.
fn identifiers(tokens: &proc_macro2::TokenStream) -> Vec<String> {
    let mut out = Vec::new();
    for t in tokens.clone() {
        match t {
            proc_macro2::TokenTree::Ident(i) => out.push(i.to_string()),
            proc_macro2::TokenTree::Group(g) => out.extend(identifiers(&g.stream())),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `ctx.accounts.vault.amount` -> Some("vault")
fn ctx_account_root(expr: &syn::Expr) -> Option<String> {
    let mut names = Vec::new();
    let mut cur = expr;
    loop {
        match cur {
            syn::Expr::Field(f) => {
                if let syn::Member::Named(id) = &f.member {
                    names.push(id.to_string());
                }
                cur = &f.base;
            }
            syn::Expr::Path(p) => {
                names.push(p.path.segments.last()?.ident.to_string());
                break;
            }
            syn::Expr::MethodCall(m) => cur = &m.receiver,
            _ => return None,
        }
    }
    names.reverse(); // ["ctx", "accounts", "vault", "amount"]
    if names.len() >= 3 && names[0] == "ctx" && names[1] == "accounts" {
        Some(names[2].clone())
    } else {
        None
    }
}

impl<'ast> Visit<'ast> for BodyVisitor {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        let op = match node.op {
            syn::BinOp::Add(_) => Some("+"),
            syn::BinOp::Sub(_) => Some("-"),
            syn::BinOp::Mul(_) => Some("*"),
            syn::BinOp::Div(_) => Some("/"),
            _ => None,
        };
        if let Some(op) = op {
            self.body.arithmetic.push(ArithOp {
                op: op.to_string(),
                line: node.span().start().line as u32,
                checked: false,
            });
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if name.starts_with("checked_")
            || name.starts_with("saturating_")
            || name.starts_with("wrapping_")
        {
            self.body.arithmetic.push(ArithOp {
                op: name.clone(),
                line: node.span().start().line as u32,
                checked: true,
            });
        }
        self.body.calls.push(CallSite {
            name,
            line: node.span().start().line as u32,
            is_cpi: false,
        });
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let name = {
            let f = &node.func;
            quote::quote!(#f).to_string().replace(' ', "")
        };
        let is_cpi = name.ends_with("invoke")
            || name.ends_with("invoke_signed")
            || name.contains("CpiContext")
            || node
                .args
                .iter()
                .any(|a| quote::quote!(#a).to_string().contains("CpiContext"));
        self.body.calls.push(CallSite {
            name,
            line: node.span().start().line as u32,
            is_cpi,
        });
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let kind = match name.as_str() {
            "require" => Some(CheckKind::Require),
            "require_eq" | "require_neq" | "require_gt" | "require_gte" => Some(CheckKind::RequireEq),
            "require_keys_eq" | "require_keys_neq" => Some(CheckKind::RequireKeysEq),
            _ => None,
        };
        if let Some(kind) = kind {
            self.body.checks.push(ImperativeCheck {
                kind,
                referenced_accounts: identifiers(&node.tokens),
                line: node.span().start().line as u32,
            });
        }
        visit::visit_macro(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(account) = ctx_account_root(&node.left) {
            self.body.state_writes.push(StateWrite {
                account,
                line: node.span().start().line as u32,
            });
        }
        visit::visit_expr_assign(self, node);
    }
}

pub fn summarize_body(f: &syn::ItemFn) -> HandlerBody {
    let mut v = BodyVisitor::default();
    for attr in &f.attrs {
        if attr.path().is_ident("access_control") {
            let tokens = attr.meta.require_list().map(|l| l.tokens.clone()).unwrap_or_default();
            v.body.checks.push(ImperativeCheck {
                kind: CheckKind::AccessControl,
                referenced_accounts: identifiers(&tokens),
                line: attr.span().start().line as u32,
            });
        }
    }
    v.visit_block(&f.block);
    v.body
}
```

Wire it up: in `program.rs`, replace `body: HandlerBody::default()` with
`body: crate::parser::body::summarize_body(f)`, and add `pub mod body;` to `parser/mod.rs`.

- [ ] **Step 4: Add the fixture program and the `dike ir` command**

`tests/fixtures/programs/vault/src/lib.rs` — a small but realistic Anchor program with
**four handlers**, written clean (no injected bugs; mutations come later):
`initialize` (init a `Vault` with `seeds`/`bump`), `deposit` (checked arithmetic, `has_one = admin`),
`withdraw` (`Signer` authority, `has_one = admin`, `require!` on amount, a `token::transfer` CPI),
and `close_vault` (`close = admin`). Import `anchor_lang::prelude::*` and declare
`#[account] pub struct Vault { pub admin: Pubkey, pub amount: u64, pub bump: u8 }`.
This file is a **fixture, not a workspace member** — it is never compiled by `cargo test`.

`crates/dike-cli/src/commands/ir.rs`:

```rust
use anyhow::Context;
use dike_core::analyzer::SourceTree;

pub fn run(path: std::path::PathBuf) -> anyhow::Result<()> {
    let tree = SourceTree::load(&path).with_context(|| format!("reading {}", path.display()))?;
    let outcome = dike_lang_anchor::parser::parse_tree(&tree);
    println!("{}", serde_json::to_string_pretty(&outcome.program)?);
    for d in &outcome.diagnostics {
        eprintln!("warn: {:?} {}", d.kind, d.message);
    }
    Ok(())
}
```

Add `dike-lang-anchor = { path = "../dike-lang-anchor" }` to `crates/dike-cli/Cargo.toml`,
`pub mod ir;` to `commands/mod.rs`, and an `Ir { path: PathBuf }` variant to the CLI enum
dispatching to `commands::ir::run(path)`.

- [ ] **Step 5: Run the tests and the command**

Run: `cargo test -p dike-lang-anchor`
Expected: PASS — 16 tests.

Run: `cargo run -p dike-cli -- ir tests/fixtures/programs/vault`
Expected: JSON containing 4 instructions, each with a non-empty `context_ty` that
resolves in `accounts_structs`, and a `Vault` entry in `state_structs`.

- [ ] **Step 6: Commit**

```bash
git add crates/ tests/fixtures
git commit -m "feat: handler body summaries and the dike ir debug command"
```

---

## Phase 3 — Track 1: Static Detectors

Deliverable: `dike analyze tests/fixtures/programs/vault` reports real findings, deterministically, with no LLM and no network.

**Per-track class coverage (D16)** — declare this in `detectors/mod.rs` as a doc comment and in the README, so the eval table is readable rather than alarming:

| Class | Track 1 | Track 2 | Severity | Detector confidence |
|---|---|---|---|---|
| `missing-signer` | yes | yes | Critical | 0.90 |
| `missing-owner-check` | yes | yes | High | 0.75 |
| `missing-authority-binding` | yes | yes | High | 0.70 |
| `pda-validation-gap` | yes | yes | High | 0.65 |
| `unchecked-arithmetic` | yes | yes | Medium | 0.35 |
| `removed-guard` | **no** | yes | High | — |
| `missing-reload` | no (deferred) | yes | High | — |
| `rounding-leak` | no (deferred) | yes | Medium | — |

Confidence values are the per-detector constants required by the spec: a missing signer on an authority is near-certain; bare arithmetic is frequently benign, hence 0.35.

### Task 9: Detector framework, missing-signer, missing-owner-check

**Files:**
- Create: `crates/dike-lang-anchor/src/detectors/mod.rs`, `crates/dike-lang-anchor/src/detectors/signer.rs`, `crates/dike-lang-anchor/src/detectors/owner.rs`
- Modify: `crates/dike-lang-anchor/src/lib.rs`

**Interfaces:**
- Consumes: `ir::Program`, `dike_core::finding::{Finding, Location, Severity, Track, VulnClass}`.
- Produces: `pub trait Detector { fn class(&self) -> &'static str; fn severity(&self) -> Severity; fn confidence(&self) -> f32; fn run(&self, program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding>; }`; `pub fn all_detectors() -> Vec<Box<dyn Detector>>`; `pub fn finding_from(detector: &dyn Detector, handler: &Handler, decl: &AccountDecl, evidence: String) -> Finding`; class constants `pub const MISSING_SIGNER: &str = "missing-signer";` etc.; `MissingSignerDetector`, `MissingOwnerCheckDetector`.

`finding_from` is the single place a Track 1 `Finding` is constructed — it stamps `Track::Static`, the detector's constant confidence, and a stable `id` (`blake3(handler_id + class + decl.name)` truncated to 16 hex chars). Detectors are **pure functions with no I/O**; a detector that reads a file or the network is a bug.

**Missing-signer rule:** for each `AccountDecl` whose name matches `authority|admin|owner|signer|payer|delegate|manager` (case-insensitive, substring) and which does **not** `enforces_signer()` and is not `is_address_pinned()`, emit. Skip decls whose wrapper is `Program | SystemAccount | Sysvar`.

**Missing-owner-check rule:** for each `is_unchecked()` decl that is not `is_address_pinned()` and carries no `Constraint::Owner`, `Seeds`, or `Raw` constraint, emit. Rationale: `UncheckedAccount`/`AccountInfo` get no discriminator or owner validation from Anchor, so something must pin them.

- [ ] **Step 1: Write the failing test**

In `crates/dike-lang-anchor/src/detectors/signer.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::Detector;
    use crate::parser::parse_tree;
    use dike_core::analyzer::{SourceFile, SourceTree};
    use std::path::PathBuf;

    fn findings_for(src: &str) -> Vec<dike_core::Finding> {
        let tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile { path: PathBuf::from("src/lib.rs"), text: src.into() }],
        };
        let out = parse_tree(&tree);
        let d = MissingSignerDetector;
        out.program
            .instructions
            .iter()
            .flat_map(|h| {
                let accounts = out.program.accounts_for(h).cloned().unwrap_or_default();
                d.run(&out.program, h, &accounts)
            })
            .collect()
    }

    const VULNERABLE: &str = r#"
        #[program]
        pub mod vault {
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            pub authority: AccountInfo<'info>,
            #[account(mut)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    const SAFE: &str = r#"
        #[program]
        pub mod vault {
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            pub authority: Signer<'info>,
            #[account(mut)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    #[test]
    fn flags_authority_without_signer() {
        let f = findings_for(VULNERABLE);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "missing-signer");
        assert_eq!(f[0].severity, dike_core::Severity::Critical);
        assert_eq!(f[0].track, dike_core::Track::Static);
        assert_eq!(f[0].location.handler, "withdraw");
        assert!((f[0].confidence - 0.90).abs() < 1e-6);
    }

    #[test]
    fn does_not_flag_typed_signer() {
        assert!(findings_for(SAFE).is_empty());
    }

    #[test]
    fn does_not_flag_legacy_signer_attribute() {
        let src = SAFE.replace(
            "pub authority: Signer<'info>,",
            "#[account(signer)]\n            pub authority: AccountInfo<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_flag_address_pinned_authority() {
        let src = SAFE.replace(
            "pub authority: Signer<'info>,",
            "#[account(address = crate::ADMIN)]\n            pub authority: AccountInfo<'info>,",
        );
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn is_deterministic_across_runs() {
        let a = findings_for(VULNERABLE);
        let b = findings_for(VULNERABLE);
        assert_eq!(a, b);
    }
}
```

Write the parallel test module in `owner.rs`: an `UncheckedAccount` with no pinning
constraint is flagged `missing-owner-check` at `Severity::High` / `0.75`; the same
account with `#[account(owner = token_program.key())]`, with `seeds`/`bump`, or with
`address =` is not flagged; an `Account<'info, Vault>` is never flagged.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-lang-anchor detectors`
Expected: FAIL — `MissingSignerDetector` not found.

- [ ] **Step 3: Implement the framework**

`crates/dike-lang-anchor/src/detectors/mod.rs`:

```rust
pub mod owner;
pub mod signer;

use crate::ir::{AccountDecl, AccountsStruct, Handler, Program};
use dike_core::finding::{Finding, Location, Severity, Track, VulnClass};

pub const MISSING_SIGNER: &str = "missing-signer";
pub const MISSING_OWNER_CHECK: &str = "missing-owner-check";
pub const MISSING_AUTHORITY_BINDING: &str = "missing-authority-binding";
pub const PDA_VALIDATION_GAP: &str = "pda-validation-gap";
pub const UNCHECKED_ARITHMETIC: &str = "unchecked-arithmetic";
/// Track 2 only — the absence of an arbitrary `constraint = ...` is not a
/// structural signal (D16).
pub const REMOVED_GUARD: &str = "removed-guard";

/// Pure. No I/O, no network, no clock. Track 1's numbers must never move
/// for any reason other than a code change to a detector.
pub trait Detector {
    fn class(&self) -> &'static str;
    fn severity(&self) -> Severity;
    /// A per-detector constant, not a computed value.
    fn confidence(&self) -> f32;
    fn run(&self, program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding>;
}

pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(signer::MissingSignerDetector),
        Box::new(owner::MissingOwnerCheckDetector),
    ] // extended in Tasks 10 and 11
}

/// The single construction point for a Track 1 finding.
pub fn finding_from(
    detector: &dyn Detector,
    handler: &Handler,
    decl: &AccountDecl,
    evidence: String,
) -> Finding {
    let location = Location {
        file: handler.file.clone(),
        line: decl.line,
        handler: handler.name.clone(),
    };
    let id = {
        let seed = format!("{}|{}|{}", location.handler_id(), detector.class(), decl.name);
        blake3::hash(seed.as_bytes()).to_hex()[..16].to_string()
    };
    Finding {
        id,
        class: VulnClass::new(detector.class()),
        severity: detector.severity(),
        confidence: detector.confidence(),
        track: Track::Static,
        location,
        evidence,
        citations: vec![],
    }
}

/// Account names that conventionally denote a privileged party.
pub(crate) const AUTHORITY_NAMES: [&str; 7] =
    ["authority", "admin", "owner", "signer", "payer", "delegate", "manager"];

pub(crate) fn looks_like_authority(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    AUTHORITY_NAMES.iter().any(|n| lower.contains(n))
}
```

Add `blake3 = "1"` to `[workspace.dependencies]` and to `dike-lang-anchor`.

`signer.rs`:

```rust
use super::{finding_from, looks_like_authority, Detector, MISSING_SIGNER};
use crate::ir::{AccountsStruct, Handler, Program, Wrapper};
use dike_core::finding::{Finding, Severity};

pub struct MissingSignerDetector;

impl Detector for MissingSignerDetector {
    fn class(&self) -> &'static str { MISSING_SIGNER }
    fn severity(&self) -> Severity { Severity::Critical }
    fn confidence(&self) -> f32 { 0.90 }

    fn run(&self, _program: &Program, handler: &Handler, accounts: &AccountsStruct) -> Vec<Finding> {
        accounts
            .decls
            .iter()
            .filter(|d| {
                !matches!(d.wrapper, Wrapper::Program(_) | Wrapper::SystemAccount | Wrapper::Sysvar(_))
                    && looks_like_authority(&d.name)
                    && !d.enforces_signer()
                    && !d.is_address_pinned()
            })
            .map(|d| {
                finding_from(
                    self,
                    handler,
                    d,
                    format!(
                        "`{}` is named as a privileged account but is declared `{:?}` with no \
                         `Signer<'info>` type, `signer` constraint, or `address =` pin. Anyone \
                         may pass an arbitrary account here.",
                        d.name, d.wrapper
                    ),
                )
            })
            .collect()
    }
}
```

`owner.rs`: same shape — `class() = MISSING_OWNER_CHECK`, `Severity::High`, `0.75`,
filtering on `d.is_unchecked() && !d.is_address_pinned() && !d.has_seeds() && !d.constraints.iter().any(|c| matches!(c, Constraint::Owner(_) | Constraint::Raw(_)))`,
with evidence explaining that Anchor performs no owner or discriminator check on the wrapper.

Add `pub mod detectors;` to `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-lang-anchor`
Expected: PASS — 24 tests.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/dike-lang-anchor
git commit -m "feat: detector framework with missing-signer and missing-owner-check"
```

---

### Task 10: Authority-binding and PDA-validation detectors

**Files:**
- Create: `crates/dike-lang-anchor/src/detectors/authority.rs`, `crates/dike-lang-anchor/src/detectors/pda.rs`
- Modify: `crates/dike-lang-anchor/src/detectors/mod.rs`

**Interfaces:**
- Consumes: Task 9 framework.
- Produces: `MissingAuthorityBindingDetector`, `PdaValidationGapDetector`; both registered in `all_detectors()`.

**Authority-binding rule:** a decl whose wrapper is `Account(T)` or `InterfaceAccount(T)`, where the resolved `StateStruct` for `T` has a `Pubkey` field named in `AUTHORITY_NAMES`, and the decl has **no** `has_one` naming that field and no `Raw` constraint mentioning it, **and** the accounts struct also contains a signer-enforcing decl. That last condition matters: a struct with no signer at all is a missing-signer finding, not an unbound-authority one, and emitting both would double-report the same bug. This is the detector that requires the state-struct type table from Task 7.

**PDA-validation rule:** a decl that has `seeds` but no `bump` (or vice versa) → gap. Additionally, a decl that is `is_init()` with `seeds` but no `bump` → gap. Do **not** flag accounts with neither, since not every account is a PDA.

- [ ] **Step 1: Write the failing tests**

In `authority.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // Reuse the harness shape from signer.rs::tests: parse a source string,
    // run this detector over every handler, return the findings.

    const BASE: &str = r#"
        #[program]
        pub mod vault {
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
        }
        #[account]
        pub struct Vault { pub admin: Pubkey, pub amount: u64 }
        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            pub admin: Signer<'info>,
            #[account(mut, HASONE)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    #[test]
    fn flags_state_authority_field_with_no_has_one() {
        let f = findings_for(&BASE.replace("HASONE", ""));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "missing-authority-binding");
        assert_eq!(f[0].severity, dike_core::Severity::High);
        assert!(f[0].evidence.contains("admin"));
    }

    #[test]
    fn does_not_flag_when_has_one_is_present() {
        assert!(findings_for(&BASE.replace("HASONE", "has_one = admin")).is_empty());
    }

    #[test]
    fn does_not_flag_when_a_raw_constraint_mentions_the_field() {
        let src = BASE.replace("HASONE", "constraint = vault.admin == admin.key()");
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_double_report_when_the_struct_has_no_signer_at_all() {
        let src = BASE
            .replace("HASONE", "")
            .replace("pub admin: Signer<'info>,", "pub other: AccountInfo<'info>,");
        assert!(findings_for(&src).is_empty());
    }

    #[test]
    fn does_not_flag_state_structs_without_an_authority_field() {
        let src = BASE
            .replace("HASONE", "")
            .replace("pub admin: Pubkey, pub amount: u64", "pub amount: u64");
        assert!(findings_for(&src).is_empty());
    }
}
```

In `pda.rs`: `#[account(seeds = [b"vault"], bump)]` → no finding;
`#[account(seeds = [b"vault"])]` (no bump) → one `pda-validation-gap` at `Severity::High` / `0.65`;
`#[account(bump)]` with no seeds → one finding; `#[account(mut)]` alone → no finding.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-lang-anchor authority pda`
Expected: FAIL — detectors not found.

- [ ] **Step 3: Implement both detectors and register them**

Key helper for `authority.rs` — resolving the state struct is why `Program` is passed in:

```rust
fn authority_fields(program: &Program, decl: &AccountDecl) -> Vec<String> {
    let ty = match &decl.wrapper {
        Wrapper::Account(t) | Wrapper::InterfaceAccount(t) => t,
        _ => return Vec::new(),
    };
    let Some(state) = program.state_structs.get(ty) else { return Vec::new() };
    state
        .fields
        .iter()
        .filter(|(name, field_ty)| field_ty.contains("Pubkey") && super::looks_like_authority(name))
        .map(|(name, _)| name.clone())
        .collect()
}
```

Then flag each authority field not covered by `decl.has_one_targets()` and not
mentioned in any `Constraint::Raw` text, guarded by
`accounts.decls.iter().any(|d| d.enforces_signer())`.

Extend `all_detectors()` with both.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-lang-anchor`
Expected: PASS — 33 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/dike-lang-anchor
git commit -m "feat: authority-binding and PDA-validation detectors"
```

---

### Task 11: Unchecked-arithmetic detector

**Files:**
- Create: `crates/dike-lang-anchor/src/detectors/arithmetic.rs`
- Modify: `crates/dike-lang-anchor/src/detectors/mod.rs`

**Interfaces:**
- Consumes: `ir::HandlerBody` from Task 8, Task 9 framework.
- Produces: `UncheckedArithmeticDetector`; a second construction helper
  `pub fn finding_at_line(detector: &dyn Detector, handler: &Handler, line: u32, key: &str, evidence: String) -> Finding`
  in `detectors/mod.rs`, for detectors that anchor to a body line rather than an account decl.

This detector reads `handler.body.arithmetic` only — it never touches `syn` (D9). One
finding per handler, not per operation: an auditor wants "arithmetic in `withdraw` is
unchecked", not forty rows. Evidence lists the lines. Confidence 0.35 reflects that
most bare arithmetic is benign; recall still demands we report it.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_a_handler_with_bare_arithmetic_once() {
        let f = findings_for(r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                    ctx.accounts.vault.amount = ctx.accounts.vault.amount - amount;
                    let fee = amount * 3 / 100;
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> { pub authority: Signer<'info> }
        "#);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].class.as_str(), "unchecked-arithmetic");
        assert_eq!(f[0].severity, dike_core::Severity::Medium);
        assert!((f[0].confidence - 0.35).abs() < 1e-6);
        assert!(f[0].evidence.contains("line"));
    }

    #[test]
    fn does_not_flag_fully_checked_arithmetic() {
        let f = findings_for(r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                    ctx.accounts.vault.amount =
                        ctx.accounts.vault.amount.checked_sub(amount).ok_or(ErrorCode::Overflow)?;
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> { pub authority: Signer<'info> }
        "#);
        assert!(f.is_empty());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-lang-anchor arithmetic`
Expected: FAIL — detector not found.

- [ ] **Step 3: Implement**

```rust
impl Detector for UncheckedArithmeticDetector {
    fn class(&self) -> &'static str { UNCHECKED_ARITHMETIC }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> f32 { 0.35 }

    fn run(&self, _program: &Program, handler: &Handler, _accounts: &AccountsStruct) -> Vec<Finding> {
        let unchecked: Vec<u32> = handler
            .body
            .arithmetic
            .iter()
            .filter(|a| !a.checked)
            .map(|a| a.line)
            .collect();
        if unchecked.is_empty() {
            return Vec::new();
        }
        let lines = unchecked.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ");
        vec![finding_at_line(
            self,
            handler,
            unchecked[0],
            "arithmetic",
            format!(
                "Unchecked arithmetic in `{}` at line(s) {lines}. Solana programs build in \
                 release mode, where overflow wraps silently rather than panicking.",
                handler.name
            ),
        )]
    }
}
```

Register in `all_detectors()`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-lang-anchor`
Expected: PASS — 35 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/dike-lang-anchor
git commit -m "feat: unchecked-arithmetic detector"
```

---

### Task 12: Imperative-check suppression pass

**Files:**
- Create: `crates/dike-lang-anchor/src/detectors/suppression.rs`
- Modify: `crates/dike-lang-anchor/src/detectors/mod.rs`

**Interfaces:**
- Consumes: `ir::{Handler, AccountsStruct, CheckKind}`, `dike_core::Finding`.
- Produces: `pub struct Suppression { pub finding: Finding, pub reason: String }`; `pub fn apply(findings: Vec<Finding>, handler: &Handler, accounts: &AccountsStruct) -> (Vec<Finding>, Vec<Suppression>)`.

D15, and the single largest false-positive source on real code. A program that
validates imperatively — `require_keys_eq!(ctx.accounts.vault.admin, ctx.accounts.authority.key())`
or `#[access_control(only_admin(&ctx))]` — is correct, but a detector reading only
`#[account(...)]` sees a missing constraint and reports it.

Suppression rules, deliberately narrow (recall is primary — over-suppressing costs a bug):
- `missing-signer` and `missing-authority-binding` on account `X` are suppressed if any `ImperativeCheck` in the handler has `X` in `referenced_accounts`, **or** if the handler has an `AccessControl` check (which we cannot resolve into the callee, so we suppress conservatively for those two classes only).
- `missing-owner-check` is suppressed only by a check that references the account by name — never by a bare `#[access_control]`, which almost never performs owner validation.
- `unchecked-arithmetic` and `pda-validation-gap` are **never** suppressed. A `require!` does not make arithmetic safe.

Suppressed findings are counted into `Coverage::suppressed` and listed in a
report subsection, never silently dropped.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // `findings_and_suppressions_for(src)` parses, runs all_detectors(), then apply().

    #[test]
    fn require_keys_eq_suppresses_missing_signer_on_the_named_account() {
        let (kept, suppressed) = findings_and_suppressions_for(r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    require_keys_eq!(ctx.accounts.vault.admin, ctx.accounts.authority.key());
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub authority: AccountInfo<'info>,
                pub vault: Account<'info, Vault>,
            }
        "#);
        assert!(!kept.iter().any(|f| f.class.as_str() == "missing-signer"));
        assert!(suppressed.iter().any(|s| s.finding.class.as_str() == "missing-signer"));
        assert!(suppressed[0].reason.contains("require_keys_eq") || suppressed[0].reason.contains("imperative"));
    }

    #[test]
    fn access_control_suppresses_authority_classes_only() {
        let (kept, _) = findings_and_suppressions_for(r#"
            #[program]
            pub mod vault {
                #[access_control(only_admin(&ctx))]
                pub fn withdraw(ctx: Context<W>) -> Result<()> {
                    let x = ctx.accounts.vault.amount - 1;
                    Ok(())
                }
            }
            #[account]
            pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            #[derive(Accounts)]
            pub struct W<'info> {
                pub authority: AccountInfo<'info>,
                pub raw: UncheckedAccount<'info>,
                pub vault: Account<'info, Vault>,
            }
        "#);
        assert!(!kept.iter().any(|f| f.class.as_str() == "missing-signer"));
        // owner-check and arithmetic survive a bare access_control
        assert!(kept.iter().any(|f| f.class.as_str() == "missing-owner-check"));
        assert!(kept.iter().any(|f| f.class.as_str() == "unchecked-arithmetic"));
    }

    #[test]
    fn unrelated_requires_do_not_suppress() {
        let (kept, _) = findings_and_suppressions_for(r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                    require!(amount > 0, ErrorCode::Zero);
                    Ok(())
                }
            }
            #[derive(Accounts)]
            pub struct W<'info> { pub authority: AccountInfo<'info> }
        "#);
        assert!(kept.iter().any(|f| f.class.as_str() == "missing-signer"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-lang-anchor suppression`
Expected: FAIL — `apply` not found.

- [ ] **Step 3: Implement**

`Finding` does not carry the account name, and it must not grow one — that field would be
a language-specific need widening a domain-agnostic type. Recover the subject instead:
implement `fn subject_account(finding: &Finding, accounts: &AccountsStruct) -> Option<String>`
returning the first `accounts.decls` name that appears as `` `name` `` in the finding's
evidence. **Scope this correctly (amended 2026-08-28, Task 11 review).** The
account-oriented detectors — missing-signer, missing-owner-check,
missing-authority-binding — format the account name in backticks. The
**body-oriented** ones do not and cannot: `arithmetic.rs` backticks the *handler*
name, because an unchecked-arithmetic finding has no account subject. Add the
guard test in `detectors/mod.rs`, but scope it to the three SUPPRESSIBLE classes,
asserting that each of their findings' evidence contains its subject account in
backticks. A blanket "every detector" assertion would fail against
`unchecked-arithmetic` on its first run, and the failure would look like a real
defect rather than a mis-scoped test.

This costs nothing in coverage: `never_suppressed` (below) short-circuits
`unchecked-arithmetic` and `pda-validation-gap` *before* `subject_account` is ever
called, so their evidence format cannot break suppression. The test exists to stop
a future *suppressible* detector from silently dropping the backticks.

```rust
pub fn apply(
    findings: Vec<Finding>,
    handler: &Handler,
    accounts: &AccountsStruct,
) -> (Vec<Finding>, Vec<Suppression>) {
    let has_access_control = handler
        .body
        .checks
        .iter()
        .any(|c| c.kind == CheckKind::AccessControl);

    let mut kept = Vec::new();
    let mut suppressed = Vec::new();

    for f in findings {
        let class = f.class.as_str().to_string();
        let suppressible_by_access_control =
            class == MISSING_SIGNER || class == MISSING_AUTHORITY_BINDING;
        let never_suppressed = class == UNCHECKED_ARITHMETIC || class == PDA_VALIDATION_GAP;

        if never_suppressed {
            kept.push(f);
            continue;
        }

        let subject = subject_account(&f, accounts);
        let named_check = subject.as_ref().and_then(|name| {
            handler
                .body
                .checks
                .iter()
                .find(|c| c.referenced_accounts.iter().any(|r| r == name))
        });

        if let Some(check) = named_check {
            suppressed.push(Suppression {
                reason: format!(
                    "imperative {:?} check at line {} references `{}`",
                    check.kind,
                    check.line,
                    subject.unwrap_or_default()
                ),
                finding: f,
            });
        } else if has_access_control && suppressible_by_access_control {
            suppressed.push(Suppression {
                reason: "handler carries #[access_control]; authority validation may be delegated"
                    .to_string(),
                finding: f,
            });
        } else {
            kept.push(f);
        }
    }
    (kept, suppressed)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dike-lang-anchor`
Expected: PASS — 38 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/dike-lang-anchor
git commit -m "feat: suppress constraint findings covered by imperative checks"
```

---

## Phase 4 — Static Pipeline End to End

### Task 13: `AnchorAnalyzer` and full static wiring

**Files:**
- Modify: `crates/dike-lang-anchor/src/lib.rs`, `crates/dike-cli/src/commands/analyze.rs`, `crates/dike-cli/src/pipeline.rs`
- Create: `crates/dike-lang-anchor/tests/end_to_end.rs`

**Interfaces:**
- Consumes: everything in Phases 2–3.
- Produces: `pub struct AnchorAnalyzer;` implementing `dike_core::Analyzer`, plus
  `pub struct AnchorAnalysis { pub result: AnalysisResult, pub handlers: usize, pub suppressed: usize }`
  and `pub fn analyze_program(tree: &SourceTree) -> AnchorAnalysis` so the CLI can populate `Coverage` without a second parse.

`Analyzer::analyze` delegates to `analyze_program` and discards the extra counts.
`pipeline::run` keeps its `&dyn Analyzer` parameter — putting `AnchorAnalysis` in the
signature would drag Anchor types into `dike-core`'s consumer. Instead add one parameter,
`coverage_extra: (usize /*handlers*/, usize /*suppressed*/)`, which `commands/analyze.rs`
fills from `analyze_program`. `dike-cli` stays the only place the two worlds meet.

- [ ] **Step 1: Write the failing test**

`crates/dike-lang-anchor/tests/end_to_end.rs`:

```rust
use dike_core::analyzer::{Analyzer, SourceTree};
use std::path::Path;

fn fixture() -> SourceTree {
    SourceTree::load(Path::new("../../tests/fixtures/programs/vault")).unwrap()
}

#[test]
fn clean_fixture_produces_a_low_noise_floor() {
    let result = dike_lang_anchor::AnchorAnalyzer.analyze(&fixture());
    // The fixture is written correctly. Some Info/Medium noise is acceptable;
    // a Critical finding on clean code means a detector is wrong.
    assert!(
        !result.findings.iter().any(|f| f.severity == dike_core::Severity::Critical),
        "critical finding on the clean fixture: {:#?}",
        result.findings
    );
}

#[test]
fn injecting_a_missing_signer_produces_exactly_that_finding() {
    let mut tree = fixture();
    for f in &mut tree.files {
        f.text = f.text.replace("pub authority: Signer<'info>", "pub authority: AccountInfo<'info>");
    }
    let result = dike_lang_anchor::AnchorAnalyzer.analyze(&tree);
    assert!(result.findings.iter().any(|f| f.class.as_str() == "missing-signer"));
}

#[test]
fn analysis_is_byte_stable_across_runs() {
    let tree = fixture();
    let a = dike_lang_anchor::AnchorAnalyzer.analyze(&tree).findings;
    let b = dike_lang_anchor::AnchorAnalyzer.analyze(&tree).findings;
    assert_eq!(a, b);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p dike-lang-anchor --test end_to_end`
Expected: FAIL — `AnchorAnalyzer` not found.

- [ ] **Step 3: Implement**

```rust
pub struct AnchorAnalyzer;

pub struct AnchorAnalysis {
    pub result: dike_core::analyzer::AnalysisResult,
    pub handlers: usize,
    pub suppressed: usize,
}

pub fn analyze_program(tree: &dike_core::analyzer::SourceTree) -> AnchorAnalysis {
    let parsed = parser::parse_tree(tree);
    let detectors = detectors::all_detectors();
    let mut findings = Vec::new();
    let mut diagnostics = parsed.diagnostics;
    let mut suppressed_total = 0;

    for handler in &parsed.program.instructions {
        let Some(accounts) = parsed.program.accounts_for(handler) else {
            diagnostics.push(dike_core::analyzer::Diagnostic {
                file: Some(handler.file.clone()),
                kind: dike_core::analyzer::DiagnosticKind::Skipped,
                message: format!(
                    "handler `{}` references unknown context type `{}`",
                    handler.name, handler.context_ty
                ),
            });
            continue;
        };
        let raw: Vec<_> = detectors
            .iter()
            .flat_map(|d| d.run(&parsed.program, handler, accounts))
            .collect();
        let (kept, suppressed) = detectors::suppression::apply(raw, handler, accounts);
        suppressed_total += suppressed.len();
        findings.extend(kept);
    }

    dike_core::merge::rank(&mut findings);

    AnchorAnalysis {
        result: dike_core::analyzer::AnalysisResult {
            findings,
            diagnostics,
            files_analyzed: parsed.files_parsed,
        },
        handlers: parsed.program.instructions.len(),
        suppressed: suppressed_total,
    }
}

impl dike_core::analyzer::Analyzer for AnchorAnalyzer {
    fn name(&self) -> &'static str { "anchor-static" }
    fn analyze(&self, tree: &dike_core::analyzer::SourceTree) -> dike_core::analyzer::AnalysisResult {
        analyze_program(tree).result
    }
}
```

In `commands/analyze.rs`, delete `NullAnalyzer` and call
`dike_lang_anchor::analyze_program(&tree)`, passing `(handlers, suppressed)` into
`pipeline::run` for the coverage block.

- [ ] **Step 4: Run everything**

Run: `cargo test --workspace`
Expected: PASS.

Run: `cargo run -p dike-cli -- analyze tests/fixtures/programs/vault; echo "exit=$?"`
Expected: a Markdown report with a populated Track 1 section, an empty Track 2 section, a coverage block, and `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add crates/ && git commit -m "feat: wire the full static track into dike analyze"
```

---

## Phase 5 — Retrieval

> **Re-planned 2026-08-28**, replacing the original Tasks 14–17. The original
> Phases 5–6 were written before any code existed; this version is written against
> the real API surface of Tasks 1–13 and corrects seven concrete defects recorded
> in decisions D19–D31 below. Phase 7–8 tasks are renumbered **22–26 → 23–27**
> because this phase grew by one task; nothing in Phases 7–8 changes otherwise.

Deliverable: `dike corpus fetch && dike corpus index && dike corpus query "..."` returns fused, ranked precedent documents from a local index with no server running.

### Decisions added by the re-plan

| # | Decision | Why |
|---|---|---|
| D19 | Retrieval is consumed through a `Retrieve` **trait**, not the concrete `HybridRetriever`. | The original plan gave `LlmAnalyzer` a concrete `Retriever` field and then specified tests using "a stub retriever". That is impossible. Track 2's whole test story needs an injectable double. |
| D20 | Corpus fetching splits out of the corpus data model into its own task. | Manifest parsing, chunking and hashing are pure and unit-testable; fetching is network I/O that can only be `#[ignore]`d. Bundling them made the pure half unverifiable without a network. |
| D21 | A changed upstream source **warns**, it does not fail. Hard-fail moves behind `dike corpus fetch --verify`. | Three of the four backbone sources are live web pages that change weekly. "Fail loudly on sha256 mismatch" would make the second-ever fetch an error. |
| D22 | `Source` gains `kind = "page" \| "archive" \| "local"`. | Sealevel Attacks — the corpus **backbone** — is a GitHub repository. `GET https://github.com/coral-xyz/sealevel-attacks` returns a nav-chrome landing page, not the vulnerability samples. The original plan could not fetch its most important source. |
| D23 | `html_to_text` is specified concretely (script/style **contents** dropped, block tags → newline, five XML entities + `&nbsp;` + `&#39;` decoded, blank runs collapsed). | "A minimal tag-stripper" is a placeholder. A naive `<[^>]*>` strip inlines every line of JavaScript on the page into the corpus, and BM25 then happily retrieves it. |
| D24 | One `http::HttpClient` in `dike-core`, shared by corpus fetch, the embedder, and the LLM client. | Three separate `reqwest` setups meant three timeout policies and three error taxonomies for the same two failure modes. |
| D25 | Vector store is plain `rusqlite` with `BLOB` vectors and a linear cosine scan. **Documented deviation from spec §10's `sqlite-vec`.** | The spec's stated requirements are "one file, no server, reproducible from the fetch script" — all three hold. At v1 corpus size (hundreds of chunks) a linear scan is sub-millisecond, and the `VectorStore` interface hides the choice if that ever stops being true. |
| D26 | Model names are configuration with defaults, never constants. Vector-store metadata records `(model, dim)` and a mismatched search is a **refusal with a re-index message**, not a silent wrong answer. | The original asserted 384 dimensions for `bge-small-en-v1.5`. Swapping the embedding model then produces dimension-mismatched cosine scores that look like plausible numbers. This is also the single point where a Hermes/other-model swap happens. |
| D27 | `validate_citations` takes `file: &Path`. | Pre-flight scan row 14: `RawLlmFinding` carries `handler` and `line` but no file, so it cannot construct a complete `Location` alone. |
| D28 | `AnalysisResult` gains `units: Option<UnitCoverage>`; `Coverage` gains `units_total` / `units_examined`. | Without it a thin Track 2 section is indistinguishable from a broken one. "0 findings" and "0 findings because 11 of 12 handlers retrieved nothing groundable" are different reports. |
| D29 | The Track 2 prompt **never** receives Track 1 findings, and this is asserted by a test. | Otherwise corroboration is circular: Track 2 agrees because it was told the answer, `Track::Corroborated` inflates confidence on nothing, and the eval numbers become self-congratulatory. This is the operational form of the spec's hard rule. |
| D30 | The prompt does **not** tell the model to avoid classes Track 1 already covers. | The original plan's prompt did. That instruction would suppress exactly the overlap that `merge_key` collision detection exists to find — `Track::Corroborated` would become unreachable code and the merged track would be a concatenation. Overlap is the feature, not the waste. |
| D31 | Corpus test fixtures inside `crates/dike-core/src/**` must avoid the ten tokens banned by `tests/seam.rs`. | The original Task 16 test used the string `invoke_signed`, which is on the banned list, inside `dike-core/src/retrieval/bm25.rs`. That is a guaranteed seam-test failure — the same trap Task 4 already hit once. Use `try_borrow_mut_data` / `CpiContext` / `close_account` instead: still real snake/camel-case identifiers, none of them banned. |

### Derives required across Phases 5–6

Stated once so no task has to guess, and so the tests above compile:

- `Document`, `Source`, `SourceKind`, `RawLlmFinding` — `Debug, Clone, PartialEq, Serialize, Deserialize`
  (`Document` is cloned into every `RetrievalHit`; `Source` is deserialized from TOML;
  `RawLlmFinding` is deserialized from the model's JSON and cloned across retry).
- `RetrievalHit`, `UnitCoverage` — `Debug, Clone`.
- `HttpError`, `StoreError`, `LlmError`, `SchemaViolation` — `Debug` plus
  `impl std::error::Error` via `thiserror` (already a workspace dependency). Every test
  above uses `unwrap_err()` or `{err:?}`, both of which need `Debug`.
- `LlmRequest` — `Debug, Clone` (the retry path clones and mutates `user`).

`Finding`, `Location`, `Citation`, `Severity`, `Track`, `DiagnosticKind` already derive
what these tasks need; do not add to them.

---

---

### Task 14: Corpus document model, manifest, chunking, and hashing

**Files:**
- Create: `crates/dike-core/src/retrieval/mod.rs`, `crates/dike-core/src/retrieval/document.rs`, `corpus/sources.toml`
- Modify: `crates/dike-core/src/lib.rs`, `crates/dike-core/Cargo.toml`, root `Cargo.toml`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```rust
  pub enum SourceKind { Page, Archive, Local }
  pub struct Source {
      pub id: String, pub url: String, pub title: String, pub license: String,
      pub retrieved: String, pub sha256: String, pub class_tags: Vec<String>,
      pub kind: SourceKind,
  }
  pub struct Document {
      pub id: String, pub source_url: String, pub title: String,
      pub text: String, pub class_tags: Vec<String>,
  }
  pub fn load_manifest(path: &Path) -> anyhow::Result<Vec<Source>>;
  pub fn corpus_hash(docs: &[Document]) -> String;
  pub fn chunk_by_finding(source: &Source, raw_text: &str) -> Vec<Document>;
  ```

**Licensing — non-negotiable (spec §7).** The repo commits `corpus/sources.toml`
and the fetch code; it **never** commits fetched PDFs or report text. `corpus/cache/`
is gitignored (Task 1 added it — verify with `grep corpus .gitignore`). Derived notes
we write ourselves go in `corpus/notes/` and are committable.

**Seam constraint (D31).** Every string literal you write in this file — including
test fixtures — is scanned by `crates/dike-core/tests/seam.rs`. Banned:
`anchor`, `solana`, `Signer<`, `AccountInfo`, `UncheckedAccount`, `has_one`,
`invoke_signed`, `pubkey`, `Pubkey`, `spl_`. Class-name strings like
`"missing-signer"` are fine (`Signer<` with the angle bracket is what is banned).

`corpus/sources.toml`:

```toml
[[source]]
id = "sealevel-attacks"
kind = "archive"
url = "https://codeload.github.com/coral-xyz/sealevel-attacks/tar.gz/refs/heads/master"
title = "Sealevel Attacks — canonical Solana vulnerability classes"
license = "Apache-2.0 (code samples); cite, do not redistribute verbatim"
retrieved = "2026-08-28"
sha256 = ""
class_tags = ["missing-signer", "missing-owner-check", "missing-authority-binding", "pda-validation-gap"]

[[source]]
id = "neodyme-pitfalls"
kind = "page"
url = "https://neodyme.io/en/blog/solana_common_pitfalls/"
title = "Neodyme — Solana common pitfalls"
license = "All rights reserved; fetched for local indexing only, not redistributed"
retrieved = "2026-08-28"
sha256 = ""
class_tags = ["missing-signer", "unchecked-arithmetic", "missing-owner-check"]

[[source]]
id = "anchor-constraints"
kind = "page"
url = "https://www.anchor-lang.com/docs/references/account-constraints"
title = "Anchor account constraint reference"
license = "Apache-2.0"
retrieved = "2026-08-28"
sha256 = ""
class_tags = ["pda-validation-gap", "missing-authority-binding"]

[[source]]
id = "notes-local"
kind = "local"
url = "corpus/notes"
title = "Derived notes (original work)"
license = "Ours"
retrieved = "2026-08-28"
sha256 = ""
class_tags = []
```

Add at least three published audit reports (OtterSec / Zellic / sec3) as `kind = "page"`
entries pointing at their HTML report pages, not their PDFs.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> Source {
        Source {
            id: "os-report".into(), url: "https://example.invalid/r".into(),
            title: "T".into(), license: "l".into(), retrieved: "2026-08-28".into(),
            sha256: "h".into(), class_tags: vec!["missing-signer".into()],
            kind: SourceKind::Page,
        }
    }

    fn doc(id: &str, text: &str) -> Document {
        Document { id: id.into(), source_url: "u".into(), title: "t".into(),
                   text: text.into(), class_tags: vec![] }
    }

    #[test]
    fn manifest_round_trips_including_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sources.toml");
        std::fs::write(&path, r#"
[[source]]
id = "a"
kind = "archive"
url = "https://example.invalid/x.tar.gz"
title = "T"
license = "Apache-2.0"
retrieved = "2026-08-28"
sha256 = "deadbeef"
class_tags = ["missing-signer"]
"#).unwrap();
        let sources = load_manifest(&path).unwrap();
        assert_eq!(sources.len(), 1);
        assert!(matches!(sources[0].kind, SourceKind::Archive));
        assert_eq!(sources[0].class_tags, vec!["missing-signer".to_string()]);
    }

    #[test]
    fn manifest_defaults_kind_to_page_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sources.toml");
        std::fs::write(&path, r#"
[[source]]
id = "a"
url = "https://example.invalid/x"
title = "T"
license = "l"
retrieved = "2026-08-28"
sha256 = ""
class_tags = []
"#).unwrap();
        assert!(matches!(load_manifest(&path).unwrap()[0].kind, SourceKind::Page));
    }

    #[test]
    fn corpus_hash_is_order_independent() {
        let (a, b) = (doc("a", "x"), doc("b", "y"));
        assert_eq!(corpus_hash(&[a.clone(), b.clone()]), corpus_hash(&[b, a]));
    }

    #[test]
    fn corpus_hash_changes_when_content_changes() {
        let a = doc("a", "x");
        let mut b = a.clone();
        b.text = "z".into();
        assert_ne!(corpus_hash(&[a]), corpus_hash(&[b]));
    }

    #[test]
    fn corpus_hash_changes_when_a_document_is_added() {
        let a = doc("a", "x");
        assert_ne!(corpus_hash(&[a.clone()]), corpus_hash(&[a, doc("b", "y")]));
    }

    #[test]
    fn splits_on_finding_headings_not_token_counts() {
        let text = "\
# OS-VLT-ADV-00 Missing signer check
The withdraw instruction does not verify that the caller authorized the transaction,
so any account may drain the vault. Severity: Critical. Recommendation: require the
account type that enforces a transaction signature on the authority field.

# OS-VLT-ADV-01 Unchecked arithmetic
The deposit instruction adds to the stored balance without an overflow check, which
wraps silently in release builds. Recommendation: use the checked_add helper instead
of the bare addition operator so the overflow surfaces as an error.
";
        let chunks = chunk_by_finding(&src(), text);
        assert_eq!(chunks.len(), 2, "one chunk per finding heading");
        assert!(chunks[0].title.contains("OS-VLT-ADV-00"));
        assert!(chunks[0].text.contains("drain the vault"), "the body travels with its heading");
        assert!(!chunks[0].text.contains("OS-VLT-ADV-01"), "chunks do not bleed into each other");
        assert_eq!(chunks[0].id, "os-report#0");
        assert_eq!(chunks[1].id, "os-report#1");
        assert!(chunks[0].class_tags.contains(&"missing-signer".to_string()),
                "source tags are inherited");
    }

    #[test]
    fn extends_class_tags_from_chunk_text() {
        let text = format!("# F\n{}\nThis finding is an unchecked-arithmetic issue in the \
                            deposit path and the recommendation is to use checked math.",
                           "x".repeat(200));
        let chunks = chunk_by_finding(&src(), &text);
        assert!(chunks[0].class_tags.contains(&"unchecked-arithmetic".to_string()));
        assert!(chunks[0].class_tags.contains(&"missing-signer".to_string()),
                "inherited tags survive extension");
    }

    #[test]
    fn merges_fragments_shorter_than_200_chars() {
        assert_eq!(chunk_by_finding(&src(), "# A\nshort\n\n# B\nalso short\n").len(), 1);
    }

    #[test]
    fn splits_on_bracketed_finding_ids_without_a_heading() {
        let body = "x".repeat(250);
        let text = format!("[OS-VLT-00] First\n{body}\n[OS-VLT-01] Second\n{body}\n");
        assert_eq!(chunk_by_finding(&src(), &text).len(), 2);
    }

    #[test]
    fn text_with_no_boundaries_yields_exactly_one_chunk() {
        let chunks = chunk_by_finding(&src(), &"a ".repeat(300));
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].id, "os-report#0");
    }

    #[test]
    fn empty_text_yields_no_chunks_and_does_not_panic() {
        assert!(chunk_by_finding(&src(), "").is_empty());
        assert!(chunk_by_finding(&src(), "   \n\n  ").is_empty());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dike-core retrieval`
Expected: FAIL — `load_manifest` not found.

- [ ] **Step 3: Implement**

Add to `[workspace.dependencies]`: `toml = "0.8"`. In `crates/dike-core/Cargo.toml`
add `toml.workspace = true` and make sure `blake3`, `serde`, `tempfile` (dev) are there.

`SourceKind` derives `Deserialize` with `#[serde(rename_all = "lowercase")]` and the
field on `Source` carries `#[serde(default)]` with `impl Default for SourceKind`
returning `Page`.

`load_manifest` reads the file, deserializes `struct Manifest { source: Vec<Source> }`,
and returns `manifest.source`. Surface the path in the error context so a typo in a
manifest is diagnosable: `.with_context(|| format!("reading corpus manifest {}", path.display()))`.

`corpus_hash` (D17): blake3 over the **sorted** concatenation of
`format!("{}:{}\n", doc.id, blake3::hash(doc.text.as_bytes()).to_hex())`. Sorting is
what makes it order-independent, which matters because fetch order depends on network
timing and the hash goes into every report.

`chunk_by_finding` — boundaries, in priority order:
1. A line matching `^#{1,4} ` (Markdown heading).
2. A line matching `^\[?[A-Z]{2,5}-[A-Z0-9-]*\d+\]?\b` (finding IDs like `OS-VLT-ADV-00`).

Write these as hand-rolled character predicates, not a regex — this codebase has no
regex dependency and these two patterns do not warrant adding one. A helper
`fn is_boundary(line: &str) -> bool` with the two checks is about 20 lines.

Accumulate lines into the current chunk until the next boundary. On close:
- `title` = the boundary line with leading `#`/whitespace trimmed; if the chunk had no
  boundary line, `title` = `source.title`.
- `text` = the whole chunk **including** its boundary line.
- **Merging (amended 2026-08-28 after Task 14 review — do not implement the older
  "merge into its predecessor" phrasing).** Fragments accumulate into a *pending*
  chunk. While the pending chunk's current combined length is under 200 characters,
  the next fragment is appended to it. Once the pending chunk reaches or exceeds 200
  characters it is closed out and emitted, and the following fragment starts a new
  pending chunk. A final pending chunk still under 200 with no successor is emitted
  as-is — there is nothing left to merge it with, and dropping it would lose content.

  This is deliberately **not** "merge each short fragment into its predecessor."
  Read literally, that phrasing lets an unbounded run of short findings collapse into
  a single ever-growing chunk across an entire document: chunk 1 absorbs chunk 2, the
  merged result is still "the predecessor" so it absorbs chunk 3, and nothing ever
  closes it. Terse audit findings — a common real format — are exactly the shape that
  triggers it, and one document-sized soup chunk is a worse failure than the
  sub-200 noise chunk the floor exists to prevent: it averages its embedding across
  many unrelated findings, polluting top-k rather than merely being less sharp, and
  it is close to useless to an auditor who follows a citation expecting to verify one
  specific claim. Accumulating against the pending chunk's own length bounds that
  growth while still guaranteeing a short *leading* fragment attaches to the next one
  rather than shipping standalone.
- `id` = `format!("{}#{}", source.id, emitted_index)` — index over **emitted** chunks,
  so ids stay dense after merging.
- `class_tags` = `source.class_tags`, plus any of the five class constants
  (`missing-signer`, `missing-owner-check`, `missing-authority-binding`,
  `pda-validation-gap`, `unchecked-arithmetic`) whose literal string appears in the
  lowercased chunk text. Deduplicate, then sort — determinism.

Whitespace-only input yields an empty `Vec`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p dike-core` — PASS, including `core_contains_no_solana_identifiers`.
Run: `cargo clippy --workspace --all-targets -- -D warnings` — clean.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml corpus/sources.toml crates/
git commit -m "feat: corpus document model, manifest, chunking and hashing"
```

---

### Task 15: HTTP layer, source fetching, and `dike corpus fetch`

**Files:**
- Create: `crates/dike-core/src/http.rs`, `crates/dike-core/src/retrieval/fetch.rs`, `crates/dike-cli/src/commands/corpus.rs`
- Modify: `crates/dike-core/src/lib.rs`, `crates/dike-core/src/retrieval/mod.rs`, `crates/dike-cli/src/commands/mod.rs`, `crates/dike-cli/src/main.rs`, both `Cargo.toml`s, root `Cargo.toml`

**Interfaces:**
- Consumes: `Source`, `SourceKind`, `Document`, `chunk_by_finding`.
- Produces:
  ```rust
  // http.rs
  pub enum HttpError { Unavailable(String), Timeout, Status(u16), Transport(String) }
  pub struct HttpClient { /* wraps reqwest::blocking::Client */ }
  impl HttpClient {
      pub fn new(timeout: Duration) -> Result<Self, HttpError>;
      pub fn get_bytes(&self, url: &str) -> Result<Vec<u8>, HttpError>;
      pub fn post_json(&self, url: &str, body: &serde_json::Value)
          -> Result<serde_json::Value, HttpError>;
  }
  // retrieval/fetch.rs
  pub fn html_to_text(html: &str) -> String;
  pub fn extract_archive(gz: &[u8], keep_ext: &[&str]) -> anyhow::Result<Vec<(String, String)>>;
  pub enum FetchOutcome { Fetched { hash: String }, Unchanged, Changed { old: String, new: String } }
  pub fn fetch_source(http: &HttpClient, s: &Source, cache_dir: &Path)
      -> anyhow::Result<FetchOutcome>;
  pub fn load_cached(sources: &[Source], cache_dir: &Path) -> anyhow::Result<Vec<Document>>;
  ```

`HttpClient` is the **single** HTTP surface in this codebase (D24). The embedder
(Task 17) and the LLM client (Task 19) both use it, so timeout policy and the
connection-refused-to-`Unavailable` mapping are written once. Map, in this order:
`err.is_timeout()` → `Timeout`; `err.is_connect()` → `Unavailable`; a non-2xx response →
`Status(code)`; anything else → `Transport`. `Unavailable` is what the pipeline later
turns into a degraded run rather than a failure, so getting this mapping right is
load-bearing, not cosmetic.

**Change policy (D21).** `fetch_source` computes the sha256 of the normalized text.
If `s.sha256` is empty it returns `Fetched`. If it matches, `Unchanged`. If it differs
it returns `Changed { old, new }` and **still writes the new content**. The CLI prints
a warning per changed source and exits 0. `dike corpus fetch --verify` makes any
`Changed` an error instead — that is the CI/reproducibility mode. `--update-hashes`
rewrites `sources.toml` in place with the new hashes and the current date.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_to_text_drops_script_and_style_contents() {
        let html = "<html><head><style>body{color:red}</style>\
                    <script>var x = 1; alert('hi');</script></head>\
                    <body><p>Real content here.</p></body></html>";
        let text = html_to_text(html);
        assert!(text.contains("Real content here."));
        assert!(!text.contains("color:red"), "style body must not enter the corpus");
        assert!(!text.contains("alert"), "script body must not enter the corpus");
    }

    #[test]
    fn html_to_text_separates_block_elements_with_newlines() {
        let text = html_to_text("<p>One</p><p>Two</p><li>Three</li>");
        assert!(text.contains("One\nTwo"), "got: {text:?}");
        assert!(text.contains("Three"));
    }

    #[test]
    fn html_to_text_keeps_inline_runs_on_one_line() {
        let text = html_to_text("<p>a <code>close_account</code> call</p>");
        assert!(text.contains("a close_account call"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_decodes_the_entities_that_matter() {
        let text = html_to_text("<p>a &amp; b &lt;T&gt; &quot;q&quot; &#39;s&#39; x&nbsp;y</p>");
        assert!(text.contains("a & b <T> \"q\" 's' x y"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_collapses_blank_line_runs() {
        let text = html_to_text("<p>a</p><div></div><div></div><p>b</p>");
        assert!(!text.contains("\n\n\n"), "got: {text:?}");
    }

    #[test]
    fn extract_archive_keeps_only_requested_extensions() {
        let gz = build_test_tar_gz(&[
            ("repo/a.rs", "fn main() {}"),
            ("repo/b.md", "# notes"),
            ("repo/c.png", "\u{0}binary"),
        ]);
        let out = extract_archive(&gz, &["rs", "md"]).unwrap();
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"repo/a.rs"));
        assert!(names.contains(&"repo/b.md"));
        assert!(!names.iter().any(|n| n.ends_with(".png")));
    }

    #[test]
    fn extract_archive_is_deterministically_ordered() {
        let gz = build_test_tar_gz(&[("repo/z.rs", "z"), ("repo/a.rs", "a")]);
        let out = extract_archive(&gz, &["rs"]).unwrap();
        assert_eq!(out[0].0, "repo/a.rs", "entries sort by path");
    }

    #[test]
    fn extract_archive_skips_non_utf8_without_failing_the_whole_archive() {
        let gz = build_test_tar_gz_raw(&[
            ("repo/good.rs", b"fn main() {}".to_vec()),
            ("repo/bad.rs", vec![0xff, 0xfe, 0xff]),
        ]);
        let out = extract_archive(&gz, &["rs"]).unwrap();
        assert_eq!(out.len(), 1, "partial results beat no results");
        assert_eq!(out[0].0, "repo/good.rs");
    }

    #[test]
    fn extract_archive_rejects_path_traversal_entries() {
        let gz = build_test_tar_gz(&[("../../etc/evil.rs", "pwn"), ("repo/ok.rs", "ok")]);
        let out = extract_archive(&gz, &["rs"]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "repo/ok.rs");
    }

    #[test]
    fn a_dead_endpoint_is_unavailable_not_a_panic() {
        let c = HttpClient::new(std::time::Duration::from_millis(500)).unwrap();
        let err = c.get_bytes("http://127.0.0.1:1/x").unwrap_err();
        // Amended 2026-08-28 (Task 15 review): assert `Unavailable` EXACTLY. The
        // original fixture here hedged with `| Transport(_)`, which would pass even
        // if the mapping regressed — one paragraph after this plan calls that exact
        // distinction load-bearing. A connection refusal misclassified as Transport
        // turns "Ollama is not running" into a hard failure of the whole analysis
        // instead of a degraded run (Task 22 branches on `Unavailable` specifically).
        assert!(matches!(err, HttpError::Unavailable(_)), "got: {err:?}");
    }

    #[test]
    fn load_cached_returns_no_documents_when_the_cache_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_cached(&[page_source("a")], dir.path()).unwrap().is_empty());
    }

    #[test]
    fn load_cached_chunks_each_cached_file() {
        let dir = tempfile::tempdir().unwrap();
        let body = "x".repeat(250);
        std::fs::write(dir.path().join("a.txt"),
                       format!("# F1 finding one\n{body}\n# F2 finding two\n{body}\n")).unwrap();
        let docs = load_cached(&[page_source("a")], dir.path()).unwrap();
        assert_eq!(docs.len(), 2);
        assert!(docs.iter().all(|d| d.id.starts_with("a#")));
    }

    // `#[ignore]` — needs the network. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn fetches_a_live_page_into_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let http = HttpClient::new(std::time::Duration::from_secs(30)).unwrap();
        let s = Source { url: "https://www.anchor-lang.com/docs/references/account-constraints".into(),
                         ..page_source("anchor-constraints") };
        let outcome = fetch_source(&http, &s, dir.path()).unwrap();
        assert!(matches!(outcome, FetchOutcome::Fetched { .. }));
        let text = std::fs::read_to_string(dir.path().join("anchor-constraints.txt")).unwrap();
        assert!(text.len() > 1000, "a docs page should yield real text");
        assert!(!text.contains("<div"), "tags must not survive normalization");
    }
}
```

Write `build_test_tar_gz` and `build_test_tar_gz_raw` as small test helpers using
`tar::Builder` over `flate2::write::GzEncoder`; `page_source(id)` returns a `Source`
with `kind: SourceKind::Page` and an `example.invalid` URL.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p dike-core fetch` → FAIL — `html_to_text` not found.

- [ ] **Step 3: Implement**

Add to `[workspace.dependencies]`:
```toml
reqwest = { version = "0.12", default-features = false, features = ["blocking", "json", "rustls-tls"] }
flate2 = "1"
tar = "0.4"
sha2 = "0.10"
```
`default-features = false` matters: it drops the `native-tls` / OpenSSL system
dependency, which is the usual cause of a "works on my machine" build break.

`HttpClient::new` builds a `reqwest::blocking::Client` with the timeout and
`user_agent("dike/0.1 (+security triage; contact via repository)")` — several docs
hosts reject requests with no UA.

`html_to_text` (D23), a single pass over the char stream:
1. On `<script` or `<style` (case-insensitive), skip to the matching `</script>` /
   `</style>` and emit nothing.
2. On any other `<`, first decide whether it actually STARTS A TAG. It does only
   if the next character is ASCII-alphabetic, `/`, or `!`. Otherwise it is literal
   text (`a < b`) — push it and continue. **Amended 2026-08-28 after the Task 15
   review**, which found the unguarded version silently swallowed `b and c` from
   `a < b and c > d`.
3. Having decided it is a tag, consume to the closing `>` **while tracking quote
   state**: a `>` inside a single- or double-quoted attribute value does not end the
   tag. The same review found the unguarded version turned
   `<a title="x>y">link text</a>` into the fragment `y">link text`, leaking markup
   into the corpus where it would be indexed, embedded and cited.
4. If the tag name is block-level
   (`p div br li tr h1 h2 h3 h4 h5 h6 section article header footer pre blockquote table ul ol`),
   push `\n`; otherwise push nothing (inline runs stay on one line).
3. Otherwise push the char.
Then decode `&amp; &lt; &gt; &quot; &#39; &nbsp;` (in that order — `&amp;` last would
double-decode `&amp;lt;`; do `&amp;` **last**, not first, for exactly that reason).
Finally, trim trailing spaces per line and collapse runs of 3+ newlines to 2.

`extract_archive`: `GzDecoder` → `tar::Archive` → for each entry, take
`entry.path()?.to_string_lossy().into_owned()`; **skip** any path containing a `..`
component or starting with `/` (a tarball is untrusted input); skip entries whose
extension is not in `keep_ext`; read to a `Vec<u8>` and skip on `String::from_utf8`
error rather than aborting (partial results beat no results — spec §9). Sort the
result by path before returning: determinism.

`fetch_source`:
- `Page`: `get_bytes` → `String::from_utf8_lossy` → `html_to_text`.
- `Archive`: `get_bytes` → `extract_archive(&bytes, &["rs", "md"])` → join the entries
  as `format!("# {path}\n{content}\n\n")` so `chunk_by_finding` sees each file as its
  own unit.
- `Local`: read every `.md` under `s.url` (a repo-relative directory), same join.
Write the normalized text to `cache_dir/<s.id>.txt`, compute sha256, and return the
`FetchOutcome` per the change policy above.

`load_cached` reads `cache_dir/<s.id>.txt` for each source (missing file → skip, no
error) and returns `chunk_by_finding(s, &text)` flattened.

`dike corpus fetch [--update-hashes] [--verify]` in `commands/corpus.rs`: load the
manifest, fetch each source, print one line per source
(`fetched | unchanged | CHANGED`), and a summary. Register the `Corpus` subcommand in
`main.rs` with `fetch` as its only variant for now — `index`, `query` and `hash` are
added in Task 18.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p dike-core` → PASS.
Run: `cargo clippy --workspace --all-targets -- -D warnings` → clean.
Run (network, optional): `cargo test -p dike-core -- --ignored` → PASS.
Run: `cargo run -p dike-cli -- corpus fetch --update-hashes`
Expected: files under `corpus/cache/`, hashes filled in `sources.toml`, exit 0.
Run: `git status --short corpus/cache` → **no output** (gitignored).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml corpus/sources.toml crates/
git commit -m "feat: shared HTTP layer, corpus fetching and normalization"
```

---

### Task 16: BM25 index over the corpus

**Files:**
- Create: `crates/dike-core/src/retrieval/bm25.rs`
- Modify: `crates/dike-core/src/retrieval/mod.rs`, `crates/dike-core/Cargo.toml`, root `Cargo.toml`

**Interfaces:**
- Consumes: `Document`.
- Produces:
  ```rust
  pub struct Bm25Index { /* .. */ }
  impl Bm25Index {
      pub fn build(docs: &[Document], dir: &Path) -> anyhow::Result<Bm25Index>;
      pub fn open(dir: &Path) -> anyhow::Result<Bm25Index>;
      pub fn search(&self, query: &str, k: usize) -> anyhow::Result<Vec<(String, f32)>>;
  }
  ```

Sparse retrieval earns its place by catching exact identifiers — `try_borrow_mut_data`,
`CpiContext`, `close =` — that embeddings blur. Configure the tokenizer so identifiers
survive: `SimpleTokenizer` + `LowerCaser`, **no stemmer**. A stemmer turns
`try_borrow_mut_data` into something that no longer matches itself. Index `id` as
`STRING | STORED` (not tokenized) so hits map back to documents, and `text` + `title`
as `TEXT` with the custom tokenizer.

**Seam constraint (D31).** Do not use `invoke_signed`, `UncheckedAccount`, `Pubkey`,
`has_one`, `anchor`, or `solana` in any literal in this file — `tests/seam.rs` bans
them and this file lives in `dike-core/src`. The tests below already respect this.

**Spec §12 open item** — whether tantivy is warranted at v1 corpus size. Resolution:
build tantivy now (it is correct by construction) behind the interface above. If the
corpus stays under ~500 documents, a hand-rolled BM25 over an in-memory inverted index
is ~80 lines and drops a heavy dependency; the interface makes that a one-file swap.
Do not make that call now — make it with a real corpus and a real compile time.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn doc(id: &str, text: &str) -> Document {
        Document { id: id.into(), source_url: "u".into(), title: "t".into(),
                   text: text.into(), class_tags: vec![] }
    }

    #[test]
    fn exact_identifier_matches_rank_first() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![
            doc("d1", "The instruction calls try_borrow_mut_data on an account it does not own."),
            doc("d2", "General discussion of privilege escalation in program design."),
        ];
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        let hits = idx.search("try_borrow_mut_data", 5).unwrap();
        assert_eq!(hits[0].0, "d1");
    }

    #[test]
    fn an_underscored_identifier_is_not_stemmed_away() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Bm25Index::build(&[doc("d1", "call close_account here")], dir.path()).unwrap();
        assert_eq!(idx.search("close_account", 5).unwrap().len(), 1,
                   "a stemmer would break this");
    }

    #[test]
    fn search_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Bm25Index::build(&[doc("d1", "uses CpiContext to sign")], dir.path()).unwrap();
        assert_eq!(idx.search("cpicontext", 5).unwrap().len(), 1);
    }

    #[test]
    fn returns_at_most_k_hits() {
        let dir = tempfile::tempdir().unwrap();
        let docs: Vec<_> = (0..10).map(|i| doc(&format!("d{i}"), "missing signature check")).collect();
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        assert_eq!(idx.search("signature", 3).unwrap().len(), 3);
    }

    #[test]
    fn a_query_matching_nothing_returns_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Bm25Index::build(&[doc("d1", "alpha beta")], dir.path()).unwrap();
        assert!(idx.search("zzzznomatch", 5).unwrap().is_empty());
    }

    #[test]
    fn an_index_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        Bm25Index::build(&[doc("d1", "missing owner validation")], dir.path()).unwrap();
        let reopened = Bm25Index::open(dir.path()).unwrap();
        assert_eq!(reopened.search("owner", 5).unwrap().len(), 1);
    }

    #[test]
    fn rebuilding_over_an_existing_directory_does_not_duplicate_documents() {
        let dir = tempfile::tempdir().unwrap();
        Bm25Index::build(&[doc("d1", "missing owner validation")], dir.path()).unwrap();
        let idx = Bm25Index::build(&[doc("d1", "missing owner validation")], dir.path()).unwrap();
        assert_eq!(idx.search("owner", 5).unwrap().len(), 1, "build must replace, not append");
    }

    #[test]
    fn scores_are_positive_and_descending() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "owner owner owner check"), doc("d2", "owner check")];
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        let hits = idx.search("owner", 5).unwrap();
        assert!(hits[0].1 > 0.0);
        assert!(hits[0].1 >= hits[1].1);
    }
}
```

`rebuilding_over_an_existing_directory_does_not_duplicate_documents` is the one that
matters operationally: `dike corpus index` will be run repeatedly against the same
directory, and a tantivy index that appends silently doubles every score contribution.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-core bm25` → FAIL.
- [ ] **Step 3: Add `tantivy = "0.22"` to `[workspace.dependencies]` and implement.**
  `build` must `delete_all_documents()` (or recreate the directory) before writing,
  then `commit()`. `search` uses `QueryParser::for_index(&index, vec![text_field, title_field])`
  and returns `(stored id, BM25 score)` pairs in descending score order.
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-core` → PASS; clippy clean.
- [ ] **Step 5: Commit** — `git commit -am "feat: BM25 corpus index via tantivy"`

---

### Task 17: Embeddings and the vector store

**Files:**
- Create: `crates/dike-core/src/retrieval/dense.rs`, `crates/dike-core/src/retrieval/store.rs`
- Modify: `crates/dike-core/src/retrieval/mod.rs`, `crates/dike-core/Cargo.toml`, root `Cargo.toml`

**Interfaces:**
- Consumes: `HttpClient`, `HttpError`.
- Produces:
  ```rust
  pub trait Embedder {
      fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, HttpError>;
      fn model_name(&self) -> String;
  }
  pub struct OllamaEmbedder { pub host: String, pub model: String, /* http */ }
  impl OllamaEmbedder { pub fn new(host: impl Into<String>, model: impl Into<String>) -> Result<Self, HttpError>; }

  pub enum StoreError { Sql(String), ModelMismatch { built_with: String, built_dim: usize, got: String, got_dim: usize } }
  pub struct VectorStore { /* .. */ }
  impl VectorStore {
      pub fn open(path: &Path) -> Result<VectorStore, StoreError>;
      pub fn init(&self, model: &str, dim: usize) -> Result<(), StoreError>;
      pub fn meta(&self) -> Result<Option<(String, usize)>, StoreError>;
      pub fn upsert(&self, rows: &[(String, Vec<f32>)]) -> Result<(), StoreError>;
      pub fn search(&self, q: &[f32], k: usize) -> Result<Vec<(String, f32)>, StoreError>;
      pub fn len(&self) -> Result<usize, StoreError>;
  }
  ```

**Storage (D25) — documented deviation from spec §10.** The spec names `sqlite-vec`.
We use plain `rusqlite` with vectors as `BLOB` (little-endian `f32`) and compute cosine
in Rust over all rows. Every requirement the spec actually states is preserved: one
file, no server, index reproducible from the fetch script. At v1 corpus size (hundreds
of chunks) a linear scan is sub-millisecond. The `VectorStore` interface hides the
choice, so adopting the extension later is a one-file change. Record this deviation in
the ledger; do not silently drop it.

**Dimension safety (D26).** The store's `meta` table holds `(model, dim)`. `search`
returns `ModelMismatch` when the query's dimension or the configured model name
disagrees with what the index was built with. This is the difference between "re-index
your corpus" and cosine scores computed across mismatched dimensions, which are
numbers that look fine and mean nothing.

**Model configuration.** `OllamaEmbedder::new` takes host and model as parameters —
no constants. Defaults live in the CLI: host `http://localhost:11434`, model
`bge-small-en-v1.5`. This is the swap point for any other embedding model.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trips_and_ranks_by_cosine() {
        let dir = tempfile::tempdir().unwrap();
        let store = VectorStore::open(&dir.path().join("v.db")).unwrap();
        store.init("m", 2).unwrap();
        store.upsert(&[("a".into(), vec![1.0, 0.0]), ("b".into(), vec![0.0, 1.0])]).unwrap();
        let hits = store.search(&[0.9, 0.1], 2).unwrap();
        assert_eq!(hits[0].0, "a");
        assert!(hits[0].1 > hits[1].1);
    }

    #[test]
    fn cosine_ignores_magnitude() {
        let dir = tempfile::tempdir().unwrap();
        let store = VectorStore::open(&dir.path().join("v.db")).unwrap();
        store.init("m", 2).unwrap();
        store.upsert(&[("a".into(), vec![1.0, 0.0]), ("big".into(), vec![100.0, 0.0])]).unwrap();
        let hits = store.search(&[1.0, 0.0], 2).unwrap();
        assert!((hits[0].1 - hits[1].1).abs() < 1e-5, "parallel vectors score equally");
    }

    #[test]
    fn upsert_replaces_rather_than_duplicating() {
        let dir = tempfile::tempdir().unwrap();
        let store = VectorStore::open(&dir.path().join("v.db")).unwrap();
        store.init("m", 2).unwrap();
        store.upsert(&[("a".into(), vec![1.0, 0.0])]).unwrap();
        store.upsert(&[("a".into(), vec![0.0, 1.0])]).unwrap();
        assert_eq!(store.len().unwrap(), 1);
        let hits = store.search(&[0.0, 1.0], 5).unwrap();
        assert!(hits[0].1 > 0.99, "the second vector won");
    }

    #[test]
    fn a_dimension_mismatch_is_a_refusal_not_a_wrong_answer() {
        let dir = tempfile::tempdir().unwrap();
        let store = VectorStore::open(&dir.path().join("v.db")).unwrap();
        store.init("bge-small-en-v1.5", 384).unwrap();
        let err = store.search(&[1.0, 0.0], 5).unwrap_err();
        assert!(matches!(err, StoreError::ModelMismatch { built_dim: 384, got_dim: 2, .. }),
                "got: {err:?}");
    }

    #[test]
    fn meta_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        VectorStore::open(&path).unwrap().init("m1", 7).unwrap();
        let reopened = VectorStore::open(&path).unwrap();
        assert_eq!(reopened.meta().unwrap(), Some(("m1".to_string(), 7)));
    }

    #[test]
    fn re_initing_with_a_different_model_clears_the_vectors() {
        let dir = tempfile::tempdir().unwrap();
        let store = VectorStore::open(&dir.path().join("v.db")).unwrap();
        store.init("m1", 2).unwrap();
        store.upsert(&[("a".into(), vec![1.0, 0.0])]).unwrap();
        store.init("m2", 2).unwrap();
        assert_eq!(store.len().unwrap(), 0, "vectors from another model are meaningless");
    }

    #[test]
    fn searching_an_empty_store_returns_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = VectorStore::open(&dir.path().join("v.db")).unwrap();
        store.init("m", 2).unwrap();
        assert!(store.search(&[1.0, 0.0], 5).unwrap().is_empty());
    }

    #[test]
    fn a_zero_vector_does_not_produce_nan_scores() {
        let dir = tempfile::tempdir().unwrap();
        let store = VectorStore::open(&dir.path().join("v.db")).unwrap();
        store.init("m", 2).unwrap();
        store.upsert(&[("z".into(), vec![0.0, 0.0])]).unwrap();
        let hits = store.search(&[1.0, 0.0], 5).unwrap();
        assert!(hits.iter().all(|h| h.1.is_finite()), "division by a zero norm");
    }

    #[test]
    fn a_dead_ollama_is_unavailable_not_a_panic() {
        let e = OllamaEmbedder::new("http://127.0.0.1:1", "nope").unwrap();
        let err = e.embed(&["hello".to_string()]).unwrap_err();
        assert!(matches!(err, HttpError::Unavailable(_) | HttpError::Transport(_) | HttpError::Timeout));
    }

    #[test]
    #[ignore = "needs a running Ollama with the embedding model pulled"]
    fn live_embedder_returns_a_consistent_dimension() {
        let e = OllamaEmbedder::new("http://localhost:11434", "bge-small-en-v1.5").unwrap();
        let v = e.embed(&["a signer check is missing".into(), "unchecked arithmetic".into()]).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].len(), v[1].len(), "all rows share one dimension");
        assert!(v[0].len() >= 128, "a real embedding, not an error body");
    }
}
```

Note what the live test asserts and does not: **consistency**, not `384`. Hard-coding
the dimension bakes one model choice into a test that has no business knowing it (D26).

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-core dense` → FAIL.
- [ ] **Step 3: Add `rusqlite = { version = "0.32", features = ["bundled"] }` and implement.**
  `bundled` compiles SQLite from source — no system library, no version skew.
  Schema:
  ```sql
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS vectors (doc_id TEXT PRIMARY KEY, vec BLOB NOT NULL);
  ```
  `init(model, dim)` writes both meta keys and, if either differs from what is stored,
  `DELETE FROM vectors` first. `upsert` uses `INSERT INTO vectors (doc_id, vec) VALUES
  (?1, ?2) ON CONFLICT(doc_id) DO UPDATE SET vec = excluded.vec`. `search` reads every
  row, computes `dot / (norm_a * norm_b)` guarding a zero norm to `0.0`, sorts
  descending with `partial_cmp(..).unwrap_or(Ordering::Equal)` and a `doc_id` tie-break
  (determinism — the same lesson Task 3 learned twice), and truncates to `k`.

  `OllamaEmbedder::embed` POSTs to `{host}/api/embed` with
  `{"model": .., "input": [..]}` and reads `response["embeddings"]` as
  `Vec<Vec<f32>>`. Ollama's newer `/api/embed` accepts a batch; if the deployed
  server only has the older single-input `/api/embeddings`, fall back to one request
  per text and say so in a code comment. Return `HttpError` unchanged from
  `HttpClient` — do **not** invent a second error type here.
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-core` → PASS; clippy clean.
  The `#[ignore]` live test stays unrun at this point — see the STOP gate before Task 18's
  step 5.
- [ ] **Step 5: Commit** — `git commit -am "feat: Ollama embedder and the sqlite vector store"`

---

### Task 18: RRF fusion, the `Retrieve` seam, and the corpus CLI

**Files:**
- Create: `crates/dike-core/src/retrieval/rrf.rs`, `crates/dike-core/src/retrieval/retriever.rs`
- Modify: `crates/dike-core/src/retrieval/mod.rs`, `crates/dike-core/src/lib.rs`, `crates/dike-cli/src/commands/corpus.rs`, `crates/dike-cli/src/main.rs`

**Interfaces:**
- Consumes: `Document`, `Bm25Index`, `VectorStore`, `Embedder`.
- Produces:
  ```rust
  pub fn rrf(ranked_lists: &[Vec<String>], k: f32) -> Vec<(String, f32)>;

  pub struct RetrievalHit {
      pub document: Document,
      pub rrf_score: f32,
      pub dense_score: Option<f32>,
      pub bm25_score: Option<f32>,
  }
  pub fn is_grounded(hits: &[RetrievalHit]) -> bool;

  /// The seam Track 2 consumes. `LlmAnalyzer` holds a `Box<dyn Retrieve>`, never
  /// a concrete retriever, so it can be tested against a stub (D19).
  pub trait Retrieve {
      fn search(&self, query: &str, top_k: usize) -> anyhow::Result<Vec<RetrievalHit>>;
      fn corpus_hash(&self) -> String;
      fn describe(&self) -> String;
  }

  pub struct HybridRetriever { /* bm25, store, embedder, docs, corpus_hash */ }
  impl HybridRetriever {
      pub fn open(index_dir: &Path, docs: Vec<Document>, embedder: Box<dyn Embedder>)
          -> anyhow::Result<HybridRetriever>;
      pub fn build(index_dir: &Path, docs: &[Document], embedder: Box<dyn Embedder>)
          -> anyhow::Result<HybridRetriever>;
  }
  impl Retrieve for HybridRetriever { /* .. */ }
  ```

**RRF, k = 60** (spec §7): `score(d) = Σ_lists 1 / (k + rank(d))`, rank **1-based**.
Chosen because dense cosine and BM25 scores live on incomparable scales; rank fusion
needs no tuning and no calibration.

**D11 — the grounding gate.** `is_grounded` returns true iff any hit has
`dense_score >= 0.35` **or** any hit has `bm25_score > 0.0`. Never threshold the RRF
score: it is rank-derived, so its magnitude carries no relevance information — a
document ranked first in a list of garbage scores exactly `1/61`, the same as a perfect
match.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn hit(id: &str, rrf: f32, dense: Option<f32>, bm25: Option<f32>) -> RetrievalHit {
        RetrievalHit {
            document: Document { id: id.into(), source_url: "u".into(), title: "t".into(),
                                 text: "x".into(), class_tags: vec![] },
            rrf_score: rrf, dense_score: dense, bm25_score: bm25,
        }
    }

    #[test]
    fn rrf_ranks_a_document_appearing_in_both_lists_above_a_list_leader() {
        let dense = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let sparse = vec!["c".to_string(), "b".to_string(), "z".to_string()];
        let fused = rrf(&[dense, sparse], 60.0);
        assert_eq!(fused[0].0, "b", "2nd in both beats 1st in one");
    }

    #[test]
    fn rrf_uses_one_based_ranks() {
        let fused = rrf(&[vec!["a".to_string()]], 60.0);
        assert!((fused[0].1 - 1.0 / 61.0).abs() < 1e-6, "rank 1 scores 1/(60+1)");
    }

    #[test]
    fn rrf_output_is_sorted_descending() {
        let fused = rrf(&[vec!["a".into(), "b".into()], vec!["b".into()]], 60.0);
        assert!(fused[0].1 >= fused[1].1);
    }

    #[test]
    fn rrf_ties_break_deterministically_by_id() {
        let a = rrf(&[vec!["y".to_string(), "x".to_string()]], 60.0);
        let b = rrf(&[vec!["y".to_string(), "x".to_string()]], 60.0);
        assert_eq!(a, b);
        let swapped = rrf(&[vec!["x".to_string()], vec!["y".to_string()]], 60.0);
        assert_eq!(swapped[0].0, "x", "equal scores order by id, not by input order");
    }

    #[test]
    fn rrf_of_no_lists_is_empty() {
        assert!(rrf(&[], 60.0).is_empty());
        assert!(rrf(&[vec![]], 60.0).is_empty());
    }

    #[test]
    fn grounding_requires_a_real_signal_not_a_fused_rank() {
        assert!(!is_grounded(&[hit("a", 0.9, Some(0.10), None)]),
                "a high RRF score alone is not evidence");
        assert!(is_grounded(&[hit("a", 0.01, Some(0.40), None)]));
        assert!(is_grounded(&[hit("a", 0.01, None, Some(2.5))]));
        assert!(!is_grounded(&[hit("a", 0.99, None, Some(0.0))]), "a zero BM25 score is no signal");
        assert!(!is_grounded(&[]));
    }

    #[test]
    fn grounding_fires_if_any_hit_qualifies_not_only_the_first() {
        let hits = vec![hit("a", 0.9, Some(0.10), None), hit("b", 0.1, Some(0.90), None)];
        assert!(is_grounded(&hits));
    }
}
```

And in `retriever.rs`, against a stub embedder (no network):

```rust
#[test]
fn hybrid_search_returns_hits_carrying_both_component_scores() {
    let dir = tempfile::tempdir().unwrap();
    let docs = vec![
        doc("d1", "The withdraw path calls close_account without checking the destination."),
        doc("d2", "Overflow in the deposit path wraps the stored balance."),
    ];
    let r = HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::orthogonal())).unwrap();
    let hits = r.search("close_account", 5).unwrap();
    assert!(!hits.is_empty());
    assert!(hits.iter().any(|h| h.bm25_score.is_some()), "sparse leg ran");
    assert!(hits.iter().any(|h| h.dense_score.is_some()), "dense leg ran");
    assert!(hits.iter().all(|h| h.rrf_score > 0.0));
}

#[test]
fn hybrid_search_degrades_to_sparse_when_the_embedder_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let docs = vec![doc("d1", "The withdraw path calls close_account.")];
    let r = HybridRetriever::build(dir.path(), &docs, Box::new(DeadEmbedder)).unwrap();
    let hits = r.search("close_account", 5).unwrap();
    assert!(!hits.is_empty(), "a dead embedder must not zero out retrieval");
    assert!(hits.iter().all(|h| h.dense_score.is_none()));
}

#[test]
fn hybrid_search_respects_top_k() {
    let dir = tempfile::tempdir().unwrap();
    let docs: Vec<_> = (0..8).map(|i| doc(&format!("d{i}"), "missing owner validation")).collect();
    let r = HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::orthogonal())).unwrap();
    assert!(r.search("owner", 3).unwrap().len() <= 3);
}

#[test]
fn corpus_hash_is_reported_from_the_indexed_documents() {
    let dir = tempfile::tempdir().unwrap();
    let docs = vec![doc("d1", "text")];
    let r = HybridRetriever::build(dir.path(), &docs, Box::new(StubEmbedder::orthogonal())).unwrap();
    assert_eq!(r.corpus_hash(), crate::retrieval::corpus_hash(&docs));
}
```

`hybrid_search_degrades_to_sparse_when_the_embedder_is_unavailable` is the load-bearing
one. Retrieval that returns nothing when Ollama is down would make Track 2 look like a
recall failure instead of an availability failure, and the eval harness would record it
as one.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-core rrf` → FAIL.
- [ ] **Step 3: Implement.**
  `rrf`: accumulate into a `BTreeMap<String, f32>`, then sort by score descending with
  a `doc_id` ascending tie-break. The `BTreeMap` plus the explicit tie-break is what
  makes the "ties break deterministically" test pass regardless of input order.

  `HybridRetriever::search`: embed the query (on `Err`, log at `warn`, skip the dense
  leg entirely — do not fail); `store.search(q, top_k * 4)`; `bm25.search(query, top_k * 4)`;
  fuse the two id lists with `rrf(.., 60.0)`; take the top `top_k`; attach each id's
  `Document` and whichever component scores it had. Over-fetch `4×` per leg so fusion
  has material to work with — fusing two 5-item lists mostly returns the union.

  A `ModelMismatch` from the store is **not** a degradation: propagate it as an error
  with its re-index message. A stale index producing wrong answers is worse than an
  error.
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-core` → PASS; clippy clean.
- [ ] **Step 5: Wire the corpus CLI.** Extend `commands/corpus.rs` with:
  - `dike corpus index [--rebuild] [--embed-model <name>] [--ollama-host <url>]` —
    `load_cached` → `HybridRetriever::build` into `corpus/index/`.
  - `dike corpus query "<text>" [--top-k 5]` — prints each hit as
    `<rrf_score>  <doc_id>  <title>` with `dense=` / `bm25=` columns, then a final
    `grounded: true|false` line.
  - `dike corpus hash` — prints the corpus hash for embedding in reports.

  Defaults: host `http://localhost:11434`, embed model `bge-small-en-v1.5`.

> ### ⛔ STOP — hand back to the user before running anything against Ollama
>
> Everything through Task 18 step 4 is verifiable with no model running. Step 5's
> `dike corpus index` is the **first command in this project that requires a live
> Ollama**, and `corpus fetch` is the first that requires network access.
>
> Stop here and report: Tasks 14–18 implemented and unit-verified, ready for the
> first live run. Do not run `corpus fetch`, `corpus index`, or any `--ignored`
> test until the user says to. The two model choices to settle at that point are
> the **embedding** model (default `bge-small-en-v1.5`) and, at Task 19, the
> **generation** model (spec §10 says Qwen2.5-Coder 14B Q4; a Hermes model is a
> drop-in alternative — it is a `--model` string and nothing else changes).

- [ ] **Step 6: Commit** — `git commit -am "feat: RRF fusion, hybrid retriever seam and the corpus CLI"`

---

## Phase 6 — Track 2: Retrieval-Grounded LLM

Deliverable: `dike analyze --llm <path>` adds a Track 2 section whose every finding cites a real retrieved document, and degrades to Track-1-only when Ollama is not running.

### Task 19: LLM client interface with Ollama and Gemini backends

**Files:**
- Create: `crates/dike-core/src/llm/mod.rs`, `crates/dike-core/src/llm/ollama.rs`, `crates/dike-core/src/llm/gemini.rs`
- Modify: `crates/dike-core/src/lib.rs`

**Interfaces:**
- Consumes: `HttpClient`, `HttpError`.
- Produces:
  ```rust
  pub struct LlmRequest { pub system: String, pub user: String, pub temperature: f32, pub timeout: Duration }
  pub enum LlmError { Unavailable(String), Timeout, Transport(String), Refused(String) }
  pub trait LlmClient {
      fn name(&self) -> String;
      fn complete(&self, req: &LlmRequest) -> Result<String, LlmError>;
  }
  pub struct OllamaClient { pub host: String, pub model: String, /* http */ }
  pub struct GeminiClient { pub model: String, /* api_key, http */ }
  impl OllamaClient { pub fn new(host: impl Into<String>, model: impl Into<String>) -> Result<Self, LlmError>; }
  impl GeminiClient { pub fn from_env(model: impl Into<String>) -> Result<Self, LlmError>; }
  ```

Per-unit timeout (spec §9, "pathological handler") lives on `LlmRequest` and defaults
to 120s. `LlmError::Unavailable` is what Task 22 turns into a `TrackSkipped`
diagnostic — degraded, not failed. `temperature` defaults to `0.0`: Track 2 is not
deterministic, but there is no reason to add avoidable variance to an eval loop.

**Model is a parameter, never a constant.** Spec §10's `qwen2.5-coder:14b` is the CLI
default and nothing more. Swapping to any other local model — a Hermes build, for
instance — must be a `--model` string with no code change.

**Secrets.** The Gemini key is read from `GEMINI_API_KEY` at construction. Never
persist it, never log it, never put it in a report, and never include it in an error
message — `from_env` returns `LlmError::Refused("GEMINI_API_KEY is not set")`, which
must not echo any partial value.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> LlmRequest {
        LlmRequest { system: "s".into(), user: "u".into(), temperature: 0.0,
                     timeout: std::time::Duration::from_millis(500) }
    }

    #[test]
    fn a_dead_endpoint_is_unavailable_not_a_panic() {
        let c = OllamaClient::new("http://127.0.0.1:1", "nope").unwrap();
        let err = c.complete(&req()).unwrap_err();
        assert!(matches!(err, LlmError::Unavailable(_) | LlmError::Transport(_) | LlmError::Timeout),
                "got: {err:?}");
    }

    #[test]
    fn client_name_identifies_the_model_for_the_report() {
        let c = OllamaClient::new("http://127.0.0.1:1", "qwen2.5-coder:14b").unwrap();
        assert!(c.name().contains("qwen2.5-coder:14b"),
                "RunMetadata::model comes from here; a bare backend name is not reproducible");
    }

    #[test]
    fn a_missing_gemini_key_is_refused_without_echoing_anything() {
        std::env::remove_var("GEMINI_API_KEY");
        let err = GeminiClient::from_env("gemini-2.0-flash").unwrap_err();
        match err {
            LlmError::Refused(m) => assert!(!m.to_lowercase().contains("aiza"), "never echo key material"),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn the_trait_is_object_safe() {
        let c: Box<dyn LlmClient> = Box::new(OllamaClient::new("http://127.0.0.1:1", "m").unwrap());
        assert!(!c.name().is_empty());
    }

    #[test]
    #[ignore = "needs a running Ollama with the generation model pulled"]
    fn live_ollama_returns_text() {
        let c = OllamaClient::new("http://localhost:11434", "qwen2.5-coder:14b").unwrap();
        let out = c.complete(&LlmRequest {
            system: "You reply with exactly one word.".into(),
            user: "Say OK.".into(), temperature: 0.0,
            timeout: std::time::Duration::from_secs(120),
        }).unwrap();
        assert!(!out.trim().is_empty());
    }
}
```

`the_trait_is_object_safe` looks trivial and is not: Task 22 stores a
`Box<dyn LlmClient>`, and adding a generic method here later would break that with a
confusing error far from its cause.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-core llm` → FAIL.
- [ ] **Step 3: Implement both backends** on top of `HttpClient`.
  Ollama: POST `{host}/api/generate` with
  `{"model":.., "system":.., "prompt":.., "stream": false, "options": {"temperature": ..}}`,
  read `response["response"]` as a string.
  Gemini: POST `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`
  with the key in the `x-goog-api-key` header (**not** the URL — URLs land in logs), read
  `candidates[0].content.parts[0].text`.
  Map `HttpError::Unavailable → LlmError::Unavailable`, `Timeout → Timeout`,
  `Status(401 | 403) → Refused`, everything else → `Transport`.
  `name()` returns `format!("ollama/{}", self.model)` / `format!("gemini/{}", self.model)`.
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-core` → PASS; clippy clean.
  Leave the `#[ignore]` live test unrun — see the STOP gate in Task 18.
- [ ] **Step 5: Commit** — `git commit -am "feat: LLM client interface with Ollama and Gemini backends"`

---

### Task 20: Handler chunking and derived query construction

**Files:**
- Create: `crates/dike-lang-anchor/src/chunker.rs`
- Modify: `crates/dike-lang-anchor/src/lib.rs`

**Interfaces:**
- Consumes: `ir::{Program, Handler, AccountsStruct, StateStruct, Wrapper, Constraint}`, `dike_core::SourceTree`.
- Produces:
  ```rust
  pub struct HandlerUnit {
      pub handler_name: String, pub file: PathBuf, pub line: u32,
      pub source: String, pub query: String,
  }
  pub fn chunk(program: &Program, tree: &SourceTree) -> Vec<HandlerUnit>;
  pub fn derive_query(program: &Program, handler: &Handler, accounts: Option<&AccountsStruct>) -> String;
  ```

A `HandlerUnit` is handler body + its accounts struct + every referenced state struct
(spec §6) — the smallest self-contained review unit.

`accounts` is an **`Option`** because `parse_handlers` records `context_ty` even when
the struct is unresolvable across files (Task 7's ledger entry: unresolvable
`context_ty` produces a `Skipped` diagnostic downstream, not a parse failure). A unit
with no accounts struct still gets a query and still gets reviewed — degraded, not
dropped.

**The query is derived, never raw source** (spec §7). Raw Rust embeds poorly; a
description of behavior embeds well. Build the sentence from the IR: wrapper types
present, constraints **absent**, and operations performed. Target shape:

```
Solana Anchor instruction `withdraw` with 4 accounts. Account types: Signer,
Account<Vault>, UncheckedAccount, Program<Token>. Present constraints: mut, has_one.
Absent on unchecked accounts: owner, address, seeds. Operations: cross-program
invocation, state mutation, unchecked subtraction. State struct Vault has field admin.
```

The **absent** clause is the part that carries retrieval signal: audit findings are
written about what was missing.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"
#[program]
pub mod vault {
    use super::*;
    pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.amount = v.amount - amount;
        let cpi_ctx = CpiContext::new(a, b);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }
}
#[account]
pub struct Vault { pub admin: Pubkey, pub amount: u64 }
#[derive(Accounts)]
pub struct W<'info> {
    pub authority: UncheckedAccount<'info>,
    #[account(mut, has_one = admin)]
    pub vault: Account<'info, Vault>,
}
"#;

    #[test]
    fn query_describes_behavior_and_never_quotes_raw_rust() {
        let q = derive_query_for(SRC);
        assert!(q.contains("withdraw"));
        assert!(q.contains("UncheckedAccount"), "wrapper types are the retrieval signal");
        assert!(q.contains("cross-program invocation"));
        assert!(q.contains("unchecked"), "unchecked arithmetic is described in words");
        assert!(!q.contains("ctx.accounts"), "the query is a description, not source");
        assert!(!q.contains("->"), "no Rust syntax");
        assert!(!q.contains("{"), "no Rust syntax");
    }

    #[test]
    fn query_names_absent_constraints_not_only_present_ones() {
        let q = derive_query_for(SRC);
        let absent = q.split("Absent").nth(1).expect("an Absent clause exists");
        assert!(absent.contains("owner") || absent.contains("address") || absent.contains("seeds"),
                "audit findings are written about what is missing; got: {q}");
    }

    #[test]
    fn query_is_deterministic() {
        assert_eq!(derive_query_for(SRC), derive_query_for(SRC));
    }

    #[test]
    fn query_survives_an_unresolvable_accounts_struct() {
        let program = parse_for(r#"
#[program]
pub mod p { pub fn go(ctx: Context<Elsewhere>) -> Result<()> { Ok(()) } }
"#);
        let h = program.handler("go").unwrap();
        let q = derive_query(&program, h, None);
        assert!(q.contains("go"));
        assert!(!q.is_empty(), "an unresolvable context degrades, it does not vanish");
    }

    #[test]
    fn unit_includes_accounts_struct_and_referenced_state_structs() {
        let units = chunk_for(SRC);
        assert_eq!(units.len(), 1);
        assert!(units[0].source.contains("pub fn withdraw"), "the handler body");
        assert!(units[0].source.contains("pub struct W"), "its accounts struct");
        assert!(units[0].source.contains("pub struct Vault"), "the referenced state struct");
    }

    #[test]
    fn unit_does_not_include_unreferenced_state_structs() {
        let units = chunk_for(&format!("{SRC}\n#[account]\npub struct Unrelated {{ pub x: u64 }}\n"));
        assert!(!units[0].source.contains("Unrelated"),
                "padding the unit with irrelevant structs wastes the context window");
    }

    #[test]
    fn unit_line_points_at_the_handler_not_the_file_start() {
        let units = chunk_for(SRC);
        assert!(units[0].line > 1);
        assert_eq!(units[0].handler_name, "withdraw");
    }

    #[test]
    fn a_program_with_no_handlers_yields_no_units() {
        assert!(chunk_for("pub fn not_a_handler() {}").is_empty());
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-lang-anchor chunker` → FAIL.
- [ ] **Step 3: Implement.**
  `source` is reconstructed by slicing the original file text between `line` and
  `end_line` for the handler, its accounts struct, and each referenced state struct —
  all three carry `line`/`end_line` from Task 5, and Task 6/7 populate them from
  `span().start().line` / `span().end().line`. Look the file text up in
  `tree.files` by comparing `SourceFile::path` to the IR node's `file`. Lines are
  **1-based** (that is what `proc-macro2`'s `span-locations` produces); slice with
  `lines().skip(line - 1).take(end_line - line + 1)`. If the file is not in the tree or
  the range is out of bounds, emit that piece as empty rather than panicking.

  "Referenced state struct" = any `StateStruct` whose name appears as the inner type of
  an `Account`/`InterfaceAccount` wrapper in the accounts struct. Deduplicate and
  order by name.

  `derive_query` clauses, in this fixed order (determinism):
  1. `Solana Anchor instruction \`{name}\` with {n} accounts.`
  2. `Account types: {sorted unique wrapper renderings}.`
  3. `Present constraints: {sorted unique constraint kind names}.` — omit the clause
     entirely if empty rather than printing `Present constraints: .`
  4. `Absent on unchecked accounts: {of owner/address/seeds/signer, those appearing on
     no `is_unchecked()` decl}.` — omit if the struct has no unchecked decls.
  5. `Operations: {from handler.body}` — `cross-program invocation` if any
     `CallSite::is_cpi`; `state mutation` if `state_writes` is non-empty;
     `unchecked addition|subtraction|multiplication|division` per distinct unchecked
     `ArithOp::op`; `imperative checks present` if `checks` is non-empty.
  6. `State struct {name} has field {f}.` for each referenced state struct, fields
     joined by `, `.

  Render `Wrapper` in words, never with Rust punctuation the tests ban: `Account<Vault>`
  is fine (it is a type name, and the test only bans `->` and `{`), but do not emit
  lifetimes.
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-lang-anchor` → PASS; clippy clean.
- [ ] **Step 5: Commit** — `git commit -am "feat: handler chunking and derived retrieval queries"`

---

### Task 21: Structured output, retry, and citation validation

**Files:**
- Create: `crates/dike-core/src/llm/structured.rs`
- Modify: `crates/dike-core/src/llm/mod.rs`

**Interfaces:**
- Consumes: `LlmClient`, `LlmRequest`, `LlmError`, `RetrievalHit`, `merge::track2_confidence`, `Finding`, `Location`, `Citation`, `Severity`, `Track`, `VulnClass`.
- Produces:
  ```rust
  pub struct RawLlmFinding {
      pub class: String, pub severity: String, pub confidence: f32,
      pub handler: String, pub line: Option<u32>,
      pub evidence: String, pub citations: Vec<String>,
  }
  pub struct SchemaViolation(pub String);
  pub fn parse_findings(raw: &str) -> Result<Vec<RawLlmFinding>, SchemaViolation>;
  pub fn complete_structured(client: &dyn LlmClient, req: &LlmRequest)
      -> Result<Vec<RawLlmFinding>, LlmError>;
  /// `file` is required because `RawLlmFinding` carries no path and `Location` needs one (D27).
  pub fn validate_citations(f: RawLlmFinding, offered: &[RetrievalHit], file: &Path)
      -> Option<Finding>;
  ```

Three mechanisms, all straight from the spec:

1. **One retry with the violation appended** (§9). If `parse_findings` fails, re-issue
   with `\n\nYour previous response was rejected: {violation}. Return only a JSON array
   matching the schema, with no prose and no code fences.` appended to `user`. On a
   second failure, drop and log at `warn`. Never a third attempt, never a crash.
2. **Tolerant parsing.** Strip ```` ```json ```` fences; if prose surrounds the array,
   extract from the first `[` to the last `]` and parse that. A 14B model wraps JSON in
   commentary constantly, and failing on that throws away good findings.
3. **Citation validation (D12).** Filter `citations` to `doc_id`s actually present in
   `offered`. If none survive, return `None` — the finding is dropped. This is what
   turns the grounding rule from decoration into a filter.

Confidence goes through `track2_confidence(raw, surviving.len())`. Severity parses
case-insensitively and defaults to `Medium` on anything unrecognized. `track` is
`Track::Llm`; `id` is left empty (`merge` clears ids anyway) or blake3 of
`(class, handler, line)` — match whatever `detectors::finding_from` does so the two
tracks' ids are shaped alike.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn hit_with_id(id: &str) -> RetrievalHit { /* Document { id, .. }, scores Some(1.0) */ }
    fn raw_finding(citations: Vec<String>) -> RawLlmFinding {
        RawLlmFinding { class: "missing-owner-check".into(), severity: "high".into(),
                        confidence: 0.8, handler: "withdraw".into(), line: Some(12),
                        evidence: "e".into(), citations }
    }
    fn file() -> std::path::PathBuf { "src/lib.rs".into() }

    #[test]
    fn parses_json_wrapped_in_prose_and_fences() {
        let raw = "Here is what I found:\n```json\n[{\"class\":\"missing-signer\",\
                   \"severity\":\"critical\",\"confidence\":0.8,\"handler\":\"withdraw\",\
                   \"line\":12,\"evidence\":\"e\",\"citations\":[\"d1\"]}]\n```\nHope that helps!";
        let parsed = parse_findings(raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].class, "missing-signer");
    }

    #[test]
    fn parses_a_bare_array_with_no_decoration() {
        assert_eq!(parse_findings("[]").unwrap().len(), 0);
    }

    #[test]
    fn empty_array_is_a_valid_response_not_a_violation() {
        assert!(parse_findings("Nothing found.\n[]\n").is_ok());
    }

    #[test]
    fn a_null_line_parses_as_none() {
        let raw = "[{\"class\":\"c\",\"severity\":\"low\",\"confidence\":0.1,\
                   \"handler\":\"h\",\"line\":null,\"evidence\":\"e\",\"citations\":[]}]";
        assert!(parse_findings(raw).unwrap()[0].line.is_none());
    }

    #[test]
    fn a_missing_optional_field_does_not_reject_the_whole_array() {
        let raw = "[{\"class\":\"c\",\"severity\":\"low\",\"confidence\":0.1,\
                   \"handler\":\"h\",\"evidence\":\"e\",\"citations\":[]}]";
        assert!(parse_findings(raw).is_ok(), "`line` is optional; #[serde(default)]");
    }

    #[test]
    fn rejects_non_json_with_a_violation_message() {
        let err = parse_findings("I could not find anything of note.").unwrap_err();
        assert!(!err.0.is_empty(), "the message is fed back to the model on retry");
    }

    #[test]
    fn rejects_a_json_object_that_is_not_an_array() {
        assert!(parse_findings("{\"class\":\"c\"}").is_err());
    }

    #[test]
    fn hallucinated_citations_are_stripped_and_uncited_findings_dropped() {
        let offered = vec![hit_with_id("d1"), hit_with_id("d2")];
        let mut f = raw_finding(vec!["d1".into(), "d99".into()]);
        let kept = validate_citations(f.clone(), &offered, &file()).unwrap();
        assert_eq!(kept.citations.len(), 1);
        assert_eq!(kept.citations[0].doc_id, "d1");

        f.citations = vec!["d99".into()];
        assert!(validate_citations(f.clone(), &offered, &file()).is_none(),
                "no valid citation, no finding");
        f.citations = vec![];
        assert!(validate_citations(f, &offered, &file()).is_none());
    }

    #[test]
    fn a_kept_finding_carries_a_complete_location() {
        let offered = vec![hit_with_id("d1")];
        let f = validate_citations(raw_finding(vec!["d1".into()]), &offered, &file()).unwrap();
        assert_eq!(f.location.file, file(), "D27: the file comes from the caller");
        assert_eq!(f.location.handler, "withdraw");
        assert_eq!(f.location.line, 12);
        assert_eq!(f.track, dike_core::Track::Llm);
    }

    #[test]
    fn citations_carry_the_document_url_and_title_for_the_report() {
        let offered = vec![hit_with_id("d1")];
        let f = validate_citations(raw_finding(vec!["d1".into()]), &offered, &file()).unwrap();
        assert!(!f.citations[0].source_url.is_empty());
        assert!(!f.citations[0].title.is_empty());
    }

    #[test]
    fn single_citation_findings_are_down_weighted() {
        let offered = vec![hit_with_id("d1"), hit_with_id("d2")];
        let one = validate_citations(raw_finding(vec!["d1".into()]), &offered, &file()).unwrap();
        let two = validate_citations(raw_finding(vec!["d1".into(), "d2".into()]), &offered, &file()).unwrap();
        assert!(one.confidence < two.confidence);
    }

    #[test]
    fn an_unrecognized_severity_defaults_to_medium() {
        let offered = vec![hit_with_id("d1")];
        let mut f = raw_finding(vec!["d1".into()]);
        f.severity = "spicy".into();
        assert_eq!(validate_citations(f, &offered, &file()).unwrap().severity,
                   dike_core::Severity::Medium);
    }

    #[test]
    fn severity_parsing_is_case_insensitive() {
        let offered = vec![hit_with_id("d1")];
        let mut f = raw_finding(vec!["d1".into()]);
        f.severity = "CRITICAL".into();
        assert_eq!(validate_citations(f, &offered, &file()).unwrap().severity,
                   dike_core::Severity::Critical);
    }

    #[test]
    fn a_duplicate_citation_is_counted_once() {
        let offered = vec![hit_with_id("d1"), hit_with_id("d2")];
        let dup = validate_citations(raw_finding(vec!["d1".into(), "d1".into()]), &offered, &file()).unwrap();
        assert_eq!(dup.citations.len(), 1, "duplicates must not inflate confidence");
    }

    #[test]
    fn a_first_violation_is_retried_once_and_the_retry_is_used() {
        let client = ProseThenJsonClient::default(); // prose first, valid JSON second
        let out = complete_structured(&client, &sample_request()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(client.calls(), 2, "exactly one retry");
    }

    #[test]
    fn the_retry_prompt_carries_the_violation_back_to_the_model() {
        let client = RecordingClient::default();
        let _ = complete_structured(&client, &sample_request());
        let second = &client.requests()[1];
        assert!(second.user.contains("was rejected"), "the model is told what was wrong");
        assert!(second.user.contains(&client.requests()[0].user), "the original task survives");
    }

    #[test]
    fn a_second_schema_violation_drops_the_unit_without_erroring() {
        let client = AlwaysProseClient::default();
        let out = complete_structured(&client, &sample_request());
        assert!(matches!(out, Ok(ref v) if v.is_empty()), "drop and log, never crash");
        assert_eq!(client.calls(), 2, "never a third attempt");
    }

    #[test]
    fn a_transport_error_propagates_rather_than_being_swallowed_as_empty() {
        let client = DeadClient;
        assert!(matches!(complete_structured(&client, &sample_request()),
                         Err(LlmError::Unavailable(_) | LlmError::Transport(_))));
    }
}
```

The last one matters: if an unavailable model were flattened into `Ok(vec![])`, Task 22
could never tell "the model reviewed this and found nothing" from "the model is not
running", and the report would claim clean coverage it never had.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-core structured` → FAIL.
- [ ] **Step 3: Implement all three mechanisms.** Test doubles (`AlwaysProseClient`,
  `ProseThenJsonClient`, `RecordingClient`, `DeadClient`) live in the `#[cfg(test)]`
  module and implement `LlmClient` with a `Cell`/`RefCell` call counter. Remember the
  seam: these doubles' fixture strings must avoid the ten banned tokens.
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-core` → PASS; clippy clean;
  `core_contains_no_solana_identifiers` still passes.
- [ ] **Step 5: Commit** — `git commit -am "feat: structured LLM output with retry and citation validation"`

---

### Task 22: `LlmAnalyzer` — the assembled Track 2

**Files:**
- Create: `crates/dike-lang-anchor/src/llm_analyzer.rs`, `crates/dike-lang-anchor/prompts/track2.md`
- Modify: `crates/dike-core/src/analyzer.rs`, `crates/dike-core/src/report/mod.rs`, `crates/dike-core/src/report/{markdown,json}.rs`, `crates/dike-lang-anchor/src/lib.rs`, `crates/dike-cli/src/commands/analyze.rs`, `crates/dike-cli/src/config.rs`, `crates/dike-cli/src/pipeline.rs`, `crates/dike-cli/src/main.rs`

**Interfaces:**
- Consumes: Tasks 18–21, `dike_core::Analyzer`.
- Produces:
  ```rust
  // dike-core/src/analyzer.rs — additive (D28)
  pub struct UnitCoverage { pub total: usize, pub examined: usize }
  pub struct AnalysisResult {
      pub findings: Vec<Finding>, pub diagnostics: Vec<Diagnostic>,
      pub files_analyzed: usize,
      pub units: Option<UnitCoverage>,   // None for a track with no unit concept
  }
  // dike-core/src/report/mod.rs — additive
  pub struct Coverage { /* .. existing .. */ pub units_total: usize, pub units_examined: usize }

  // dike-lang-anchor/src/llm_analyzer.rs
  pub struct LlmAnalyzer {
      pub client: Box<dyn LlmClient>,
      pub retriever: Box<dyn Retrieve>,   // D19 — a trait, so it can be stubbed
      pub top_k: usize,
  }
  impl dike_core::Analyzer for LlmAnalyzer { /* .. */ }
  ```

**Per unit:** derive query → `retriever.search(query, top_k)` → `is_grounded`? if not,
skip the unit and continue → build the prompt with each document labeled
`[doc_id: <id>] <title>\n<text>` → `complete_structured` → `validate_citations` → emit.
On `LlmError::Unavailable`, stop immediately, emit one `TrackSkipped` diagnostic, and
return what was collected — the run is degraded, not failed.

`top_k` defaults to 5.

**`prompts/track2.md`** (loaded with `include_str!`) must state:
- the model is reviewing one Solana Anchor instruction;
- it must ground every finding in the provided documents and cite their `doc_id`s;
- it must return **only** a JSON array with the exact schema fields;
- it must return `[]` when nothing is supported by the documents;
- speculation without a citation will be discarded (true, and empirically reduces invention).

**It must NOT tell the model to skip classes Track 1 already covers (D30).** The
original plan's prompt did. That instruction suppresses precisely the overlap that
`merge_key` collision detection exists to find: with it, `Track::Corroborated` becomes
unreachable and the merged track degenerates into a concatenation. Two independent
methods agreeing is the strongest signal this tool can produce — do not instruct it
away.

**The prompt never contains Track 1 findings (D29).** Not as context, not as hints,
not as a "check these" list. Track 2 must reach its conclusions independently or
corroboration is circular and every eval number built on it is self-congratulatory.
This is the operational form of the spec's hard rule, and there is a test for it below.

- [ ] **Step 1: Write the failing test** — with a test-double `LlmClient` returning a
  fixed JSON array and a stub `Retrieve`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Stubs: StubRetriever::grounded() returns two hits with dense_score Some(0.9);
    // StubRetriever::ungrounded() returns hits with dense 0.1 / bm25 0.0;
    // FixedClient(json) always returns that JSON; DeadClient returns LlmError::Unavailable.

    #[test]
    fn track2_findings_are_tagged_llm_and_carry_citations() {
        let result = analyzer(FixedClient::one_finding(), StubRetriever::grounded())
            .analyze(&fixture_tree());
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().all(|f| f.track == dike_core::Track::Llm));
        assert!(result.findings.iter().all(|f| !f.citations.is_empty()));
    }

    #[test]
    fn emits_no_findings_for_ungrounded_units() {
        let result = analyzer(FixedClient::one_finding(), StubRetriever::ungrounded())
            .analyze(&fixture_tree());
        assert!(result.findings.is_empty(), "the grounding gate is a filter, not a hint");
    }

    #[test]
    fn an_ungrounded_unit_is_counted_but_not_examined() {
        let result = analyzer(FixedClient::one_finding(), StubRetriever::ungrounded())
            .analyze(&fixture_tree());
        let u = result.units.expect("Track 2 reports unit coverage");
        assert!(u.total > 0);
        assert_eq!(u.examined, 0, "a thin report must be distinguishable from a broken one");
    }

    #[test]
    fn the_model_never_sees_track_1_findings() {
        let client = RecordingClient::default();
        let _ = analyzer_with(client.clone(), StubRetriever::grounded()).analyze(&fixture_tree());
        for req in client.requests() {
            let all = format!("{} {}", req.system, req.user);
            assert!(!all.contains("Track 1"), "D29: no static results in the prompt");
            assert!(!all.contains("static_track"));
            assert!(!all.contains("missing-signer at line"),
                    "no rendered Track 1 finding may leak into the prompt");
        }
    }

    #[test]
    fn the_prompt_labels_every_offered_document_with_its_doc_id() {
        let client = RecordingClient::default();
        let _ = analyzer_with(client.clone(), StubRetriever::grounded()).analyze(&fixture_tree());
        let user = &client.requests()[0].user;
        assert!(user.contains("[doc_id: d1]"), "citations are only checkable if ids are shown");
        assert!(user.contains("[doc_id: d2]"));
    }

    #[test]
    fn an_unavailable_model_degrades_rather_than_failing() {
        let result = analyzer(DeadClient, StubRetriever::grounded()).analyze(&fixture_tree());
        assert!(result.findings.is_empty());
        assert!(result.diagnostics.iter()
            .any(|d| d.kind == dike_core::DiagnosticKind::TrackSkipped));
    }

    #[test]
    fn an_unavailable_model_emits_exactly_one_diagnostic_not_one_per_unit() {
        let result = analyzer(DeadClient, StubRetriever::grounded()).analyze(&fixture_tree());
        assert_eq!(result.diagnostics.iter()
            .filter(|d| d.kind == dike_core::DiagnosticKind::TrackSkipped).count(), 1);
    }

    #[test]
    fn llm_findings_locate_to_a_real_handler_so_corroboration_can_fire() {
        let result = analyzer(FixedClient::one_finding(), StubRetriever::grounded())
            .analyze(&fixture_tree());
        assert!(result.findings.iter().all(|f| f.location.handler == "withdraw"));
    }

    #[test]
    fn a_finding_naming_an_unknown_handler_is_discarded() {
        let result = analyzer(FixedClient::handler("does_not_exist"), StubRetriever::grounded())
            .analyze(&fixture_tree());
        assert!(result.findings.is_empty(),
                "an unmappable handler cannot be located, cited, or corroborated");
    }

    #[test]
    fn a_matching_static_finding_corroborates_through_merge() {
        let llm = analyzer(FixedClient::one_finding(), StubRetriever::grounded())
            .analyze(&fixture_tree()).findings;
        let stat = vec![static_finding("withdraw", "missing-owner-check")];
        let merged = dike_core::merge::merge(stat, llm);
        assert!(merged.iter().any(|f| f.track == dike_core::Track::Corroborated),
                "D30: overlap between tracks is the product, not waste");
    }
}
```

`the_model_never_sees_track_1_findings` and `a_matching_static_finding_corroborates_through_merge`
are the two that justify this whole architecture. The first proves the tracks are
independent; the second proves the independence still produces agreement. Neither can
be checked by reading the prompt file.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-lang-anchor llm_analyzer` → FAIL.
- [ ] **Step 3: Implement `LlmAnalyzer` and `prompts/track2.md`.**
  Map the model's `handler` field back to a real `Handler` by **exact name**; discard
  findings naming an unknown handler. Fall back to `handler.line` when the model gives
  no line — a finding pointing at line 0 destroys trust (the same rule Task 10 applies
  to `attr_line`).
- [ ] **Step 4: Extend coverage plumbing (D28).**
  Add `units: Option<UnitCoverage>` to `AnalysisResult` (it derives `Default`, so
  existing `Default::default()` call sites in `pipeline.rs` keep compiling and static
  analyzers simply leave it `None`). Add `units_total` / `units_examined` to `Coverage`,
  populate them in `pipeline::run` from the LLM result, and render them in the markdown
  and JSON coverage sections. Assert in the existing `pipeline` test that a `None` unit
  coverage renders as `0`, not as a panic.
- [ ] **Step 5: Wire `--llm` in the CLI.**
  `RunConfig` gains `ollama_host: String`, `model: String`, `embed_model: String`,
  `index_dir: PathBuf`, `top_k: usize`. `main.rs` adds the matching `--ollama-host`,
  `--model` (default `qwen2.5-coder:14b`), `--embed-model` (default
  `bge-small-en-v1.5`), `--top-k` (default 5) flags to `Analyze`.
  `commands/analyze.rs`, when `cfg.llm`: construct `OllamaClient` + `HybridRetriever`,
  pass `Some(&llm_analyzer)` to `pipeline::run`, and set `RunMetadata::model` from
  `client.name()` and `corpus_hash` from `retriever.corpus_hash()`. If the index
  directory does not exist, print
  `no corpus index at <path>; run \`dike corpus index\` first` and run Track 1 only,
  exit 0 — a missing index is a degraded run, not a tool failure.
- [ ] **Step 6: Verify without a model.**
  `cargo test --workspace` → PASS.
  `cargo clippy --workspace --all-targets -- -D warnings` → clean.
  `cargo run -p dike-cli -- analyze --llm tests/fixtures/programs/vault`
  Expected with Ollama **stopped**: full Track 1 section, a "Track 2 skipped"
  diagnostic, coverage showing `units_examined: 0`, **exit 0**.

> ### ⛔ STOP — the live end-to-end run is a user checkpoint
>
> Step 7 is the first full Track 2 run against a real model and a real corpus. Do
> not run it unattended. Report readiness and hand back.

- [ ] **Step 7: Verify end to end (user-gated).** With Ollama running and the corpus indexed:
  `cargo run -p dike-cli -- analyze --llm tests/fixtures/programs/vault`
  Expected: a populated Track 2 section, every row carrying at least one citation link,
  and a Merged section where any agreeing finding shows as corroborated and sorts first.
- [ ] **Step 8: Commit** — `git commit -am "feat: assembled retrieval-grounded Track 2 analyzer"`

---

## Phase 7 — Mutation Engine

Deliverable: `dike eval mutate <program>` writes N mutant copies of a program, each with exactly one injected vulnerability and a machine-readable label, and each verified to still compile.

### Task 23: The six v1 mutation operators

**Files:**
- Create: `crates/dike-lang-anchor/src/mutations/mod.rs`, `crates/dike-lang-anchor/src/mutations/operators.rs`
- Create: `crates/dike-core/src/eval/mod.rs` (the `MutationLabel` type only; the rest lands in Task 24)

**Interfaces:**
- Consumes: `ir::Program` (to locate mutation sites), `SourceTree` (to rewrite text).
- Produces:

`MutationLabel` lives in **`dike-core::eval`**, not in `dike-lang-anchor` — the eval
harness consumes it and `dike-core` can never depend on a language crate. It is
domain-agnostic by construction: a class string, a severity, and a source location.

```rust
// in dike-core::eval
pub struct MutationLabel { pub id: String, pub class: String, pub severity: Severity,
                           pub file: PathBuf, pub line: u32, pub handler: String,
                           pub operator: String }

// in dike-lang-anchor::mutations
pub struct Mutant { pub label: MutationLabel, pub files: Vec<(PathBuf, String)> }
pub trait MutationOperator {
    fn name(&self) -> &'static str;
    fn class(&self) -> &'static str;
    fn apply(&self, program: &Program, tree: &SourceTree) -> Vec<Mutant>;
}
pub fn all_operators() -> Vec<Box<dyn MutationOperator>>;
```

The six operators (D13), each producing **one** mutant per applicable site:

| Operator | Rewrite | Emitted class | Severity |
|---|---|---|---|
| `signer_to_account_info` | `Signer<'info>` → `AccountInfo<'info>` on an authority-named decl | `missing-signer` | Critical |
| `account_to_unchecked` | `Account<'info, T>` → `UncheckedAccount<'info>` | `missing-owner-check` | High |
| `strip_has_one` | delete a `has_one = X` from an `#[account(..)]` list | `missing-authority-binding` | High |
| `strip_constraint` | delete a `constraint = ...` expression | `removed-guard` | High |
| `strip_seeds_bump` | delete `seeds = [...]` and `bump` together | `pda-validation-gap` | High |
| `checked_to_bare` | `x.checked_add(y).unwrap()` → `x + y` (and `_sub`/`_mul`/`_div`) | `unchecked-arithmetic` | Medium |

**Mutation happens on text, not on the IR.** The IR gives the *site* (file + line +
handler + decl name); the rewrite is a targeted line edit so the mutant stays a readable
Anchor program a human can inspect. Deleting a constraint must also clean up the now-dangling
comma — `#[account(mut, has_one = admin)]` → `#[account(mut)]`, not `#[account(mut, )]`,
which does not compile and would be rejected by Task 24's gate anyway.

Labels are exact and unlimited (spec §8): the label is emitted by the operator that made
the edit, so ground truth is never guessed.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = r#"
        #[program]
        pub mod vault {
            pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                ctx.accounts.vault.amount = ctx.accounts.vault.amount.checked_sub(amount).unwrap();
                Ok(())
            }
        }
        #[account]
        pub struct Vault { pub admin: Pubkey, pub amount: u64 }
        #[derive(Accounts)]
        pub struct W<'info> {
            pub admin: Signer<'info>,
            #[account(mut, has_one = admin, seeds = [b"vault"], bump)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    #[test]
    fn signer_operator_produces_one_labeled_mutant() {
        let mutants = apply_operator(SignerToAccountInfo, CLEAN);
        assert_eq!(mutants.len(), 1);
        assert_eq!(mutants[0].label.class, "missing-signer");
        assert_eq!(mutants[0].label.handler, "withdraw");
        assert_eq!(mutants[0].label.severity, dike_core::Severity::Critical);
        let text = &mutants[0].files[0].1;
        assert!(text.contains("pub admin: AccountInfo<'info>"));
        assert!(!text.contains("pub admin: Signer<'info>"));
    }

    #[test]
    fn strip_has_one_leaves_valid_attribute_syntax() {
        let text = &apply_operator(StripHasOne, CLEAN)[0].files[0].1;
        assert!(!text.contains("has_one"));
        assert!(!text.contains(", )") && !text.contains("(, "));
        assert!(text.contains("#[account(mut, seeds"));
    }

    #[test]
    fn checked_to_bare_rewrites_the_arithmetic() {
        let text = &apply_operator(CheckedToBare, CLEAN)[0].files[0].1;
        assert!(!text.contains("checked_sub"));
        assert!(text.contains("ctx.accounts.vault.amount - amount"));
    }

    #[test]
    fn each_mutant_changes_exactly_one_thing() {
        for op in all_operators() {
            for m in op.apply(&parse(CLEAN).program, &tree(CLEAN)) {
                let diff_lines = line_diff_count(CLEAN, &m.files[0].1);
                assert!(diff_lines <= 2, "{} changed {diff_lines} lines", op.name());
            }
        }
    }

    #[test]
    fn strip_seeds_bump_removes_both() {
        let text = &apply_operator(StripSeedsBump, CLEAN)[0].files[0].1;
        assert!(!text.contains("seeds") && !text.contains("bump"));
    }

    #[test]
    fn labels_point_at_the_line_that_changed() {
        let m = &apply_operator(SignerToAccountInfo, CLEAN)[0];
        let changed = first_differing_line(CLEAN, &m.files[0].1);
        assert_eq!(m.label.line, changed);
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-lang-anchor mutations` → FAIL.
- [ ] **Step 3: Implement the operators.**
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-lang-anchor` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: six vulnerability-injection mutation operators"`

---

### Task 24: Mutant materialization and the compile gate

**Files:**
- Modify: `crates/dike-core/src/eval/mod.rs` (created in Task 23)
- Create: `crates/dike-cli/src/commands/eval.rs`
- Modify: `crates/dike-cli/src/commands/mod.rs`, `crates/dike-cli/src/main.rs`

**Interfaces:**
- Consumes: `Mutant`, `MutationLabel`.
- Produces: `pub struct EvalCase { pub name: String, pub original: PathBuf, pub mutant: PathBuf, pub label: MutationLabel }`; `pub fn materialize(program_root: &Path, mutants: Vec<Mutant>, out_dir: &Path) -> Vec<EvalCase>`; `pub fn compile_gate(case_dir: &Path) -> Result<(), String>`; CLI `dike eval mutate <PROGRAM> --out <DIR> [--no-compile-check]`.

D14 and the reason it exists: a mutant that no longer compiles is not a vulnerable
program, it is a broken one. A finding triggered by broken code counts as a true positive
under differential matching and silently inflates recall — exactly the number the whole
harness exists to make trustworthy.

`materialize` copies the whole program directory per mutant (they are small), overwrites
the mutated files, and writes `label.json` alongside. `compile_gate` runs
`cargo check --quiet --manifest-path <dir>/Cargo.toml` with a 300s timeout; non-zero exit
means reject. This is the one place the tool shells out to cargo, and it runs against
eval fixtures we control — never against user input (Global Constraints).

Rejected mutants are recorded in `<out_dir>/rejected.json` with the compiler's stderr, so
a broken operator is visible rather than quietly reducing the case count.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn materialize_writes_one_directory_per_mutant_with_a_label() {
    let out = tempfile::tempdir().unwrap();
    let cases = materialize(Path::new("tests/fixtures/programs/vault"), sample_mutants(), out.path());
    assert_eq!(cases.len(), 2);
    for c in &cases {
        assert!(c.mutant.join("label.json").exists());
        assert!(c.mutant.join("src/lib.rs").exists());
        assert!(c.original.join("src/lib.rs").exists());
    }
}

#[test]
fn the_compile_gate_rejects_a_syntactically_broken_mutant() {
    let dir = tempfile::tempdir().unwrap();
    write_minimal_crate(dir.path(), "fn main() { let x = ; }");
    assert!(compile_gate(dir.path()).is_err());
}

#[test]
fn the_compile_gate_accepts_a_valid_crate() {
    let dir = tempfile::tempdir().unwrap();
    write_minimal_crate(dir.path(), "fn main() {}");
    assert!(compile_gate(dir.path()).is_ok());
}
```

Mark the two `compile_gate` tests `#[ignore]` if `cargo check` inside a test proves slow
on the dev machine; they must still run in the `just eval` target.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-core eval` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify against the real fixture.**

The fixture at `tests/fixtures/programs/vault` must become a **compilable crate** for the
gate to mean anything: give it a `Cargo.toml` depending on `anchor-lang = "0.30"`, and
keep it out of the workspace with `[workspace]` (empty table) in its manifest so
`cargo test` at the root never builds it.

Run: `cargo run -p dike-cli -- eval mutate tests/fixtures/programs/vault --out target/mutants`
Expected: one directory per mutant, each with `label.json`; `rejected.json` present and
listing zero entries (a non-empty list means an operator emits broken code — fix the
operator, do not disable the gate).

- [ ] **Step 5: Commit** — `git commit -am "feat: mutant materialization with a cargo check validity gate"`

---

## Phase 8 — Differential Eval Harness

Deliverable: `just eval` produces a per-class, per-track recall/precision table plus a noise floor, appended to `benchmarks/history.json`; CI runs the Track-1-only subset on every push.

### Task 25: Differential runner

**Files:**
- Create: `crates/dike-core/src/eval/differential.rs`

**Interfaces:**
- Consumes: `EvalCase`, `Report`, `Finding`.
- Produces: `pub struct CaseOutcome { pub case: String, pub label: MutationLabel, pub detected: bool, pub detecting_tracks: Vec<Track>, pub introduced: Vec<Finding>, pub persistent: Vec<Finding> }`; `pub fn diff_runs(original: &[Finding], mutant: &[Finding], label: &MutationLabel) -> CaseOutcome`.

The mechanism that makes every other number trustworthy (spec §8). It sidesteps
"is the base program actually clean?" — unanswerable, and it would otherwise poison every
precision figure.

- **True positive**: a finding present in the mutant run, **absent** in the original run, whose `(handler, class)` matches the label. Handler granularity + class, never line-exact — line-exact is too strict and would understate real hits.
- **Noise floor**: findings present in **both** runs. Reported separately, per 1000 LOC of the whole program (D18), never counted as false positives against the mutation.
- **False positive**: introduced by the mutation but matching neither the label's class nor its handler.

Set membership uses `merge_key()` — the same key the merge stage uses, so a finding that
corroborates is the same finding that matches.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn a_finding_that_appears_only_in_the_mutant_at_the_label_site_is_a_true_positive() {
    let label = label("missing-signer", "withdraw");
    let original = vec![];
    let mutant = vec![f("missing-signer", "withdraw", Track::Static)];
    let o = diff_runs(&original, &mutant, &label);
    assert!(o.detected);
    assert_eq!(o.detecting_tracks, vec![Track::Static]);
}

#[test]
fn a_finding_present_in_both_runs_is_noise_not_a_detection() {
    let label = label("missing-signer", "withdraw");
    let pre_existing = vec![f("missing-signer", "withdraw", Track::Static)];
    let o = diff_runs(&pre_existing, &pre_existing, &label);
    assert!(!o.detected, "it was already there; the mutation did not cause it");
    assert_eq!(o.persistent.len(), 1);
}

#[test]
fn matching_is_handler_granular_not_line_exact() {
    let label = MutationLabel { line: 42, ..label("missing-signer", "withdraw") };
    let mut found = f("missing-signer", "withdraw", Track::Static);
    found.location.line = 7;
    assert!(diff_runs(&[], &[found], &label).detected);
}

#[test]
fn the_right_class_in_the_wrong_handler_is_not_a_detection() {
    let label = label("missing-signer", "withdraw");
    let found = f("missing-signer", "deposit", Track::Static);
    let o = diff_runs(&[], &[found], &label);
    assert!(!o.detected);
    assert_eq!(o.introduced.len(), 1);
}

#[test]
fn both_tracks_detecting_is_recorded_per_track() {
    let label = label("missing-signer", "withdraw");
    let mutant = vec![
        f("missing-signer", "withdraw", Track::Static),
        f("missing-signer", "withdraw", Track::Llm),
    ];
    let o = diff_runs(&[], &mutant, &label);
    assert_eq!(o.detecting_tracks.len(), 2);
}
```

That last test is why `diff_runs` takes an **unmerged** per-track finding list: merging
first would collapse the two into one corroborated finding and destroy the per-track
attribution the spec's hard rule requires.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-core differential` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-core` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: differential evaluation of original vs mutant runs"`

---

### Task 26: Metrics, noise floor, and history

**Files:**
- Create: `crates/dike-core/src/eval/metrics.rs`, `crates/dike-core/src/eval/history.rs`
- Create: `benchmarks/history.json` (initialized to `[]`)

**Interfaces:**
- Consumes: `CaseOutcome`.
- Produces: `pub struct ClassMetrics { pub class: String, pub track: Track, pub true_positives: usize, pub total_cases: usize, pub false_positives: usize, pub recall: f32, pub precision: f32 }`; `pub struct NoiseFloor { pub track: Track, pub findings: usize, pub loc: usize, pub per_kloc: f32 }`; `pub struct EvalSummary { pub run_id: String, pub timestamp: String, pub tool_version: String, pub model: Option<String>, pub corpus_hash: Option<String>, pub per_class: Vec<ClassMetrics>, pub noise: Vec<NoiseFloor>, pub cases_rejected: usize }`; `pub fn summarize(outcomes: &[CaseOutcome], loc: usize) -> EvalSummary`; `pub fn append_history(path: &Path, summary: &EvalSummary) -> anyhow::Result<()>`; `pub fn render_table(summary: &EvalSummary) -> String`.

**Recall is the primary metric** (spec §1, §8) — put it in the first numeric column of
`render_table` and label the table with that fact. Report `static`, `llm`, and `merged` as
three separate rows per class, never a single blended number.

`append_history` reads `benchmarks/history.json` as an array, pushes the summary, and
writes it back pretty-printed with a stable key order so diffs stay readable. Schema is
`EvalSummary`'s serde representation; add a `schema_version: u32` field set to `1` so a
later change is detectable rather than silently corrupting the series.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn recall_is_computed_per_class_and_per_track() {
    let outcomes = vec![
        outcome("missing-signer", true, vec![Track::Static]),
        outcome("missing-signer", true, vec![Track::Static, Track::Llm]),
        outcome("missing-signer", false, vec![]),
        outcome("removed-guard", true, vec![Track::Llm]),
    ];
    let s = summarize(&outcomes, 1000);
    let static_signer = s.per_class.iter()
        .find(|m| m.class == "missing-signer" && m.track == Track::Static).unwrap();
    assert_eq!(static_signer.true_positives, 2);
    assert_eq!(static_signer.total_cases, 3);
    assert!((static_signer.recall - 2.0 / 3.0).abs() < 1e-6);

    let static_guard = s.per_class.iter()
        .find(|m| m.class == "removed-guard" && m.track == Track::Static).unwrap();
    assert_eq!(static_guard.recall, 0.0, "Track 1 has no removed-guard detector by design");
}

#[test]
fn noise_floor_is_per_1000_loc_of_the_whole_program() {
    let outcomes = vec![outcome_with_persistent("missing-signer", 5)];
    let s = summarize(&outcomes, 2000);
    let n = s.noise.iter().find(|n| n.track == Track::Static).unwrap();
    assert!((n.per_kloc - 2.5).abs() < 1e-6);
}

#[test]
fn history_appends_without_losing_prior_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.json");
    std::fs::write(&path, "[]").unwrap();
    append_history(&path, &sample_summary("run-1")).unwrap();
    append_history(&path, &sample_summary("run-2")).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let runs: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0]["run_id"], "run-1");
    assert_eq!(runs[0]["schema_version"], 1);
}

#[test]
fn the_table_leads_with_recall_and_separates_tracks() {
    let t = render_table(&sample_summary("r"));
    assert!(t.contains("Recall"));
    assert!(t.contains("static") && t.contains("llm") && t.contains("merged"));
    let header = t.lines().find(|l| l.contains("Recall")).unwrap();
    assert!(header.find("Recall").unwrap() < header.find("Precision").unwrap());
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-core metrics` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify it passes.** `cargo test -p dike-core` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: per-class per-track eval metrics with noise floor and history"`

---

### Task 27: `dike eval run`, CI, invocation targets, and the holdout scaffold

**Files:**
- Create: `justfile`, `.github/workflows/ci.yml`, `benchmarks/holdout/cases.toml`, `README.md`
- Modify: `crates/dike-cli/src/commands/eval.rs`

**Interfaces:**
- Consumes: everything.
- Produces: CLI `dike eval run <PROGRAM>... [--track static|llm|merged|all] [--out benchmarks/history.json]` and `dike eval holdout`.

**`dike eval run`** per program: parse → generate mutants → compile-gate → for each
surviving case, analyze the original once and the mutant once (caching the original run —
it is identical across every mutant of that program and is otherwise the dominant cost) →
`diff_runs` → `summarize` → `render_table` to stdout → `append_history`.

`--track static` skips Track 2 entirely, requires no model, and is the mode CI runs
(spec §8: GitHub Actions runners have no GPU, so the local model cannot run there).

**`justfile`** — this is the invocation story from §9.1. Cargo has no pre-build hook
(`build.rs` is not one: it runs per-package during compilation, fires on dependency
changes, and cannot cleanly abort a workspace with a readable report), and `anchor build`
offers no hook either, so invocation is a wrapper task:

```make
# Advisory security pass, then the real build. dike never blocks: exit code is always 0.
check program:
    cargo run -p dike-cli -- analyze {{program}}
    anchor build

# Full local eval including Track 2. Requires Ollama running and an indexed corpus.
eval:
    cargo run -p dike-cli -- corpus index
    cargo run -p dike-cli -- eval run tests/fixtures/programs/* --track all

# What CI runs. Deterministic, no model, no network.
eval-static:
    cargo run -p dike-cli -- eval run tests/fixtures/programs/* --track static

install-hook:
    printf '#!/bin/sh\ncargo run -q -p dike-cli -- analyze .\nexit 0\n' > .git/hooks/pre-push
    chmod +x .git/hooks/pre-push
```

**`.github/workflows/ci.yml`**: `cargo fmt --check`, `cargo clippy -- -D warnings`,
`cargo test --workspace`, then `just eval-static`. Add an **optional** job, gated on
`secrets.GEMINI_API_KEY` being present and `continue-on-error: true`, running a
smoke subset against the Gemini free tier — a missing key must never fail the build.

**Holdout scaffold** — `benchmarks/holdout/cases.toml`, 15–30 published findings mapped to
specific commits:

```toml
[[case]]
id = "wormhole-uninitialized-2022"
repo = "https://github.com/..."
commit = "0000000"
handler = "verify_signatures"
class = "missing-owner-check"
severity = "critical"
source = "https://.../disclosure"
```

`dike eval holdout` reads this file, and **fails with a clear message** if the harness has
been run against it more than once in a git-tracked way. Two rules, both from the spec:
this set is touched **only at the end** — iterating on it means tuning on the test set —
and every report of holdout numbers must state the memorization caveat explicitly, since
famous bugs are plausibly in the model's pretraining data. Print that caveat as part of
the command's output, not as a footnote someone can drop.

**`README.md`** must carry the through-line: *the eval harness turns every extension from
a guess into a measurable experiment* — plus the D16 coverage table, the $0 cost story
(local model in the loop, frontier model as reference), and an unmissable statement that
dike is a triage tool that never proves absence and never blocks a build.

- [ ] **Step 1: Write the failing test**

`crates/dike-cli/tests/eval_cli.rs`:

```rust
#[test]
fn static_eval_runs_end_to_end_without_a_model_and_exits_zero() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_dike"))
        .args(["eval", "run", "tests/fixtures/programs/vault", "--track", "static",
               "--out", "target/test-history.json"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Recall"));
    assert!(stdout.contains("missing-signer"));
    assert!(stdout.contains("Noise floor"));
}

#[test]
fn static_eval_detects_every_track1_covered_class_on_the_fixture() {
    // The fixture is built so all five Track 1 classes have an applicable
    // mutation site. Anything below 100% here is a detector bug, not a model result.
    let summary = run_static_eval_and_parse();
    for class in ["missing-signer", "missing-owner-check", "missing-authority-binding",
                  "pda-validation-gap", "unchecked-arithmetic"] {
        let m = summary.per_class.iter()
            .find(|m| m.class == class && m.track == dike_core::Track::Static)
            .unwrap_or_else(|| panic!("no static row for {class}"));
        assert!(m.recall > 0.0, "{class} recall is zero");
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p dike-cli` → FAIL.
- [ ] **Step 3: Implement `dike eval run` and `dike eval holdout`.**
- [ ] **Step 4: Write `justfile`, the CI workflow, `cases.toml`, and `README.md`.**
- [ ] **Step 5: Verify the whole thing**

Run: `cargo fmt --check && cargo clippy --workspace -- -D warnings && cargo test --workspace`
Expected: PASS, no warnings.

Run: `just eval-static`
Expected: a table whose first numeric column is Recall, one row per (class, track), a noise-floor line, and a new entry in `benchmarks/history.json`.

Run (Ollama up, corpus indexed): `just eval`
Expected: the same table with populated `llm` and `merged` rows.

- [ ] **Step 6: Commit**

```bash
git add justfile .github benchmarks README.md crates/
git commit -m "feat: eval CLI, CI workflow, invocation targets and holdout scaffold"
```

---

## Spec Coverage Map

| Spec section | Where it lands |
|---|---|
| §1 triage not gate, recall primary | Global Constraints; Task 4 (exit 0); Task 26 (recall first) |
| §1 non-goals | Task 4 (no `--fail-on`); Task 27 README |
| §3 `dike-core` domain-agnostic | Tasks 1–4; enforced by the seam test in Task 4 |
| §3 `Finding` fields | Task 1 |
| §3 per-detector confidence constants | Task 9 (D16 table) |
| §3 Track 2 confidence clamped/down-weighted | Task 3 (`track2_confidence`), Task 21 |
| §3 `Analyzer` trait as the seam | Task 2; used by Tasks 13 and 22 |
| §4 two independent tracks, hard separation | Task 4 (`TrackFindings`), Task 25 (unmerged input) |
| §5 IR | Tasks 5–8 (extended per D7–D10) |
| §6 data flow steps 1–6 | Tasks 2, 7, 13, 22, 3, 4 |
| §6 corroboration and ranking | Task 3 |
| §7 corpus + licensing | Tasks 14 (model, manifest), 15 (fetch, normalization) |
| §7 chunk by finding | Task 14 (`chunk_by_finding`) |
| §7 derived query | Task 20 (`derive_query`) |
| §7 hybrid + RRF k=60 + vector store | Tasks 16 (BM25), 17 (dense + store), 18 (RRF fusion). **`sqlite-vec` deviated from per D25** — plain `rusqlite` BLOB + linear cosine; spec §10's stated requirements (one file, no server, reproducible) all hold. |
| §7 grounding rule | Tasks 18 (`is_grounded`), 21 (`validate_citations`) |
| §7 no reranker in v1 | Not implemented — deliberate (spec §11.2) |
| §8 mutation catalogue | Task 23 (six of eight, D13) |
| §8 differential evaluation | Task 25 |
| §8 handler-granular matching | Task 25 |
| §8 metrics per class/track + noise floor | Task 26 |
| §8 real holdout, touched last | Task 27 |
| §8 CI constraint (no GPU) | Task 27 |
| §9 error handling table | Task 2 (parse), 21 (schema retry), 22 (unavailable), 18 (ungrounded), 19 (timeout), 4 (provenance) |
| §9.1 invocation | Task 27 (`justfile`, CI step, pre-push hook) |
| §10 stack and cost | Tasks 15, 17, 19 (all local/free) |
| §11 extension paths | Task 27 README; the seam test keeps path 1 open |
| §12 open item — holdout selection | Task 27 (`cases.toml` to be populated) |
| §12 open item — tantivy vs simple BM25 | Task 16 (decided: tantivy behind the `Bm25Index` interface; revisit with a real corpus) |

## Deferred, on purpose

- `state write after CPI` and `rounding flip` mutation operators (D13) — no Track 1 detector, semantically hard rewrites. Add after single-handler numbers are solid.
- `missing-reload` and `rounding-leak` detectors — same reason.
- Cross-encoder reranking (spec §11.2) — the harness now exists to prove its value rather than assume it.
- Cross-instruction invariants, native Solana programs, `dike-lang-solidity` (spec §11).
