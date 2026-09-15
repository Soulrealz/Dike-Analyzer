# Dike

Security triage for Solana Anchor programs.

Dike parses Anchor source, runs deterministic static detectors over a
Solana-aware IR, adds a retrieval-grounded LLM pass, and produces a ranked report
of candidate vulnerabilities for a human auditor.

Dike is triage. It never proves absence and it never blocks a build. A clean
report means these detectors found nothing, which is weaker than there being
nothing to find. Findings never change the exit code; non-zero is reserved for
the tool itself failing. There is no `--fail-on` flag and there will not be one,
because a security tool that blocks builds gets uninstalled. The report is
evidence for a human to work from.

Recall is the primary metric. A false positive costs you a minute, a false
negative costs you the bug, so ambiguous calls in this codebase resolve toward
reporting more.

Extensions are meant to be measurable. The eval harness injects one known
vulnerability at a time into a program that is known clean, runs the analyzer
over both copies, and scores only what the injection caused. That is what makes
"this change improved recall" a claim you can check:

```bash
just eval-static     # no model, no network — the mode CI runs
```

```
| Class                       | Track  | Recall | Detected | Cases | Precision |
|-----------------------------|--------|-------:|---------:|------:|----------:|
| `missing-authority-binding` | static |  1.000 |        3 |     3 |     1.000 |
| `missing-owner-check`       | static |  1.000 |        4 |     4 |     1.000 |
| `missing-signer`            | static |  1.000 |        3 |     3 |     1.000 |
| `pda-validation-gap`        | static |  1.000 |        4 |     4 |     1.000 |
| `unchecked-arithmetic`      | static |  1.000 |        2 |     2 |     1.000 |
```

Every class with a Track 1 detector is at 1.000 there. `pda-validation-gap` sat
at 0.000 for three days first: the harness caught a detector that could not fire
on any program Anchor will compile, which is what it is for. See
[Known gaps](#known-gaps) for what is still missing.

## Requirements

| | Version | Needed for |
|---|---|---|
| Rust | stable (pinned in `rust-toolchain.toml`, developed on 1.93) | everything |
| `just` | any | the invocation targets; every one is a plain `cargo` command you can also run directly |
| Ollama | 0.33+ | Track 2 and `just eval` only; static analysis and `just eval-static` do not need it |

`rustup` will install the pinned toolchain automatically on first build, along
with `rustfmt` and `clippy`.

## Setup

```bash
git clone <this repo>
cd Dike-Analyzer
cargo build
```

That is the whole setup. There is no code generation step, no schema build, and
nothing to vendor. The first build is slow (the workspace pulls `syn`,
`tantivy`, `reqwest` and `rusqlite`); later builds are fast.

Verify the install:

```bash
cargo test --workspace
cargo run -p dike-cli -- analyze tests/fixtures/programs/vault
```

The second command should print a report with `Handlers found: 4`, no findings,
and exit `0`. That fixture is deliberately correct code, so finding nothing in it
is the pass condition.

## Usage

```bash
# Analyze a program directory (Markdown to stdout)
dike analyze path/to/program

# JSON, for tooling
dike analyze path/to/program --format json

# Write to a file
dike analyze path/to/program --out report.md

# Debug: dump the parsed IR
dike ir path/to/program
```

Run it from the workspace with `cargo run -p dike-cli -- analyze …`, or
`cargo install --path crates/dike-cli` to get a `dike` binary on your PATH.

### Corpus

The LLM track grounds every finding in retrieved precedent. The corpus manifest
lives in `corpus/sources.toml`.

```bash
dike corpus fetch                  # download and normalize sources
dike corpus fetch --update-hashes  # …and record content hashes in the manifest
dike corpus fetch --verify         # fail if any source changed upstream (CI mode)
```

`fetch` makes live network requests. Fetched text lands in `corpus/cache/`,
which is gitignored: audit reports are published but not public domain, so we
never redistribute them. The manifest and the fetch code are committed, the
content is not. Notes we write ourselves go in `corpus/notes/` and *are*
committed.

Three audit-report sources are currently commented out in the manifest. They
pointed at blog index pages, which fetch as navigation chrome instead of finding
text. Curate specific report URLs before the first real fetch.

## What it detects

Per-track class coverage, declared up front so the eval table reads as
information. A `0.000` in a row Track 1 does not cover is the expected result
rather than a regression.

| Class | Track 1 | Track 2 | Severity | Confidence | What it means |
|---|:---:|:---:|---|---:|---|
| `missing-signer` | yes | yes | Critical | 0.90 | A privileged-looking account is not a `Signer` and nothing else pins it |
| `missing-owner-check` | yes | yes | High | 0.75 | An unchecked wrapper with nothing pinning its identity |
| `missing-authority-binding` | yes | yes | High | 0.70 | A stored authority field is never validated against the caller |
| `pda-validation-gap` | yes | yes | High | 0.65 | An account this program derives with `seeds` elsewhere is taken here without pinning the derivation |
| `unchecked-arithmetic` | yes | yes | Medium | 0.35 | Bare arithmetic in a release-mode program, where overflow wraps |
| `removed-guard` | no | yes | High | — | A `constraint = ...` guard is absent. Track 2 only, because the absence of an arbitrary expression is not a structural signal a detector can see |

Track 1 confidences are pinned constants, never computed. The eval harness
compares runs across time, so a "small improvement" to one silently invalidates
every earlier number in `benchmarks/history.json`.

A suppression pass removes findings already covered by an imperative check in the
handler body (`require_keys_eq!`, an `X.is_signer` assertion, an
`X.field == other.key()` comparison). Suppressed findings are counted in the
coverage block, never silently dropped.

## Evaluating it

The harness mutates a clean program, one injected defect per mutant, labelled by
the operator that injected it. It validates that each mutant still compiles, runs
the analyzer over the clean copy and the mutant, and credits a finding only when
the mutation caused it. A finding the analyzer already made on the clean program
is the *noise floor*: reported separately, counted against neither recall nor
precision. This sidesteps "is the base program actually clean?", which is
unanswerable and would otherwise poison every precision number.

```bash
just eval-static   # Track 1 only. No model, no network. What CI runs.
just eval-fast     # …skipping the validity gate. For iterating, never for numbers.
just eval          # Both tracks. Needs Ollama running and an indexed corpus.
just holdout       # List the real holdout and its memorization caveat.
just holdout-dry   # The scoring path, offline. Records nothing, spends no run.
just holdout-score # THE scored run. Once, ever. Clones each program.

# Or the commands underneath:
dike eval mutate tests/fixtures/programs/vault --out target/mutants
dike eval run    tests/fixtures/programs/vault --track static
```

Each run appends to `benchmarks/history.json`, which is committed: the harness
exists to compare runs over time, and a series that is not kept answers nothing.

A mutant that no longer compiles is broken code rather than vulnerable code, and
a finding triggered by broken code still counts as a true positive, inflating the
one number the harness exists to make trustworthy. So every mutant goes through
`cargo check` first, and rejects are recorded with the compiler's own reason
instead of being dropped. This is the only place dike shells out to `cargo`, and
it runs only against fixtures in this repository, never against a program you
asked it to analyze.

## Cost

Running Dike costs nothing, which is a design constraint. Eval loops need
unlimited iterations, and a per-token bill would cap how often the harness can
run, which caps how often a change can be checked.

| Component | Choice | Cost |
|---|---|---|
| Analyzer, CLI, detectors | Rust + `syn` | $0 |
| LLM (eval loops) | Qwen2.5-Coder 14B Q4 via Ollama, local | $0 |
| LLM (spot checks) | Gemini free tier | $0 |
| Embeddings | BGE-small-en v1.5, local | $0 |
| Sparse index / vector store | `tantivy` / `rusqlite` | $0 |
| Corpus | Public sources | $0 |
| CI | GitHub Actions | $0 |

The local model runs in the loop and the hosted free tier is kept for comparison
runs against a frontier model, never for iteration.

## Known gaps

- **The holdout has six verified cases and has not been scored.**
  `benchmarks/holdout/cases.toml` was populated on 2026-09-06 from two public
  Solana audit contests (WOOFi and Orderly, accepted findings only) plus the
  Cashio infinite-mint. Six rather than the 15–30 target, because the
  intersection of "published finding", "Anchor program" and "resolvable public
  commit" is small: most of the widely cited Solana disclosures are native
  programs, which yield zero handlers. `dike eval holdout --score` can score
  them now, and `runs.json` is still `[]` because the set permits one run and
  spending it is a decision, not a step. Four of the six cases are
  `removed-guard`, which only Track 2 reports, while the scorer runs Track 1
  only — so a run today reaches two of the six. The command says so before it
  scores anything.
- **Track 2 has never detected anything in a scored run.** Recall is 0.000 on
  every class against `qwen2.5-coder:14b`, and that is a real measurement rather
  than a broken pipe: the plumbing was fixed until dropped replies went from 36
  to 0, and the number did not move. The model returns an empty array for most
  units. The open question is whether retrieval is too coarse (one query per
  handler, built from the whole handler description) or whether the local model
  is the ceiling, and comparing it against a frontier model on the same
  retrieved context is what would tell the two apart.
- **`cargo fmt --check` is not a gate.** The house style is hand-formatted and no
  rustfmt configuration reproduces it, so the CI gate is `clippy`, which is
  deny-by-default here.

## Repo layout

```
crates/dike-core/         Domain-agnostic: Finding, Analyzer seam, merge, report, retrieval
crates/dike-lang-anchor/  Solana/Anchor: IR, parser, detectors
crates/dike-cli/          Orchestration and the `dike` binary
corpus/                   Retrieval corpus manifest and notes
benchmarks/               The eval series, and the real holdout
docs/                     Architecture map, design spec, implementation plan
tests/fixtures/programs/  Anchor fixture programs, parsed as text
```

`tests/fixtures/programs/vault` is the exception to "parsed as text": it is a
real crate, because the mutation-validity gate has to build its mutants. An
empty `[workspace]` table in its manifest keeps it out of the root workspace, so
`cargo test` never builds it.

`dike-core` knows nothing about Solana, so adding Solidity support would mean a
new crate beside it. `crates/dike-core/tests/seam.rs` enforces that mechanically.

Start here:

- [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md): architecture, invariants, and the decisions that look odd until you know why
- [`CLAUDE.md`](CLAUDE.md): rules for AI assistants working in this repo
- [`docs/superpowers/specs/`](docs/superpowers/specs/): the approved design
- [`docs/superpowers/plans/`](docs/superpowers/plans/): the task-by-task build plan

## Development

```bash
cargo test --workspace                                  # full suite
cargo clippy --workspace --all-targets -- -D warnings   # lints are deny-by-default
cargo test -p dike-core --test seam                     # the architectural gate
cargo run -p dike-cli -- analyze tests/fixtures/programs/vault   # exit 0, no findings
```

Or `just gates`. All four must be clean. `clippy` warnings are errors here and
have broken the build more than once.

Before adding a test, ask what change would make it fail. If the answer is
"nothing," it is not a test. See Rule 6 in `CLAUDE.md`.

## Status

Both tracks run end to end, and the eval harness scores them. On the clean
fixture Track 1 reaches recall 1.000 and precision 1.000 on the four classes with
a reachable detector, at a noise floor of zero. Track 2 has been verified against
a live local model: on the vulnerable fixture it independently reports
`missing-signer` on `withdraw`, which merges with Track 1's finding into a
corroborated Critical carrying its citation.

Still open: the holdout can be scored but has not been, and the CI LLM job is a
build check rather than a scored run, because GitHub runners have no GPU and the
local model cannot run there. See `docs/PROJECT_CONTEXT.md` for the current state in
detail.

## License

MIT OR Apache-2.0
