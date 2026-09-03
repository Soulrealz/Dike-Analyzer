# Dike

Security triage for Solana Anchor programs.

Dike parses Anchor source, runs deterministic static detectors over a
Solana-aware IR, adds a retrieval-grounded LLM pass, and produces a ranked report
of candidate vulnerabilities for a human auditor.

> ### Dike is triage. It never proves absence, and it never blocks a build.
>
> A clean report means *these detectors found nothing*, which is not the same as
> *there is nothing*. Findings never change the exit code — non-zero is reserved
> for the tool itself failing. There is no `--fail-on` flag and there will not
> be one: a security tool that blocks a build is a security tool people
> uninstall. The report is evidence for a human, not a verdict.

**Recall is the primary metric.** A false positive costs you a minute. A false
negative costs you the bug. Every ambiguous call in this codebase resolves
toward reporting more, not less.

**Every extension is a measurable experiment, not a guess.** The eval harness
injects one known vulnerability at a time into a program that is known clean,
runs the analyzer over both copies, and scores only what the injection caused.
That is what makes "this change improved recall" a claim you can check rather
than a feeling:

```bash
just eval-static     # no model, no network — the mode CI runs
```

```
| Class                       | Track  | Recall | Detected | Cases | Precision |
|-----------------------------|--------|-------:|---------:|------:|----------:|
| `missing-authority-binding` | static |  1.000 |        3 |     3 |     1.000 |
| `missing-owner-check`       | static |  1.000 |        4 |     4 |     1.000 |
| `missing-signer`            | static |  1.000 |        3 |     3 |     1.000 |
| `pda-validation-gap`        | static |  0.000 |        0 |     4 |         - |
| `unchecked-arithmetic`      | static |  1.000 |        2 |     2 |     1.000 |
```

That `0.000` is the harness doing its job on its first run. See
[Known gaps](#known-gaps).

---

## Requirements

| | Version | Needed for |
|---|---|---|
| Rust | stable (pinned in `rust-toolchain.toml`, developed on 1.93) | everything |
| `just` | any | the invocation targets; every one is a plain `cargo` command you can also run directly |
| Ollama | 0.33+ | Track 2 and `just eval` only — not needed for static analysis or `just eval-static` |

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
and exit `0`. That fixture is deliberately correct code — finding nothing in it
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
which is gitignored — **audit reports are published, not public-domain, so we
never redistribute them.** The manifest and the fetch code are committed; the
content is not. Notes we write ourselves go in `corpus/notes/` and *are*
committed.

> Three audit-report sources are currently commented out in the manifest: they
> pointed at blog index pages, which fetch as navigation chrome rather than
> finding text. Curate specific report URLs before the first real fetch.

## What it detects

Per-track class coverage. Declared up front so the eval table reads as
information rather than as alarm — a `0.000` in a row Track 1 does not cover is
the expected result, not a regression.

| Class | Track 1 | Track 2 | Severity | Confidence | What it means |
|---|:---:|:---:|---|---:|---|
| `missing-signer` | yes | yes | Critical | 0.90 | A privileged-looking account is not a `Signer` and nothing else pins it |
| `missing-owner-check` | yes | yes | High | 0.75 | An unchecked wrapper with nothing pinning its identity |
| `missing-authority-binding` | yes | yes | High | 0.70 | A stored authority field is never validated against the caller |
| `pda-validation-gap` | yes | yes | High | 0.65 | An account's PDA derivation is not pinned |
| `unchecked-arithmetic` | yes | yes | Medium | 0.35 | Bare arithmetic in a release-mode program, where overflow wraps |
| `removed-guard` | **no** | yes | High | — | A `constraint = ...` guard is absent. Track 2 only: the absence of an arbitrary expression is not a structural signal a detector can see |

Track 1 confidences are pinned constants, never computed. The eval harness
compares runs across time, so a "small improvement" to one silently invalidates
every earlier number in `benchmarks/history.json`.

A suppression pass removes findings already covered by an imperative check in the
handler body (`require_keys_eq!`, an `X.is_signer` assertion, an
`X.field == other.key()` comparison). Suppressed findings are counted in the
coverage block, never silently dropped.

## Evaluating it

The harness mutates a clean program — one injected defect per mutant, labelled
by the operator that injected it — validates that each mutant still compiles,
runs the analyzer over the clean copy and the mutant, and credits a finding only
when the mutation caused it. A finding the analyzer already made on the clean
program is the *noise floor*: reported separately, counted against neither
recall nor precision. This sidesteps "is the base program actually clean?",
which is unanswerable and would otherwise poison every precision number.

```bash
just eval-static   # Track 1 only. No model, no network. What CI runs.
just eval-fast     # …skipping the validity gate. For iterating, never for numbers.
just eval          # Both tracks. Needs Ollama running and an indexed corpus.
just holdout       # The real-holdout scaffold, with its memorization caveat.

# Or the commands underneath:
dike eval mutate tests/fixtures/programs/vault --out target/mutants
dike eval run    tests/fixtures/programs/vault --track static
```

Each run appends to `benchmarks/history.json`, which is committed: the harness
exists to compare runs over time, and a series that is not kept answers nothing.

**A mutant that no longer compiles is not a vulnerable program, it is a broken
one** — and a finding triggered by broken code counts as a true positive and
silently inflates the one number the harness exists to make trustworthy. So
every mutant is put through `cargo check` first, and rejects are recorded with
the compiler's own reason rather than dropped. This is the only place dike shells
out to `cargo`, and it runs only against fixtures in this repository, never
against a program you asked it to analyze.

## Cost

**$0**, and that is a design constraint rather than a boast: eval loops need
unlimited iterations, and a per-token bill would cap how often the harness can be
run — which is the same as capping how often a change can be checked.

| Component | Choice | Cost |
|---|---|---|
| Analyzer, CLI, detectors | Rust + `syn` | $0 |
| LLM — eval loops | Qwen2.5-Coder 14B Q4 via Ollama, local | $0 |
| LLM — spot checks | Gemini free tier | $0 |
| Embeddings | BGE-small-en v1.5, local | $0 |
| Sparse index / vector store | `tantivy` / `rusqlite` | $0 |
| Corpus | Public sources | $0 |
| CI | GitHub Actions | $0 |

Local model in the loop, frontier model as reference. The hosted free tier is
reserved for comparison runs, never for iteration.

## Known gaps

- **`pda-validation-gap` scores 0.000 and that number is real.** The detector
  fires on an *inconsistent* pair — `seeds` without `bump`, or the reverse — and
  that condition cannot occur in a program Anchor will compile. Verified against
  `anchor-lang` 0.30: `seeds` without `bump` is rejected at compile time with
  "bump must be provided with seeds". So the detector cannot fire on any real
  program, while the mutation operator removes a whole PDA constraint, which is
  a genuine defect it was never built to see. The class stays in the table at
  zero rather than being quietly excluded, and
  `crates/dike-cli/tests/eval_cli.rs` pins it so that fixing the detector makes
  a test fail rather than passing unnoticed.
- **`benchmarks/holdout/cases.toml` is empty.** Populating it means reading real
  disclosures and resolving real commits; an invented entry would produce a
  real-looking number with no way to tell the difference.
- **`cargo fmt --check` is not a gate.** The house style is hand-formatted and no
  rustfmt configuration reproduces it, so the CI gate is `clippy`, which is
  deny-by-default here.

## Repo layout

```
crates/dike-core/         Domain-agnostic: Finding, Analyzer seam, merge, report, retrieval
crates/dike-lang-anchor/  Solana/Anchor: IR, parser, detectors
crates/dike-cli/          Orchestration and the `dike` binary
corpus/                   Retrieval corpus manifest and notes
benchmarks/               The eval series, and the real-holdout scaffold
docs/                     Architecture map, design spec, implementation plan
tests/fixtures/programs/  Anchor fixture programs, parsed as text
```

`tests/fixtures/programs/vault` is the exception to "parsed as text": it is a
real crate, because the mutation-validity gate has to build its mutants. An
empty `[workspace]` table in its manifest keeps it out of the root workspace, so
`cargo test` never builds it.

`dike-core` knows nothing about Solana — a Solidity port would be a new crate,
not a rewrite. `crates/dike-core/tests/seam.rs` enforces that mechanically.

**Start here:**
- [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) — architecture, invariants, and the decisions that look odd until you know why
- [`CLAUDE.md`](CLAUDE.md) — rules for AI assistants working in this repo
- [`docs/superpowers/specs/`](docs/superpowers/specs/) — the approved design
- [`docs/superpowers/plans/`](docs/superpowers/plans/) — the task-by-task build plan

## Development

```bash
cargo test --workspace                                  # full suite
cargo clippy --workspace --all-targets -- -D warnings   # lints are deny-by-default
cargo test -p dike-core --test seam                     # the architectural gate
cargo run -p dike-cli -- analyze tests/fixtures/programs/vault   # exit 0, no findings
```

Or `just gates`. All four must be clean. `clippy` warnings are errors here and have broken the
build more than once.

Before adding a test, ask what change would make it fail. If the answer is
"nothing," it is not a test — see Rule 6 in `CLAUDE.md`.

## Status

Both tracks run end to end, and the eval harness scores them. On the clean
fixture Track 1 reaches recall 1.000 and precision 1.000 on the four classes with
a reachable detector, at a noise floor of zero. Track 2 has been verified against
a live local model: on the vulnerable fixture it independently reports
`missing-signer` on `withdraw`, which merges with Track 1's finding into a
corroborated Critical carrying its citation.

What is not done: the real holdout is an empty scaffold, and the CI LLM job is a
build check rather than a scored run — GitHub runners have no GPU, so the local
model cannot run there. See `docs/PROJECT_CONTEXT.md` for the current state in
detail.

## License

MIT OR Apache-2.0
