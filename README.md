# Dike

Security triage for Solana Anchor programs.

Dike parses Anchor source, runs deterministic static detectors over a
Solana-aware IR, and produces a ranked report of candidate vulnerabilities for a
human auditor. A retrieval-grounded LLM pass and a mutation-based evaluation
harness are in progress.

**It is triage, not a gate.** Findings never change the exit code — non-zero is
reserved for tool failure. The report is advice; you decide what to do with it.

**Recall is the primary metric.** A false positive costs you a minute. A false
negative costs you the bug.

---

## Requirements

| | Version | Needed for |
|---|---|---|
| Rust | stable (pinned in `rust-toolchain.toml`, developed on 1.93) | everything |
| Ollama | 0.33+ | Phase 6 Track 2 only — not needed for static analysis |

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

### Corpus (Phase 5, in progress)

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

Five deterministic classes today, each with a pinned confidence:

| Class | Severity | What it means |
|---|---|---|
| `missing-signer` | Critical | A privileged-looking account is not a `Signer` and nothing else pins it |
| `missing-owner-check` | High | An unchecked wrapper with nothing pinning its identity |
| `missing-authority-binding` | High | A stored authority field is never validated against the caller |
| `pda-validation-gap` | High | `seeds` without `bump`, or `bump` without `seeds` |
| `unchecked-arithmetic` | Medium | Bare arithmetic in a release-mode program, where overflow wraps |

A suppression pass removes findings already covered by an imperative check in the
handler body (`require_keys_eq!`, an `X.is_signer` assertion, an
`X.field == other.key()` comparison). Suppressed findings are counted in the
coverage block, never silently dropped.

## Repo layout

```
crates/dike-core/         Domain-agnostic: Finding, Analyzer seam, merge, report, retrieval
crates/dike-lang-anchor/  Solana/Anchor: IR, parser, detectors
crates/dike-cli/          Orchestration and the `dike` binary
corpus/                   Retrieval corpus manifest and notes
docs/                     Architecture map, design spec, implementation plan
tests/fixtures/programs/  Anchor fixture programs (parsed as text, never built)
```

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
```

All three must be clean. `clippy` warnings are errors here and have broken the
build more than once.

Before adding a test, ask what change would make it fail. If the answer is
"nothing," it is not a test — see Rule 6 in `CLAUDE.md`.

## Status

Phases 1–4 complete; Phase 5 (retrieval) in progress. The static track runs end
to end and is verified to report real findings on vulnerable code. Track 2 (LLM),
the mutation engine, and the differential eval harness are not yet built. See
`docs/PROJECT_CONTEXT.md` for the current state in detail.

## License

MIT OR Apache-2.0
