# PROJECT_CONTEXT.md — Architecture & Structure

This file describes **what exists in this repo and why it is laid out this way**.
It is read by AI assistants (Claude Code, Codex) and human contributors to build
an accurate mental model before making changes.

For workflow and process rules, see [../CLAUDE.md](../CLAUDE.md).
This file is architecture, structure, and binding decisions only.

## Maintenance rule

**This file must be kept up to date.** Any change that adds, removes, or
meaningfully restructures a crate, module, command, or major dependency must
update the relevant section here in the same commit. A stale map is worse than
no map — if you are unsure whether a change is "meaningful," ask: would a new
contributor be misled by the old description? If yes, update it.

Do log: new crates, new CLI subcommands, new module boundaries, new
dependencies, changes to the invariants below, and any decision that reverses
one recorded here.

Do not log: a new detector inside an existing detector module, a bugfix, a
dependency patch bump, a new test.

---

## What Dike is

An **AI-assisted security triage tool for Solana Anchor programs.** It parses
Rust source, runs deterministic static detectors over an Anchor-aware IR, and
(from Phase 6) adds a retrieval-grounded LLM pass. It emits a ranked report of
candidate vulnerabilities for a human auditor.

**It is a triage tool, not a gate.** Exit code is `0` even when findings exist;
non-zero is reserved strictly for tool failure (unreadable path, unwritable
output). The developer decides what to do about the report; the tool never
decides for them.

**Recall is the primary metric.** A false positive costs an auditor a minute; a
false negative costs them the bug. Every ambiguous design call in this repo
resolves toward reporting more, not less.

## Current status

**Phases 1–4 complete. Phase 5 (Retrieval) in progress.**

`dike analyze <path>` runs the full static track end to end: it parses an Anchor
program, builds the IR, runs five detectors, applies the imperative-check
suppression pass, ranks the results, and renders Markdown or JSON. It is
verified to report real findings on vulnerable code — not merely silence on
clean code.

- **Phase 1** — core contract: `Finding`, the `Analyzer` seam, merge/ranking, report renderers, CLI shell.
- **Phase 2** — Anchor IR and parser (`syn`-based), `dike ir` debug command.
- **Phase 3** — five static detectors plus the suppression pass.
- **Phase 4** — `AnchorAnalyzer` wired into the pipeline; coverage reporting.
- **Phase 5** — corpus document model, manifest, chunking, hashing (done); HTTP layer and `dike corpus fetch` (done); BM25, embeddings, RRF fusion (next).
- **Phases 6–8** — Track 2 LLM, mutation engine, differential eval harness. Not started.

171 tests pass. `cargo clippy --workspace --all-targets -- -D warnings` is clean.

---

## Folder structure

```
.
├── .superpowers/              SDD agent scaffolding — GITIGNORED, not project history
├── corpus/
│   ├── sources.toml           Corpus manifest: url, kind, licence, retrieval date, class tags
│   ├── notes/                 Our own derived notes — COMMITTED (original work)
│   └── cache/                 Fetched source text — GITIGNORED (see Licensing below)
├── crates/
│   ├── dike-core/             Domain-AGNOSTIC. No Solana vocabulary. See "The seam".
│   │   ├── src/
│   │   │   ├── finding.rs     Finding, Severity, VulnClass, Track, Location, Citation
│   │   │   ├── analyzer.rs    Analyzer trait, SourceTree ingest, Diagnostic, AnalysisResult
│   │   │   ├── merge.rs       Two-track merge, corroboration, deterministic ranking
│   │   │   ├── http.rs        The single HTTP surface (corpus fetch, embedder, LLM client)
│   │   │   ├── report/        Markdown + JSON renderers, Coverage, RunMetadata
│   │   │   └── retrieval/     Corpus Document/Source model, chunking, hashing, fetching
│   │   └── tests/seam.rs      ARCHITECTURAL GATE — fails the build on Solana vocabulary
│   ├── dike-lang-anchor/      Solana/Anchor-specific. Everything domain lives here.
│   │   ├── src/
│   │   │   ├── ir.rs          The Anchor IR: Program, Handler, AccountsStruct, Constraint…
│   │   │   ├── parser/        syn-based parsing: accounts, program, symbols, body summary
│   │   │   ├── detectors/     Five static detectors + the suppression pass
│   │   │   └── lib.rs         AnchorAnalyzer, analyze_program
│   │   └── tests/end_to_end.rs
│   └── dike-cli/              Orchestration only. The ONE place core and Anchor meet.
│       └── src/
│           ├── main.rs        clap subcommands: analyze, ir, corpus
│           ├── pipeline.rs    Runs both tracks, merges, builds the Report
│           ├── config.rs      RunConfig
│           └── commands/      analyze, ir, corpus
├── docs/
│   ├── PROJECT_CONTEXT.md     This file
│   └── superpowers/
│       ├── specs/             Approved design docs
│       └── plans/             Phased implementation plans
├── tests/fixtures/programs/   Anchor fixture programs (deliberately NO Cargo.toml —
│                              they are parsed as text, never built)
├── Cargo.toml                 Workspace root; all dependency versions pinned here
├── Cargo.lock                 COMMITTED — this workspace ships a binary
├── rust-toolchain.toml        Pins stable + rustfmt + clippy
├── CLAUDE.md                  Rules for AI assistants working in this repo
└── README.md                  Setup and usage
```

---

## Architecture

### Three crates, one seam

```
dike-cli  ──uses──>  dike-core   (domain-agnostic: Finding, Analyzer, merge, report, retrieval)
    │                    ▲
    └──uses──>  dike-lang-anchor ─implements─┘   (Solana/Anchor: IR, parser, detectors)
```

`dike-core` defines the `Analyzer` trait and knows nothing about Solana.
`dike-lang-anchor` implements it. `dike-cli` is the only place the two meet.

**Why:** a Solidity port should be a new crate (`dike-lang-solidity`), not a
rewrite. `crates/dike-core/tests/seam.rs` enforces this mechanically — it fails
the build if any non-comment line under `dike-core/src` contains
`anchor`, `solana`, `Signer<`, `AccountInfo`, `UncheckedAccount`, `has_one`,
`invoke_signed`, `pubkey`, `Pubkey`, or `spl_`.

That gate applies to **string literals and test fixtures**, not just
identifiers, and it has caught real violations twice — both times in corpus code
whose natural subject matter *is* Solana. Doc comments (`//`) are exempt.

### Two tracks, merged only at the end

- **Track 1 (static)** — deterministic Rust detectors over the IR. Pure: no I/O,
  no clock, no network. Byte-identical output for identical input.
- **Track 2 (LLM)** — retrieval-grounded model pass over handler units. *Not yet built.*

**Hard rule: Track 2 never feeds Track 1's metrics.** The tracks reach their
conclusions independently and are merged only at the end. When both find the
same `(handler, class)` pair, the finding is marked `Corroborated` and its
confidence rises via noisy-OR. Two independent methods agreeing is the strongest
signal this tool can produce — which is why the Track 2 prompt must **not** be
told to skip classes Track 1 covers, and must **never** be shown Track 1's
findings.

### Data flow

```
SourceTree ──parse──> Program (IR) ──detectors──> raw findings
                                          │
                                   suppression pass
                                          │
                     Track 2 (future) ────┴──> merge ──> rank ──> Report
```

---

## Invariants

These are load-bearing. Breaking one is a defect, not a preference.

| # | Invariant | Enforced by |
|---|---|---|
| 1 | `dike-core` contains no Solana vocabulary | `crates/dike-core/tests/seam.rs` |
| 2 | Exit 0 when findings exist; non-zero only on tool failure | `commands/analyze.rs`, end-to-end checks |
| 3 | Detectors are pure — no I/O, no clock, no randomness | Convention + review; Track 1 must be reproducible |
| 4 | Per-detector confidence values are pinned constants | The eval harness compares runs over time |
| 5 | Identical input yields byte-identical output | `merge::rank` sorts with explicit tiebreakers |
| 6 | Partial results beat no results | Per-file parse tolerance; per-entry archive tolerance |
| 7 | Findings merge on `(handler_id, class)`, never on span or id | `Finding::merge_key` |
| 8 | Fetched corpus content is never committed | `.gitignore`, and the licensing note below |
| 9 | A finding never points at line 0 | `attr_line`-with-fallback in constraint detectors |

---

## Quirks & constraint-driven decisions

Only decisions that look odd at first glance but were the best option under a
real constraint. Ordinary choices need no justification.

- **`VulnClass` is a `String` newtype, not an enum.** An enum would force every
  language's vulnerability vocabulary into `dike-core`, breaking the seam. The
  class constants live in `dike-lang-anchor/src/detectors/mod.rs`.

- **`AccountDecl` carries both `line` and `attr_line`/`attr_end_line`.**
  `line` is the `pub name: Type` line (from `field.ident.span()`);
  `attr_line` spans the `#[account(...)]` attribute. Wrapper-type findings point
  at `line` (that is the line a human edits to fix it); constraint findings point
  at `attr_line`. `syn`'s `Field::span()` *includes* outer attributes, which is
  why `ident.span()` is used instead — this is pinned by a test.

- **`proc-macro2` needs the `span-locations` feature.** Without it every span
  line silently returns 0 and every finding points at line 0.

- **The suppression pass keys on specific idioms, not on account mention.**
  `ImperativeCheck::referenced_accounts` is every identifier in the macro's
  tokens — it means "mentioned", never "validated". A bounds check like
  `require!(amount <= vault.amount, …)` mentions `vault`. So suppression requires
  an anchored `X.is_signer` (for missing-signer — key equality proves identity,
  never authorization), or an anchored `X.key()`, or `require_keys_eq!` plus a
  dereference of `X`, or an `X.field == other.key()` adjacency. This took four
  fix rounds; the reasoning is in code comments at each site. **Do not "simplify"
  them to match each other** — `owner.rs` and `authority.rs` differ deliberately,
  because only one of them has a field-name anchor.

- **Corpus chunks accumulate to 200 characters rather than "merging into the
  predecessor".** The literal predecessor rule lets an unbounded run of short
  findings collapse into one document-sized chunk, which pollutes top-k
  retrieval and is useless to an auditor following a citation.

- **The vector store is plain `rusqlite` with BLOB vectors and a linear cosine
  scan, not `sqlite-vec`.** A documented deviation from the design doc. All three
  of its stated requirements hold (one file, no server, reproducible from the
  fetch script), and at v1 corpus size a linear scan is sub-millisecond.

- **`dike corpus fetch --update-hashes` rewrites `sources.toml` by targeted text
  surgery**, not a TOML round-trip. A round-trip would destroy the commented-out
  source entries and the prose explaining them. The rewrite scopes by the
  preceding `id = "…"` line and writes atomically (temp file + rename).

- **Fixture Anchor programs have no `Cargo.toml`.** They are parsed as text and
  must never be built. The analyzer never invokes `cargo` or `anchor` on a target
  program — the sole exception is the mutation-validity gate in the future eval
  harness, which runs against eval fixtures.

## Licensing (binding)

Audit reports are **published, not public-domain**. The repo commits
`corpus/sources.toml` and the fetch code; it **never** commits fetched PDFs or
report text. `corpus/cache/` is gitignored. `corpus/notes/` holds our own derived
notes and *is* committed.

## Known gaps

- Three audit-report sources in `corpus/sources.toml` are commented out: they
  pointed at blog *index* pages, which fetch as navigation chrome rather than
  finding text. Curating specific report URLs is a prerequisite for the first
  real `corpus fetch`.
- `cargo fmt --check` fails repo-wide; there is no `rustfmt.toml` and the house
  style does not match rustfmt defaults. Must be settled before CI adds a fmt gate.
- `html_to_text` (`crates/dike-core/src/retrieval/fetch.rs`) silently drops
  text during resync. When a malformed tag's quoted attribute never resolves
  (an unterminated quote, or two colliding malformed openers), the scanner
  recovers by skipping to the next `<` or `>` — and whatever text sat between
  the malformed tag and that point is discarded. Content loss only: the
  variant that used to leak a `<script>`/`<style>` body as plain text is
  closed, and so is the one that leaked a fragment of a *legal* `<` inside an
  attribute (`title="a < b"`). Both have regression tests. Guard for what
  remains open: `html_to_text_keeps_trailing_content_when_a_balanced_odd_looking_tag_resyncs`.

  The scanner is hand-rolled and took six fix rounds, each round's own new
  code becoming the next round's defect. If corpus quality ever disappoints,
  replacing it with a real HTML parser is one decision rather than another
  six rounds — see the round-by-round reasoning in `fetch.rs`'s own comments.

---

## Where to look for what

| I want to… | Go to |
|---|---|
| Understand the design rationale | `docs/superpowers/specs/analyzer/…-design.md` |
| See the task-by-task build plan | `docs/superpowers/plans/analyzer/…-dike-analyzer.md` |
| Add a vulnerability detector | `crates/dike-lang-anchor/src/detectors/` — implement `Detector`, register in `all_detectors()` |
| Change what the IR captures | `crates/dike-lang-anchor/src/ir.rs`, then `parser/` |
| Change how findings are ranked or merged | `crates/dike-core/src/merge.rs` |
| Change the report | `crates/dike-core/src/report/` |
| Add a CLI subcommand | `crates/dike-cli/src/main.rs` + `commands/` |
| Add a corpus source | `corpus/sources.toml` |
| Understand why `dike-core` rejects a word | `crates/dike-core/tests/seam.rs` |
