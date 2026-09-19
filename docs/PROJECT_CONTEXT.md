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

**All eight phases complete.** The analyzer runs both tracks, and the eval harness scores them.

`dike analyze <path>` runs the full static track end to end: it parses an Anchor
program, builds the IR, runs five detectors, applies the imperative-check
suppression pass, ranks the results, and renders Markdown or JSON. It is
verified to report real findings on vulnerable code — not merely silence on
clean code.

- **Phase 1** — core contract: `Finding`, the `Analyzer` seam, merge/ranking, report renderers, CLI shell.
- **Phase 2** — Anchor IR and parser (`syn`-based), `dike ir` debug command.
- **Phase 3** — five static detectors plus the suppression pass.
- **Phase 4** — `AnchorAnalyzer` wired into the pipeline; coverage reporting.
- **Phase 5** — complete: corpus document model, manifest, chunking, hashing; HTTP layer and `dike corpus fetch`; BM25 sparse index; embedder + sqlite vector store; RRF fusion and the `Retrieve` seam; the `dike corpus index|query|hash` CLI. The first *live* run (fetch, then index against Ollama) has not happened yet.
- **Phase 6** — complete. `dike analyze --llm` runs both tracks and is verified end to end against a live model: on the vulnerable fixture Track 2 independently reports `missing-signer` on `withdraw`, which merges with Track 1's finding into a **corroborated** Critical at confidence 0.97 carrying its citation link.
- **Phase 7** — complete. The six mutation operators, `MutationLabel`, mutant
  materialization and the `cargo check` validity gate, behind `dike eval mutate`.
- **Phase 8** — complete. The differential runner, per-class/per-track metrics,
  the noise floor, the history series, `dike eval run`/`dike eval holdout`, the
  `justfile`, CI, and the holdout scaffold.

**First scored run (2026-09-03, `benchmarks/history.json`):** 16 mutants of the
clean fixture, 0 refused by the validity gate. Track 1 reaches recall **1.000**
and precision **1.000** on `missing-signer`, `missing-owner-check`,
`missing-authority-binding` and `unchecked-arithmetic`, at a noise floor of
**0**. `pda-validation-gap` scored **0.000** — the harness found that on its
first run, which is what it is for. It reaches **1.000** since 2026-09-12; see
the quirk below.

**The fixture now yields 19 mutants (2026-09-06).** Three `constraint = ...`
expressions were added to the clean fixture so `strip_constraint` has sites;
before that, `removed-guard` — the one Track-2-only class — had never had a
single case, and its `0.000` was indistinguishable from a class that ran and
found nothing. Every other class holds its previous count and score exactly,
and the re-scored 19-case run is appended to `benchmarks/history.json` as a
second entry (0 refused by the validity gate, noise floor 0 over 166 LOC).
`removed-guard` still scores 0.000 on Track 1 *by design*: there is no Track 1
detector for it, and the class exists to be measured by Track 2, which has not
been scored yet.

**First Track 2 runs (2026-09-06, three entries in `benchmarks/history.json`):**
Track 2 has been scored. `model` is `ollama/qwen2.5-coder:14b` and `corpus_hash`
is non-null on all three, so the track genuinely ran, and the `llm` rows differ
from the `static` rows, so Track 1 findings are not leaking across.

| Run | Change | Units dropped | Best `llm` recall |
|---|---|---:|---|
| `…14:25:22…-all` | as built | 36 / 80 | `missing-owner-check` 0.500 |
| `…14:43:48…-all` | JSON extractor fixed, `removed-guard` added to the prompt | 24 / 80 | `missing-owner-check` 0.500 |
| `…20:48:35…-all` | reply constrained to a JSON Schema | **0 / 80** | **none — every class 0.000** |

**The honest reading: the plumbing is fixed and Track 2 still finds almost
nothing.** A dropped unit is one the model was never scored on, and it is
invisible in the table — it looks exactly like a miss — so the first two runs
could not distinguish "the model missed it" from "the model was never asked
properly". Now they can, and the answer is that Track 2's recall is genuinely
near zero on this fixture.

**Do not read the 0.500 → 0.000 as the schema causing harm.** That is a change
of two detections out of four cases, well inside what 19 mutants of one program
can resolve, and a live probe (2026-09-06, `qwen2.5-coder:14b`) shows the
schema does not degrade the model on a grounded, clearly vulnerable handler: with
no `format` it emitted two correct `missing-owner-check` findings and with the
schema one correct consolidated finding, both cited to the offered `doc_id`. The
unconstrained reply was also **truncated by `MAX_OUTPUT_TOKENS`** mid-array,
which is itself a drop. More cases is the answer here, not a revert.

What the probes did surface, on the real retriever rather than a hand-written
document: Track 2 returns an empty array for most units, and the one finding it
did produce on `leaky_vault` was classed `pitfall` — not the vocabulary — and
cited a **URL** rather than an offered `doc_id`, so the grounding filter
correctly dropped it. Retrieval and citation discipline, not output format, are
where Track 2 is losing.

567 tests pass. `cargo clippy --workspace --all-targets -- -D warnings` is clean.

---

## Folder structure

```
.
├── .superpowers/              SDD agent scaffolding — GITIGNORED, not project history
├── action.yml                 The composite GitHub Action: build, analyze, upload SARIF
├── .github/workflows/ci.yml   clippy, tests, seam, clean fixtures, `eval run --track
│                               static`, and `action-smoke` (the action end to end
│                               against `leaky_vault`, `upload: false`). Deliberately NO
│                               `cargo fmt` gate (see Quirks)
├── benchmarks/
│   ├── history.json           The eval series: one EvalSummary per run. COMMITTED —
│   │                           the harness exists to compare runs over time
│   ├── adjudication/          Findings on real programs, read at the source and
│   │                           labelled by hand. The only precision number that is
│   │                           not measured against defects we injected ourselves
│   └── holdout/               The real holdout: cases.toml (six cases) + runs.json.
│                               checkouts/ is GITIGNORED — other people's repos at
│                               other people's commits, never redistributed here
├── corpus/
│   ├── sources.toml           Corpus manifest: url, kind, licence, retrieval date, class
│   │                           tags, optional include_paths, and the refresh rule
│   ├── notes/                 Our own derived notes — COMMITTED (original work)
│   └── cache/                 Fetched source text — GITIGNORED (see Licensing below)
├── crates/
│   ├── dike-core/             Domain-AGNOSTIC. No Solana vocabulary. See "The seam".
│   │   ├── src/
│   │   │   ├── finding.rs     Finding, Severity, VulnClass, Track, Location, Citation;
│   │   │   │                   subject + absorbed_handlers (the collapse's record)
│   │   │   ├── analyzer.rs    Analyzer trait, SourceTree ingest, Diagnostic, AnalysisResult
│   │   │   ├── merge.rs       Two-track merge, corroboration, deterministic ranking,
│   │   │   │                   collapse_by_subject (one row per defect, not per handler)
│   │   │   ├── http.rs        The single HTTP surface (corpus fetch, embedder, LLM client)
│   │   │   ├── llm/           LlmClient seam, Ollama and Gemini backends, structured output
│   │   │   ├── eval/         MutationLabel, Mutant, EvalCase; mutant materialization
│   │   │   │   │               and the `cargo check` validity gate
│   │   │   │   ├── differential.rs  original-vs-mutant diff: what the mutation caused
│   │   │   │   ├── holdout.rs   scoring published defects: outcomes, recall, rendering
│   │   │   │   ├── metrics.rs   per-class, per-track recall/precision + noise floor
│   │   │   │   └── history.rs   append-only run series (benchmarks/history.json)
│   │   │   ├── report/        Markdown + JSON + SARIF renderers, Coverage, RunMetadata
│   │   │   └── retrieval/     Corpus Document/Source model, chunking, hashing, fetching,
│   │   │                       BM25 sparse index, dense embedder, sqlite vector store,
│   │   │                       RRF fusion, the Retrieve seam + HybridRetriever
│   │   └── tests/seam.rs      ARCHITECTURAL GATE — fails the build on Solana vocabulary
│   ├── dike-lang-anchor/      Solana/Anchor-specific. Everything domain lives here.
│   │   ├── src/
│   │   │   │   │   ├── ir.rs          The Anchor IR: Program, Handler, AccountsStruct, Constraint…
│   │   │   ├── parser/        syn-based parsing: accounts, program, symbols, body summary
│   │   │   ├── chunker/       HandlerUnit chunking + derived retrieval queries
│   │   │   ├── detectors/     Six static detectors + the suppression pass
│   │   │   ├── llm_analyzer/  Track 2 assembled: chunk, retrieve, ask, validate
│   │   │   ├── mutations/     The six vulnerability-injection operators (Phase 7)
│   │   │   ├── rules.rs       RuleDoc catalog: the six classes, documented for SARIF consumers
│   │   │   └── lib.rs         AnchorAnalyzer, analyze_program
│   │   └── tests/end_to_end.rs
│   └── dike-cli/              Orchestration only. The ONE place core and Anchor meet.
│       └── src/
│           ├── main.rs        clap subcommands: analyze (--format md|json|sarif,
│           │                   --base-dir), ir, eval mutate|run|holdout,
│           │                   corpus fetch|index|query|hash
│           ├── pipeline.rs    Runs both tracks, merges, builds the Report
│           ├── config.rs      RunConfig
│           └── commands/      analyze, ir, corpus, eval, holdout (checkout, score,
│                               record; the run-once guard)
├── docs/
│   ├── PROJECT_CONTEXT.md     This file
│   └── superpowers/
│       ├── specs/             Approved design docs
│       └── plans/             Phased implementation plans
├── tests/fixtures/programs/   Anchor fixture programs, parsed as text
│   ├── vault/                 a clean mutation source. HAS a Cargo.toml: the eval
│   │                           harness builds every mutant of it.
│   ├── escrow/                the second clean mutation source, and the one that poses
│   │                           what vault cannot: multi-file, delegating handlers, an
│   │                           account pinned by a SIBLING declaration, a staged
│   │                           authority. Also a buildable crate.
│   │                           Its `constraint = ...` expressions are the only
│   │                           `removed-guard` sites that exist — see "Quirks"
│   └── leaky_vault/           the vulnerable counterpart: both tracks must fire on it.
│                               No Cargo.toml — nothing builds it
├── justfile                   The invocation story: check, gates, eval*, holdout,
│                               install-hook. Cargo has no pre-build hook and neither
│                               does `anchor build`, so invocation is a wrapper task
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
| 5 | Identical input yields byte-identical output | `merge::rank` sorts with explicit tiebreakers; `Bm25Index::search` truncates *after* its sort (see Quirks — `TopDocs::with_limit` is not build-stable) |
| 6 | Partial results beat no results | Per-file parse tolerance; per-entry archive tolerance |
| 7 | Findings merge on `(handler_id, class)`, never on span or id | `Finding::merge_key` |
| 8 | Fetched corpus content is never committed | `.gitignore`, and the licensing note below |
| 9 | A finding never points at line 0 | `attr_line`-with-fallback in constraint detectors |
| 10 | A vector search across a model/dimension mismatch refuses rather than scoring | `StoreError::ModelMismatch`; the store's `meta` table records `(model, dim)` |
| 11 | An unavailable embedder degrades retrieval to sparse-only; it never empties it | `HybridRetriever::dense_leg` returns `None` on `HttpError`, and two tests cover the build-time and query-time paths separately |
| 12 | `RetrievalHit::dense_score` is `None` only when the dense leg did not run | `HybridRetriever::search` backfills via `VectorStore::scores_for`; the grounding gate reads this distinction |
| 13 | A mutant carries exactly one injected defect, labelled by the operator that made the edit | `mutations::operators` — one mutant per site, and `MutationLabel` is built at the edit, never inferred |
| 14 | A mutant is still a parseable program | `dike-lang-anchor/tests/mutants_are_valid_rust.rs` |
| 15 | A mutant that does not compile is never scored | `eval::compile_gate`; `dike eval mutate` moves a rejected case to `rejected/` and records the compiler's own reason |
| 16 | A finding the analyzer already made on the clean program is never scored as a detection | `eval::differential::diff_runs` — it is `persistent`, the noise floor, attributable to neither side |
| 17 | The eval history is append-only and written atomically | `eval::history::append_history` — temp file + rename, and a missing file is an error, never a fresh series |

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

- **`corpus index` and `corpus query` split into an inner function taking
  explicit paths and a `Box<dyn Embedder>`.** The public wrappers supply the
  repo paths and an `OllamaEmbedder`; the inner ones are what the tests drive,
  with a stub embedder and a tempdir corpus. Without the split, every test of
  the CLI wiring would need a live model and the repo's own corpus.

- **A missing component score prints `-`, not `0.0000`.** "The model scored
  this zero" and "the dense leg did not run" are different claims, and a
  sparse-only run is exactly what an operator needs to see when the embedder
  is down.

- **Archive sources carry an optional `include_paths` filter, matched under
  the archive's top-level directory.** A codeload tarball names every entry
  `<repo>-<ref>/…`, but a filter is naturally written against the repository
  layout (`content/rules/`), so the top-level component is stripped before
  matching. Comparing raw paths would match nothing and fail *silently* — an
  empty corpus, not an error — which is why a filter that matches nothing is
  an explicit error and has its own test.

- **`FetchOutcome::Changed` carries sizes as well as hashes.** Two of the
  corpus sources are living repositories, so "this changed" is the expected
  outcome and says nothing on its own. The byte delta is what separates "the
  maintainers added findings" from "the fetch captured a login page", and only
  the second needs a human.

- **`GeminiClient` has a hand-written, redacting `Debug`.** A derived one would
  print the API key into every `{:?}`, `unwrap` panic, `assert!` message and
  `tracing` field that ever touched the struct — the usual way secrets reach
  logs. The key travels in the `x-goog-api-key` header rather than the URL for
  the same reason: URLs reach logs, proxies and error messages.

- **`HttpClient::post_json_with` takes headers and a per-request timeout.** A
  generation call needs minutes where a corpus fetch needs seconds, and one
  backend authenticates with a header. Letting the LLM clients build their own
  `reqwest` requests instead would duplicate the connection-refused-to-
  `Unavailable` mapping this module exists to centralise.

- **The generation request caps output tokens (`num_predict`).** Measured on
  2026-09-01: one handler consumed the entire 120-second per-unit budget twice
  running and was dropped, while an identically shaped prompt answered in 7
  seconds — a runaway generation, not a slow one. The cap turns that into a
  truncated reply, which is a schema violation costing one retry and then a
  logged drop. With it, the clean fixture went from 3/4 units examined in 2m43
  to 4/4 in 1m01.

- **A hallucinated citation deletes itself, and an uncited finding is
  dropped.** `validate_citations` keeps only ids that were actually offered to
  the model. Without it, "cite your sources" is a request the model can decline
  silently, and grounding becomes decoration rather than a filter. Duplicate
  citations collapse first, because `track2_confidence` reads the count — citing one
  document twice must not buy the same up-weighting as citing two.

- **A schema violation is retried exactly once, then dropped.** The violation text
  goes back to the model in the retry prompt. A third attempt would spend another
  full timeout on a model that has already failed the same schema twice. A
  *transport* failure propagates instead: flattening it into an empty result would
  make "the model reviewed this and found nothing" indistinguishable from "the model
  is not running", and the report would claim coverage the run never had.

- **HTML headings are re-emitted as Markdown headings.** `chunk_by_finding`
  splits on Markdown headings and finding-ID tokens, and a stripped HTML page has
  neither — so every fetched page became *one* document. Measured on the live
  corpus before the fix: the constraint reference was a single 11 KB chunk and the
  pitfalls page a single 23 KB chunk, they topped nearly every search, and their
  citations pointed at a whole page. After it: 33 and 25 chunks, medians 255 and
  325 characters. `h5`/`h6` render as four hashes because that is the deepest level
  the chunker treats as a boundary. Anchor-link pilcrows are stripped in the same
  pass — generated docs put one inside every heading, and it reached every citation.

- **A short untitled lead-in adopts the heading it absorbs.** Fetched pages open
  with untitled chrome before their first heading; when that fragment is under the
  200-character merge threshold it merges forward, and keeping its absent title
  meant the first real section's heading never reached a citation. Adoption only
  fills an absent title, never overwrites one — otherwise a chunk would be named
  after the last section merged into it.

- **The derived query renders wrappers as `Account of Vault`, not
  `Account<Vault>`.** `Bm25Index::search` turns each whitespace-separated term into
  a zero-slop phrase, so the angle-bracket form tokenises to the adjacent pair
  `account vault` and misses a document written `Account<'info, Vault>`
  (`account info vault`). This is the caller obligation that module documents, and
  the derived query is its first real caller.

- **The grounding gate never thresholds the RRF score.** `is_grounded` asks the
  component legs. An RRF score is rank-derived, so its magnitude says nothing
  about relevance: the top document of a garbage list scores `1/61`, exactly
  what a perfect match scores.

- **The grounding thresholds are measured, not inherited from the spec**
  (revised 2026-08-31). The spec's "dense ≥ 0.35 OR any non-zero BM25" accepted
  every query, including nonsense ones. Measured over the real 358-document
  corpus with BGE-small-en v1.5, best score per query: off-topic queries reach
  dense **0.566** and BM25 **16.0**; on-topic queries bottom out at dense
  **0.664** and BM25 **2.6**. Two consequences. Dense separates cleanly but only
  well above 0.35 — these embeddings put unrelated text at ~0.5 — so the
  threshold is now **0.62**, with deliberately asymmetric margins because the
  on-topic minimum is an identifier query, the case dense retrieval handles
  worst. And BM25 cannot stand alone: its ranges overlap almost completely, so
  it grounds only when the dense leg did not run at all. Re-tuning for another
  embedding model means re-running that measurement, not nudging the number;
  a test pins the threshold inside the measured envelope.

- **`Bm25Index::search` collects every match and truncates after sorting.**
  `TopDocs::with_limit(k)` chooses *which* equally-scoring documents survive by
  internal document address, which depends on how tantivy's multi-threaded
  writer laid out segments during the build — so two builds of the same corpus
  returned different tied sets, changing the fused ranking and the citations.
  Found as a flaky test; on the real corpus 21 documents tied on one query. The
  cost is bounded by corpus size (hundreds at v1). If that stops being true, the
  fix is a collector that breaks ties on the id field, never a return to an
  unstable limit.

- **A chunk's title carries its source, not only its heading.** The live corpus
  produced citations reading "Mitigation Guidance", "Review Signals" and "See it
  in code" — headings that identify nothing. Titles are now
  `<source title> — <heading>`.

- **A dead embedder degrades; a model mismatch does not.** `HybridRetriever`
  treats an unreachable embedder as an availability problem and retrieves with
  BM25 alone — retrieval that returned nothing would make Track 2 look like a
  recall failure, and the eval harness would record it as one. A
  `ModelMismatch`, by contrast, propagates: a stale index that answers
  confidently is worse than an error.

- **`dike corpus fetch --update-hashes` rewrites `sources.toml` by targeted text
  surgery**, not a TOML round-trip. A round-trip would destroy the commented-out
  source entries and the prose explaining them. The rewrite scopes by the
  preceding `id = "…"` line and writes atomically (temp file + rename).

- **`tests/fixtures/programs/vault` is a real crate; `leaky_vault` is not.**
  Reverses the earlier "fixture programs have no `Cargo.toml`" decision, for the
  exception that decision already anticipated: the mutation-validity gate
  runs `cargo check` over every mutant, and it needs something buildable. The
  alternative — a second, buildable copy of the same program under a separate
  eval fixture directory — was rejected because the two copies drift, and an
  operator developed against one would then be validated against the other. An
  empty `[workspace]` table in the manifest detaches it from the root workspace,
  so `cargo test` and `cargo clippy --workspace` never build it. The analyzer
  still never builds a target program: `SourceTree::load` reads `.rs` as text,
  and `cargo` is invoked only by the eval harness, only on this fixture.

- **The `declare_id!` in a fixture has to be a real 32-byte key.** The clean
  fixture carried `Vau1t1111…` (30 bytes) from the day it was written; nothing
  noticed, because until the validity gate existed nothing ever compiled it. It
  is now the standard placeholder. The validity gate caught it first, and
  caught it in the fixture rather than in a mutant — which is the argument for
  the gate in miniature.

- **`compile_gate` takes a shared `CARGO_TARGET_DIR`**, a deviation from the
  plan's one-argument signature. Every case is a copy of the same crate with the
  same dependency graph; pointing them all at one target directory builds that
  graph once instead of once per mutant. With 16 cases and a Solana dependency
  tree, that is the difference between a gate that runs and one nobody waits for.

- **The compiler's output goes to a file, not a pipe.** A pipe whose buffer
  fills blocks the child, and the child is what is being polled for the timeout —
  so the two would deadlock on exactly the verbose failures worth reading.

- **`materialize` refuses to clear a directory it did not create.** It writes a
  `.dike-eval` marker and requires it before removing anything, because `--out`
  is a user-supplied path and a typo would otherwise recursively delete
  somebody's source tree.

- **A rejected mutant is moved, not deleted.** `cases/` holds what is scoreable
  and `rejected/` holds what is not, so iterating the case set never has to
  consult a manifest to skip a broken one — while the broken tree is still on
  disk to be read. A compile failure is a defect in an *operator*, and deleting
  the evidence is how it stays undiagnosed.

- **`rejected.json` is absent when the gate did not run, rather than empty.**
  `--no-compile-check` writes no file at all. An empty list would claim every
  case was checked and passed, which is the opposite of what happened — the same
  reasoning that makes an absent `corpus/cache/` this project's evidence that no
  fetch has run.

- **A mutation operator skips a site where its own rewrite would not compile.**
  `account_to_unchecked` passes over an account carrying `init`, `close`,
  `has_one`, or a `seeds`/`bump` expression that reads the field's own data —
  all four are defined against the deserialized type. A mutant Anchor rejects is
  not a hard case for the analyzer, it is one the harness never gets to score,
  and it would be dropped by the compile gate anyway; the cheaper place to
  know that is at the operator, where the reason is visible.

- **The two wrapper operators insert a `/// CHECK:` doc comment.** Anchor
  refuses to compile an unvalidated field without one, so `Signer<'info>` ->
  `AccountInfo<'info>` and `Account<'info, T>` -> `UncheckedAccount<'info>`
  would otherwise produce nothing scoreable at all. This is why the diff-size
  guard admits two changed lines rather than one. The comment goes directly
  above the field, after any `#[account(...)]`, so the first line that differs
  from the clean program is still the line the label points at.

- **Deleting an attribute item takes the comma *after* it, never the one
  before.** Reaching backwards is what a last item appears to need, but on a
  one-item-per-line attribute that crosses a newline and merges two surviving
  lines into one — three lines of diff for a one-item deletion. A trailing comma
  before `)` is legal Rust, so the last item leaves one behind and
  `tidy_inline_attr` removes it only in the single-line case, where it is merely
  ugly rather than wrong.

- **A mutation label's line comes from diffing the file, not from the IR site.**
  The two agree for a plain single-line edit and diverge everywhere else — an
  inserted `/// CHECK:` line, an item deleted from a multi-line attribute. The
  label is what an auditor opens the file at when the harness scores a miss, so
  it points at what actually changed.

- **An `#[derive(Accounts)]` struct shared by two handlers is one mutation
  site.** It is declared once, so mutating it once is the honest count;
  attribution goes to the first handler by name, because `Program::instructions`
  is sorted and parse order is not (invariant 5).

- **The differential key is `(handler, class)` — deliberately not
  `Finding::merge_key`.** `merge_key` is `(handler_id, class)` and `handler_id`
  carries the file path. The two runs being compared are two *copies* of one
  program in two directories, and the label names a third path (the repository
  fixture the operator read), so no two of the three ever agree on a path.
  Keying on it would make every mutant finding look introduced, every persistent
  finding invisible, and every label unmatched — the harness would report 0%
  recall and 100% noise with nothing actually wrong. Dropping the file is safe
  because a handler name identifies an instruction uniquely within a program,
  which is the granularity findings are already compared at.

- **`diff_runs` takes the *unmerged* per-track findings.** Merging first
  collapses a static and an LLM finding on the same handler and class into one
  corroborated finding, which destroys exactly the per-track attribution the
  two-track design exists to produce: the harness has to be able to say Track 1
  caught something Track 2 missed.

- **`CaseOutcome::introduced` includes the true positive; `false_positives()` is
  the subset that does not match the label.** Keeping the matching findings in
  the list preserves their evidence and confidence for a per-case report; a
  boolean `detected` alone would throw that away, and the metrics pass needs
  both counts out of the same structure.

- **`MetricTrack` is not `Track`.** The three views the spec asks for are
  static, LLM and **merged**, and merged is the *union* — what the tool as a
  whole shows an auditor, so its recall is at least each single track's.
  `Track`'s third variant is `Corroborated`, the *intersection*, whose recall is
  at most each track's. Reusing it would print `"track": "corroborated"` in
  `history.json` against a number meaning the opposite of what that word means
  everywhere else in the codebase — a misreading nobody would catch from the
  file.

- **The noise floor is deduplicated across cases, never summed.** Every case's
  `persistent` list is drawn from the same clean-program run, so summing them
  multiplies the floor by the number of mutants and reports a property of the
  harness as a property of the analyzer. Dedupe is on the same `(handler, class)`
  key the differential runner compares on.

- **`ClassMetrics::precision` is `Option<f32>` and renders as `-`.** Same rule
  as a missing retrieval component score: "it reported nothing" and "everything
  it reported was wrong" are different claims, and `0.000` states the second.
  Recall is always defined, because a row exists only because a case produced it.

- **`summarize` leaves `run_id`, `timestamp`, `model`, `corpus_hash` and
  `cases_rejected` for the caller.** `dike-core` stays free of the clock, the
  same split that already has `RunMetadata::timestamp` filled in
  `dike-cli/src/pipeline.rs` rather than in core.

- **`EvalSummary` carries `cases_rejected`.** A validity gate that starts
  refusing mutants shrinks the denominator, and a shrinking denominator looks
  exactly like improving recall. The count travels with the numbers it explains.

- **`append_history` refuses a missing file.** `benchmarks/history.json` is
  committed, so its absence means a wrong path or a lost file; creating an empty
  one would erase the comparison the run was about to make.

- **A false positive must match *neither* the label's class nor its handler.**
  Not "anything introduced that is not the true positive". One mutation
  routinely injects two real defects at one site — rewriting `Signer<'info>` to
  `AccountInfo<'info>` removes the signature check *and* the owner check, and
  the analyzer correctly reports both — so counting the second as a false
  positive penalizes the analyzer for being right. Measured on the first eval
  run, that alone put `missing-signer` precision at 0.5 instead of 1.0. A
  finding sharing the label's handler is collateral from the same edit; one
  sharing its class is the same defect read elsewhere. Neither is evidence
  anything was invented.

- **`TrackSelection` has no `merged` mode, but the CLI accepts the word.**
  Merged is a view of results, not something that can be run; `--track merged`
  runs both tracks and says so on stderr rather than quietly doing something the
  word does not mean.

- **`dike eval run` analyzes the clean copy once per program, not once per
  mutant.** The clean run is identical for every mutant and is otherwise the
  largest cost in the loop — with Track 2 on, it would be a full model pass per
  case.

- **`dike eval run` refuses to record a run whose requested track could not be
  built.** A Track 2 that failed to start would otherwise write zeros into
  `benchmarks/history.json` that are indistinguishable from a detector
  regression.

- **There is no `cargo fmt --check` gate, and that is now a decision rather
  than a gap.** Measured 2026-09-03: rustfmt's default disagrees with the house
  style in 257 places across 43 files, and `use_small_heuristics = "Max"` — the
  closest configuration — disagrees in 283. No configuration reproduces the
  style, so enforcing it would mean a tree-wide reformat that rewrites blame
  across every file for no behavioural gain. The gate is `clippy`, which is
  deny-by-default here and has caught real defects.

- **`removed-guard` has a Track 1 detector; its recall went 0.200 → 0.600 when
  the detector learned to read dataflow (2026-09-19).** The class was Track-2-only on
  the reasoning that "the absence of an arbitrary expression is not a
  structural signal". That is true of an arbitrary expression and false of the
  one programs actually write. Surveyed over three real Anchor programs, every
  `constraint` but two had one shape: `a.field == field.key()` — a stored
  `Pubkey`, an account of that name, and a requirement that they match. That is
  `has_one` written by hand, and its absence is structural: the struct declares
  both halves of a binding and never makes it.

  `RemovedGuardDetector` reports exactly that, for the non-authority fields
  (`user`, `maker`, `resolver`) that `missing-authority-binding` leaves alone —
  reporting the authority ones too would put the same defect under two class
  names. Zero findings on both clean fixtures and all three real programs.

  **That first rule scored 0.200, and the reading of why was half wrong.** The
  four uncredited `strip_constraint` mutants were recorded as "not detector
  failures", with `vault/deposit` and `vault/withdraw` blamed on `TokenAccount`
  being an `anchor_spl` type with no state struct in the program, so the
  analyzer had no field list for it. The conclusion drawn — *raising this number
  means teaching the analyzer about external account types* — was wrong. It
  needed a different question, not a bigger symbol table.

  A fourth rule added later the same day takes those two. It fires when an
  account reaches a value-moving CPI in the handler body
  (`HandlerBody.reaches_value_sink`, see Quirks), is named after an account the
  handler state-writes, and nothing pins its identity. `vault_token_account` is
  the destination of the transfer whose amount is credited to `vault`, and with
  the constraint stripped nothing says which token account it is. **0.200 →
  0.600 (3 of 5), precision still 1.000, noise floor still 0, every other class
  unchanged.** The name condition is doing more of the work than the dataflow —
  see "Known gaps".

  The two that remain are still not detector failures:

  | mutant | why it is not credited |
  |---|---|
  | `vault/close_vault` | `constraint = vault.amount == 0` is a business rule. Nothing structural says a vault must be empty before closing, and no detector can infer it |
  | `escrow/accept_admin` | detected, on the right handler, and reported as `missing-authority-binding` — a more precise name than the operator's label. The harness credits by class, so it counts for neither |

- **Guards written as plain Rust were invisible to the suppression pass, and
  an owner comparison did not count as an owner check (both fixed
  2026-09-19).** Found by scoring against `coral-xyz/sealevel-attacks`, the
  Anchor authors' reference set of 35 programs in insecure/secure/recommended
  triples — the first ground truth this project has that nobody here wrote.

  On the first run, **six of its eleven categories reported identically on the
  insecure and the secure variant**: a rule firing on something both versions
  share is not detection. Two causes. `parser/body.rs` recorded an
  `ImperativeCheck` only from macro calls, so
  `if !ctx.accounts.authority.is_signer { return Err(..) }` — the canonical fix
  in that set — was never seen; `CheckKind::ManualIf` had been in the IR from
  the start with nothing producing it. And suppression accepted only `X.key()`
  for `missing-owner-check`, so `ctx.accounts.token.owner != ctx.program_id`,
  the check the class is named after, did not suppress it.

  The owner needle is the qualified `accounts.X.owner`. A bare `X.owner` is as
  often a field of a deserialized struct sharing the account's name, and in
  `1-account-data-matching/secure` that struct's field is all there is — that
  program genuinely still lacks an owner check, so the bare form would have
  deleted a true positive.

  **A third spelling was missing for the same reason, found the same day:**
  suppression accepted `X.key()`, the *method* a typed account carries, but not
  `X.key`, the *field* on `AccountInfo` — and a bare `AccountInfo` is the only
  shape `missing-owner-check` fires on, so the recognizer was blind to the one
  form that matters most for the class it governs. `5-arbitrary-cpi/secure`
  fixes its whole category with
  `if &spl_token::ID != ctx.accounts.token_program.key`, and dike reported it
  identically to `insecure` until `accounts.X.key` was added. That needle is
  bounded on *both* sides, unlike the others: a bare field name would otherwise
  match the prefix of a longer one (`.key` inside `.keypair`).

  Category 7 (`bump-seed-canonicalization`) closed separately, in
  `detectors/pda.rs` rather than in suppression — see the scorecard addendum.

  Dike now discriminates in 5 of 11 categories. Full scorecard and the honest
  gaps in `benchmarks/adjudication/2026-09-19-sealevel-attacks.md`. **Track 2
  must never be scored against this set**: `corpus/cache/` holds its prose, so
  the retriever would hand the model the answer key.

- **A mutant that is still secure is not a vulnerable program either.**
  `strip_has_one` removed a `has_one = X` from accounts whose own `seeds`
  already derive from `X`. Stripping it injects nothing: the PDA still only
  derives for that X, and X signs. The mutant compiles, so the validity gate
  passes it, and the harness then scores the analyzer for failing to report a
  defect that is not there.

  Found 2026-09-19, the hour `escrow` joined the corpus:
  `missing-authority-binding` recall read **0.800** with nothing wrong with the
  analyzer. `has_one_is_redundant` now skips those sites and it reads 1.000
  again over a larger case set. The validity gate answers "does this mutant
  build?"; this answers the other half of the same question, and exists for the
  same reason.

- **The mutation corpus is two programs, because one could not pose the
  question.** `vault` is a single file in which every account is pinned on its
  own declaration, so a harness scored against it alone was blind to both
  false-positive classes adjudicated on real code — and scored 1.000 on every
  class while the tool was wrong about every real finding. `escrow` is
  multi-file with delegating handlers, pins an account from a sibling
  declaration, and stages an authority. Reverting either detector fix turns it
  from clean into three findings, one per adjudicated shape; that was verified
  by reverting them, not assumed. Pinned by
  `end_to_end::the_escrow_fixture_is_clean`.

  Case counts went 19 → 33 and the noise-floor denominator 166 → 470 LOC.

- **Precision on real programs is 0.000 (0/4), measured 2026-09-19.** Every
  Track 1 finding on all 7,211 LOC of real Anchor code available was read at the
  source and labelled: four findings, four false positives. Full adjudication in
  `benchmarks/adjudication/2026-09-19-real-programs.md`.

  Two causes, both narrow. **Three of four: the pin lives on a sibling
  declaration.** Detectors judge one `AccountDecl` in isolation and ask whether
  *it* carries `address`, `owner`, `seeds`, `has_one` or a naming `constraint`.
  Anchor lets you pin account X from account Y — X named in Y's `seeds`,
  `constraint = Y.field == X.key()`, or `address = Y.field` placed on X — and
  all three are idiomatic. The suppression pass already handles the imperative
  form of this in the handler body; the declarative form inside
  `#[derive(Accounts)]` has no equivalent. **One of four: a staged authority is
  not a live one.** `pending_admin` in a two-step admin transfer is bound in the
  single handler where it is the authority and inert in the other eight.

  Neither needed dataflow, and **both were fixed the same day.** Cause A:
  `pinned_by_sibling` in `owner.rs` and `field_pinned_by_sibling` in
  `authority.rs`. Cause B: `claims_authority` now treats a staged authority and
  a live one as different authorities, returning false when exactly one of the
  two names carries a staging qualifier — the test is on disagreement, so
  `new_admin` does not claim `admin` while `new_admin` claiming `pending_admin`
  still counts.

  Findings on the same population went 4 → 1 → **0**, with every eval class
  still at 1.000, the noise floor still 0, and `leaky_vault` still yielding all
  8 of its findings (a Track 1 count read that day; the value-sink rule added
  later on 2026-09-19 took it to 9 before subject collapse, 8 merged). Precision is no longer 0.000; it is **undefined**, on a
  denominator of zero. Nothing distinguishes "these programs have no defect of
  these classes" from "the detectors cannot see theirs" — the holdout is that
  instrument and it is unspent. Recall on real
  code stays unmeasured — the holdout is that instrument, and it is unspent.

  The low volume and the zero precision are not in tension: the detectors are
  conservative, and the conservatism is measured against the wrong unit — one
  declaration rather than one accounts struct.

- **A finding points at the file its declaration is in, and identity no longer
  carries a file at all (fixed 2026-09-19).** `Location::file` used to be the
  *handler's* file, so in a module-per-instruction layout it was `lib.rs` for
  everything while `Location::line` came from a declaration in a different
  file. Measured on polyclone: a finding reported at `src/lib.rs:13`
  (`pub use message::*;`) whose declaration is at
  `src/instructions/refund.rs:13`. Every finding in that day's adjudication had
  to be located by hand.

  `finding_at` now takes the file the line belongs to — the accounts struct's,
  for an account-declaration finding, because that is the code someone edits.
  `unchecked-arithmetic` keeps the handler's file, which is where its evidence
  actually is.

  That forced the second half: `Location::handler_id` **drops the file**, and
  so does `MutationLabel::handler_id`. The two tracks disagree about a
  finding's file and both are right — Track 1 points at the accounts struct,
  Track 2 at the handler it reviewed — so a key carrying the path meant the
  tracks could never corroborate each other in a program that puts one
  instruction per module. A handler name is unique within a program, so the
  file added nothing to identity and took away matching. `eval::differential`
  had already reached the same conclusion for its own key, for the same
  reason. Pinned by
  `finding::tests::identity_is_the_handler_not_the_file_it_was_reported_from`
  and `end_to_end::a_finding_points_at_the_file_its_declaration_is_in`.

- **The differential harness compared findings across tracks, so one track's
  false positive erased the other's detection (found 2026-09-15).** `diff_runs`
  asked "was this here before the mutation?" with a key of `(handler, class)`
  and no track. The clean program is analyzed by both tracks, so a Track 2 false
  positive on a clean handler marked Track 1's genuine detection of the injected
  defect as pre-existing noise, and Track 1 lost the credit.

  Measured the hour Track 2 first reported anything: static `pda-validation-gap`
  read **0.250** instead of 1.000 (Track 2 reported that class on three clean
  handlers), `missing-owner-check` 0.500, `missing-signer` 0.667, and the static
  noise floor read **5** findings on a fixture Track 1 reports nothing for. The
  key is now qualified by track. Pinned by
  `differential::tests::one_tracks_noise_does_not_swallow_the_other_tracks_detection`.

  The bug was ten days old and invisible for all of them, because a track that
  reports nothing contaminates nothing. Fixing Track 2 is what exposed it. The
  lesson generalises: a harness that has only ever run with one of its inputs
  empty has not been tested, and its numbers were never safe to quote.

- **A root-level array response schema made Track 2 score 0.000 on every class
  for ten days (found 2026-09-15).** `findings_schema()` described the reply as
  a JSON array. Ollama passes the schema to a grammar-constrained decoder, and a
  root-level array is satisfied and closed by `[]` — the shortest path through
  that grammar, and the one the decoder took every time.

  Measured against `qwen2.5-coder:14b` over the vulnerable fixture, from a
  byte-identical prompt, two handlers, two runs each:

  | response schema | `withdraw` | `set_admin` | citations |
  |---|---|---|---|
  | root-level array | 0, 0 | 0, 0 | — |
  | object wrapping the array | 3, 3 | 2, 2 | correct `doc_id`s |
  | none at all | 3, 3 | 1, 1 | correct `doc_id`s |

  The schema is now `{"findings": [ ... ]}`. An object has to be opened and its
  required key emitted before anything can close, so the decoder cannot take the
  empty path for free. The object form also beat *no* schema on `set_admin`, so
  this is not an argument for dropping constrained decoding — it is an argument
  for not rooting it at an array.

  Every earlier explanation of Track 2's zero was wrong, and all of them were
  plausible: dropped replies, coarse retrieval, the model being too small. The
  retrieval was in fact already returning the right document — "Missing
  ownership check" ranked top for `withdraw` at 0.82 — and the model was already
  able to use it. Pinned by
  `structured::tests::the_schema_wraps_the_array_in_an_object`, which exists
  because flattening the wrapper back looks exactly like a tidy-up.

- **`absorbed_handlers` is a field because a machine reads it.** The subject
  collapse folds one defect seen from many handlers into one row, and the row
  has always named the handlers it swallowed in its `evidence` prose. The
  holdout scorer compares per handler, so it needs that list too — and
  parsing it back out of an English sentence would mean that rewording the
  sentence silently turns every absorbed hit into a miss. The sentence is now
  rendered *from* the field, so the two cannot disagree. The general rule:
  anything downstream has to read is a field, never a sentence.

- **The holdout admits only cases resolved against a repository.**
  `benchmarks/holdout/cases.toml` shipped empty until 2026-09-06 under that
  rule, and the rule still governs every entry added to it: an invented
  repository, commit or handler would look exactly like a real case and produce
  a real-looking number, with nothing in the output to distinguish it. An empty
  holdout is preferable to a populated fictional one. `dike eval holdout`
  prints the memorization caveat *first*, before anything that could fail or be
  skimmed, because a caveat in a document is something a downstream summary can
  drop and a line in the output is not.

- **CI's clippy is ahead of the local one, so `-D warnings` can pass here and
  fail there.** `rust-toolchain.toml` says `channel = "stable"`, which resolves
  to whatever stable the machine last installed — 1.93 here — while
  `dtolnay/rust-toolchain@stable` in CI fetches the current one. On 2026-09-06
  that gap was five releases and it broke the build on two lints that no local
  toolchain could even name: `useless_conversion` on
  `.chain(llm_findings.into_iter())` and `chunks_exact_to_as_chunks` on
  `b.chunks_exact(4)`. Local nightly (1.95) did not know them either —
  `cargo clippy --explain clippy::chunks_exact_to_as_chunks` answered "unknown
  lint", which is the quickest way to tell "my clippy agrees" from "my clippy
  has never heard of this". **A green local clippy is therefore not evidence CI
  is green.** Either `rustup update` before trusting the gate, or read the CI
  log as the authority.

- **`LlmRequest` carries a JSON Schema, and the backends spell it differently.**
  A prompt cannot make a model emit a shape. Measured 2026-09-06: with
  "Return ONLY a JSON array. No prose before or after it, no code fences." in
  capitals in the prompt, `qwen2.5-coder:14b` answered a review request with a
  multi-section essay about what the handler does, and answered the single
  retry with a JSON array in a schema of its own invention (`instruction`,
  `description`, `constraints`). 24 of 80 units died that way. `LlmRequest`
  now has `response_schema`, and Ollama sends it as `format`, Gemini as
  `generationConfig.responseSchema` alongside `responseMimeType`. The field
  holds the *schema*, never a backend's encoding of it, because the whole
  point of the seam is that Track 2 never names a backend.

  Three consequences worth knowing:
  - The schema comes from `structured::findings_schema()`, next to
    `RawLlmFinding` itself. A hand-copied schema drifts from the struct, and
    a drifted schema is worse than none: the model is then *constrained* to
    emit something the parser rejects, and it reads as a model failure.
  - `class` is a plain string in it, not an `enum`. The vocabulary is domain
    knowledge that does not live in `dike-core`, and the prompt deliberately
    lets the model invent a label when nothing fits (Rule 3).
  - It is sent only when asked. `format` switches Ollama to constrained
    decoding, so an unconditional one would impose JSON on every caller of
    the seam, including callers that want prose.

- **The JSON extractor takes every balanced `[...]` span, not the first `[` to
  the last `]`.** The old rule assumed the first bracket in a reply opens the
  findings array. It does not: a 14B model writes prose, and prose about Anchor
  code is full of brackets — `seeds = [b"vault", vault.admin.as_ref()]` inside a
  fenced Rust block is a balanced span that `strip_code_fences` happily leaves
  behind. The old span began there and serde reported `expected value at line 1
  column 2` — column 2 being the character right after a `[`, which is the
  signature of the bug. Where the stray bracket opened a real array of something
  that was not a finding, the span swallowed both arrays and the error was
  ``missing field `class` `` instead. Those were the *only* two errors the
  2026-09-06 eval logged, 34 and 36 times. The replacement scans balanced,
  string-aware spans and takes the one parsing into the **most** findings —
  most rather than first because the prompt tells the model `[]` is a valid
  answer, so a reply that muses "I would return `[]` if nothing applied" before
  its real answer contains two parseable arrays, and taking the first reports a
  clean bill of health the model never gave (Rule 3).

- **The Track 2 prompt must offer every class the tool speaks, and now a test
  says so.** The prompt calls its class list "the vocabulary the rest of the
  tool speaks" and nothing enforced it. `removed-guard` — the one Track-2-only
  class, the class Track 2 exists to justify — was missing from it, so its 0/3
  in the first scored Track 2 run was guaranteed before the model read a line of
  code. `llm_analyzer::tests::the_prompt_offers_every_class_the_tool_speaks`
  fails on exactly that drift. This is the same family as the free-form-label
  gap below: `Finding::merge_key` is `(handler_id, class)`, so a class the
  prompt omits can neither be reported nor corroborate a Track 1 finding.

- **The CLI honours `RUST_LOG`; `tracing_subscriber::fmt().init()` does not.**
  The builder's default filter is a fixed INFO that ignores the environment
  entirely, which silently swallowed the `debug!` carrying the model reply that
  failed the schema — the only evidence that distinguishes "the extractor took
  the wrong span" from "the model answered in prose". Both look identical in the
  `warn!`. `tracing-subscriber` therefore carries the `env-filter` feature, and
  `RUST_LOG=dike_core=debug dike analyze <path> --llm` prints failing replies.

- **The fixture's `constraint = ...` expressions live on the `vault` account,
  not on the accounts they talk about.** `constraint = vault_token_account.owner
  == vault.key()` reads as if it belongs on `vault_token_account`, and putting it
  there is wrong twice over. First, `account_to_unchecked` skips any declaration
  whose own attribute text mentions `<its own name>.` — a `seeds`/`bump`
  expression that reads the field's own data does not compile once the wrapper
  becomes `UncheckedAccount` — so hosting the constraint on
  `vault_token_account` silently *deletes* a `missing-owner-check` mutation site,
  trading one new class for the loss of a measured one. Second,
  `owner.rs::raw_is_identity_pinning` treats any raw constraint containing
  `.key()` as pinning identity, so the constraint would suppress the very
  finding that mutation is meant to inject. Hosting it on `vault` — already
  skipped by `account_to_unchecked` for its `bump = vault.bump`, and already
  carrying `has_one` — costs nothing. Verified by inventory: the fixture yields
  the same 16 mutants it did before plus 3 `removed-guard`, with no class's
  count or score moved.

- **A `constraint` on the `vault` declaration must never contain the string
  `admin`.** `authority.rs::raw_pins_field` suppresses a
  `missing-authority-binding` finding when a raw constraint's text mentions the
  authority field *and* contains `.key()` or `==`. The fixture's constraints
  are `vault_token_account.owner == vault.key()` and `vault.amount == 0`;
  either one rewritten to mention `admin` would silently zero out
  `strip_has_one`'s 3/3 recall.

- **`close_vault`'s emptiness guard was moved from the handler body into a
  `constraint`, not duplicated into one.** Leaving
  `require!(vault.amount == 0, …)` in the body while adding the same check as a
  constraint makes `strip_constraint`'s mutant carry no defect at all: the body
  still enforces it. The harness would then score a correct silence as a miss,
  which is worse than not measuring the class.

### SARIF severity is mapped faithfully, and that can fail someone's PR check

GitHub fails a pull request's code-scanning check for alerts at `level: error`
or `security-severity` at or above 7.0, unless the repository owner raises the
threshold in Settings → Code security → Code scanning → "Protection rules".
Dike maps `Critical`/`High` to `error` at 9.0/7.0, so on default settings a
dike alert can block a merge.

The alternative was capping every severity below the threshold so a dike run
could never gate anything. That was rejected: it would mean reporting a
critical missing-signer as a medium — a false statement about severity, made
to work around a UI default in someone else's product.

**Rule 4 is not in tension with this.** Rule 4 governs dike's exit code, which
is 0 unconditionally, findings or not. What a consumer's CI does with an
uploaded alert is the consumer's setting, and the README names it.

The map is pinned in the same sense as the per-detector confidences: consumers
triage against it, so a change moves every alert at once.

### SARIF carries no timestamp, though the JSON report does

`RunMetadata.timestamp` is rendered by the JSON and Markdown reporters and
deliberately omitted from SARIF. A SARIF document is a CI artifact that gets
diffed, cached and compared between runs; a clock in it makes every run look
changed and defeats Rule 5's byte-identical guarantee for the one output most
likely to be diffed.

### `HandlerBody.reaches_value_sink` is dataflow, and it over-approximates

Added 2026-09-19. A flow-insensitive, intra-procedural taint pass in
`parser/body.rs` propagates every `ctx.accounts.<name>` through `let` bindings,
struct literals and calls into a sink set of value-moving CPIs (`transfer`,
`transfer_checked`, `burn`, `mint_to`, matched on the last path segment, plus a
native `lamports` / `borrow_mut` assignment). The result is a sorted,
deduplicated `Vec<String>` on `HandlerBody`, so `dike ir` shows it — a dataflow
fact nobody can inspect is one nobody can trust. It is `#[serde(default)]`
because older IR JSON must still deserialize.

**Why it is not "accounts named in the sink call".** `tests/fixtures/programs/vault`
builds its `Transfer` into a local and hands that to `CpiContext::new`, three
hops from the account to `token::transfer`;
`sealevel-attacks/5-arbitrary-cpi/insecure` inlines the same accounts directly
into the call. A rule reading only the sink's own argument tokens treats those
two differently, which is keying on code shape rather than on semantics — the
mistake that invalidated an earlier attempt at this
(`benchmarks/adjudication/2026-09-19-sealevel-attacks.md`).

**`CpiContext::new` is deliberately not a sink**, and for the same reason
`CallSite::is_cpi` cannot serve as the sink predicate — `is_cpi` is already true
for the constructor, so reusing it would report a handler that builds a context
and never invokes it.

**It over-approximates, on purpose (Rule 3).** Taint follows a value wherever it
goes, including into a signer-seed array: in `vault`'s `withdraw`, `admin` is
listed because `ctx.accounts.admin.key()` reaches
`CpiContext::new_with_signer` through `vault_seeds` and `signer_seeds`. That
account does not move tokens — it derives the PDA authorizing the move. Read
membership as "touches a value-moving call", never as "is a party to the
transfer".

No loops, no branches, no cross-function propagation. Nothing in scope needs
them, and each would make the result depend on evaluation order the visitor does
not model.

## Licensing (binding)

Audit reports are **published, not public-domain**. The repo commits
`corpus/sources.toml` and the fetch code; it **never** commits fetched PDFs or
report text. `corpus/cache/` is gitignored. `corpus/notes/` holds our own derived
notes and *is* committed.

## Known gaps

- **`removed-guard`'s value-sink rule ties a token account to state by NAME
  (2026-09-19).** The rule fires when an account reaches a value-moving CPI, is
  named after an account the handler state-writes, and nothing pins it. The
  relationship it is reaching for — *this token account holds the balance that
  state account accounts for* — is exactly what `constraint =
  vault_token_account.owner == vault.key()` expresses, and nothing in this slice
  recovers it in general. **A program that names its vault token account
  `treasury` while writing state to `vault` is missed.** The dataflow rules out
  accounts that never touch value; the *name* is what separates the program's
  own side of a transfer from the counterparty's, and it is carrying more of the
  discrimination than the dataflow is. The name condition is not optional
  padding: without it the rule fires on `depositor_token_account` and
  `admin_token_account` in the clean `vault` fixture, both of which are correct
  code — an unpinned account reaching a transfer is the ordinary case, not a
  defect. Recorded with the rule itself, not discovered afterwards.

- **`pda-sharing` (sealevel-attacks category 8) is not separable by any static
  rule, and the attempt was deliberately abandoned (2026-09-19).** The
  category's `insecure` and `secure` variants have *identical* accounts
  structs, identical handler shapes and identical call sequences. The only
  difference is which field seeds the CPI signer: `pool.mint` in the insecure
  one, `pool.withdraw_destination` in the secure one. Telling those apart
  requires knowing that a mint is shared across pools while a withdraw
  destination is unique to one — a fact about the protocol's data model, not
  about its code. Any rule firing on "the CPI signer's seeds come from a field
  of an account" fires on both variants, which is the "rule firing on
  something both versions share" the adjudication doc already names as proving
  nothing. Reaching this needs the seed expression related to the account's
  cardinality, which is dataflow plus a data model — not a detector.
  `benchmarks/adjudication/2026-09-19-sealevel-attacks.md` carries the
  evidence.

- **A finding merged from multiple sources carries no id, and therefore no
  SARIF fingerprint (found 2026-09-19, in whole-branch review of the SARIF
  work).** `merge::corroborate` and the same-track branch of `merge::merge`
  set `id: String::new()` on the combined finding — reachable on a
  Track-1-only run, since `collapse_by_subject` can keep two same-class
  findings on one handler distinct (different subjects) while
  `Finding::merge_key` still folds them together at `merge()`. `sarif.rs`'s
  `result_for` now omits `partialFingerprints` entirely when `finding.id` is
  empty, rather than emitting the empty string as every such finding's
  fingerprint — which would have made GitHub treat two distinct findings as
  one alert, silently dropping the other (a reporting-layer false negative,
  which Rule 3 forbids). GitHub falls back to its own source-hash
  fingerprinting for these results: degraded, but correct and
  collision-free. Recomputing a merged id so it carries a real fingerprint is
  out of scope here — it would move pinned output under Rule 5, and is a
  decision reserved for the repo owner. See the design spec's "Fingerprints
  are the load-bearing detail" section for the corrected invariant.
- **The SARIF fingerprint has no program component.** `Location::handler_id`
  is `handler` alone (no file, see the entry above on why), so a repository
  analyzing two programs with a handler of the same name and the same defect
  produces the same `finding.id` in both, and GitHub matches alerts within a
  category — the second program's finding does not surface as a separate
  alert. Not fixed: changing the fingerprint scheme is a `/v1` → `/v2` bump,
  which the spec designates as the repo owner's call. Documented instead:
  the README's "In CI" section and `action.yml`'s `category` input both say a
  multi-program repository must pass a distinct `category` per invocation.
- **Track 2 invents its own class labels, and nothing yet constrains them.**
  Observed live on 2026-08-31: asked to review an unauthenticated privileged
  operation, the model answered with class
  `PrivilegedOperationWithoutAuthentication` rather than `missing-signer`.
  `Finding::merge_key` is `(handler_id, class)`, so a Track 2 finding can only
  corroborate a Track 1 one when the class strings match exactly — with free-form
  labels, corroboration would essentially never fire and every LLM finding
  would arrive as a separate, uncorroborated row. The Track 2 prompt must pass
  the known class vocabulary (the constants in
  `dike-lang-anchor/src/detectors/mod.rs`) and constrain the model to it; the CLI
  is the place that can see both sides of the seam to do that.
- Three audit-report sources in `corpus/sources.toml` are commented out: they are
  PDF corpora, and the fetch pipeline reads no PDFs. Two MIT-licensed Markdown
  sources now cover the same classes, so this may never need solving — see the
  commented block in `corpus/sources.toml`.
- **`pda-validation-gap` fires on a cross-handler inconsistency, because the
  shape it used to look for cannot compile (fixed 2026-09-12).** The detector
  filtered on `has_seeds() != has_bump()` — an inconsistent pair — and Anchor
  rejects that at compile time. Verified 2026-09-03 against `anchor-lang` 0.30:
  `seeds` without `bump` fails with "bump must be provided with seeds". So it
  was unreachable on real code and scored 0.000 for three days while
  `strip_seeds_bump`, which removes an entire PDA constraint, injected a
  genuine defect it was never built to see.

  What it looks for now: an account whose type **this program derives with
  `seeds` in some other accounts struct**, declared here with no `seeds` and no
  `address`. The program itself supplies the evidence that the account is a
  PDA, which is what makes the rule quiet — an account no handler ever derives
  yields nothing, so the detector does not fire on every account in every
  program. `Account<'info, T>` still proves owner and discriminator, so this is
  not forgery; it is that any other `T` the program owns is accepted, including
  one the caller created.

  Measured: recall **1.000** (4/4) and precision **1.000** on the mutants, noise
  floor still **0** on the clean fixture, and **0 findings** across 7,211 LOC of
  three real Anchor programs that use `seeds` 75 times between them and reuse
  one account type across as many as 21 declarations. The old inconsistent-pair
  arm is kept: it costs one comparison and is still the right answer for source
  that does not compile, which a triage tool does get handed.

  The pinned confidence (0.65) did not move, so the history series stays
  comparable; the per-class recall row did, deliberately.
- **Corpus chunks carry their ancestor headings, and are capped at 1500 chars.**
  A source structured `### Missing signer check` / `#### Example` used to split
  so the Example chunk was titled just "Example" with the defect named in
  neither its title nor its text — the chunk holding the evidence was divorced
  from the chunk holding the label, and could not be retrieved by the thing it
  was evidence of. Chunks now inherit the root-to-leaf heading path into the
  title *and* the indexed text, because both retrieval legs score the text and a
  breadcrumb that reaches only the citation changes nothing. The cap exists
  because a 5.5 KB chunk embeds to an average over everything inside it, which
  sits moderately close to any query of the same genre and beats sharper small
  chunks on all of them: all four handlers of the vulnerable fixture were
  retrieving the same two blobs. Oversized sections are split at line
  boundaries, never truncated. Corpus went 397 → 470 chunks, max 5534 → 1500,
  and the corpus hash with it — so Track 2 runs either side of this are not
  comparable, while Track 1 is untouched. **It did not help**: Track 2 re-scored
  at 0.000 on every class, now with 0 dropped units rather than 36.

- **Real-program noise went 4.21 → 0.64 findings/KLOC (2026-09-06).** Two
  changes, measured by re-running the same 12-program sweep after each, with the
  mutation eval as the recall guard — every Track 1 class held recall and
  precision at exactly its previous value through both.

  | | findings | /KLOC |
  |---|---:|---:|
  | baseline | 119 | 4.21 |
  | + authority narrowing | 49 | 1.73 |
  | + subject collapse | **18** | **0.64** |

  **The narrowing:** `missing-authority-binding` now fires only when the
  accounts struct declares an account that *claims* the stored authority —
  either named exactly for the field, or carrying an authority role
  (`authority`, `admin`, `owner`, `delegate`, `manager`; `payer` and `signer`
  are excluded as too generic, since nearly every `init` struct has a payer).
  A handler taking a `sender` or a `user` and reading a config that happens to
  store an `admin` is not acting on that authority and has nothing to bind.
  Keyed on the accounts struct rather than the handler body because real
  programs delegate (`fn claim(ctx) { claim::handler(ctx) }`) and the body
  carries no state writes to reason from — a body-based rule would silence
  every delegating program.

  **The collapse:** [`merge::collapse_by_subject`] groups on
  `(class, subject, file)` and keeps one row, whose evidence names every other
  handler the same defect reaches. `Finding::subject` is the anchor. Read the
  row count honestly: **it reduces triage rows, not the number of edits.** One
  `config.pending_admin` row stands for eight accounts structs that each still
  need a `has_one`, and the evidence enumerates all eight. Note also that
  `Location::file` is the *handler's* file — for a delegating program every
  handler reports `lib.rs`, so the file component of the key does no work
  there, and two same-named accounts in different structs will share a row.
  Nothing is deleted, so this stays inside Rule 3, but a future change that
  wanted per-declaration rows would need the accounts struct's own file on the
  finding.

  **A detector whose key is a constant must set `subject = None`.**
  `arithmetic.rs` passes the literal `"arithmetic"` to `finding_at` — it is an
  id seed, not an anchor — so every handler's arithmetic finding shared one
  subject and the collapse folded `deposit`'s and `withdraw`'s into a single
  row. That class is handler-scoped: there is no "same thing seen from several
  handlers" to collapse. Caught by
  `end_to_end::analysis_is_byte_stable_across_runs`, which needs one arithmetic
  finding in each handler. The rule for any new detector: `subject` is an
  anchor that is meaningful ACROSS handlers, or it is `None`.

- **The holdout holds six verified cases (2026-09-06), and scoring it is still
  unimplemented.** Populated from two public Solana audit contests (WOOFi,
  Orderly — accepted findings only, not the rejected and duplicate submissions
  those judging repos also carry) plus the Cashio infinite-mint, whose fix
  commit adds the one missing `assert_keys_eq!`. Every commit hash was resolved
  against the repository and every path and handler read at that commit, with
  Dike run over each program to confirm it parses before the case was written.
  Six rather than the 15–30 target because the intersection of "published
  finding" × "Anchor program" × "resolvable public commit" is genuinely small:
  the most-cited Solana disclosures are native programs, which yield zero
  handlers and would measure the parser's scope rather than detector recall.
  **That conflict is settled (2026-09-12).** The collapse above reports one row
  per `(class, subject)` while the holdout compares per handler — verified
  on the WOOFi case, where Dike finds the defect but reports it under a
  different handler with the real one among 17 absorbed. `Finding` now carries
  `absorbed_handlers`, and the scorer counts a case as a hit when its handler is
  either the reported one or one the row absorbed. The alternative, making the
  collapse presentation-only, was rejected: it would have moved the real-program
  headline back from 0.64 to 1.73 findings/KLOC for every JSON consumer to fix a
  problem that only the scorer had.

- **First measurement on real programs (2026-09-06): 119 findings over 28,247
  LOC of production Anchor code — but only 31 distinct sites.** Track 1 was run
  over 12 real programs (a production cross-chain messaging stack plus four
  in-house projects), 155 handlers. The headline rate is **4.21 findings/KLOC**;
  deduplicated to one row per `(account, field)` it is **1.10/KLOC**, because
  each site is re-reported **3.8×** on average — once per handler that touches
  the same config account.

  | | |
  |---|---|
  | findings | 119 (117 High, 2 Critical) |
  | distinct sites | 31 |
  | `missing-authority-binding` | 101 findings from **19** sites |
  | `missing-owner-check` | 16 |
  | `missing-signer` | 2 |
  | suppressed | 0 across all 12 programs |

  Two defects fall straight out of the shape of that table. **The same finding
  is emitted once per handler**: a config PDA storing `pending_admin` was
  reported 19 times in one program, `pending_authority` 14 times in another,
  because every instruction that reads the config re-triggers it. And
  **`missing-authority-binding` over-fires on stored config**: it flags any
  state struct carrying an authority-shaped `Pubkey` that the handler's accounts
  struct does not bind, including handlers that merely *read* the config and
  perform no privileged action — and including `pending_*` fields, which are
  staged values rather than live authorities. Audited production code trips it
  five times on one global settings account.

  The noise is therefore concentrated, not diffuse, which is the good case: one
  dedup and one predicate narrowing address ~85% of it. The measurement also
  found real signal — three unpinned `UncheckedAccount` payout recipients in a
  prediction-market program, in `claim`, `place_bet` and `refund`.

- **Retrieval, not the model, is why Track 2 is silent — measured, not
  suspected.** Logged 2026-09-06 (`RUST_LOG=dike_lang_anchor=debug`) over
  `leaky_vault`, whose four handlers include a blatant unsigned authority:

  | handler | top hits |
  |---|---|
  | `deposit` | `anchor-constraints#3` "#[account(mut)]", `solana-security-standard#104`, `neodyme-pitfalls#14` "Example" |
  | `initialize` | `anchor-constraints#3`, `neodyme-pitfalls#14` "Example", `anchor-constraints#24` "On this page" |
  | `set_admin` | `anchor-constraints#3`, `neodyme-pitfalls#14` "Example", `anchor-constraints#24` "On this page" |
  | `withdraw` | `neodyme-pitfalls#11` "Example", `neodyme-pitfalls#14` "Example", `anchor-constraints#3` |

  Two defects in one table. **The same documents come back for every handler** —
  `anchor-constraints#3` and `neodyme-pitfalls#14` appear in all four, and
  `withdraw`'s missing-signer bug pulls the same generic constraint reference as
  `initialize`. And **the chunks that come back are navigation furniture**:
  "Example", "On this page", a constraint reference for `#[account(mut)]`. The
  prompt says "Report only defects that the reference documents actually
  support", so the model returns `[]` — which is the *correct* answer to the
  documents it was handed. Track 2's zeros are a retrieval result, not a
  judgement result.

  This makes "retrieve once per concern" (below) concrete rather than
  speculative, and adds a second, cheaper lever: chunks titled "On this page"
  are table-of-contents fragments with no rule text in them, and indexing them
  at all is what lets them outrank the rule they sit next to. **Neither is fixed
  by adding eval cases** — a bigger corpus of programs measures the same silence
  more precisely.

- **Track 2 cites URLs instead of `doc_id`s, and still invents class labels.**
  Observed 2026-09-06 on `leaky_vault` with the real retriever: the one finding
  the model produced was classed `pitfall` and cited
  `https://docs.solana.com/...` rather than the `doc_id` the prompt offered, so
  the grounding filter dropped it. `validate_citations` now resolves a
  citation by id, source URL *or* title, so naming an offered document any way
  it was shown counts — but that did not recover this finding and was never
  going to: the URL names no offered document at all, which makes it a genuine
  hallucination rather than a naming mismatch, and the filter is right to drop
  it.
  What remains is the label half, which has a measurable cost:
  `Finding::merge_key` is `(handler_id, class)`, so an invented label can never
  corroborate a Track 1 finding. A schema `enum` on `class` would forbid the
  latter outright but also forbids the honest "none of these fit" the prompt
  deliberately allows (Rule 3) — that trade is unresolved.
- **`MAX_OUTPUT_TOKENS` (1024) truncates verbose replies mid-array.** Seen
  directly in a 2026-09-06 probe: unconstrained, `qwen2.5-coder:14b` wrote a
  two-finding reply that ran out of tokens inside the second `citations` list.
  Truncation is a schema violation, which costs a retry and then a drop — the
  cap is doing its job against runaway generation (2026-09-01) but it also
  silently costs findings on legitimately long replies. Constrained decoding
  makes replies much more compact, which is a second reason to keep it.
- **Track 2's numbers are still a floor, but no longer a plumbing floor.**
  Until 2026-09-06 nothing constrained the model's output format and up to 36 of
  80 units were dropped before scoring — invisible in the table, where a dropped
  unit looks exactly like a miss. `LlmRequest::response_schema` closed that: the
  drop count is now 0. What remains genuinely unknown is whether retrieval is
  the next bottleneck. Track 2 retrieves once per handler on a query built from
  the whole handler description, and a clean handler and a vulnerable one return
  nearly the same hits. Retrieving once per *concern* is the next thing to try,
  and it is now measurable rather than a matter of taste.
- **`removed-guard` now has cases but still has no number.** The clean fixture
  grew three `constraint = ...` expressions on 2026-09-06 so `strip_constraint`
  has sites at all — before that the class had never produced a single mutant,
  and its `0.000` said nothing. It is Track-2-only by design, so Track 1
  scoring it 0/3 is correct, not a gap. The gap is that Track 2 has never been
  scored, so the class the harness now measures is still unmeasured.
- `benchmarks/holdout/cases.toml` holds six verified cases (2026-09-06) and
  `dike eval holdout --score` can now score them, but the scored run has not
  been spent: `runs.json` is still `[]`. Four of the six cases are
  `removed-guard`, which is Track-2-only, and the holdout scorer runs
  Track 1 only — so a run today measures Track 1 against a set it can reach
  two cases of. The command warns about exactly this before it scores.
- The CI LLM job is a build check, not a scored run: GitHub runners have no GPU,
  so the local generation model cannot run there, and Track 2 also needs an
  indexed corpus that needs an embedding model.
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
| Change what Track 2 sees per handler | `crates/dike-lang-anchor/src/chunker.rs` — the unit's source and its derived query |
| Run or extend the eval harness | `just eval-static`; the CLI is `crates/dike-cli/src/commands/eval.rs` |
| Change how recall, precision or the noise floor are computed | `crates/dike-core/src/eval/metrics.rs` |
| Change the eval history format | `crates/dike-core/src/eval/history.rs`; bump `metrics::SCHEMA_VERSION` in the same change |
| Change what counts as a detection, a false positive or noise | `crates/dike-core/src/eval/differential.rs` |
| Materialize or validate mutants | `crates/dike-core/src/eval/` — `materialize`, `compile_gate`, `reject`; the CLI wiring is `crates/dike-cli/src/commands/eval.rs` |
| Add or change a mutation operator | `crates/dike-lang-anchor/src/mutations/operators.rs` — implement `MutationOperator`, register in `all_operators()`; the shared text surgery is in `mutations/mod.rs` |
| Change what ground truth the eval harness gets | `crates/dike-core/src/eval/` — `MutationLabel` |
| Add a CLI subcommand | `crates/dike-cli/src/main.rs` + `commands/` |
| Change the embedding host or model default | `DEFAULT_OLLAMA_HOST` / `DEFAULT_EMBED_MODEL` in `crates/dike-cli/src/commands/corpus.rs` — the only defaults in the project |
| Swap the generation model or backend | `crates/dike-core/src/llm/` — implement `LlmClient`, or pass a different model string; the pipeline holds a `Box<dyn LlmClient>` |
| Change what shape Track 2 must reply in | `crates/dike-core/src/llm/structured.rs` — `findings_schema()` and `RawLlmFinding` change together; each backend translates it in its own `complete` |
| See why Track 2 dropped a unit | `RUST_LOG=dike_core=debug dike analyze <path> --llm` — prints the reply that failed the schema, which the `warn!` alone cannot tell you |
| Add a corpus source | `corpus/sources.toml` — set `include_paths` for any repository whose Markdown is mostly not corpus material |
| Know when to re-fetch the corpus | The refresh rule at the top of `corpus/sources.toml` |
| Swap the embedding model | It is configuration, not a constant — pass host/model to `OllamaEmbedder::new`; defaults live in the CLI |
| Change how vectors are stored or scored | `crates/dike-core/src/retrieval/store.rs` (the `VectorStore` interface hides the sqlite choice) |
| Change how the two retrieval legs are combined | `crates/dike-core/src/retrieval/rrf.rs` (fusion + the grounding gate) and `retriever.rs` (the legs) |
| Re-tune grounding for a different embedding model | Re-run the measurement recorded in `retrieval/rrf.rs`'s module docs, then move `DENSE_GROUNDING_THRESHOLD` and its envelope test together |
| Give Track 2 a stub corpus in a test | Implement `Retrieve` — Track 2 holds a `Box<dyn Retrieve>`, never a concrete retriever |
| Understand why `dike-core` rejects a word | `crates/dike-core/tests/seam.rs` |
