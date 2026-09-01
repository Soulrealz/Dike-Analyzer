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
- **Phase 5** — complete: corpus document model, manifest, chunking, hashing; HTTP layer and `dike corpus fetch`; BM25 sparse index; embedder + sqlite vector store; RRF fusion and the `Retrieve` seam; the `dike corpus index|query|hash` CLI. The first *live* run (fetch, then index against Ollama) has not happened yet.
- **Phase 6** — complete. `dike analyze --llm` runs both tracks and is verified end to end against a live model: on the vulnerable fixture Track 2 independently reports `missing-signer` on `withdraw`, which merges with Track 1's finding into a **corroborated** Critical at confidence 0.97 carrying its citation link.
- **Phases 7–8** — mutation engine, differential eval harness. Not started.

369 tests pass. `cargo clippy --workspace --all-targets -- -D warnings` is clean.

---

## Folder structure

```
.
├── .superpowers/              SDD agent scaffolding — GITIGNORED, not project history
├── corpus/
│   ├── sources.toml           Corpus manifest: url, kind, licence, retrieval date, class
│   │                           tags, optional include_paths, and the refresh rule
│   ├── notes/                 Our own derived notes — COMMITTED (original work)
│   └── cache/                 Fetched source text — GITIGNORED (see Licensing below)
├── crates/
│   ├── dike-core/             Domain-AGNOSTIC. No Solana vocabulary. See "The seam".
│   │   ├── src/
│   │   │   ├── finding.rs     Finding, Severity, VulnClass, Track, Location, Citation
│   │   │   ├── analyzer.rs    Analyzer trait, SourceTree ingest, Diagnostic, AnalysisResult
│   │   │   ├── merge.rs       Two-track merge, corroboration, deterministic ranking
│   │   │   ├── http.rs        The single HTTP surface (corpus fetch, embedder, LLM client)
│   │   │   ├── llm/           LlmClient seam, Ollama and Gemini backends, structured output
│   │   │   ├── report/        Markdown + JSON renderers, Coverage, RunMetadata
│   │   │   └── retrieval/     Corpus Document/Source model, chunking, hashing, fetching,
│   │   │                       BM25 sparse index, dense embedder, sqlite vector store,
│   │   │                       RRF fusion, the Retrieve seam + HybridRetriever
│   │   └── tests/seam.rs      ARCHITECTURAL GATE — fails the build on Solana vocabulary
│   ├── dike-lang-anchor/      Solana/Anchor-specific. Everything domain lives here.
│   │   ├── src/
│   │   │   │   │   ├── ir.rs          The Anchor IR: Program, Handler, AccountsStruct, Constraint…
│   │   │   ├── parser/        syn-based parsing: accounts, program, symbols, body summary
│   │   │   ├── chunker/       HandlerUnit chunking + derived retrieval queries
│   │   │   ├── detectors/     Five static detectors + the suppression pass
│   │   │   ├── llm_analyzer/  Track 2 assembled: chunk, retrieve, ask, validate
│   │   │   └── lib.rs         AnchorAnalyzer, analyze_program
│   │   └── tests/end_to_end.rs
│   └── dike-cli/              Orchestration only. The ONE place core and Anchor meet.
│       └── src/
│           ├── main.rs        clap subcommands: analyze, ir, corpus fetch|index|query|hash
│           ├── pipeline.rs    Runs both tracks, merges, builds the Report
│           ├── config.rs      RunConfig
│           └── commands/      analyze, ir, corpus
├── docs/
│   ├── PROJECT_CONTEXT.md     This file
│   └── superpowers/
│       ├── specs/             Approved design docs
│       └── plans/             Phased implementation plans
├── tests/fixtures/programs/   Anchor fixture programs (deliberately NO Cargo.toml —
│   ├── vault/                 they are parsed as text, never built)
│   └── leaky_vault/           the vulnerable counterpart: both tracks must fire on it
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
  `Unavailable` mapping that D24 exists to centralise.

- **The generation request caps output tokens (`num_predict`).** Measured on
  2026-09-01: one handler consumed the entire 120-second per-unit budget twice
  running and was dropped, while an identically shaped prompt answered in 7
  seconds — a runaway generation, not a slow one. The cap turns that into a
  truncated reply, which is a schema violation costing one retry and then a
  logged drop. With it, the clean fixture went from 3/4 units examined in 2m43
  to 4/4 in 1m01.

- **A hallucinated citation deletes itself, and an uncited finding is dropped
  (D12).** `validate_citations` keeps only ids that were actually offered to the
  model. Without it, "cite your sources" is a request the model can decline
  silently, and grounding becomes decoration rather than a filter. Duplicate
  citations collapse first, because `track2_confidence` reads the count — citing one
  document twice must not buy the same up-weighting as citing two.

- **A schema violation is retried exactly once, then dropped.** The violation text
  goes back to the model in the retry prompt. A third attempt would spend another
  full timeout on a model that has already failed the same schema twice. A
  *transport* failure propagates instead: flattening it into an empty result would
  make "the model reviewed this and found nothing" indistinguishable from "the model
  is not running", and the report would claim coverage the run never had.

- **HTML headings are re-emitted as Markdown headings (D31).** `chunk_by_finding`
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

- **The grounding thresholds are measured, not inherited from the spec (D11,
  revised 2026-08-31).** The spec's "dense ≥ 0.35 OR any non-zero BM25" accepted
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

- **Track 2 invents its own class labels, and nothing yet constrains them.**
  Observed live on 2026-08-31: asked to review an unauthenticated privileged
  operation, the model answered with class
  `PrivilegedOperationWithoutAuthentication` rather than `missing-signer`.
  `Finding::merge_key` is `(handler_id, class)`, so a Track 2 finding can only
  corroborate a Track 1 one when the class strings match exactly — with free-form
  labels, corroboration (D4) would essentially never fire and every LLM finding
  would arrive as a separate, uncorroborated row. Task 22's prompt must pass the
  known class vocabulary (the constants in
  `dike-lang-anchor/src/detectors/mod.rs`) and constrain the model to it; the CLI
  is the place that can see both sides of the seam to do that.
- Three audit-report sources in `corpus/sources.toml` are commented out: they are
  PDF corpora, and the fetch pipeline reads no PDFs. Two MIT-licensed Markdown
  sources now cover the same classes, so this may never need solving — see the
  commented block in `corpus/sources.toml`.
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
| Change what Track 2 sees per handler | `crates/dike-lang-anchor/src/chunker.rs` — the unit's source and its derived query |
| Add a CLI subcommand | `crates/dike-cli/src/main.rs` + `commands/` |
| Change the embedding host or model default | `DEFAULT_OLLAMA_HOST` / `DEFAULT_EMBED_MODEL` in `crates/dike-cli/src/commands/corpus.rs` — the only defaults in the project |
| Swap the generation model or backend | `crates/dike-core/src/llm/` — implement `LlmClient`, or pass a different model string; the pipeline holds a `Box<dyn LlmClient>` |
| Add a corpus source | `corpus/sources.toml` — set `include_paths` for any repository whose Markdown is mostly not corpus material |
| Know when to re-fetch the corpus | The refresh rule at the top of `corpus/sources.toml` |
| Swap the embedding model | It is configuration, not a constant — pass host/model to `OllamaEmbedder::new`; defaults live in the CLI |
| Change how vectors are stored or scored | `crates/dike-core/src/retrieval/store.rs` (the `VectorStore` interface hides the sqlite choice) |
| Change how the two retrieval legs are combined | `crates/dike-core/src/retrieval/rrf.rs` (fusion + the grounding gate) and `retriever.rs` (the legs) |
| Re-tune grounding for a different embedding model | Re-run the measurement recorded in `retrieval/rrf.rs`'s module docs, then move `DENSE_GROUNDING_THRESHOLD` and its envelope test together |
| Give Track 2 a stub corpus in a test | Implement `Retrieve` — Track 2 holds a `Box<dyn Retrieve>`, never a concrete retriever |
| Understand why `dike-core` rejects a word | `crates/dike-core/tests/seam.rs` |
