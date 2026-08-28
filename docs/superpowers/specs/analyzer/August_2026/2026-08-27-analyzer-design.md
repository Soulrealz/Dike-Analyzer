# Dike — Anchor Security Analyzer — Design Spec

> Status: approved design, pre-implementation.
> Date: 2026-08-27.
> Named for Dike, the Greek goddess of human justice. The other sense — a dike as
> the embankment holding back the flood — fits the tool at least as well.
> Crates: `dike-core`, `dike-lang-anchor`, `dike-cli`. Binary: `dike`.

---

## 1. Purpose

An AI-assisted security triage tool for Solana Anchor programs. Point it at a
program directory; it returns prioritized, precedent-backed findings that tell a
human auditor where to look first.

It is a **triage tool, not a gate**. It optimizes recall over precision: a false
positive costs an auditor a minute, a false negative costs them the bug. This
decision propagates everywhere — into the exit-code policy, the ranking function,
and which metric the eval harness treats as primary.

### Why this is tractable

Anchor encodes most account-security properties *declaratively*, in
`#[account(...)]` attributes on `#[derive(Accounts)]` structs. A large class of
vulnerabilities is therefore a **missing attribute** — a structural AST query,
not a dataflow problem. The Solidity equivalent would require real dataflow
analysis and would not fit the timeframe.

### Non-goals

- **Not a CI gate.** Exit code 0 even when findings exist. It runs as an advisory
  step in the build/acceptance flow (see §9.1), reporting rather than blocking.
  A gating mode was considered and rejected: gating demands precision, this tool
  optimizes recall, and a noisy build check gets disabled within a week.
- No on-chain component.
- No proof of absence. The report says "look here", never "this is safe".
- Native (non-Anchor) Solana programs are out of scope for v1.
- No agentic/tool-calling loop. Rejected deliberately (see §4).

---

## 2. Users and use case

Primary user: an auditor or reviewer facing an unfamiliar Anchor codebase, who
wants a prioritized starting map before manual review.

Secondary user: the author of a program, running it on their own code before
requesting review.

Implication: the tool must work on code it **cannot build**. Missing deps, private
crates, or a mismatched toolchain are the normal case, not the exception.
Analysis is source-only.

---

## 3. Architecture

Two crates. The split IS the extensibility story.

### `dike-core` — domain-agnostic; knows nothing about Solana

| Component | Responsibility |
|---|---|
| `Finding` | The typed struct everything emits: id, severity, confidence, location, class, evidence, precedent citations |

`severity: Critical | High | Medium | Low | Info` — intrinsic to the vulnerability
class, not to how sure we are.

`confidence: f32` — how sure this instance is real. **Track 1 confidence is a
per-detector constant**, not a computed value: a missing `Signer` on an authority
account is near-certain, while unchecked arithmetic is frequently benign. Each
detector declares its own. **Track 2 confidence** comes from the model's structured
output, clamped and down-weighted when only one precedent document was cited.
| `Analyzer` trait | The seam. Source tree in, `Vec<Finding>` out. Every pass is an implementation |
| `retrieval` | Hybrid dense + BM25 with RRF fusion |
| `llm` | One interface over Ollama and Gemini |
| `merge` | Dedupe, confidence combination, ranking |
| `eval` | Harness, mutation runner, metrics |
| `report` | Markdown (human) and JSON (machine) renderers |

### `dike-lang-anchor` — everything Solana-specific

| Component | Responsibility |
|---|---|
| `parser` | `syn`-based; source → IR |
| `detectors` | Constraint-class rules over the IR |
| `chunker` | Emits `HandlerUnit`s for the LLM track |
| `mutations` | The vulnerability-injection catalogue |

### The seam test

Adding Solidity must mean writing `dike-lang-solidity` and touching **nothing** in
`dike-core`. If a port would force a change to `Finding` or to the eval harness,
the boundary is wrong. Validate this by sketching the Solidity `Finding` before
finalizing the struct.

---

## 4. Approach: two-track, merged

Rejected alternatives, recorded so they are not relitigated:

- **Static-gated** (LLM only judges static candidates): recall is hard-capped by
  the static detectors, so it structurally cannot find logic patterns. Contradicts
  the scope.
- **Agentic** (LLM drives, calls the analyzer as a tool): nondeterministic, so
  evals go flaky exactly where they must be trustworthy. On a local 14B the
  sequential tool loop is also too slow for iteration.

**Chosen: two independent tracks over the same program, merged.**

- **Track 1 (static)** — deterministic Rust detectors over the IR. Pure functions,
  no I/O. Account-constraint classes.
- **Track 2 (LLM)** — retrieval-grounded model pass over handler units. Protocol
  logic patterns with audit precedent.

**Hard rule: Track 2 never feeds Track 1's metrics.** Track 1 is reproducible and
its numbers must never move because a prompt changed. Report per-track and merged,
always separately. This separation is what makes the eval table trustworthy, and
it is the main reason this architecture was chosen over the alternatives.

---

## 5. Intermediate representation

```
Program   { instructions: Vec<Handler> }
Handler   { name, args, body_ast, accounts: AccountsStruct }
AccountsStruct { decls: Vec<AccountDecl> }
AccountDecl {
    name,
    wrapper: Signer | Account(ty) | UncheckedAccount | AccountInfo
           | Program | SystemAccount | Sysvar,
    constraints: Vec<Constraint>,
}
Constraint = Mut | Init | Close(expr) | Seeds(expr) | Bump(expr)
           | HasOne(target) | Raw(expr) | Owner(expr) | Signer
```

The IR is the contract between `dike-lang-anchor` and everything downstream.
Detectors, the chunker, and the mutation engine all read it; nothing else parses
Rust.

---

## 6. Data flow

1. **Ingest** — walk the program directory, `syn::parse_file` each `.rs`. No build.
2. **Normalize** — produce the IR.
3. **Track 1** — detectors over the IR emit `Finding`s. Deterministic.
4. **Track 2** — chunker emits `HandlerUnit` (handler body + accounts struct +
   referenced state structs). Per unit: build a derived query, retrieve precedent,
   prompt, parse structured output, emit `Finding`s.
5. **Merge and rank** — dedupe on `(location, class)`. When both tracks report the
   same finding it is **corroborated**: keep the higher severity and raise
   confidence above either track's individual value. Sort by
   `severity x confidence`. Corroborated findings therefore surface first, which
   is the correct triage order.
6. **Render** — Markdown for humans, JSON for the eval harness.

The same `Finding` type flows end to end.

---

## 7. Retrieval

### Corpus

Sealevel Attacks (backbone: canonical classes with vulnerable/fixed pairs),
Neodyme's Solana security series, public OtterSec / Zellic / sec3 reports,
Anchor constraint documentation.

**Licensing:** audit reports are published, not public-domain. Do **not** vendor
PDFs. Commit `corpus/sources.toml` (URL, license note, retrieval date) plus a
fetch script that normalizes into `Document { id, source_url, title, text,
class_tags }`. Derived notes are original work and may be committed.

### Chunking

**By finding, not by token count.** An audit finding is already a semantic unit
(title, description, impact, recommendation). Same principle as the code side: the
domain defines the boundary.

### Query construction

**The query is derived, never raw source.** Build a structured description from the
IR — account wrapper types present, constraints absent, operations performed
(transfer, mint, close, CPI) — and query with that. Raw Rust embeds poorly; a
description of behavior embeds well.

### Fusion

- Dense: `bge-small-en-v1.5` via Ollama, local.
- Sparse: BM25 via `tantivy` (stays in Rust).
- Combination: **Reciprocal Rank Fusion**, k=60. Chosen because dense and sparse
  scores are not on comparable scales; rank fusion needs no tuning.
- Store: `sqlite-vec` — one file, no server, index reproducible from the fetch
  script.

Hybrid genuinely earns its place: BM25 catches exact identifiers (`invoke_signed`,
`UncheckedAccount`, `close =`) that embeddings blur; dense catches conceptual
matches ("privilege escalation via missing owner validation").

### Grounding rule

**Every Track 2 finding must cite at least one retrieved document or it is
dropped.** Uncited findings are precisely the ones that cannot be defended in a
report. This turns retrieval from decoration into a filter.

No reranker in v1 (YAGNI). See §11.

---

## 8. Eval harness

### Synthetic ground truth — mutation testing applied to security

Take working Anchor programs (polyclone: 20 instructions; zk-medical-vault: 7;
plus open-source programs) and apply mutations that each introduce exactly one
vulnerability:

| Mutation | Class |
|---|---|
| `Signer<'info>` -> `AccountInfo<'info>` | Missing signer check |
| `Account<'info, T>` -> `UncheckedAccount<'info>` | Missing owner/type validation |
| Strip `has_one = admin` | Missing authority binding |
| Strip `constraint = ...` | Removed guard |
| Remove `seeds` / `bump` | PDA validation gap |
| `checked_add` -> `+` | Unchecked arithmetic |
| Move state write after CPI | Missing reload |
| Flip rounding direction | Value leak |

Each mutation emits its label: file, span, class, severity. Exact, unlimited, and
immune to memorization because the bug did not exist until injected.

### Differential evaluation (the critical mechanism)

Run on **both** the original and the mutated program.

- **True positive** = finding present in the mutated run, absent in the original
  run, at the mutation site, with matching class.
- **Noise floor** = findings present in both runs, reported separately as findings
  per 1000 LOC.

This sidesteps "is the base program actually clean?" — unanswerable, and it would
otherwise poison every precision number reported.

Matching is at **handler granularity + class**, not line-exact. Line-exact is too
strict and would understate real hits.

### Metrics

Recall and precision per vulnerability class, per track (static / LLM / merged),
plus the noise floor. Primary metric is **recall**, per §1.

### Real holdout

15–30 published findings mapped to specific commits. Touched **only at the end** —
iterating on it means tuning on the test set. Report separately, and state the
memorization caveat explicitly: famous bugs are plausibly in the model's
pretraining data.

### CI constraint

GitHub Actions runners have no GPU, so the local model cannot run there.

- **In CI, every push:** Track 1 only. Deterministic, no LLM, fast.
- **Locally, via make target:** full suite including Track 2. Results committed to
  `benchmarks/history.json`.
- **Optional:** small CI smoke subset against the Gemini free tier.

---

## 9. Error handling

Governing principle: **partial results beat no results.** A triage tool that
crashes on one malformed file is useless on exactly the unfamiliar code it targets.

| Condition | Behavior |
|---|---|
| File fails to parse | Warn, skip, list in the report's coverage section. Never silent |
| LLM output violates schema | One retry with the violation appended; then drop and log |
| LLM unavailable | Track 1 completes; report states Track 2 was skipped. Degraded, not failed |
| Retrieval returns nothing above threshold | Grounding rule applies — Track 2 emits nothing |
| Pathological handler | Per-unit timeout |
| Every run | Record model name, version, and corpus hash in the report |

**Exit code 0 even when findings exist.** Non-zero is reserved for tool failure.
Follows directly from triage-not-gate (§1).

### 9.1 Invocation

Dike runs as the last step before a build, advisory only.

**Cargo has no pre-build hook.** `build.rs` is not one — it runs per-package during
compilation, fires on dependency changes, and cannot cleanly abort a workspace with
a readable report. `anchor build` offers no hook either. So invocation is a wrapper
task, not a hook:

- a `just` / `cargo-make` target that runs `dike` and then `anchor build`
- the same command as a CI step (Track 1 only — no GPU on runners, per §8)
- optionally a `pre-push` git hook

In all three the report is printed and the exit code stays 0. The developer decides
what to do about it; the tool never decides for them.

---

## 10. Stack and cost

| Component | Choice | Cost |
|---|---|---|
| Language | Rust (analyzer, CLI, detectors) | $0 |
| Parsing | `syn` | $0 |
| LLM — eval loops | Qwen2.5-Coder 14B Q4 via Ollama, local | $0 |
| LLM — spot checks | Gemini free tier (key in hand) | $0 |
| Embeddings | `bge-small-en-v1.5`, local | $0 |
| Sparse index | `tantivy` | $0 |
| Vector store | `sqlite-vec` | $0 |
| CI | GitHub Actions (free for public repos) | $0 |
| Corpus | Public sources | $0 |

**Total: $0.** Hardware: RTX 5070 12GB VRAM / 15GB system RAM. Stay at 8–14B
quantized — system RAM is the binding constraint, so anything requiring
significant CPU offload will crawl.

Cost discipline: run eval loops locally where iterations are unlimited; reserve
the hosted free tier for reference comparisons against a frontier model. This
split is also a legitimate design story ("local model in the loop, frontier model
as reference").

---

## 11. Extension paths

1. **`dike-lang-solidity`** — the one that matters. New crate implementing
   `Analyzer`, parsing via `solang-parser` or `slang`. Core untouched. Corpus gains
   a Solidity partition (Code4rena, Sherlock, Solodit); mutation catalogue gains
   Solidity operators. This is what eventually covers Desultory_Lending. A feature
   of the analyzer, not a second project.
2. **Reranking** — cross-encoder after RRF. Deferred deliberately: with the harness
   built, its value can be *proven* rather than assumed.
3. **Cross-instruction invariants** — the IR already models every handler; needs a
   state-effect summary per handler plus a search over call sequences. Attempt only
   once single-handler numbers are solid.
4. **Native Solana programs** — no declarative constraints, so every check becomes
   dataflow. Genuinely hard; distant.
5. **Self-healing docs tool** — reuses core wholesale (AST layer, LLM client,
   structured output, CI harness, eval methodology). Doc drift = extract claims
   from docs, check against the IR, report divergence.

The through-line: **the eval harness turns every extension from a guess into a
measurable experiment.** That belongs in the README.

---

## 12. Open items

- Exact holdout case selection (which published findings, which commits).
- Whether `tantivy` or a simpler BM25 implementation is warranted at v1 corpus size.
