# Improvement plan — from "well engineered" to "usable and showable"

**Written 2026-09-19.** Value-ranked. Work the tiers in order; within a tier the
order is mostly free.

Two goals drive the ranking, and they are not the same goal:

- **Use it on my own projects** rewards low false-positive rate, easy
  invocation, and not breaking on real code.
- **Pitch or showcase it** rewards demonstrated evidence that it finds real
  bugs somebody else confirmed.

They converge on Tier 1, which is why Tier 1 is Tier 1. They diverge once at
Tier 3 (Track 2), noted there.

## Where the project actually is

Strong: the eval harness with its noise floor and validity gate, determinism,
the core/language seam, the suppression pass, a holdout with a run-once guard,
504 tests, and a habit of recording the measurement behind each decision. The
last two sessions each found a bug *in the measurement apparatus* rather than in
the analyzer, which is the apparatus doing its job.

Thin: five detectors of moderate sophistication; every recall number comes from
19 mutants of one 166-line fixture whose mutation operators were written
alongside the detectors that score against them; six holdout cases, never
scored; **zero adjudicated findings on real code**; an LLM track that started
working three days ago and reports 36 findings/KLOC on a clean program.

The engineering is roughly a year ahead of the evidence. Everything below is
about closing that gap, in the order that closes it fastest.

---

## Tier 1 — Evidence. Nothing else counts until this exists.

### 1. Adjudicate real findings, and run on everything available

**Value: highest. Cost: one session. No code.**

Track 1 currently reports 4 findings over 7,211 LOC of real Anchor code and not
one of them has been checked. `0.64/KLOC` is a volume number; it says the tool
is quiet, not that it is right.

Do: run dike over every Anchor program on disk — the three under `~/work`, the
six holdout checkouts already cloned, plus any others — and label every single
finding true positive / false positive / unsure, with a one-line reason each.
Commit the table.

Unlocks: the first precision number on code nobody tuned against. Every pitch
needs it, and it is also the only honest answer to "should I run this on my own
repos". If precision is bad, that is the most valuable thing to learn this
month, and it is cheap to learn.

Done when: a committed table of every real-program finding with a verdict, and
a precision figure with its denominator stated.

### 2. Put more than one program in the mutation corpus

**Value: very high. Cost: half a session, mostly mechanical.**

Every recall number in the project comes from one 166-line fixture. `eval run`
already accepts multiple programs. Add 3–5 real buildable Anchor crates (the
holdout checkouts are already on disk and already parse).

Unlocks: recall numbers that mean something outside `vault`, and a noise floor
measured over thousands of lines instead of 166. Also stops the fixture's
quirks from being the definition of correctness.

Done when: `eval run` scores over ≥4 programs and `benchmarks/history.json`
holds that run.

### 3. Adjudicate Track 2's noise, then decide its fate

**Value: high. Cost: half a session.**

Track 2 reports 6 findings on the *clean* fixture against Track 1's 0. Some of
those are probably real defects Track 1 misses — `removed-guard` on `deposit`
is plausible — and some are hallucination-shaped. Nobody has looked.

Until they are labelled, "36 findings/KLOC" is unusable as a decision input.
After labelling, the decision is obvious in one direction or the other.

Done when: each of the 6 is labelled, and Track 2 is either kept on by default,
demoted to opt-in, or removed.

---

## Tier 2 — Capability. The ceiling the current design hits.

### 4. A Track 1 detector for `removed-guard`

**Value: high, and it gates the holdout. Cost: one to two sessions.**

It is the only class with no static detector, it scores 0.000 on both tracks,
and it is **four of the six holdout cases**. Until it exists, the holdout mostly
measures a class the tool cannot reach, and spending the one scored run would
produce a number nobody would quote.

This is where the current architecture runs out: "a validation that is simply
absent" is not a pattern you can match on a declaration. It needs the next item,
at least in a limited form.

### 5. Dataflow over the handler body

**Value: high and structural. Cost: several sessions.**

Every detector today is a pattern match over account declarations plus a
substring scan of the body. That cannot answer: does this account's data reach
the authority of a CPI? Is this bump the one stored on the account? Is the
signer compared against *this* field?

Intraprocedural dataflow over the handler body is the step from linter to
analyzer. It is the single biggest capability increase available, it makes
`removed-guard` and the harder PDA cases reachable, and it makes the suppression
pass principled instead of textual.

Start narrow: one dataflow question (does value X reach sink Y within this
handler), used by one detector.

### 6. Widen the holdout from a new seam

**Value: high for pitching, moderate for use. Cost: ongoing, an hour at a time.**

The audit-contest seam is exhausted — Sherlock has exactly two Solana Anchor
contests and both are mined. Untried, in rough order of likely yield: Immunefi
disclosures with public fix commits; OtterSec / Neodyme / Zellic public reports,
whose PDFs name a repo and a commit; GitHub Security Advisories on Anchor
projects; and post-mortems of Solana exploits where the fix commit is public.

Target 15–30 cases. Every field resolved against the repository, never recalled.

### 7. Spend the holdout run — once, at the end

**Value: this is the pitch headline. Cost: an afternoon, unrepeatable.**

Only after 4 and 6. "Dike finds N of M independently published vulnerabilities
in real deployed Anchor programs, at K findings/KLOC on clean code" is the
sentence that makes the project credible to anyone who does not read the source.

Do not spend it before the holdout is worth spending.

---

## Tier 3 — Product. Makes it usable by someone who is not you.

### 8. SARIF output and a GitHub Action

**Value: high for adoption, low for correctness. Cost: half a session.**

SARIF is how a triage tool appears in GitHub code scanning, inline on the diff.
It fits the project's "never block a build" stance exactly: annotations, not
failures. This is the single biggest usability step for putting dike in your
other repos.

### 9. Ergonomics for repeat use

**Value: moderate-high for your own use. Cost: one session.**

What a second user needs and the tool does not have: a config file, per-finding
suppression with a reason (`// dike:allow missing-owner-check — checked in
handler`), and a baseline mode that reports only what is new since a recorded
run. Baseline mode is what makes a tool survive contact with an existing
codebase that has 40 findings on day one.

**Where the goals diverge:** if you only ever pitch it, skip 9. If you actually
run it on your own projects weekly, 9 matters more than 6 or 7.

### 10. Anchor IDL ingestion

**Value: moderate, strategically interesting. Cost: two sessions.**

Programs ship an IDL describing instructions and accounts. Reading it would let
dike analyze *deployed* programs with no source available — a different and
larger audience than "point it at a repo you own". Worth a spike after Tier 2.

---

## Tier 4 — Credibility polish. Cheap, do when blocked on something else.

### 11. `cargo-mutants` against dike itself

The project has a rule that tests must be able to fail and has shipped
assertions that could not, by its own count, at least four times. Mutation
testing automates exactly that check. Low effort, strong fit, and it is a good
line in a pitch: the analyzer's own test suite is mutation-tested.

### 12. A `PROJECT_CONTEXT.md` staleness gate in CI

Rule 1 says the map must be updated with any new crate, module or subcommand. A
CI check that fails when one exists that the map does not mention turns a
convention into a gate. This is the useful version of "self-healing docs";
generating prose is not.

### 13. One demo that fits on a screen

For showcasing: a single command against a real program with a real published
bug, output in under a minute, with the citation visible. Not a screencast of
the test suite.

---

## Explicitly not doing

**An agent framework (LangGraph or similar).** The orchestration here is about
fifty lines in `pipeline.rs`, the project's Rule 5 requires byte-identical
output for identical input, and the codebase is Rust. An agent graph would
import nondeterminism and a second language to solve a problem this project does
not have. If Track 2 needs more structure later, that is a second model call
with a schema, not a framework.

**More detectors before Tier 1.** Adding a sixth pattern-matching detector
increases the number of unverified findings. The bottleneck is not detector
count.

---

## Suggested order for the next few sessions

1. Item 1 — adjudicate real findings. One session, no code, unblocks judgement
   on everything else.
2. Item 3 — label Track 2's six, decide its default.
3. Item 2 — multi-program mutation corpus.
4. Item 8 — SARIF, so you can actually use it while the rest is built.
5. Items 4 and 5 — `removed-guard` and dataflow, the real capability work.
6. Item 6, then 7 — widen the holdout, then spend it once.
