# CLAUDE.md — rules for AI assistants working in this repo

Read [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) **before making any
change.** It is the architecture map: crate boundaries, the seam, the binding
invariants, and the decisions that look odd until you know why.

## Rule 1 — keep `docs/PROJECT_CONTEXT.md` current

**Any change that adds, removes, or meaningfully restructures a crate, module,
CLI subcommand, or major dependency must update `docs/PROJECT_CONTEXT.md` in the
same commit.** A stale map is worse than no map.

Update it for: new crates or modules, new subcommands, new dependencies, changed
module boundaries, a new or altered invariant, a decision that reverses one
already recorded, and any new entry for "Quirks & constraint-driven decisions" or
"Known gaps".

Do not update it for: a new detector inside the existing detector module, a
bugfix, a patch bump, a new test.

If you are unsure whether a change is "meaningful," ask whether a new
contributor would be misled by the old description. If yes, update it.

## Rule 2 — the seam is not negotiable

`crates/dike-core` must contain no Solana or Anchor vocabulary in non-comment
lines. `crates/dike-core/tests/seam.rs` enforces this and **applies to string
literals and test fixtures**, not just identifiers. It has caught real violations
twice. If it fires, fix the code — never the gate.

Domain vocabulary belongs in `crates/dike-lang-anchor`. `crates/dike-cli` is the
only place the two worlds meet.

## Rule 3 — recall over precision

A false positive costs an auditor a minute; a false negative costs them the bug.
When a design call is ambiguous, report more rather than less. This applies with
particular force to `detectors/suppression.rs`, the only component that *deletes*
findings.

## Rule 4 — exit 0 is a feature

Dike is triage, not a gate. Findings never change the exit code. Non-zero is
reserved for tool failure. Do not add a `--fail-on` flag.

## Rule 5 — determinism

Track 1 must produce byte-identical output for identical input. No clock, no
randomness, no `HashMap` iteration order in any path that reaches a `Finding`.
Per-detector confidence values are pinned constants — the eval harness compares
runs across time, so a "small improvement" to one silently invalidates history.

## Rule 6 — tests must be able to fail

Before adding a test, ask what change would make it fail. If the answer is
"nothing," it is not a test. This project has repeatedly shipped assertions that
could not fail for the reason their name claimed — a mutation test whose mutation
no-ops, a stability test comparing two empty vectors, an atomicity test that
passes against a non-atomic write. When fixing a bug, write the test first and
**confirm it fails** against the unfixed code.

## Rule 7 — verify before claiming

Run the command and read the output before saying something passes. The
project's gates:

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p dike-core --test seam
cargo run -p dike-cli -- analyze tests/fixtures/programs/vault   # exit 0, zero findings
```

`clippy` is deny-by-default here and `redundant_comparisons`, `ptr_arg`,
`bool_assert_comparison`, `useless_format`, `question_mark`, `derivable_impls`
and `cloned_ref_to_slice_refs` have each broken this build at least once.

## Rule 8 — network and model access are opt-in

Do not run `dike corpus fetch`, do not run `cargo test -- --ignored`, and do not
invoke Ollama unless the user has explicitly asked in the current session.
`corpus/cache/` being absent is the project's evidence that no fetch has run.
Connecting to a closed local port in a test is fine.

## Rule 9 — the user owns version control

Do not run `git` commands unless asked. Propose the commit; let the user run it.
