# Invocation targets. Dike has no build hook to attach to: cargo offers none
# (`build.rs` is not one — it runs per package during compilation, fires on
# dependency changes, and cannot cleanly abort a workspace with a readable
# report), and neither does `anchor build`. So invocation is a wrapper task.

# The mutation sources: clean programs only, because a mutation applied to
# already-broken code cannot be attributed. Both are buildable crates, which
# the validity gate needs.
#
# `escrow` is the one that poses the questions `vault` cannot — it is
# multi-file, its handlers delegate, an account is pinned by a sibling
# declaration, and it stages an authority. Two false-positive classes found by
# adjudicating real code were invisible to a harness scored against `vault`
# alone.
fixture := "tests/fixtures/programs/vault"
fixtures := "tests/fixtures/programs/vault tests/fixtures/programs/escrow"

_default:
    @just --list

# Advisory security pass, then the real build. Dike never blocks: its exit code
# is always 0 unless the tool itself failed.
check program:
    cargo run -p dike-cli -- analyze {{program}}
    anchor build

# The three gates that must be clean before anything is committed.
gates:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo test -p dike-core --test seam
    cargo run -p dike-cli -- analyze {{fixture}}

# What CI runs: deterministic, no model, no network beyond the crate registry.
# The validity gate builds the fixture's dependency tree, so the first run on a
# cold machine is slow; later runs reuse target/eval/vault/.cargo-target.
eval-static:
    cargo run -p dike-cli -- eval run {{fixtures}} --track static

# Same, skipping the validity gate. Findings on a mutant that no longer compiles
# inflate recall, so this is for iterating on operators — never for
# numbers you intend to quote.
eval-fast:
    cargo run -p dike-cli -- eval run {{fixtures}} --track static --no-compile-check

# Full local eval including Track 2. Needs Ollama running and an indexed corpus;
# `corpus index` makes live requests to the embedding model, so it is deliberately
# not folded into this target.
eval:
    cargo run -p dike-cli -- eval run {{fixtures}} --track all

# List the real holdout with its memorization caveat. Scores nothing.
holdout:
    cargo run -p dike-cli -- eval holdout

# The whole scoring path against checkouts already on disk. Fetches nothing, and
# records nothing unless a case was actually scored, so the one run stays unspent.
holdout-dry:
    cargo run -p dike-cli -- eval holdout --score --offline

# THE scored run. Touched once, at the end — it clones each case's
# repository and `runs.json` refuses a second pass. Not part of any gate.
holdout-score:
    cargo run -p dike-cli -- eval holdout --score

# Advisory pre-push pass. `exit 0` is not defensive: dike is triage, and a
# triage tool that blocks a push is a triage tool people uninstall.
install-hook:
    printf '#!/bin/sh\ncargo run -q -p dike-cli -- analyze .\nexit 0\n' > .git/hooks/pre-push
    chmod +x .git/hooks/pre-push
