# Invocation targets. Dike has no build hook to attach to: cargo offers none
# (`build.rs` is not one — it runs per package during compilation, fires on
# dependency changes, and cannot cleanly abort a workspace with a readable
# report), and neither does `anchor build`. So invocation is a wrapper task.

# The clean fixture is the only mutation source: a mutation applied to
# already-broken code cannot be attributed, and `leaky_vault` is broken on
# purpose. It is also the only fixture that is a buildable crate, which the
# mutation-validity gate needs.
fixture := "tests/fixtures/programs/vault"

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
    cargo run -p dike-cli -- eval run {{fixture}} --track static

# Same, skipping the validity gate. Findings on a mutant that no longer compiles
# inflate recall (D14), so this is for iterating on operators — never for
# numbers you intend to quote.
eval-fast:
    cargo run -p dike-cli -- eval run {{fixture}} --track static --no-compile-check

# Full local eval including Track 2. Needs Ollama running and an indexed corpus;
# `corpus index` makes live requests to the embedding model, so it is deliberately
# not folded into this target.
eval:
    cargo run -p dike-cli -- eval run {{fixture}} --track all

# The real holdout. Touched once, at the end — see benchmarks/holdout/cases.toml.
holdout:
    cargo run -p dike-cli -- eval holdout

# Advisory pre-push pass. `exit 0` is not defensive: dike is triage, and a
# triage tool that blocks a push is a triage tool people uninstall.
install-hook:
    printf '#!/bin/sh\ncargo run -q -p dike-cli -- analyze .\nexit 0\n' > .git/hooks/pre-push
    chmod +x .git/hooks/pre-push
