# Handler-body dataflow, slice one — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `removed-guard` a fourth rule that fires when an account reaches a
value-moving CPI, is named after state the handler writes, and nothing pins its
identity — moving static recall on that class from 0.200 to 0.600.

**Architecture:** A flow-insensitive, intra-procedural taint pass inside the
existing `syn` visitor in `crates/dike-lang-anchor/src/parser/body.rs`
propagates `ctx.accounts.<name>` through `let` bindings, struct literals and
calls into a sink set of value-moving CPIs. The result is stored on
`HandlerBody::reaches_value_sink`, sorted and deduplicated, so `dike ir` can
show it. `detectors/removed_guard.rs` then reads that field and adds one rule
under the existing class, severity and confidence. Everything lives in
`dike-lang-anchor`; the `dike-core` seam is not touched.

**Tech Stack:** Rust 2021, `syn` 2.x visitor API, `proc-macro2`, `quote`,
`serde`. No new dependencies.

**Spec:** [`docs/superpowers/specs/dataflow/September_2026/2026-09-19-handler-dataflow-design.md`](../../../specs/dataflow/September_2026/2026-09-19-handler-dataflow-design.md)
— read it end to end before starting, in particular §7 (two framings already
tried and rejected) and §9 (the pinned expectations this change must move).

## Global Constraints

Copied from `CLAUDE.md` and the spec's §10. Every task's requirements include
these.

- **Rule 2 — the seam.** `crates/dike-core` must contain no Solana or Anchor
  vocabulary in non-comment lines, including string literals and test fixtures.
  All work here is in `dike-lang-anchor`. Run `cargo test -p dike-core --test seam`
  in every task anyway.
- **Rule 3 — recall over precision**, except in `detectors/suppression.rs`. This
  work adds findings, so the bias favours it — but the clean-fixture gate
  (`vault` and `escrow` report **zero** findings) is absolute and outranks it.
- **Rule 4 — exit 0 is a feature.** Findings never change the exit code. No
  `--fail-on` flag.
- **Rule 5 — determinism.** Byte-identical output for identical input. No clock,
  no randomness, **no `HashMap` iteration order in any path reaching a
  `Finding`**. `reaches_value_sink` must be sorted and deduplicated — build it
  in a `BTreeSet<String>` and collect at the end, never a `HashSet`.
  `RemovedGuardDetector::confidence()` stays **exactly 0.60**; per-detector
  confidences are pinned constants and moving one invalidates the whole
  `benchmarks/history.json` series.
- **Rule 6 — tests must be able to fail.** For every new test, name the change
  that breaks it, then *prove it* by mutating the implementation and checking
  that the test notices. Expect *equivalent* mutants — a mutation that changes
  no behaviour and correctly catches nothing is not a gap in the test.
- **Rule 7 — verify before claiming.** Run the command and read the output.
  Grep for `FAILED` explicitly or read the tail: a grep for `test result: ok`
  has reported a green build over a failing test in this repo before.
  `cargo test --workspace` prints one `test result:` line **per test binary** —
  the workspace total is the sum, and three implementers have quoted a single
  line as the total and been wrong by a factor of two.
- **Rule 9 — the user owns version control.** **Do not run `git`.** Each task's
  final step *proposes* a commit; print the message and stop. Commit messages in
  this repo are a **single lowercase line — no body, no trailers, no
  co-author lines.**
- **Rule 10 — `learning/`.** No action required: `learning/README.md:67` lists
  `parser/{body,program,symbols}.rs` among the files not yet toured, and Part 06
  covers `parser/{mod,accounts}.rs` only. Re-read that line rather than trusting
  this sentence if the index has moved. `learning/` is gitignored regardless.
- **Never point `eval run --out` at `benchmarks/history.json`.** It appends a
  series entry. Use a throwaway path, and pass `--work-dir` somewhere outside
  `target/`. The scratch directory for this session is
  `$CLAUDE_JOB_DIR/tmp`.

## Verified baseline (read from the commands' own output, 2026-09-19)

```
cargo clippy --workspace --all-targets -- -D warnings          clean
cargo test --workspace                                         576 passing, 8 ignored
cargo test -p dike-core --test seam                            green
analyze tests/fixtures/programs/vault                          exit 0, 0 findings
analyze tests/fixtures/programs/escrow                         exit 0, 0 findings
eval run (static, --no-compile-check):
  missing-signer               1.000  5/5   precision 1.000
  missing-owner-check          1.000  4/4   precision 1.000
  missing-authority-binding    1.000  4/4   precision 1.000
  pda-validation-gap           1.000 13/13  precision 1.000
  unchecked-arithmetic         1.000  2/2   precision 1.000
  removed-guard                0.200  1/5   precision 1.000     <-- the target
  noise floor (static)         0 findings / 470 LOC
leaky_vault SARIF                                              7 results, 5 rules
```

---

## File Structure

| File | Responsibility after this change |
|---|---|
| `crates/dike-lang-anchor/src/ir.rs` | Gains `HandlerBody::reaches_value_sink: Vec<String>` with `#[serde(default)]`. No logic. |
| `crates/dike-lang-anchor/src/parser/body.rs` | Gains the taint map, `expr_taint`, the sink set, and the sink hooks in `visit_expr_call` / `visit_expr_method_call` / `visit_expr_assign`. Owns *what reaches a value sink*. |
| `crates/dike-lang-anchor/src/detectors/owner.rs` | `pinned_by_sibling` becomes `pub(crate)`. Nothing else changes. |
| `crates/dike-lang-anchor/src/detectors/removed_guard.rs` | Gains the fourth rule and two private helpers (`named_after_written_state`, `identity_is_pinned`). Owns *whether an unpinned account reaching a sink is a defect*. |
| `crates/dike-cli/tests/analyze_sarif.rs` | `leaky_vault` counts move 7/5 → 8/6. |
| `.github/workflows/ci.yml` | `action-smoke`'s three assertions move the same way. |
| `docs/PROJECT_CONTEXT.md` | Documents the new IR field and the known false negative from spec §6. |

The split is deliberate: the parser answers a dataflow question with no opinion
about security, and the detector answers a security question with no parsing.
That is the boundary `dike ir` makes inspectable.

---

## Task 1: The taint pass and the IR field

**Files:**
- Modify: `crates/dike-lang-anchor/src/ir.rs:29-35` (the `HandlerBody` struct)
- Modify: `crates/dike-lang-anchor/src/parser/body.rs` (visitor struct, new
  helpers, three `visit_*` methods, `summarize_body`)
- Test: `crates/dike-lang-anchor/src/parser/body.rs` (the existing `mod tests`
  at the bottom)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `crate::ir::HandlerBody::reaches_value_sink: Vec<String>` — account names,
    sorted and deduplicated. Read by Task 2.
  - No new public functions. `expr_taint`, `SINKS` and `is_sink_name` are
    private to `body.rs`.

### Step 1: Add the IR field

- [x] **Step 1: Add `reaches_value_sink` to `HandlerBody`**

In `crates/dike-lang-anchor/src/ir.rs`, replace the `HandlerBody` struct:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HandlerBody {
    pub calls: Vec<CallSite>,
    pub arithmetic: Vec<ArithOp>,
    pub checks: Vec<ImperativeCheck>,
    pub state_writes: Vec<StateWrite>,
    /// Accounts that reach a value-moving CPI in this handler, by the path the
    /// body actually takes: through `let` bindings, struct literals and method
    /// calls, not merely by appearing in the sink call's own argument tokens.
    ///
    /// The distinction is load-bearing. `tests/fixtures/programs/vault` builds
    /// its `Transfer` struct into a local and hands that to `CpiContext::new`,
    /// three hops from the account to `token::transfer`;
    /// `sealevel-attacks/5-arbitrary-cpi/insecure` inlines the same accounts
    /// directly into the call. A rule reading only the sink's own arguments
    /// treats those two differently, which is keying on code shape rather than
    /// on semantics.
    ///
    /// Flow-insensitive and intra-procedural: no loops, no branches, no
    /// cross-function propagation. Nothing in scope needs them and Rule 5 wants
    /// this cheap and deterministic.
    ///
    /// Sorted and deduplicated, so it is byte-stable across runs (Rule 5).
    #[serde(default)]
    pub reaches_value_sink: Vec<String>,
}
```

`#[serde(default)]` is required, not decorative: `HandlerBody` derives
`Deserialize` and IR JSON written before this field existed must still load.

- [x] **Step 2: Confirm the workspace still builds**

Run: `cargo build --workspace 2>&1 | tail -20`
Expected: builds. `Default` is derived, so no construction site needs editing.

### Step 3-6: The sink set and the taint map (test first)

- [x] **Step 3: Write the failing parser tests**

Append these to the existing `mod tests` block at the bottom of
`crates/dike-lang-anchor/src/parser/body.rs`. They use the `body(&str)` helper
already defined there.

```rust
    /// The three-hop shape from `tests/fixtures/programs/vault`, lines 22-28:
    /// account -> struct literal -> local -> call argument -> sink. A rule
    /// that reads only `token::transfer`'s own argument tokens sees `cpi_ctx`
    /// and `amount` and nothing else.
    ///
    /// Breaks if: struct-literal propagation is dropped, `let` propagation is
    /// dropped, argument propagation is dropped, or `transfer` leaves the sink
    /// set.
    #[test]
    fn taint_reaches_a_sink_through_a_struct_literal_a_local_and_a_cpi_context() {
        let b = body(r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                let cpi_accounts = Transfer {
                    from: ctx.accounts.depositor_token_account.to_account_info(),
                    to: ctx.accounts.vault_token_account.to_account_info(),
                    authority: ctx.accounts.depositor.to_account_info(),
                };
                let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                token::transfer(cpi_ctx, amount)?;
                Ok(())
            }
        "#);
        for want in ["depositor", "depositor_token_account", "token_program", "vault_token_account"] {
            assert!(
                b.reaches_value_sink.iter().any(|a| a == want),
                "{want} missing from {:?}",
                b.reaches_value_sink
            );
        }
    }

    /// The other half of the shape-insensitivity claim: the same accounts
    /// inlined into the sink call, with no local at all.
    ///
    /// Breaks if: propagation is implemented only over `let` bindings.
    #[test]
    fn taint_reaches_an_inlined_sink_with_no_local_binding() {
        let b = body(r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                token::transfer(
                    CpiContext::new(
                        ctx.accounts.token_program.to_account_info(),
                        Transfer {
                            from: ctx.accounts.depositor_token_account.to_account_info(),
                            to: ctx.accounts.vault_token_account.to_account_info(),
                            authority: ctx.accounts.depositor.to_account_info(),
                        },
                    ),
                    amount,
                )?;
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.iter().any(|a| a == "vault_token_account"), "{:?}", b.reaches_value_sink);
        assert!(b.reaches_value_sink.iter().any(|a| a == "depositor_token_account"), "{:?}", b.reaches_value_sink);
    }

    /// An account the handler only reads or writes state on does not reach a
    /// value sink. If this field said "every account the handler mentions" it
    /// would carry no information and the detector reading it would fire on
    /// everything.
    ///
    /// Breaks if: taint is seeded from every `ctx.accounts.X` rather than from
    /// the ones that flow into a sink.
    #[test]
    fn an_account_that_only_takes_a_state_write_does_not_reach_a_sink() {
        let b = body(r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                ctx.accounts.config.counter = amount;
                let cpi_accounts = Transfer {
                    from: ctx.accounts.source.to_account_info(),
                    to: ctx.accounts.dest.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts), amount)?;
                Ok(())
            }
        "#);
        assert!(!b.reaches_value_sink.iter().any(|a| a == "config"), "{:?}", b.reaches_value_sink);
        assert!(b.reaches_value_sink.iter().any(|a| a == "source"), "{:?}", b.reaches_value_sink);
    }

    /// `CpiContext::new` and `new_with_signer` are intermediate constructors,
    /// not sinks. A handler that builds one and never invokes it moves no
    /// value. Treating the constructor as the sink would make the field fire
    /// on dead code.
    ///
    /// Breaks if: `CpiContext` is added to the sink set, or if `is_cpi` on
    /// `CallSite` is reused as the sink predicate — `is_cpi` is already true
    /// for `CpiContext::new`.
    #[test]
    fn building_a_cpi_context_without_invoking_it_is_not_a_sink() {
        let b = body(r#"
            pub fn deposit(ctx: Context<Deposit>) -> Result<()> {
                let cpi_accounts = Transfer {
                    from: ctx.accounts.source.to_account_info(),
                    to: ctx.accounts.dest.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                let _unused = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.is_empty(), "{:?}", b.reaches_value_sink);
    }

    /// Rule 5. Two sinks touching overlapping accounts must not produce
    /// duplicates or source-order output; `dike ir` prints this field and the
    /// eval harness compares runs byte for byte.
    ///
    /// Breaks if: the accumulator becomes a `Vec` with plain `push`, or a
    /// `HashSet`.
    #[test]
    fn reaches_value_sink_is_sorted_and_deduplicated() {
        let b = body(r#"
            pub fn sweep(ctx: Context<Sweep>, amount: u64) -> Result<()> {
                token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), Transfer {
                    from: ctx.accounts.zeta.to_account_info(),
                    to: ctx.accounts.alpha.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                }), amount)?;
                token::burn(CpiContext::new(ctx.accounts.token_program.to_account_info(), Burn {
                    mint: ctx.accounts.alpha.to_account_info(),
                    from: ctx.accounts.zeta.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                }), amount)?;
                Ok(())
            }
        "#);
        let mut sorted = b.reaches_value_sink.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(b.reaches_value_sink, sorted, "{:?}", b.reaches_value_sink);
        assert!(b.reaches_value_sink.iter().any(|a| a == "alpha"));
        assert!(b.reaches_value_sink.iter().any(|a| a == "zeta"));
    }

    /// Native lamport movement, which uses no CPI at all. Both sides of the
    /// assignment are recorded: the drained account and the credited one are
    /// each moving value, and Rule 3 favours reporting both.
    ///
    /// Breaks if: the `lamports` / `borrow_mut` assignment sink is dropped.
    #[test]
    fn a_lamports_borrow_mut_assignment_is_a_sink() {
        let b = body(r#"
            pub fn drain(ctx: Context<Drain>, amount: u64) -> Result<()> {
                **ctx.accounts.vault_pda.to_account_info().try_borrow_mut_lamports()? -= amount;
                **ctx.accounts.recipient.lamports.borrow_mut() += amount;
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.iter().any(|a| a == "recipient"), "{:?}", b.reaches_value_sink);
    }

    /// Flow-insensitive, textual order, later binding wins — the same
    /// heuristic `aliases` already documents. Pinned so the choice is a
    /// decision rather than an accident.
    ///
    /// Breaks if: `let` taint is merged into the existing entry instead of
    /// replacing it.
    #[test]
    fn a_rebound_local_replaces_its_earlier_taint() {
        let b = body(r#"
            pub fn shift(ctx: Context<Shift>, amount: u64) -> Result<()> {
                let accs = Transfer {
                    from: ctx.accounts.first.to_account_info(),
                    to: ctx.accounts.dest.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                let accs = Transfer {
                    from: ctx.accounts.second.to_account_info(),
                    to: ctx.accounts.dest.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), accs), amount)?;
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.iter().any(|a| a == "second"), "{:?}", b.reaches_value_sink);
        assert!(!b.reaches_value_sink.iter().any(|a| a == "first"), "{:?}", b.reaches_value_sink);
    }

    /// A method-call sink, the spelling `anchor_spl`'s newer helpers and
    /// hand-rolled wrappers use. Matching is on the LAST path segment so
    /// `transfer`, `token::transfer` and `anchor_spl::token::transfer` all
    /// count.
    ///
    /// Breaks if: only `syn::ExprCall` is hooked and `ExprMethodCall` is not.
    #[test]
    fn a_method_call_sink_is_matched_on_its_name() {
        let b = body(r#"
            pub fn go(ctx: Context<Go>, amount: u64) -> Result<()> {
                ctx.accounts.helper.mint_to(ctx.accounts.recipient.to_account_info(), amount)?;
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.iter().any(|a| a == "recipient"), "{:?}", b.reaches_value_sink);
    }
```

- [x] **Step 4: Run the tests and watch them fail**

Run:
```
cargo test -p dike-lang-anchor --lib parser::body 2>&1 | tail -30
```

Expected: a compile error — `reaches_value_sink` does not exist yet **if Step 1
was skipped**; otherwise seven of the eight fail on empty vectors and
`building_a_cpi_context_without_invoking_it_is_not_a_sink` **passes
vacuously**, because nothing populates the field yet.

Write down which tests passed here. `building_a_cpi_context...` and
`an_account_that_only_takes_a_state_write...`'s negative half and
`a_rebound_local_replaces...`'s negative half are the vacuous ones — the spec
warns about exactly this, and Step 7 is where you prove they bind.

- [x] **Step 5: Implement the taint pass**

In `crates/dike-lang-anchor/src/parser/body.rs`:

**5a. Imports and the visitor field.** Change the first two lines and the
`BodyVisitor` struct:

```rust
use crate::ir::{ArithOp, CallSite, CheckKind, HandlerBody, ImperativeCheck, StateWrite};
use std::collections::{BTreeSet, HashMap};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

#[derive(Default)]
struct BodyVisitor {
    body: HandlerBody,
    /// local variable name -> account name it was bound to via `&ctx.accounts.<name>` /
    /// `&mut ctx.accounts.<name>`. Populated in textual visitation order, so a later
    /// `let x = ...` naturally shadows an earlier one — this is a heuristic, not a real
    /// scope model: a name rebound to something unrelated inside a nested block will
    /// incorrectly "leak" that shadow to code after the block that uses the outer binding.
    /// Acceptable for a triage IR; not sound for a real borrow checker.
    aliases: HashMap<String, String>,
    /// local variable name -> the set of accounts whose value flows into it.
    ///
    /// Distinct from `aliases`, which answers "is this local *the* account" for
    /// state-write attribution. This answers "which accounts' values are inside
    /// this local", which is a union and not a single name: a `Transfer { .. }`
    /// struct literal carries three at once.
    ///
    /// `HashMap` is safe here despite Rule 5 because it is only ever looked up
    /// by key; the accumulator that reaches the IR is the `BTreeSet` below.
    taint: HashMap<String, BTreeSet<String>>,
    /// Accounts seen flowing into a value-moving sink. A `BTreeSet` so the IR
    /// field is sorted and deduplicated without a later sort (Rule 5).
    reaches_sink: BTreeSet<String>,
}
```

**5b. The sink set.** Add below `identifiers()`:

```rust
/// Calls that move value. Domain vocabulary, and therefore in
/// `dike-lang-anchor` and never in `dike-core` (Rule 2).
///
/// Matched on the LAST path segment, so `transfer`, `token::transfer`,
/// `anchor_spl::token::transfer` and `system_program::transfer` all count
/// without enumerating the module paths people actually write.
///
/// `CpiContext::new` and `new_with_signer` are deliberately absent. They are
/// intermediate constructors: taint flows *through* them into the `transfer`
/// that consumes them, and treating the constructor as the sink would report a
/// handler that builds a context and never invokes it.
const VALUE_SINKS: [&str; 4] = ["transfer", "transfer_checked", "burn", "mint_to"];

fn is_value_sink(path: &str) -> bool {
    let last = path.rsplit("::").next().unwrap_or(path);
    VALUE_SINKS.contains(&last)
}
```

**5c. `expr_taint`.** Add below `resolve_account_root`:

```rust
/// Which accounts' values flow into `expr`.
///
/// Three propagation forms, which is everything the fixtures and the
/// `sealevel-attacks` set need (spec §4): a `let`-bound local, a struct
/// literal, and a method or function call, whose taint is the union of its
/// receiver's and its arguments'. The wrapper expressions below (`&x`, `*x`,
/// `(x)`, `x?`, `x as T`, tuples, arrays, binaries) carry taint through
/// unchanged; they are not propagation rules so much as the absence of a
/// barrier.
///
/// Deliberately NOT handled: loops, branches, and calls into other functions
/// in the crate. Nothing in scope needs them, and each would make the result
/// depend on evaluation order that this visitor does not model.
fn expr_taint(
    expr: &syn::Expr,
    aliases: &HashMap<String, String>,
    taint: &HashMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    // A `ctx.accounts.X...` chain, or a local aliased to one, is a source and
    // needs no further descent.
    if let Some(account) = resolve_account_root(expr, aliases) {
        out.insert(account);
        return out;
    }
    // Not `let mut` — it mutates only its `out` argument, never a capture, so
    // a `mut` binding here is an unused-mut warning and this build denies them.
    let union = |e: &syn::Expr, out: &mut BTreeSet<String>| {
        out.extend(expr_taint(e, aliases, taint));
    };
    match expr {
        syn::Expr::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                if let Some(t) = taint.get(&seg.ident.to_string()) {
                    out.extend(t.iter().cloned());
                }
            }
        }
        syn::Expr::Struct(s) => {
            for f in &s.fields {
                union(&f.expr, &mut out);
            }
            if let Some(rest) = &s.rest {
                union(rest, &mut out);
            }
        }
        syn::Expr::MethodCall(m) => {
            union(&m.receiver, &mut out);
            for a in &m.args {
                union(a, &mut out);
            }
        }
        syn::Expr::Call(c) => {
            for a in &c.args {
                union(a, &mut out);
            }
        }
        syn::Expr::Reference(r) => union(&r.expr, &mut out),
        syn::Expr::Unary(u) => union(&u.expr, &mut out),
        syn::Expr::Paren(p) => union(&p.expr, &mut out),
        syn::Expr::Group(g) => union(&g.expr, &mut out),
        syn::Expr::Try(t) => union(&t.expr, &mut out),
        syn::Expr::Cast(c) => union(&c.expr, &mut out),
        syn::Expr::Field(f) => union(&f.base, &mut out),
        syn::Expr::Index(i) => {
            union(&i.expr, &mut out);
            union(&i.index, &mut out);
        }
        syn::Expr::Binary(b) => {
            union(&b.left, &mut out);
            union(&b.right, &mut out);
        }
        syn::Expr::Array(a) => {
            for e in &a.elems {
                union(e, &mut out);
            }
        }
        syn::Expr::Tuple(t) => {
            for e in &t.elems {
                union(e, &mut out);
            }
        }
        _ => {}
    }
    out
}
```

**5d. Hook `visit_expr_call`.** Insert before the trailing
`visit::visit_expr_call(self, node);`:

```rust
        if is_value_sink(&name) {
            for a in &node.args {
                self.reaches_sink
                    .extend(expr_taint(a, &self.aliases, &self.taint));
            }
        }
```

**5e. Hook `visit_expr_method_call`.** Insert before the trailing
`visit::visit_expr_method_call(self, node);`:

```rust
        if is_value_sink(&node.method.to_string()) {
            self.reaches_sink
                .extend(expr_taint(&node.receiver, &self.aliases, &self.taint));
            for a in &node.args {
                self.reaches_sink
                    .extend(expr_taint(a, &self.aliases, &self.taint));
            }
        }
```

Note `name` is already moved into the `CallSite` push in this method, so use
`node.method.to_string()` again rather than reordering the existing code.

**5f. Hook `visit_expr_assign` for native lamport moves.** Insert at the top of
the existing `visit_expr_assign`, before the `resolve_account_root` block:

```rust
        // Native lamport movement uses no CPI at all:
        // `**a.try_borrow_mut_lamports()? -= n` / `**b.lamports.borrow_mut() += n`.
        // Both sides are recorded — the drained account and the credited one
        // are each moving value, and Rule 3 favours reporting both.
        let lhs = &node.left;
        let lhs_text: String = quote::quote!(#lhs).to_string().chars().filter(|c| !c.is_whitespace()).collect();
        if lhs_text.contains("lamports") && lhs_text.contains("borrow_mut") {
            self.reaches_sink
                .extend(expr_taint(&node.left, &self.aliases, &self.taint));
            self.reaches_sink
                .extend(expr_taint(&node.right, &self.aliases, &self.taint));
        }
```

Compound assignment (`-=`, `+=`) parses as `Expr::Binary` in syn 2.x, not
`Expr::Assign` — the same trap `visit_expr_binary` already documents, and
`**a.lamports.borrow_mut() -= n` is the spelling that actually appears. So add
the same sink to `visit_expr_binary` as well, inside the existing
`if is_compound_assign { ... }` arm. `syn::ExprBinary` also has `left` and
`right`, so the body is identical:

```rust
            let lhs = &node.left;
            let lhs_text: String = quote::quote!(#lhs).to_string().chars().filter(|c| !c.is_whitespace()).collect();
            if lhs_text.contains("lamports") && lhs_text.contains("borrow_mut") {
                self.reaches_sink
                    .extend(expr_taint(&node.left, &self.aliases, &self.taint));
                self.reaches_sink
                    .extend(expr_taint(&node.right, &self.aliases, &self.taint));
            }
```

If the duplication bothers clippy or a reviewer, lift it into a
`fn lamports_sink_text(expr: &syn::Expr) -> bool` free function and call it from
both. Do not lift the `self.reaches_sink.extend(...)` pair into a method that
takes `&mut self` and borrows `self.aliases` at the same time — that is a borrow
conflict, and the reason the block is written inline here.

**5g. Record `let` taint.** In `visit_local`, after the existing `aliases`
block and still inside `if let Some(name) = pat_ident_name(&node.pat)`:

```rust
                let t = expr_taint(&init.expr, &self.aliases, &self.taint);
                // Replaces rather than merges: textual order, later binding
                // wins, matching the `aliases` heuristic documented above.
                self.taint.insert(name.clone(), t);
```

Restructure the block so `name` is available to both (clone it for the
`aliases` insert). The whole `visit_local` becomes:

```rust
    fn visit_local(&mut self, node: &'ast syn::Local) {
        // Alias ONLY `let x = &ctx.accounts.y` / `let x = &mut ctx.accounts.y` (or a
        // chain through an existing alias). Anything else — e.g.
        // `let k = ctx.accounts.vault.key();` — must NOT bind `k` to the account: that
        // local holds a `Pubkey`, not the account, and writes through it are not state
        // writes to the account.
        if let Some(name) = pat_ident_name(&node.pat) {
            if let Some(init) = &node.init {
                if let syn::Expr::Reference(r) = init.expr.as_ref() {
                    if let Some(account) = resolve_account_root(&r.expr, &self.aliases) {
                        self.aliases.insert(name.clone(), account);
                    }
                }
                // Taint is broader than aliasing: a local holding a `Transfer
                // { .. }` is not any one account, but three accounts' values
                // are inside it. Replaces rather than merges — textual order,
                // later binding wins, as `aliases` above does.
                let t = expr_taint(&init.expr, &self.aliases, &self.taint);
                self.taint.insert(name, t);
            }
        }
        visit::visit_local(self, node);
    }
```

**5h. Publish the result.** In `summarize_body`, replace the final `v.body` with:

```rust
    v.visit_block(&f.block);
    v.body.reaches_value_sink = v.reaches_sink.into_iter().collect();
    v.body
}
```

A `BTreeSet` drains in sorted order, so the field is sorted and deduplicated by
construction — no sort call to forget.

- [x] **Step 6: Run the tests and verify they pass**

Run:
```
cargo test -p dike-lang-anchor --lib parser::body 2>&1 | tail -30
```
Expected: all pass, including the eight existing tests. Read the output; do not
grep for `ok`.

- [x] **Step 7: Prove the vacuous tests now bind (Rule 6)**

Three of the new tests passed in the RED phase because an empty vector
satisfies a negative assertion. Prove each one binds by mutating the
implementation and confirming the *named* test fails. Revert each mutation
before the next.

| Mutation | Test that must fail |
|---|---|
| Add `"new"` to `VALUE_SINKS` | `building_a_cpi_context_without_invoking_it_is_not_a_sink` |
| In `expr_taint`, seed `out` from every `ctx.accounts.X` in the whole handler (or: in `visit_expr_call`, extend `reaches_sink` unconditionally rather than under `is_value_sink`) | `an_account_that_only_takes_a_state_write_does_not_reach_a_sink` and `building_a_cpi_context_without_invoking_it_is_not_a_sink` |
| In `visit_local`, change `self.taint.insert(name, t)` to merge into the existing entry with `.entry(name).or_default().extend(t)` | `a_rebound_local_replaces_its_earlier_taint` |
| Replace `v.reaches_sink.into_iter().collect()` with a `Vec` built by `push` in visit order | `reaches_value_sink_is_sorted_and_deduplicated` |

Record the result of each. If a mutation changes no observable behaviour, say
so and say why — an *equivalent* mutant catching nothing is not a gap in the
test, and the spec calls this out explicitly.

- [x] **Step 8: Confirm `dike ir` shows the field on the real fixture**

Run:
```
cargo run -q -p dike-cli -- ir tests/fixtures/programs/vault \
  | python3 -c 'import json,sys; p=json.load(sys.stdin); [print(h["name"], h["body"]["reaches_value_sink"]) for h in p["instructions"]]'
```

Expected, exactly:
```
initialize []
deposit ['depositor', 'depositor_token_account', 'token_program', 'vault_token_account']
withdraw ['admin_token_account', 'token_program', 'vault', 'vault_token_account']
close_vault []
```

If `ir` wraps the program under another key, adjust the extraction, not the
expectation. `vault` appearing in `withdraw` is correct — it is the CPI
`authority` on line 47. Task 2's condition 2 is what keeps the rule off it.

- [x] **Step 9: Run the full gates**

```
cargo test --workspace 2>&1 | tail -40
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -20
cargo test -p dike-core --test seam 2>&1 | tail -10
cargo run -q -p dike-cli -- analyze tests/fixtures/programs/vault; echo "exit $?"
cargo run -q -p dike-cli -- analyze tests/fixtures/programs/escrow; echo "exit $?"
```

Expected: all green; both fixtures exit 0 with zero findings. The workspace
total is **576 + 8 new = 584** — sum the per-binary `test result:` lines, do not
read one. Clippy is deny-by-default here; `redundant_comparisons`, `ptr_arg`,
`bool_assert_comparison`, `useless_format`, `question_mark`, `derivable_impls`
and `cloned_ref_to_slice_refs` have each broken this build before.

No finding counts change in this task: nothing reads the new field yet.

- [x] **Step 10: Propose the commit (do not run git — Rule 9)**

Print for the user, verbatim:

```
git add crates/dike-lang-anchor/src/ir.rs crates/dike-lang-anchor/src/parser/body.rs
git commit -m "track which accounts reach a value-moving cpi in a handler body"
```

Single lowercase line, no body, no trailers.

---

## Task 2: The fourth `removed-guard` rule

**Files:**
- Modify: `crates/dike-lang-anchor/src/detectors/owner.rs:99` (`pinned_by_sibling` → `pub(crate)`)
- Modify: `crates/dike-lang-anchor/src/detectors/removed_guard.rs`
- Test: `crates/dike-lang-anchor/src/detectors/removed_guard.rs` (the existing `mod tests`)

**Interfaces:**
- Consumes: `handler.body.reaches_value_sink: Vec<String>` and
  `handler.body.state_writes: Vec<StateWrite>` (field `account: String`), both
  from Task 1 / the existing IR;
  `crate::detectors::owner::pinned_by_sibling(&AccountsStruct, &str) -> bool`.
- Produces: `removed-guard` findings whose `subject` is the bare account name
  (e.g. `vault_token`), distinct from the existing rule's `owner.field` subject
  (e.g. `deal.maker`). `merge::collapse_by_subject` folds equal subjects across
  handlers into one row — that is why Task 3's count goes to 8 and not 9.

### Why three conditions, not two (do not re-derive this)

Spec §5 and §7.2. Conditions 1 and 3 alone fire on the **clean** `vault`
fixture, measured against `Deposit`:

| account | pinned by | reaches sink | rule without condition 2 |
|---|---|---|---|
| `vault_token_account` | sibling `constraint` on `vault` | yes | silent |
| `depositor_token_account` | **nothing** | yes (`from`) | **FIRES** |
| `admin_token_account` (`Withdraw`) | **nothing** | yes (`to`) | **FIRES** |

Two findings on a fixture that must report zero. And they are not fixture bugs:
`depositor_token_account` is the depositor's own account and the token program
enforces that the signing authority owns it; `admin_token_account` is wherever
the admin chooses to receive funds. **An unpinned account reaching a transfer is
the ordinary case, not a defect.** Condition 2 is the repair.

- [x] **Step 1: Promote `pinned_by_sibling`**

In `crates/dike-lang-anchor/src/detectors/owner.rs`, change the signature only —
leave the doc comment, which encodes the adjudicated false positives that
produced it:

```rust
pub(crate) fn pinned_by_sibling(accounts: &AccountsStruct, name: &str) -> bool {
```

Do not move it and do not duplicate the logic.

- [x] **Step 2: Write the failing detector tests**

Append to `mod tests` in `crates/dike-lang-anchor/src/detectors/removed_guard.rs`.
`findings_for(&str)` is already defined there and runs the real parser, so
`reaches_value_sink` is populated from the source text.

```rust
    /// `SINK` is the handler body, `ATTR` is what `vault_token` declares and
    /// `VATTR` is what `vault` declares. Three placeholders rather than
    /// `str::replace` on a whole line: the pin this rule must respect is
    /// declared on the *sibling*, so tests need to vary both attributes, and
    /// matching a multi-line slice by its exact indentation is a test that
    /// breaks on a reformat.
    ///
    /// The shape is `tests/fixtures/programs/leaky_vault`'s `deposit`: the
    /// vault's own token account is the destination of a transfer, `vault.amount`
    /// is credited on the strength of it, and nothing says which token account
    /// it is.
    const SINK_PAIR: &str = r#"
        #[program]
        pub mod leaky {
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.amount = vault.amount + amount;
                SINK
                Ok(())
            }
        }
        #[account]
        pub struct Vault { pub amount: u64, pub bump: u8 }
        #[derive(Accounts)]
        pub struct Deposit<'info> {
            #[account(VATTR)]
            pub vault: Account<'info, Vault>,
            #[account(ATTR)]
            pub vault_token: Account<'info, TokenAccount>,
            #[account(mut)]
            pub depositor_token: Account<'info, TokenAccount>,
            pub depositor: Signer<'info>,
            pub token_program: Program<'info, Token>,
        }
    "#;

    const TRANSFER: &str = r#"
        let cpi_accounts = Transfer {
            from: ctx.accounts.depositor_token.to_account_info(),
            to: ctx.accounts.vault_token.to_account_info(),
            authority: ctx.accounts.depositor.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
    "#;

    /// `VATTR` is substituted first: `"ATTR"` is a substring of `"VATTR"`, so
    /// replacing `ATTR` first would corrupt the sibling's placeholder into
    /// `V<attr>`.
    fn sink_pair_with(vattr: &str, attr: &str, sink: &str) -> String {
        SINK_PAIR
            .replace("VATTR", vattr)
            .replace("ATTR", attr)
            .replace("SINK", sink)
    }

    fn sink_pair(attr: &str, sink: &str) -> String {
        sink_pair_with("mut", attr, sink)
    }

    /// The defect this rule exists for. `vault_token` reaches a transfer, is
    /// named after `vault` — which this handler writes — and nothing pins it,
    /// so a caller may substitute any token account while `vault.amount` is
    /// credited as though the vault received the tokens.
    #[test]
    fn an_unpinned_account_named_after_written_state_that_reaches_a_transfer_is_a_gap() {
        let f = findings_for(&sink_pair("mut", TRANSFER));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].class.as_str(), "removed-guard");
        assert_eq!(f[0].subject, "vault_token");
        assert_eq!(f[0].severity, dike_core::Severity::High);
        assert!((f[0].confidence - 0.60).abs() < 1e-6);
    }

    /// Condition 1. Same declarations, no transfer: an account nothing moves
    /// value through is not this rule's business, whatever it is named.
    ///
    /// Breaks if: the dataflow condition is dropped and the rule keys on the
    /// name alone.
    #[test]
    fn an_account_that_reaches_no_sink_is_not_reported() {
        let f = findings_for(&sink_pair("mut", ""));
        assert!(f.is_empty(), "{f:#?}");
    }

    /// Condition 2, the clean-fixture half. `depositor_token` reaches the same
    /// transfer and nothing pins it either — and it is correct code. It is the
    /// depositor's own account, and the token program enforces that the
    /// signing authority owns it. Only `vault_token` is reported.
    ///
    /// Breaks if: the "named after state this handler writes" condition is
    /// dropped. That framing was tried and rejected — spec §7.2.
    #[test]
    fn a_counterparty_account_reaching_the_same_transfer_is_not_reported() {
        let f = findings_for(&sink_pair("mut", TRANSFER));
        assert!(
            !f.iter().any(|x| x.subject == "depositor_token"),
            "{f:#?}"
        );
    }

    /// Condition 2, the boundary. `vault` itself reaches sinks as the CPI
    /// `authority` and is obviously "named after" itself, but the account
    /// holding the state is not the account the state accounts for. The suffix
    /// must be non-empty.
    ///
    /// Breaks if: the name test becomes `starts_with` without a length check.
    #[test]
    fn the_state_account_itself_is_not_reported_as_its_own_token_account() {
        let sink = r#"
            let cpi_accounts = Transfer {
                from: ctx.accounts.vault_token.to_account_info(),
                to: ctx.accounts.depositor_token.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            };
            token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts), amount)?;
        "#;
        let f = findings_for(&sink_pair("mut", sink));
        assert!(!f.iter().any(|x| x.subject == "vault"), "{f:#?}");
        assert!(f.iter().any(|x| x.subject == "vault_token"), "{f:#?}");
    }

    /// Condition 3, the spelling the clean `vault` fixture actually uses
    /// (`vault/src/lib.rs:91`): a sibling constraint that names the account.
    /// This is the site the `StripConstraint` operator deletes, so this test
    /// and the one above are the two halves of the mutation the rule must now
    /// catch.
    #[test]
    fn a_sibling_constraint_naming_the_account_is_the_pin() {
        let src = sink_pair_with(
            "mut, constraint = vault_token.owner == vault.key() @ E::Wrong",
            "mut",
            TRANSFER,
        );
        let f = findings_for(&src);
        assert!(!f.iter().any(|x| x.subject == "vault_token"), "{f:#?}");
    }

    /// Condition 3, the other idiomatic spellings. Seeds derive the address,
    /// `address =` pins it outright: either one makes substitution impossible.
    #[test]
    fn seeds_or_an_address_pin_the_account() {
        let seeded = findings_for(&sink_pair(
            "mut, seeds = [b\"vt\", vault.key().as_ref()], bump",
            TRANSFER,
        ));
        assert!(!seeded.iter().any(|x| x.subject == "vault_token"), "{seeded:#?}");

        let pinned = findings_for(&sink_pair("mut, address = vault.token_account", TRANSFER));
        assert!(!pinned.iter().any(|x| x.subject == "vault_token"), "{pinned:#?}");
    }

    /// The evidence must not claim more than the rule knows. Condition 2 is a
    /// name heuristic and it carries more of the discrimination than the
    /// dataflow does (spec §6); a reader who takes the evidence at face value
    /// must not come away believing the tool proved a relationship it only
    /// guessed at from a prefix.
    ///
    /// Breaks if: the evidence is rewritten to assert that the account "must"
    /// be bound, or drops the name rationale.
    #[test]
    fn the_evidence_names_the_heuristic_rather_than_claiming_proof() {
        let f = findings_for(&sink_pair("mut", TRANSFER));
        let e = &f[0].evidence;
        assert!(e.contains("named after"), "{e}");
        assert!(e.contains("`vault_token`") && e.contains("`vault`"), "{e}");
    }

    #[test]
    fn the_value_sink_rule_is_deterministic_across_runs() {
        let src = sink_pair("mut", TRANSFER);
        assert_eq!(findings_for(&src), findings_for(&src));
    }
```

- [x] **Step 3: Run the tests and watch them fail**

Run:
```
cargo test -p dike-lang-anchor --lib detectors::removed_guard 2>&1 | tail -40
```
Expected: `an_unpinned_account_named_after_written_state_...`,
`the_state_account_itself_...` (its positive half),
`the_evidence_names_the_heuristic_...` and
`the_value_sink_rule_is_deterministic_across_runs`'s index panic fail. The four
negative tests pass vacuously — the rule does not exist, so nothing is reported.
Note which. Step 5 proves they bind.

- [x] **Step 4: Implement the rule**

In `crates/dike-lang-anchor/src/detectors/removed_guard.rs`:

**4a. Imports.** Change the first two lines:

```rust
use super::{looks_like_authority, Detector, REMOVED_GUARD};
use crate::detectors::owner::pinned_by_sibling;
use crate::ir::{AccountDecl, AccountsStruct, Constraint, Handler, Program, Wrapper};
use dike_core::finding::{Finding, Severity};
```

**4b. Extend the doc comment on `RemovedGuardDetector`.** Append, after the
existing final paragraph:

```rust
/// A second shape, added 2026-09-19. The `constraint`s that programs write are
/// not all name-to-name bindings: `vault_token_account.owner == vault.key()`
/// ties a token account to the PDA that accounts for its balance, and no
/// account is called `owner`, so the rule above cannot see it. Its absence is
/// still structural — the handler credits `vault.amount` on the strength of a
/// transfer into an account whose identity nothing fixes.
///
/// So the second rule is: the account reaches a value-moving CPI in this
/// handler's body (`HandlerBody::reaches_value_sink`), it is named after an
/// account this handler state-writes, and nothing pins its identity.
///
/// **The name condition carries more of the discrimination than the dataflow
/// does**, and the evidence string says so. An unpinned account reaching a
/// transfer is the ordinary case — the counterparty's own token account is
/// exactly that, and the token program enforces its ownership. What is
/// different about the program's own side is that state is written on the
/// strength of the transfer; the name is the only handle this slice has on
/// that relationship. A program that names its vault token account `treasury`
/// while writing state to `vault` is a known false negative.
```

**4c. The rule.** Inside `run`'s `for decl in &accounts.decls` loop, after the
`Constraint::Init` `continue` and before `for field in bindable_fields(...)`:

```rust
            if let Some(state) = named_after_written_state(handler, decl) {
                if handler.body.reaches_value_sink.contains(&decl.name)
                    && !identity_is_pinned(accounts, decl)
                {
                    let line = if decl.attr_line != 0 { decl.attr_line } else { decl.line };
                    out.push(super::finding_at(
                        self,
                        handler,
                        &accounts.file,
                        &decl.name,
                        line,
                        format!(
                            "`{0}` receives or sends value in this handler, and it is \
                             named after `{1}`, whose state this handler writes — so \
                             `{1}` is credited on the strength of a transfer through \
                             `{0}`. Nothing fixes which account `{0}` is: no `seeds`, \
                             no `address`, no `has_one`, and no constraint naming it. \
                             A caller may substitute a different token account while \
                             `{1}` is updated as though the transfer had landed. Note \
                             the tie between `{0}` and `{1}` is inferred from the name; \
                             confirm it before acting.",
                            decl.name, state
                        ),
                    ));
                }
            }
```

**4d. The two helpers.** Add below `binding_exists`:

```rust
/// The account this handler state-writes that `decl` appears to be named
/// after: `vault` for `vault_token_account`, `vault` for `vault_token`.
///
/// The suffix must be non-empty. `vault` itself reaches value sinks as the CPI
/// `authority`, and the account that holds the state is not the account the
/// state accounts for — an empty suffix would report the state account against
/// itself.
///
/// A name heuristic, and the honest limit of this slice: the real relationship
/// is "this token account holds the balance `{state}` accounts for", which the
/// stripped constraint expressed and nothing here recovers in general.
fn named_after_written_state(handler: &Handler, decl: &AccountDecl) -> Option<String> {
    handler
        .body
        .state_writes
        .iter()
        .map(|w| &w.account)
        .filter(|a| decl.name.len() > a.len() && decl.name.starts_with(a.as_str()))
        // Longest match wins, so `vault_config_token` prefers `vault_config`
        // over `vault` when the handler writes both. Deterministic because
        // `state_writes` is in source order and `max_by_key` keeps the last
        // maximum — but sort the key explicitly rather than relying on that.
        .max_by_key(|a| a.len())
        .cloned()
}

/// Whether anything in this accounts struct fixes which account `decl` is.
///
/// Five spellings, all idiomatic. `seeds` derives the address; `address =` and
/// `owner =` pin it outright; a `has_one` ties it to stored data; any
/// constraint anywhere in the struct that *names* this account is doing so in
/// order to constrain it — that is the spelling the clean `vault` fixture uses
/// (`constraint = vault_token_account.owner == vault.key()`, declared on the
/// sibling `vault`); and `pinned_by_sibling` covers a sibling deriving from
/// `{name}.key()`.
///
/// `pinned_by_sibling` is reused rather than reimplemented: its doc comment
/// records three adjudicated false positives, including why `init` siblings are
/// excluded.
fn identity_is_pinned(accounts: &AccountsStruct, decl: &AccountDecl) -> bool {
    decl.has_seeds()
        || decl.is_address_pinned()
        || !decl.has_one_targets().is_empty()
        || named_in_any_constraint(accounts, &decl.name)
        || pinned_by_sibling(accounts, &decl.name)
}

/// Whether any constraint in the struct mentions `name` as a whole identifier.
///
/// Whole-identifier, not substring: `vault` is a substring of
/// `vault_token_account`, so a substring test would let a constraint about the
/// token account silence a finding about the vault and vice versa.
fn named_in_any_constraint(accounts: &AccountsStruct, name: &str) -> bool {
    accounts.decls.iter().any(|d| {
        d.constraints.iter().any(|c| {
            let text = match c {
                Constraint::Raw(t)
                | Constraint::Address(t)
                | Constraint::Owner(t)
                | Constraint::Seeds(t)
                | Constraint::Close(t) => t.as_str(),
                Constraint::Bump(Some(t)) => t.as_str(),
                _ => return false,
            };
            text.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                .any(|tok| tok == name)
        })
    })
}
```

`Wrapper` is still used by `bindable_fields`; leave the import.

- [x] **Step 5: Run the tests and verify they pass**

Run:
```
cargo test -p dike-lang-anchor --lib detectors::removed_guard 2>&1 | tail -40
```
Expected: all pass, including the nine pre-existing tests in the module. In
particular `a_stored_field_and_its_namesake_account_with_nothing_binding_them_is_a_gap`
still asserts `f.len() == 1` — if the new rule also fires on that fixture, it is
firing on a program with no CPI at all and condition 1 is broken.

- [x] **Step 6: Prove the vacuous tests bind (Rule 6)**

Revert each mutation before the next.

| Mutation | Test that must fail |
|---|---|
| Drop the `reaches_value_sink` clause from the `if` | `an_account_that_reaches_no_sink_is_not_reported` |
| Drop `named_after_written_state` and run the rule on every decl | `a_counterparty_account_reaching_the_same_transfer_is_not_reported` |
| Change `decl.name.len() > a.len()` to `decl.name.len() >= a.len()` | `the_state_account_itself_is_not_reported_as_its_own_token_account` |
| Drop `named_in_any_constraint` from `identity_is_pinned` | `a_sibling_constraint_naming_the_account_is_the_pin` |
| Drop `decl.has_seeds()` from `identity_is_pinned` | `seeds_or_an_address_pin_the_account` |

Record each result. Call out any equivalent mutant explicitly.

- [x] **Step 7: The clean-fixture gate — the one that outranks Rule 3**

```
cargo run -q -p dike-cli -- analyze tests/fixtures/programs/vault; echo "exit $?"
cargo run -q -p dike-cli -- analyze tests/fixtures/programs/escrow; echo "exit $?"
```

Expected: exit 0, **zero findings**, both. If `vault` reports anything, the
cause is condition 2 or condition 3, not the fixture — do not edit the fixture,
and do not weaken the rule beyond restoring the spec's three conditions.

- [x] **Step 8: Confirm the new finding on `leaky_vault` is the right one**

```
cargo run -q -p dike-cli -- analyze tests/fixtures/programs/leaky_vault --format json \
  | python3 -c 'import json,sys; [print(f["class"], f["subject"], f.get("handler_id")) for f in json.load(sys.stdin)["findings"]]'
```

Expected: a `removed-guard` row with subject `vault_token` and **no other new
row**. If the JSON shape differs, adjust the extraction. **Verify this before
changing any pinned expectation in Task 3** — the spec is explicit that the
count is allowed to move only once you have confirmed which finding moved it.

- [x] **Step 9: Score the class**

```
cargo run -q -p dike-cli -- eval run \
  tests/fixtures/programs/vault tests/fixtures/programs/escrow \
  --track static --no-compile-check \
  --out "$CLAUDE_JOB_DIR/tmp/dataflow-history.json" \
  --work-dir "$CLAUDE_JOB_DIR/tmp/eval-work" 2>&1 | tail -40
```

**Never `--out benchmarks/history.json`.** The run will end by reporting that
the throwaway file does not exist; that is expected and is not a failure — the
table is printed before the recording step.

Expected:

| Class | Recall | Precision |
|---|---|---|
| `removed-guard` | **0.600** (3 of 5) | 1.000 |
| `missing-signer` | 1.000 (5) | 1.000 |
| `missing-owner-check` | 1.000 (4) | 1.000 |
| `missing-authority-binding` | 1.000 (4) | 1.000 |
| `pda-validation-gap` | 1.000 (13) | 1.000 |
| `unchecked-arithmetic` | 1.000 (2) | 1.000 |
| static noise floor | **0** findings / 470 LOC | |

The two new detections are `vault/src/lib.rs:91` and `:116`, the stripped
`vault_token_account.owner == vault.key()` constraints. Site 3
(`vault.amount == 0`) is a value precondition and is out of scope — 0.600, not
0.800, is the target.

If a precision figure drops or the noise floor is non-zero, stop and report;
that is a false positive on clean code and is not a number to tune away.

- [x] **Step 10: Run the full gates**

```
cargo test --workspace 2>&1 | tail -40
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -20
cargo test -p dike-core --test seam 2>&1 | tail -10
```

Expected: clippy clean, seam green. **`cargo test --workspace` is expected to
FAIL here**, in `dike-cli`'s `analyze_sarif` tests, on the `leaky_vault` counts.
That failure is the change working. Task 3 moves those expectations. Confirm
the only failures are the `analyze_sarif` count assertions — anything else is a
real regression.

- [x] **Step 11: Propose the commit (do not run git — Rule 9)**

```
git add crates/dike-lang-anchor/src/detectors/owner.rs crates/dike-lang-anchor/src/detectors/removed_guard.rs
git commit -m "report an unpinned account that moves value and is named after written state"
```

Note the failing `analyze_sarif` tests: either hold this commit until Task 3 or
tell the user both commits go together. Say which.

---

## Task 3: Move the pinned expectations and the docs

**Files:**
- Modify: `crates/dike-cli/tests/analyze_sarif.rs:31,45` and the class set
- Modify: `.github/workflows/ci.yml`, the `action-smoke` job's assertion script
- Modify: `docs/PROJECT_CONTEXT.md`
- Check: `benchmarks/adjudication/` and `docs/PROJECT_CONTEXT.md` for any other
  quote of `7 findings` / `5 rules` on `leaky_vault`

**Interfaces:**
- Consumes: the `removed-guard` / `vault_token` finding confirmed in Task 2 Step 8.
- Produces: nothing code reads.

**Do this task only after Task 2 Step 8 printed the `vault_token` row.** The
spec's instruction is explicit: verify the new finding is the `vault_token` one
before changing any expectation, and never weaken the rule to keep the old
numbers.

- [x] **Step 1: Find every quote of the old counts**

```
grep -rn "leaky_vault" --include=*.rs --include=*.yml --include=*.md . | grep -v target
grep -rn "results\"\]) == 7\|len(run\[\|, 7,\|== 5\b" .github/workflows/ci.yml crates/dike-cli/tests/analyze_sarif.rs
grep -rn "7 findings\|5 rules\|seven findings" docs/ benchmarks/
```

List what you find before editing. The spec names `analyze_sarif.rs` and
`ci.yml`; confirm whether `docs/PROJECT_CONTEXT.md` or
`benchmarks/adjudication/` also quote them.

- [x] **Step 2: Move the SARIF test expectations**

In `crates/dike-cli/tests/analyze_sarif.rs`:

```rust
    assert_eq!(results.len(), 8, "results: {results:#?}");
```
```rust
    assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 6);
```

If the file also asserts an expected class set, add `"removed-guard"` to it.
Add a comment at the count assertion recording *why* it moved, in the style the
file already uses:

```rust
    // 7 -> 8 on 2026-09-19: `removed-guard` gained a rule for an account that
    // moves value, is named after state the handler writes, and is unpinned.
    // `vault_token` is that account in both `deposit` and `withdraw`;
    // `collapse_by_subject` folds the two handlers into one row, which is why
    // this is 8 and not 9.
```

- [x] **Step 3: Move the CI expectations**

In `.github/workflows/ci.yml`, the `action-smoke` job's Python block — three
edits:

```python
          expected = {
              "missing-signer",
              "missing-owner-check",
              "missing-authority-binding",
              "pda-validation-gap",
              "unchecked-arithmetic",
              "removed-guard",
          }
          assert ids == expected, f"got {sorted(ids)}"
          assert len(run["results"]) == 8, len(run["results"])
          assert len(run["tool"]["driver"]["rules"]) == 6
```

Leave the `startLine` and `partialFingerprints` assertions untouched — they are
the two Criticals the last session found and are unrelated to this change.

- [x] **Step 4: Verify the SARIF tests pass**

```
cargo test -p dike-cli --test analyze_sarif 2>&1 | tail -30
```
Expected: pass. Read the output.

- [x] **Step 5: Verify the CI assertion locally**

The `action-smoke` job is not runnable here, but its assertion script is. Run
the equivalent against a locally generated document:

```
cargo run -q -p dike-cli -- analyze tests/fixtures/programs/leaky_vault --format sarif > "$CLAUDE_JOB_DIR/tmp/dike.sarif"
python3 - <<'EOF'
import json, os
doc = json.load(open(os.environ["CLAUDE_JOB_DIR"] + "/tmp/dike.sarif"))
run = doc["runs"][0]
ids = {r["ruleId"] for r in run["results"]}
expected = {"missing-signer","missing-owner-check","missing-authority-binding",
            "pda-validation-gap","unchecked-arithmetic","removed-guard"}
assert ids == expected, f"got {sorted(ids)}"
assert len(run["results"]) == 8, len(run["results"])
assert len(run["tool"]["driver"]["rules"]) == 6, len(run["tool"]["driver"]["rules"])
for r in run["results"]:
    region = r["locations"][0]["physicalLocation"].get("region")
    assert region is None or region["startLine"] >= 1, region
    assert r.get("partialFingerprints", {}).get("dikeFindingId/v1") != "", r["ruleId"]
print(f"ok: {len(run['results'])} results, {len(run['tool']['driver']['rules'])} rules")
EOF
```

Expected: `ok: 8 results, 6 rules`. If the CLI's SARIF flag differs from
`--format sarif`, use the real one; the action passes `sarif-file`.

- [x] **Step 6: Update `docs/PROJECT_CONTEXT.md` (Rule 1)**

Two additions. The new IR field is a change to the IR shape, and the false
negative is a new entry under "Known gaps".

Near the IR description, add `reaches_value_sink` to whatever enumerates
`HandlerBody`'s fields, described as: *accounts that reach a value-moving CPI
in this handler, propagated through `let` bindings, struct literals and calls;
sorted and deduplicated; `#[serde(default)]` so older IR JSON still loads.*

Under **Known gaps**, in the file's existing entry style:

```markdown
- **`removed-guard`'s value-sink rule ties a token account to state by NAME.**
  The rule fires when an account reaches a value-moving CPI, is named after an
  account the handler state-writes, and nothing pins it. The relationship it is
  reaching for — *this token account holds the balance that state account
  accounts for* — is exactly what a `constraint = vault_token.owner ==
  vault.key()` expresses, and nothing in this slice recovers it in general. A
  program that names its vault token account `treasury` while writing state to
  `vault` is missed. The dataflow rules out accounts that never touch value;
  the name is what separates the program's own side of a transfer from the
  counterparty's, and it is carrying more of the discrimination than the
  dataflow is. Recorded 2026-09-19 with the rule itself, not discovered later.
```

If any line in `PROJECT_CONTEXT.md` quotes `leaky_vault`'s finding count or
says `removed-guard` is name-matching only, update it too.

- [x] **Step 7: Check `learning/` (Rule 10)**

```
sed -n '60,75p' learning/README.md
```

Expected: `parser/{body,program,symbols}.rs` still listed as not yet toured, and
Part 06 covering `parser/{mod,accounts}.rs` only. If so, no lesson is stale and
no action is needed. If the index has moved and a lesson now covers
`parser/body.rs` or `detectors/removed_guard.rs`, update that lesson in this
commit. `learning/` is gitignored either way, so it never appears in the diff.

- [x] **Step 8: Run every gate, and read every line of output**

```
cargo test --workspace 2>&1 | tail -60
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -20
cargo test -p dike-core --test seam 2>&1 | tail -10
cargo run -q -p dike-cli -- analyze tests/fixtures/programs/vault; echo "exit $?"
cargo run -q -p dike-cli -- analyze tests/fixtures/programs/escrow; echo "exit $?"
```

Expected:
- `cargo test --workspace` — all pass. **Sum the per-binary `test result:`
  lines**; the total should be 576 + 8 (Task 1) + 8 (Task 2) = **592**. Grep for
  `FAILED` explicitly rather than for `ok`.
- clippy clean, seam green.
- both clean fixtures exit 0 with zero findings.

- [x] **Step 9: Propose the commit (do not run git — Rule 9)**

```
git add crates/dike-cli/tests/analyze_sarif.rs .github/workflows/ci.yml docs/PROJECT_CONTEXT.md
git commit -m "move the leaky_vault expectations for the new removed-guard rule"
```

- [x] **Step 10: Report**

Give the user, in plain text:
- the three proposed commit messages, in order;
- the `removed-guard` before/after recall read from the eval table;
- every other class's recall, to show none moved;
- the noise floor;
- the workspace test total, as a sum of the per-binary lines;
- the mutation-testing results from Task 1 Step 7 and Task 2 Step 6, including
  any equivalent mutants;
- one sentence that the rule's discrimination rests mainly on the name
  heuristic, per spec §6 — do not let the summary imply the dataflow proves the
  account must be pinned.

---

## Not doing (spec §8, restated so nobody re-opens it)

- **Site 3, `constraint = vault.amount == 0`.** A value precondition before a
  close, not an identity binding. It is why the target is 0.600 and not 0.800.
- **Loops, branches, cross-function propagation.**
- **Any change to `merge.rs`.** `Finding::merge_key` ignoring `subject` is a
  separate known gap with its own entry and its own decision to make.
- **`sealevel-attacks` categories 3, 6, 8, 9.**
- **Spending the holdout run.** `benchmarks/holdout/runs.json` is `[]` and the
  one scored run stays unspent. The handoff's argument is that the run is worth
  more after this lands, not before — but spending it is the owner's call, not
  this plan's.

---

## What actually happened (executed 2026-09-19)

All three tasks landed. `removed-guard` static recall **0.200 → 0.600** (3 of
5), precision 1.000, noise floor 0, every other class unchanged.
`cargo test --workspace` 576 → **592** passing, 8 ignored, 0 failing. Clippy
clean, seam green, both clean fixtures exit 0 with zero findings.
`benchmarks/history.json` and `benchmarks/holdout/runs.json` untouched — the
holdout run is still unspent.

Three things the plan got wrong, recorded rather than quietly fixed:

- **Task 1 Step 8 predicted four accounts in `vault`'s `withdraw`; there are
  five.** `admin` is also listed, because `ctx.accounts.admin.key()` binds
  `admin_key`, which reaches `CpiContext::new_with_signer` through
  `vault_seeds` and `signer_seeds`. The account does not move tokens there — it
  derives the PDA that authorizes the move. The taint pass is over-approximate
  by design (Rule 3) and this is that showing up; it is documented on the IR
  field and in `PROJECT_CONTEXT.md`'s Quirks rather than special-cased away.
  Condition 2 keeps the rule off it.

- **Task 1 Step 7's second mutation did not break the test the plan named.**
  Extending `reaches_sink` unconditionally in `visit_expr_call` breaks
  `building_a_cpi_context_without_invoking_it_is_not_a_sink` but not
  `an_account_that_only_takes_a_state_write_does_not_reach_a_sink` — `config` in
  that fixture is an assignment target and never a call argument, so the
  mutation cannot reach it. The mutation that does break it is inserting the
  state-write target into `reaches_sink` in `visit_expr_assign`; run, and it
  fails exactly that test. The plan's prediction was wrong, not the test.

- **The plan missed a third pinned expectation.**
  `crates/dike-cli/tests/holdout_cli.rs` used `removed-guard` on `leaky_vault`
  as its guaranteed-miss case, on the comment "`removed-guard` is Track-2-only
  by design, so it is a miss whatever the code says". **That premise had already
  expired** when the class gained a Track 1 detector earlier on 2026-09-19; it
  survived only because that first rule needs a stored `Pubkey` field with a
  namesake account, which `leaky_vault` has not got. The new rule fires on
  `vault_token` and turned the case into a hit. Replaced with `missing-signer`
  on `initialize`, which is a miss because the fixture's `Initialize` declares
  `admin: Signer<'info>` — a reason grounded in the fixture rather than in no
  detector existing. The stale premise in
  `crates/dike-cli/src/commands/holdout.rs`'s `unreachable_class_warning` doc
  comment was corrected in the same pass.

  The general lesson, which is the second time this project has paid for it: a
  test whose expected outcome rests on *no detector existing* is a test waiting
  to break, and it breaks silently in the direction of a false premise rather
  than a red build.

Two entries in `docs/PROJECT_CONTEXT.md` were reversed by this work and
rewritten rather than appended to: the `removed-guard` recall entry, whose
conclusion "raising this number means teaching the analyzer about external
account types, not writing more rules" was wrong — it needed a different
question, not a bigger symbol table.
