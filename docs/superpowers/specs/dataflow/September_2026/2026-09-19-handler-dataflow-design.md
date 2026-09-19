# Handler-body dataflow, slice one — design

**Written 2026-09-19. Written for a cold start: the session that implements
this will have none of the context that produced it.** Everything needed is
either in this document or named by exact path. Read it end to end before
touching code — in particular §7, which lists two framings that were tried and
rejected with evidence, and §9, which lists the pinned expectations this change
is *supposed* to move.

Implements item 5 of `docs/next_steps_6.md`: "Dataflow over the handler body …
Start narrow: one dataflow question (does value X reach sink Y within this
handler), used by one detector."

---

## 0. Read these first

| File | Why |
|---|---|
| `CLAUDE.md` | Ten binding rules. Not optional. §10 below summarises the ones this work touches, but read the original. |
| `docs/PROJECT_CONTEXT.md` | Architecture map: crates, the seam, the invariants. |
| `crates/dike-lang-anchor/src/ir.rs` | `Handler`, `HandlerBody`, `CallSite`, `StateWrite`, `AccountDecl` and its helpers. |
| `crates/dike-lang-anchor/src/parser/body.rs` | `summarize_body`, the `syn` visitor this work extends. Already has an `aliases` map. |
| `crates/dike-lang-anchor/src/detectors/removed_guard.rs` | The detector that gains the new rule. |
| `tests/fixtures/programs/vault/src/lib.rs` | The clean fixture. Lines 22-28, 44-55, 84-129 are the ones that matter. |

## 1. What dike is, in three sentences

Security triage for Solana Anchor programs. Track 1 is deterministic static
analysis over an Anchor-aware IR; Track 2 is a retrieval-grounded LLM pass; the
two merge and rank. Findings never change the exit code — non-zero means the
tool failed.

`dike-core` is domain-agnostic and must contain no Solana or Anchor vocabulary.
`dike-lang-anchor` holds all of it. `dike-cli` is the only place the two meet.
**Everything in this design lives in `dike-lang-anchor`, so the seam is not at
risk** — but run `cargo test -p dike-core --test seam` anyway.

## 2. The problem, measured

`removed-guard` scores **recall 0.200, precision 1.000** on the mutation
harness — 1 of 5 mutants detected. Those mutants come from one operator,
`StripConstraint` (`mutations/operators.rs:312`), which deletes a
`constraint = …` expression. The six sites in the two clean fixtures:

| # | File | Constraint | Caught today |
|---|---|---|---|
| 1 | `vault/src/lib.rs:91` | `vault_token_account.owner == vault.key()` | no |
| 2 | `vault/src/lib.rs:116` | `vault_token_account.owner == vault.key()` | no |
| 3 | `vault/src/lib.rs:139` | `vault.amount == 0` | no |
| 4 | `escrow/…/accept_admin.rs:16` | `config.pending_admin == pending_admin.key()` | excluded as an invalid mutant (staged authority) |
| 5 | `escrow/…/resolve.rs:24` | `deal.resolver == resolver.key()` | — |
| 6 | `escrow/…/settle.rs:23` | `deal.maker == maker.key()` | — |

One of 5 and 6 is the single detection. The current rule (documented at the top
of `removed_guard.rs`) is a **name match**: a stored `Pubkey` field `f` on
account `a`, an account also called `f` in the same struct, and nothing tying
them. Sites 5 and 6 have that shape. Sites 1 and 2 cannot, because the field is
`owner` and no account is called `owner`.

**Sites 1 and 2 are this slice's target.** Site 3 is a value precondition
(`amount == 0` before a close) and is explicitly out of scope — see §8.

## 3. Why sites 1 and 2 need dataflow

`vault_token_account` is the source or destination of a token transfer, and
after the strip nothing pins which account it is. Reaching that fact is not
syntactic. In `vault/src/lib.rs:22-28` the path from account to sink is three
hops:

```rust
let cpi_accounts = Transfer {
    from: ctx.accounts.depositor_token_account.to_account_info(),
    to:   ctx.accounts.vault_token_account.to_account_info(),   // hop 1: struct literal
    authority: ctx.accounts.depositor.to_account_info(),
};
let cpi_ctx = CpiContext::new(
    ctx.accounts.token_program.to_account_info(),
    cpi_accounts,                                               // hop 2: local -> call arg
);
token::transfer(cpi_ctx, amount)?;                              // hop 3: local -> sink
```

A rule that reads only the sink call's own argument tokens sees `cpi_ctx` and
`amount` and nothing else. **This shape-sensitivity is not hypothetical**: it is
what invalidated an earlier attempt (§7.1). `tests/fixtures/programs/leaky_vault`
uses the same three-hop shape;
`benchmarks/external/sealevel-attacks/programs/5-arbitrary-cpi/insecure` inlines
its accounts directly into `invoke(...)`. Any rule that treats those two
differently is keying on code shape, not semantics.

## 4. The primitive

A per-handler taint pass in `crates/dike-lang-anchor/src/parser/body.rs`,
extending the existing `syn` visitor in `summarize_body`.

**Sources.** Every `ctx.accounts.<name>` expression. `<name>` is the account
name; `body.rs` already has `resolve_account_root` for this, including
resolution through its `aliases` map.

**Propagation.** A local is tainted with a set of account names when it is bound
to an expression carrying them. Three forms, which is all the fixtures and the
sealevel set need:

- `let x = <expr>;` — `x` carries whatever `<expr>` carries
- struct literals — `Transfer { from: ctx.accounts.a…, to: ctx.accounts.b… }`
  carries `{a, b}`
- method and function calls — `ctx.accounts.a.to_account_info()` carries `{a}`;
  a call carries the union of its arguments' taint

Propagation is flow-insensitive and intra-procedural. A name rebound by a later
`let` **replaces** the earlier binding, matching the textual visitation order
`body.rs` already documents for `aliases`. Do not attempt loops, branches or
cross-function propagation: nothing in scope needs them, and Rule 5 wants this
deterministic and cheap.

**Sinks.** A call whose name's last path segment is in the sink set. The sink
set is domain vocabulary and therefore lives in `dike-lang-anchor`, not core:

```
transfer            transfer_checked     burn      mint_to
```

plus `system_program::transfer`, matched the same way, and a direct assignment
through `lamports.borrow_mut()`.

Match on the **last path segment** so `token::transfer`, `anchor_spl::token::transfer`
and a bare `transfer` all count. `CpiContext::new` and `new_with_signer` are
**not** sinks — they are intermediate constructors, and the taint flows through
them to the `transfer` call that consumes them.

**Output.** A new field on `HandlerBody` in `crates/dike-lang-anchor/src/ir.rs`:

```rust
/// Accounts that reach a value-moving CPI in this handler, by the path the
/// body actually takes: through `let` bindings, struct literals and method
/// calls, not merely by appearing in the sink call's own arguments.
///
/// Sorted and deduplicated, so it is byte-stable across runs (Rule 5).
#[serde(default)]
pub reaches_value_sink: Vec<String>,
```

`#[serde(default)]` because `HandlerBody` derives `Deserialize` and older IR
JSON must still load. Sorted and deduplicated — Rule 5, and `dike ir` prints
this.

**Why the IR and not a side table.** `dike ir` is this project's debugging
surface, and a dataflow fact nobody can inspect is one nobody can trust. Putting
it in `HandlerBody` makes `cargo run -p dike-cli -- ir <program>` show it.

## 5. The rule

A fourth rule in `crates/dike-lang-anchor/src/detectors/removed_guard.rs`,
evaluated per account declaration. It fires when **all three** hold:

1. **`handler.body.reaches_value_sink` contains the account's name.** The
   dataflow condition.
2. **The account's name derives from an account this handler state-writes.**
   Concretely: some `w` in `handler.body.state_writes` where the account's name
   is `w.account` plus a suffix (`vault` → `vault_token_account`,
   `vault` → `vault_token`). `StateWrite` is already in the IR and already
   populated — no parser work for this condition.
3. **Nothing pins its identity.** Reuse what exists: `decl.has_seeds()`,
   `decl.is_address_pinned()`, `decl.has_one_targets()`, any `Constraint` whose
   text names the account, and the sibling pin. `pinned_by_sibling` currently
   lives in `detectors/owner.rs:99` and is private — promote it to
   `pub(crate)` in `detectors/mod.rs` or call an equivalent; do not duplicate
   the logic, it encodes a lesson (see its doc comment).

Class stays `removed-guard`, severity `High`, confidence **0.60 unchanged**.
Rule 5 pins per-detector confidence: adding a rule inside an existing detector
must not move it, or the whole history series is invalidated.

`subject` is the account's name, so `merge::collapse_by_subject` folds the two
`leaky_vault` handlers into one row. That is why §9's count goes to 8 and not 9.

### Why condition 2 exists, with the evidence

Conditions 1 and 3 alone fire on the **clean** `vault` fixture. Measured
2026-09-19 against `Deposit` (`vault/src/lib.rs:84-107`):

| account | pinned by | reaches sink | rule without cond. 2 |
|---|---|---|---|
| `vault_token_account` | sibling `constraint` on `vault` | yes | silent |
| `depositor_token_account` | **nothing** | yes (`from`) | **FIRES** |
| `admin_token_account` (`Withdraw`) | **nothing** | yes (`to`) | **FIRES** |

Two findings on a fixture that must report zero — the CI gate in
`.github/workflows/ci.yml` ("Clean fixtures report nothing") fails.

And they are not fixture bugs. `depositor_token_account` is the depositor's own
account: the depositor signs, and the token program enforces that the authority
owns it. `admin_token_account` is wherever the admin chooses to receive funds.
**An unpinned account reaching a transfer is the ordinary case, not a defect.**

What distinguishes `vault_token_account` is that it is the *program's own* side:
`vault.amount` is credited on the strength of that transfer, so which account it
is must be tied to the vault. Condition 2 approximates that by name, because
`vault_token_account` is named after `vault`, which the handler state-writes,
while `depositor_token_account` and `admin_token_account` are named after a
`Signer` and a `SystemAccount`, neither of which is written.

## 6. Honest limits — state these, do not overclaim

**Condition 2 is a name heuristic and it is carrying more of the discrimination
than the dataflow is.** The dataflow rules out accounts that never touch value;
the *name* is what separates the program's own side of a transfer from the
counterparty's. This codebase already leans on name heuristics
(`looks_like_authority` in `detectors/mod.rs`), so this is in keeping — but the
commit message, the doc comment and `PROJECT_CONTEXT.md` should say "reaches a
value sink **and is named after state this handler writes**", never "dataflow
proves this account must be pinned".

The real relationship — *this token account holds the balance that state account
accounts for* — is exactly what the stripped constraint expressed. Nothing in
this slice recovers it in general. A program that names its vault token account
`treasury` while writing state to `vault` is missed. That is a known false
negative, and it should be written into `PROJECT_CONTEXT.md`'s "Known gaps".

## 7. Two framings already tried and rejected — do not re-derive these

### 7.1 "An `AccountInfo` used only as a CPI argument needs no owner check"

Tried 2026-09-19 against the `5-arbitrary-cpi` noise. It does not survive the
fixtures. `leaky_vault` forwards its `authority` to a CPI in exactly the way
`sealevel-attacks/5-arbitrary-cpi/insecure` does; the only difference is that
`leaky_vault` builds the accounts struct into a local first while category 5
inlines it into `invoke(...)`. A rule keyed on "appears in a CPI call's
arguments" therefore suppresses one and not the other **purely by code shape**,
and resolving the local properly suppresses both — dropping `leaky_vault` below
its expected finding count. The premise is false: being forwarded to a CPI is
not evidence that an account needs no check.

The lesson that matters here: **that IR fact is the same one this design needs,
used the opposite way round.** There it deleted findings and got the direction
wrong; here it adds them, which is the side Rule 3 favours.

### 7.2 "Reaches a value-moving sink and nothing pins it"

The framing this design started from. Rejected by the table in §5 — it fires on
two clean-fixture accounts. Condition 2 is the repair.

## 8. Explicitly out of scope

- **Site 3, `constraint = vault.amount == 0`.** A value precondition before a
  close, not an identity binding. Needs reasoning about what a balance means,
  which is a different problem.
- **Loops, branches, cross-function propagation.** Nothing in scope needs them.
- **`sealevel-attacks` categories 3, 6, 9** (`type-cosplay`,
  `duplicate-mutable-accounts`, `closing-accounts`). Untouched by this.
- **Category 8, `pda-sharing`.** Already recorded in `PROJECT_CONTEXT.md`'s
  "Known gaps" as not statically separable.
- **Any change to `merge.rs`.** Findings merged from several sources carry no
  id; that is a separate known gap with its own entry.

## 9. Verification, with the numbers to hit

Run every command and read its output (Rule 7). Grep for `FAILED` explicitly or
read the tail — a grep for "test result: ok" has reported a green build over a
failing test in this repo before.

| Check | Expected |
|---|---|
| `cargo run -p dike-cli -- analyze tests/fixtures/programs/vault` | exit 0, **zero** findings |
| `cargo run -p dike-cli -- analyze tests/fixtures/programs/escrow` | exit 0, **zero** findings (it has no CPI at all, so it is unaffected) |
| `eval run … --track static --no-compile-check` | `removed-guard` static recall **0.200 → 0.600** (3 of 5), precision stays **1.000**, noise floor stays **0** |
| every other eval class | **unchanged**: `missing-signer` 1.000/5, `missing-owner-check` 1.000/4, `missing-authority-binding` 1.000/4, `pda-validation-gap` 1.000/13, `unchecked-arithmetic` 1.000/2 |
| `cargo test --workspace` | all pass; the count was **576** before this work |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p dike-core --test seam` | green |

**Point `eval run --out` at a throwaway.** It appends to
`benchmarks/history.json`, and CI must not record a series entry. Also pass
`--work-dir` somewhere outside `target/`.

### The pinned expectations this change MUST move

`leaky_vault` gains one finding, and this is correct — it is a deliberately
vulnerable fixture, `vault_token` is unpinned while `vault.amount` is credited
in both `deposit` and `withdraw`, and `collapse_by_subject` folds those two
handlers into one row. **7 findings / 5 rules becomes 8 / 6.** Update, in the
same commit:

- `crates/dike-cli/tests/analyze_sarif.rs` — the result count, the rule count
  and the expected class set (gains `removed-guard`)
- `.github/workflows/ci.yml`, the `action-smoke` job's assertion script — same
  three
- any count in `docs/PROJECT_CONTEXT.md` or
  `benchmarks/adjudication/` that quotes the old figure

Do **not** weaken the new rule to keep those numbers. Verify the new finding is
the `vault_token` one before changing any expectation.

## 10. Binding rules this work touches

- **Rule 2 — the seam.** All of this is in `dike-lang-anchor`. Run the seam test
  regardless.
- **Rule 3 — recall over precision**, except in `suppression.rs` where it
  reverses. This rule adds findings, so the bias is in its favour — but the
  clean-fixture gate is absolute and outranks it.
- **Rule 4 — exit 0 is a feature.** No exit-code change.
- **Rule 5 — determinism.** `reaches_value_sink` sorted and deduplicated; no
  `HashMap` iteration order anywhere reaching a `Finding`; confidence stays
  0.60.
- **Rule 6 — tests must be able to fail.** For each new test, name the change
  that breaks it. **Then prove it**: this repo has shipped assertions that could
  not fail for the reason their name claimed, and two were caught this way on
  2026-09-19 by mutating the implementation and checking which test noticed.
  Expect a test that passes vacuously before the feature exists; mutation is how
  you learn whether it binds. Watch for *equivalent* mutants — a mutation that
  changes no behaviour should catch nothing, and that is not a gap.
- **Rule 7 — verify before claiming.**
- **Rule 9 — the user owns version control.** Propose commits; do not run `git`
  unless asked. Commit messages in this repo are a single lowercase line, no
  body, no trailers.
- **Rule 1 / Rule 10 — docs.** A new detector rule inside an existing module
  does *not* require a `PROJECT_CONTEXT.md` update on its own, but the new IR
  field and the known false negative in §6 do. **Rule 10 needs no action:**
  `learning/README.md:67` lists `parser/{body,program,symbols}.rs` among the
  files not yet toured, and Part 06 covers `parser/{mod,accounts}.rs` only. A
  source file with no lesson is not staleness. Verified 2026-09-19; re-check
  that line rather than trusting it if the index has moved.
  Note `learning/` is gitignored, so nothing there appears in a commit.

## 11. Files

| File | Change |
|---|---|
| `crates/dike-lang-anchor/src/ir.rs` | `HandlerBody::reaches_value_sink` |
| `crates/dike-lang-anchor/src/parser/body.rs` | the taint pass; the sink set |
| `crates/dike-lang-anchor/src/detectors/removed_guard.rs` | the fourth rule and its tests |
| `crates/dike-lang-anchor/src/detectors/owner.rs` or `mod.rs` | promote `pinned_by_sibling` to `pub(crate)` |
| `crates/dike-cli/tests/analyze_sarif.rs` | `leaky_vault` 7/5 → 8/6 |
| `.github/workflows/ci.yml` | same, in `action-smoke` |
| `docs/PROJECT_CONTEXT.md` | the new IR field; the §6 known gap |

## 12. Suggested commit split

Three commits, each with its own passing gates:

1. the taint pass and the IR field, with parser tests and `dike ir` showing it
2. the detector rule, with its tests and the mutation evidence
3. the moved expectations and the docs

