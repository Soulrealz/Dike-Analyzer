# External benchmark: sealevel-attacks — 2026-09-19

[`coral-xyz/sealevel-attacks`](https://github.com/coral-xyz/sealevel-attacks) is
the Anchor equivalent of Ethernaut: eleven vulnerability categories, each with
an `insecure`, a `secure` and a `recommended` implementation of the same
program. 35 programs, written by the Anchor authors, labelled by construction.

It is the first ground truth this project has that nobody here wrote. The
mutation harness scores defects we injected ourselves, against a fixture whose
operators and detectors share a mental model. This does not.

**The test it poses is discrimination, not detection.** Reporting a finding on
`insecure` proves nothing if the same finding appears on `secure` — that is a
rule firing on something both versions share. What counts is telling them apart.

> **Track 2 must never be scored against this set.** `corpus/cache/`
> already holds the sealevel-attacks prose, so the retriever would be handing
> the model the answer key. Track 1 has no corpus and is unaffected.

## Scorecard

| # | Category | insecure | secure | recommended | verdict |
|---|---|---:|---:|---:|---|
| 0 | signer-authorization | 2 | 1 | 0 | **discriminates** |
| 1 | account-data-matching | 1 | 1 | 0 | correct: `secure` still has no owner check |
| 2 | owner-checks | 1 | 0 | 0 | **discriminates** |
| 3 | type-cosplay | 0 | 0 | 0 | no detector for the class |
| 4 | initialization | 1 | 1 | 0 | correct: `secure` still has no owner check |
| 5 | arbitrary-cpi | 5 | 4 | 0 | **discriminates** (since 2026-09-19; see below) |
| 6 | duplicate-mutable-accounts | 0 | 0 | 0 | no detector for the class |
| 7 | bump-seed-canonicalization | 1 | 0 | 0 | **discriminates** (since 2026-09-19; see below) |
| 8 | pda-sharing | 0 | 0 | 0 | not statically separable — see below |
| 9 | closing-accounts | 1 | 2 | 1 | no detector for the class; noise |
| 10 | sysvar-address-checking | 1 | 0 | 0 | **discriminates** |

Dike tells the vulnerable version from the fixed one in **5 of 11** categories,
and every `recommended` variant is clean, because `recommended` uses Anchor's
typed constraints (`Signer<'info>`, `Account<'info, T>`, `has_one`) which the
analyzer understands well.

Categories 1 and 4 are not failures: their `secure` variants fix only the
attack that category is about and genuinely still lack an owner check, which
their own `recommended` variant then adds.

## What the first run found

On the first pass, **six of eleven categories reported identically on
`insecure` and `secure`.** Two causes, both fixed the same day.

### Guards written as plain Rust were invisible

The canonical fix in this set is not an Anchor macro:

```rust
if !ctx.accounts.authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```

`parser/body.rs` recorded an `ImperativeCheck` only from macro calls —
`require!`, `require_eq!`, `require_keys_eq!` — plus `#[access_control]`. A
plain `if` was never recorded, so the suppression pass could not see any of
them. `CheckKind::ManualIf` had existed in the IR from the beginning with
nothing producing it.

`visit_expr_if` now records an `if` whose taken branch *rejects* — returns an
error, or panics. Only rejection counts: a branch that merely does something is
not a guard, and treating it as one would let any mention of an account silence
a finding about it.

### An owner comparison did not count as an owner check

Suppression accepted only `X.key()` for `missing-owner-check`, so
`if ctx.accounts.token.owner != ctx.program_id` — the check the class is named
after — did not suppress it.

The needle is the qualified `accounts.X.owner`, deliberately. A bare `X.owner`
is as often a field of a *deserialized struct* that happens to share the
account's name: `1-account-data-matching/secure` reads `&token.owner` off an
unpacked SPL account, which says nothing about who owns the account — and that
program really does still lack an owner check. Matching the bare form would
have deleted a true positive to make a number look better.

Net effect: categories 0, 2 and 10 now discriminate; `3-type-cosplay` correctly
reports nothing on *either* variant, because its `insecure` version does check
the owner and its actual bug is type confusion, which dike has no class for.
That was a false positive on both sides.

## The honest gaps

**Categories 7 and 8 are the real miss.** `bump-seed-canonicalization` and
`pda-sharing` are both about PDA derivation, which is `pda-validation-gap`'s
subject, and dike reports nothing on either variant of either. The detector
fires on a cross-handler inconsistency — a type derived with `seeds` in one
struct and not another — and neither of these programs has that shape. A
non-canonical bump and a PDA shared across authorities are both *within-handler*
properties that need the seed expression itself to be reasoned about.

**Five of eleven categories have no corresponding class at all**: type cosplay,
arbitrary CPI, duplicate mutable accounts, closing accounts, and (partly)
initialization. That is a coverage statement, not a bug, and it is the clearest
available answer to "what would a sixth detector be for".

**`5-arbitrary-cpi` produces 5 findings on both variants** and they are noise:
the program takes several `AccountInfo`s and dike reports `missing-owner-check`
on each. Worth revisiting when the owner detector is next touched.

## Reproducing

The checkout is gitignored — it is someone else's repository and not ours to
redistribute.

```
git clone --depth 1 https://github.com/coral-xyz/sealevel-attacks \
  benchmarks/external/sealevel-attacks

for d in benchmarks/external/sealevel-attacks/programs/*/*/ ; do
  echo "$d"; cargo run -q -p dike-cli -- analyze "$d" --format json
done
```

## Why this is not wired into CI

The suite is an external checkout that CI would have to clone, and its value is
as a periodic honesty check rather than a gate. The numbers above are a
snapshot; rerun them after any change to the suppression pass or to
`missing-owner-check`, which is the class doing nearly all the work here.

## Addendum, 2026-09-19 — categories 7 and 8 revisited

Both were recorded above as gaps in `pda-validation-gap`'s own subject. On a
second pass they turned out to be two different kinds of problem, and only one
of them was a detector's to solve.

### 7 — bump-seed-canonicalization: closed

The whole discriminator is in the handler body, and it was already in the IR:

| variant | derivation call | args | now reported |
|---|---|---|---:|
| `insecure` | `Pubkey::create_program_address` | `key, new_value, bump: u8` | 1 |
| `secure` | `Pubkey::find_program_address` | `key, new_value, bump: u8` | 0 |
| `recommended` | none (Anchor `seeds` + `bump`) | `key, new_value` | 0 |

`create_program_address` derives from exactly the bump it is handed and fails
only when that bump yields no valid address — and several usually do. A caller
who picks a non-canonical bump therefore derives a *different* address that
satisfies every check written against it. `find_program_address` returns the
canonical bump, so a body that calls it has something to compare against.

`detectors/pda.rs` gained a third rule: `create_program_address` in the body,
no `find_program_address` in the same body, and a caller-supplied `u8`
argument whose name reads as a bump. It needed no new IR and no dataflow.

**The caller-supplied-argument condition is load-bearing, not incidental.**
Signing a CPI with a bump the program itself persisted — `&[seed, &[vault.bump]]`
— is the ordinary correct pattern and appears in nearly every real Anchor
program. A rule without that condition fires on all of them, which would
reproduce the precision collapse `2026-09-19-real-programs.md` records. The
test `a_stored_bump_is_not_reported` pins it, and removing the condition makes
that test fail.

Measured after the change: the three variants score 1 / 0 / 0; `vault` and
`escrow` still report zero findings; and the static eval still puts
`pda-validation-gap` at recall 1.000, precision 1.000 over 13 mutants with a
noise floor of 0 — so the history series stays comparable (Rule 5).

### 8 — pda-sharing: not a detector's problem

`insecure` and `secure` have identical accounts structs, identical handler
shapes and identical call sequences. The entire difference is one seed:

```rust
// insecure
let seeds = &[ctx.accounts.pool.mint.as_ref(), &[ctx.accounts.pool.bump]];
// secure
let seeds = &[ctx.accounts.pool.withdraw_destination.as_ref(), &[ctx.accounts.pool.bump]];
```

Separating them means knowing that a mint is shared across many pools while a
withdraw destination belongs to one. That is a fact about the protocol's data
model, not about its source. Any rule firing on "the CPI signer's seeds come
from a field of a passed account" fires on both variants — precisely the
"rule firing on something both versions share" this document opens by saying
proves nothing.

Recorded in `PROJECT_CONTEXT.md`'s "Known gaps" rather than left as an open
invitation, so the next reader does not re-derive it. The `recommended`
variant is reachable today by different means — it pins the pool with
`seeds = [withdraw_destination.key().as_ref()]`, which is an Anchor constraint
the parser already sees.

## Addendum, 2026-09-19 — category 5 discriminates after all

Recorded above as five findings on both variants, "no detector for the class;
the 5 are noise". The second half was wrong, and the reason is worth keeping.

The five are `missing-signer` on `authority` plus `missing-owner-check` on
`authority`, `source`, `destination` and `token_program` — four bare
`AccountInfo`s with no constraints at all. They are not noise in the sense of
being false: nothing in the program pins any of them. They were undiscriminating
because the `secure` variant's fix was invisible to the analyzer.

That fix is one line:

```rust
if &spl_token::ID != ctx.accounts.token_program.key {
    return Err(ProgramError::IncorrectProgramId);
}
```

`parser/body.rs` recorded it correctly as a `ManualIf` check referencing
`token_program`. The suppression pass ignored it because it looked for
`<name>.key()` — the **method** a typed account carries — and this is `.key`,
the **field** on `AccountInfo`. Since a bare `AccountInfo` is the only shape
`missing-owner-check` fires on, the recognizer was missing the one spelling
that mattered for the class it governs.

`suppression.rs` now also recognises `accounts.<name>.key`, bounded on both
sides. `insecure` keeps all five; `secure` drops `token_program` and reports
four. The category discriminates.

### What was tried first, and why it was abandoned

The obvious reading — "an `AccountInfo` used only as a CPI argument is
validated by the callee, so don't owner-check it" — does not survive contact
with the fixtures. `tests/fixtures/programs/leaky_vault` forwards its
`authority` to a CPI in exactly the same way:

```rust
let cpi_accounts = Transfer { authority: ctx.accounts.authority.to_account_info(), .. };
let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
```

and that finding is one of the seven the fixture exists to produce. The only
difference from category 5 is that `leaky_vault` builds the accounts struct
into a local first while category 5 inlines it into `invoke(...)`. A rule
keyed on "appears in a CPI call's arguments" therefore suppresses one and not
the other **purely by code shape** — and resolving the local through the
parser's alias map, which is the correct implementation, suppresses both and
drops the fixture below seven findings.

The premise was simply false: being forwarded to a CPI is not evidence that an
account needs no owner check. Recorded here so the next reader does not spend
the same afternoon on it.

### Categories 3, 6 and 9 remain

Still no detector for `type-cosplay`, `duplicate-mutable-accounts` or
`closing-accounts`, and category 9's three findings across its variants are
genuinely unrelated to what that category tests.
