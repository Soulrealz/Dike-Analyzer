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
| 5 | arbitrary-cpi | 5 | 5 | 0 | no detector for the class; the 5 are noise |
| 6 | duplicate-mutable-accounts | 0 | 0 | 0 | no detector for the class |
| 7 | bump-seed-canonicalization | 0 | 0 | 0 | **gap** — this is `pda-validation-gap`'s subject |
| 8 | pda-sharing | 0 | 0 | 0 | **gap** — same |
| 9 | closing-accounts | 1 | 2 | 1 | no detector for the class; noise |
| 10 | sysvar-address-checking | 1 | 0 | 0 | **discriminates** |

Dike tells the vulnerable version from the fixed one in **3 of 11** categories,
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
