# Adjudicated findings on real programs — 2026-09-19

Every Track 1 finding on every real Anchor program available, read at the
source and labelled. This is the project's first precision measurement on code
nobody tuned the detectors against.

**Result: 4 findings, 0 true positives, 4 false positives. Precision 0.000 (0/4).**

Track 1 only — deterministic, no model, no network. Track 2's output on real
programs is not adjudicated here.

## Population

| Program | LOC | Handlers | Findings | Suppressed |
|---|---:|---:|---:|---:|
| `polyclone/programs/polyclone` | 3,830 | 21 | 2 | 0 |
| `polymarket-clone/programs/prediction-market` | 2,876 | 8 | 2 | 0 |
| `zk-medical-vault/programs/medical-vault` | 505 | 7 | 0 | 0 |
| **total** | **7,211** | **36** | **4** | **0** |

0.55 findings/KLOC.

The six holdout programs were **deliberately excluded**. Adjudicating dike's
output on them would reveal whether it finds the published defects before the
single scored run, which is the one thing that run exists to measure.

## The findings

### 1. `missing-owner-check` on `user` — polyclone, `claim` (+ `place_bet`, `refund`)

**False positive.** `user` is an `UncheckedAccount`, and its identity is pinned
three times over in the same accounts struct
(`src/instructions/refund.rs`):

```rust
pub user: UncheckedAccount<'info>,

#[account(
    seeds = [POSITION_SEED, market.key().as_ref(), user.key().as_ref(), &[outcome as u8]],
    bump = position.bump,
    constraint = position.user == user.key() @ PolycloneError::Unauthorized,
)]
pub position: Account<'info, Position>,

#[account(seeds = [USER_SEED, user.key().as_ref()], bump = user_balance.bump)]
pub user_balance: Account<'info, UserBalance>,
```

Substituting an arbitrary `user` derives a different `position` and
`user_balance` PDA, which will not exist or will belong to that other user. The
author documented exactly this in the `/// CHECK:` comment.

### 2. `missing-authority-binding` on `config.pending_admin` — polyclone, `collect_profits` (+ 7 others)

**False positive.** `pending_admin` is the staged half of a two-step admin
transfer. It is bound in the one handler where it is the authority
(`accept_admin.rs`: `constraint = config.pending_admin == new_admin.key()`) and
is deliberately inert everywhere else. The eight flagged handlers are gated by
`admin`, correctly, with `constraint = config.admin == admin.key()` — and dike
correctly did **not** flag `config.admin`.

### 3. `missing-owner-check` on `bettor` — prediction-market, `place_bet`

**False positive.** Same shape as #1, plus a signature check. `bettor` appears
in the seeds of both `user_balance` and `position`, and
`constraint = user_balance.owner == bettor.key()` pins it directly. The handler
body additionally re-parses an Ed25519 instruction from the instructions sysvar
to confirm the bettor signed the intent.

### 4. `missing-authority-binding` on `config.admin` — prediction-market, `create_market`

**False positive.** The caller is bound to `config.admin`, on the sibling
declaration rather than on `config`:

```rust
#[account(mut, address = config.admin @ PmError::Unauthorized)]
pub admin: Signer<'info>,
```

`address =` is exactly the pin the detector is looking for. It is just on the
other account.

## Root causes

Two, and both are narrow.

**A. The pin lives on a sibling declaration (3 of 4).** Every detector judges
one `AccountDecl` in isolation: it asks whether *this* declaration carries
`address`, `owner`, `seeds`, `has_one`, or a `constraint` naming it. Anchor lets
you pin account X from account Y — by naming X in Y's `seeds`, by
`constraint = Y.field == X.key()`, or by putting `address = Y.field` on X. All
three are idiomatic and all three are invisible to a per-declaration rule.

The suppression pass already handles the *imperative* version of this in the
handler body (`require_keys_eq!`, `X.field == other.key()`). The declarative
version, inside `#[derive(Accounts)]`, has no equivalent.

**B. A staged authority is not a live one (1 of 4).** The authority detector
treats any authority-shaped `Pubkey` field as something that must be bound in
every handler that takes the account. `pending_admin`, `proposed_owner`,
`next_authority` and friends are bound in exactly one handler by design.

## What this means

The tool is quiet on real code (0.55/KLOC) and everything it said was wrong.
Those are not in tension: the volume is low because the detectors are
conservative, and the precision is zero because the conservatism is measured
against the wrong unit — one declaration instead of one accounts struct.

Both causes are specified tightly enough to fix without new machinery. Fixing A
requires resolving references *within* an accounts struct, which the IR already
holds; it does not require dataflow. Fixing B requires knowing which handler a
field is the authority for, which is the same cross-handler reasoning
`collapse_by_subject` already does.

Recall on real code remains unmeasured. These three programs may contain no
defects of the classes dike reports; nothing here says otherwise. The holdout is
the instrument for that question and it is still unspent.

## A usability defect found while doing this

**The reported `file:line` does not point at the finding.** Finding #1 is
reported at `polyclone/src/lib.rs:13`, which is `pub use message::*;`. The
declaration is at `src/instructions/refund.rs:13`. `Location::file` is the
*handler's* file, and in a program whose handlers delegate to modules that is
`lib.rs` for every finding, while `Location::line` comes from the declaration in
a different file. The pair is not merely coarse, it is wrong, and it makes a
finding on any multi-file program hard to act on.

This is already recorded as a quirk, but its consequence on real code was not:
every finding in this adjudication needed a manual search to locate.

**Fixed the same day.** `finding_at` now takes the file the line belongs to,
and `Location::handler_id` drops the file entirely — the two tracks disagree
about a finding's file and both are right, so carrying the path in the identity
key meant they could never corroborate in a multi-file program. Verified on a
mutant of the multi-file fixture: the finding lands on the `#[account(` line of
the declaration rather than an unrelated line of `lib.rs`.

## Follow-up, same day: cause A fixed

Root cause A was fixed in the two detectors that carried it. Both now ask
whether a *sibling* declaration pins the account.

- `MissingOwnerCheckDetector::pinned_by_sibling` — an `UncheckedAccount` named
  in a non-`init` sibling's `seeds`, `constraint` or `address` is pinned. `init`
  and `init_if_needed` siblings are excluded: an account created at whatever
  address its seeds derive to constrains nothing, and a pin that holds only in
  the already-exists branch is not one.
- `MissingAuthorityBindingDetector::field_pinned_by_sibling` — a field is bound
  when a sibling carries `address = owner.field` or a constraint naming
  `owner.field`. The needle is the qualified `owner.field`, so a sibling
  mentioning some unrelated `admin` cannot silence it. `seeds` is not consulted:
  deriving a PDA from `config.admin` pins that address, it does not show the
  caller is the admin.

Re-measured over the same population:

| | before | after |
|---|---:|---:|
| findings | 4 | 1 |
| false positives | 4 | 1 |
| findings/KLOC | 0.55 | 0.14 |

Findings 1, 3 and 4 are gone. Finding 2 (`pending_admin`) remains, since it is
cause B and untouched.

Recall is unchanged and was checked, not assumed: every class still scores
1.000 on the mutation harness at a noise floor of 0, and the vulnerable fixture
still yields all 8 of its findings. Seven regression tests were added from the
shapes in this document, including three negative controls that fail if the new
rules suppress too much.

**Precision remains 0.000 — on a denominator of 1 instead of 4.** The tool is
now quieter but has still never been right about real code. Cause B is the next
fix.

## Follow-up, same day: cause B fixed

`claims_authority` decided whether a handler acts as a stored authority by
matching role words across `_` segments, so `admin` and `pending_admin` read as
the same role and declaring `admin` counted as claiming the staged field.

The rule now says a staged authority and a live one are different authorities.
`claims_authority` returns false when exactly one of the two names carries a
staging qualifier (`pending`, `proposed`, `next`, `new`, `incoming`,
`candidate`). The test is on *disagreement*, which makes it cut both ways:
`new_admin` does not claim `admin` — a handler taking the key it is about to
store is not thereby acting as the current authority — while `new_admin`
claiming `pending_admin` still counts, which is the shape a two-step transfer's
accept step actually has.

| | original | after A | after B |
|---|---:|---:|---:|
| findings | 4 | 1 | **0** |
| false positives | 4 | 1 | 0 |
| findings/KLOC | 0.55 | 0.14 | 0.00 |

Recall checked again, not assumed: every class still 1.000 on the mutation
harness at noise floor 0, and `leaky_vault` still yields all 8 findings. Three
more regression tests, one of them a recall control that fails if a handler
claiming the *staged* authority without binding it stops being reported.

### What zero findings does and does not mean

All four adjudicated false positives are gone and no true positive has replaced
them, because there was never one to find here. Precision is no longer 0.000 —
it is **undefined**, on a denominator of zero. That is a better position than
four wrong answers and a worse one than any right answer.

Nothing here distinguishes "these three programs contain no defect of the five
classes dike reports" from "dike cannot see the defects they contain". The
instrument for that question is the holdout, and it is still unspent. Treat
0 findings/KLOC as the absence of noise, never as evidence of safety — which is
the same thing the report's own banner says about a clean run.

## Reproducing

```
cargo run -p dike-cli -- analyze <program> --format json
```

against each program in the population table.
