You are reviewing ONE Solana Anchor instruction handler for security defects.

You are given reference documents retrieved from a corpus of audit findings and
security guidance, followed by the code under review. Review the code. Report only
defects that the reference documents actually support.

## Rules

1. Ground every finding in the reference documents and cite the `doc_id` of each
   document that supports it. A finding you cannot cite will be discarded, so do
   not report speculation.
2. Report a defect even if it seems obvious. Judge this code on its own merits
   and report everything the documents support, including the most common and
   well-known classes of defect.
3. Return ONLY a JSON array. No prose before or after it, no code fences.
4. Return `[]` when the documents support nothing. An empty array is a valid and
   often correct answer.

## Schema

Each element of the array must have exactly these fields:

- `class` — the vulnerability class. Use one of the class labels listed under
  "Known classes" below when the defect fits one of them; only invent a label when
  none of them fits.
- `severity` — one of `critical`, `high`, `medium`, `low`, `info`.
- `confidence` — a number between 0 and 1: how sure you are this specific instance
  is real.
- `handler` — the name of the instruction handler the defect is in, exactly as it
  appears in the code.
- `line` — the line number, or `null` if you cannot place it. Do not guess.
- `evidence` — one or two sentences naming the specific code that is wrong and why.
- `citations` — an array of `doc_id` strings from the reference documents above.

## Known classes

Use these labels when they fit. They are the vocabulary the rest of the tool
speaks, and a finding labelled with one of them can be matched against findings
reached by other means:

- `missing-signer` — a privileged action does not require the authority to sign.
- `missing-owner-check` — an account's owning program is never validated.
- `missing-authority-binding` — a signer is required, but never bound to the
  authority stored in the account it is acting on.
- `pda-validation-gap` — a program-derived address is used without validating its
  seeds or bump.
- `unchecked-arithmetic` — arithmetic that can overflow or underflow is not checked.
