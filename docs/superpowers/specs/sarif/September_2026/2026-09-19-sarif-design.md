# SARIF output and a GitHub Action — design

**Written 2026-09-19.** Implements item 1 of
[`docs/next_steps_6.md`](../../../../next_steps_6.md): the single biggest step
toward running dike on real repositories, and entirely offline.

Read [`PROJECT_CONTEXT.md`](../../../PROJECT_CONTEXT.md) and
[`CLAUDE.md`](../../../../CLAUDE.md) first. This document assumes both.

---

## Why now

Dike's report is Markdown or JSON, and both require a human to open a file. A
security tool that runs in CI has to put its findings where the reviewer already
is: the GitHub pull-request diff and the Security tab. SARIF is the format that
does that, and `github/codeql-action/upload-sarif` is the mechanism.

This was blocked until 2026-09-19. Before findings pointed at the file their
declaration is in, GitHub would have annotated unrelated lines — an annotation
on the wrong line is worse than no annotation, because the reviewer has to
work out that the tool is confused before they can ignore it.

It also fits the project's stance exactly. GitHub code scanning is an
annotation layer, not a build gate, which is what Rule 4 says dike is.

## What is being built

1. A SARIF 2.1.0 renderer in `dike-core`, alongside the existing Markdown and
   JSON renderers.
2. A domain-agnostic `RuleDoc` type in core, filled by a six-entry catalog in
   `dike-lang-anchor`.
3. `--format sarif` and `--base-dir` on `dike analyze`.
4. A composite `action.yml` at the repository root that other repositories can
   consume with `uses:`.
5. A CI job in this repository that exercises the action end to end without
   uploading.

## What is explicitly not being built

- **No `--fail-on` flag, and no exit-code change.** Rule 4. The SARIF's
  `invocations[0].executionSuccessful` is `true` whenever the tool ran, whatever
  it found.
- **No release workflow and no prebuilt binaries.** The action builds from the
  consumer's checked-out copy of the action source. Publishing binaries is a
  separate decision with its own maintenance cost.
- **No JSON-schema validation dependency.** Structural assertions are written by
  hand in the renderer's tests. Pulling a schema crate into the workspace to
  validate one document is not worth the dependency.
- **No SARIF ingest.** Dike emits SARIF; it does not read it.

---

## 1. `RuleDoc` — the shape, in core

`crates/dike-core/src/report/sarif.rs`:

```rust
/// Documentation for one vulnerability class, for consumers that want a rule
/// catalog rather than bare class names. Core defines the shape and never the
/// contents: class vocabularies are language-specific (Rule 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDoc {
    pub id: String,
    pub short_description: String,
    pub full_description: String,
    pub help_uri: Option<String>,
    pub tags: Vec<String>,
}
```

`RuleDoc` is re-exported from `crate::report` so the CLI and the language crate
import it from one place.

**Seam obligation.** `crates/dike-core/tests/seam.rs` checks string literals,
not only identifiers. Nothing in `sarif.rs` may contain `anchor`, `solana`,
`Pubkey`, `has_one` and the rest of the banned list outside a comment. The
renderer therefore never hard-codes a class name, a severity heuristic per
class, or a help URL — every one of those arrives as a `RuleDoc`.

## 2. The renderer

```rust
impl Report {
    pub fn render_sarif(&self, rules: &[RuleDoc], base: &Path) -> serde_json::Result<String>;
}
```

Output is SARIF 2.1.0, pretty-printed, one `runs` entry.

### `tool.driver`

- `name`: `dike`
- `version`: `RunMetadata.tool_version`
- `informationUri`: `https://github.com/Soulrealz/Dike-Analyzer`
- `rules`: **only the rules actually referenced by a result**, emitted in
  catalog order. A run that finds nothing emits an empty `rules` array. Emitting
  the whole catalog every time would advertise classes the run never examined.

Each rule renders as:

```json
{
  "id": "missing-signer",
  "name": "missing-signer",
  "shortDescription": { "text": "..." },
  "fullDescription": { "text": "..." },
  "helpUri": "...",
  "help": { "text": "..." },
  "properties": { "tags": ["security", "..."] }
}
```

`help.text` repeats `full_description`; GitHub renders `help` in the alert
detail pane and `fullDescription` in the list, and omitting either leaves a
blank panel.

`helpUri` is omitted entirely when `RuleDoc.help_uri` is `None` rather than
emitted as `null`.

### `results[]`

One result per finding in **`tracks.merged`**, in merged order. That order is
already the deterministic ranking from `merge.rs`, so no sorting happens here.

`tracks.merged` is the report's answer — a corroborated finding is one row, not
two — so per-track arrays are not emitted. The originating track survives as a
property on each result.

| SARIF field | Source |
|---|---|
| `ruleId` | `finding.class` |
| `ruleIndex` | index into the emitted `rules` array |
| `level` | severity map, below |
| `message.text` | `finding.evidence` |
| `locations[0].physicalLocation.artifactLocation.uri` | relativized `finding.location.file` |
| `locations[0].physicalLocation.region.startLine` | `finding.location.line` |
| `partialFingerprints` | `{"dikeFindingId/v1": finding.id}` |
| `properties` | see below |

`region` carries `startLine` only. Dike records a line, not a column or an end
line, and inventing a column would be a claim about span precision the IR does
not support. GitHub annotates the whole line when no column is given, which is
the honest rendering.

### Fingerprints are the load-bearing detail

`finding.id` is `blake3(handler_id | class | key)[..16]` — it contains no line
number and no file path. Feeding it to GitHub as a `partialFingerprint` means an
alert stays the *same alert* when the code around it moves: no close-and-reopen
churn on every refactor, and a dismissal survives.

If fingerprints were omitted, GitHub would fall back to hashing the surrounding
source, and every line shift would resurrect dismissed alerts. This is the
single highest-value property of the whole format and it is available only
because `Location::handler_id` deliberately excludes the file.

The `/v1` suffix is SARIF's own convention for versioning a fingerprint scheme.
Changing how `finding.id` is computed must bump it to `/v2`, or consumers
silently inherit a set of alerts whose identities all changed at once.

### `properties` on a result

```json
{
  "dikeTrack": "corroborated",
  "dikeSeverity": "critical",
  "dikeConfidence": 0.97,
  "dikeSubject": "authority",
  "dikeAbsorbedHandlers": ["deposit", "close"],
  "security-severity": "9.0"
}
```

`dikeSubject` and `dikeAbsorbedHandlers` are omitted when absent or empty.
`security-severity` is a string, not a number — GitHub requires a string here
and silently ignores a numeric value.

`dikeConfidence` is **not** emitted with `json!(finding.confidence)`. That
widens the `f32` to `f64` before anything formats it, and a confidence of
`0.9` renders as `0.8999999761581421` while the JSON report renders the same
field as `0.9` (measured 2026-09-19). The renderer round-trips through the
`f32`'s own shortest representation so both reports quote the same number.

### A class with no catalog entry

Track 2 can report a class the catalog does not carry. The result is still
emitted, with a `ruleId` and **no** `ruleIndex` — SARIF permits that, and
dropping the result instead would be a silent false negative, which Rule 3
forbids. An unlisted class contributes no entry to the `rules` array.

`finding.citations` render as `relatedLocations` with the citation title as the
message and the source URL as the artifact location, so a Track 2 finding's
grounding is visible in the alert rather than buried in a property.

### Severity map

Pinned, and in the same category as the per-detector confidences under Rule 5:
changing it changes every consumer's alert triage at once.

| `Severity` | `level` | `security-severity` |
|---|---|---|
| `Critical` | `error` | `"9.0"` |
| `High` | `error` | `"7.0"` |
| `Medium` | `warning` | `"5.0"` |
| `Low` | `note` | `"3.0"` |
| `Info` | `note` | `"1.0"` |

**This can fail a pull request's check, and that is GitHub's decision, not
dike's.** GitHub fails the code-scanning check for alerts at `level: error` or
`security-severity` at or above 7.0, unless the repository owner raises the
threshold in Settings → Code security → Code scanning → "Protection rules".

The alternative — capping everything below the threshold so a dike run can never
block a merge — was considered and rejected. It would mean reporting a critical
missing-signer as a medium, which is a false statement about severity made to
work around a UI default. Rule 4 governs dike's exit code, and dike's exit code
stays 0 unconditionally. Documenting the setting is honest; understating
severity is not.

The README and the action's documentation must both state this and name the
setting.

### `invocations`

```json
"invocations": [{
  "executionSuccessful": true,
  "toolExecutionNotifications": [ /* one per Diagnostic */ ]
}]
```

Each `Diagnostic` becomes a notification whose `level` is `warning` for
`ParseFailure` and `Skipped`, `note` for `Ambiguity` and `TrackSkipped`, with
the diagnostic's file as its location when it has one.

Without this, a run that failed to parse half the program is indistinguishable
in the Security tab from a run that found the program clean. That is the exact
failure mode Rule 3 exists to prevent.

`executionSuccessful` is `true` whenever the tool ran to completion, regardless
of findings or diagnostics.

### Determinism

`RunMetadata.timestamp` is **not** emitted, and no `startTimeUtc`,
`endTimeUtc`, or any other clock-derived field appears anywhere in the
document. Two runs over identical input produce byte-identical SARIF (Rule 5).

This is a deliberate divergence from the JSON renderer, which does emit the
timestamp. A SARIF file is a CI artifact that gets diffed and cached; a
timestamp in it makes every run look changed.

## 3. Path relativization

`finding.location.file` is the path as walked from the root the user passed —
`SourceTree::load` stores `entry.path()` verbatim. So `dike analyze
programs/vault` yields `programs/vault/src/lib.rs`, and `dike analyze
/home/me/programs/vault` yields an absolute path.

GitHub resolves SARIF URIs against the repository root and silently drops any
result it cannot map to a checked-out file. An absolute path therefore produces
a SARIF that uploads successfully and annotates nothing.

`--base-dir <PATH>` is added to `dike analyze`, defaulting to the current
working directory. The renderer:

1. strips `base` as a prefix when `finding.location.file` starts with it;
2. leaves the path unchanged when it does not;
3. normalizes path separators to `/` in the emitted URI, since SARIF `uri` is a
   URI reference, not a native path.

The same relativization applies to diagnostic locations.

`--base-dir` is accepted for every format and affects only SARIF. Rejecting it
for Markdown and JSON would mean a flag whose validity depends on another flag,
for no gain.

## 4. The Anchor rule catalog

`crates/dike-lang-anchor/src/rules.rs`, exported as
`dike_lang_anchor::rules::catalog() -> Vec<RuleDoc>`.

Six entries, keyed on the existing class constants in `detectors/mod.rs`, in
`all_detectors()` order. Wording is drawn from the detectors' own evidence
strings, so a reader who sees the annotation and then reads the detector finds
the same explanation twice rather than two different ones.

| Class | `help_uri` |
|---|---|
| `missing-signer` | sealevel-attacks `programs/0-signer-authorization` |
| `missing-owner-check` | sealevel-attacks `programs/2-owner-checks` |
| `missing-authority-binding` | sealevel-attacks `programs/1-account-data-matching` |
| `pda-validation-gap` | sealevel-attacks `programs/7-bump-seed-canonicalization` |
| `unchecked-arithmetic` | Neodyme, "Solana common pitfalls" |
| `removed-guard` | Anchor account-constraint reference |

Every one of these URLs is already a source in `corpus/sources.toml`, so the
catalog cites what the retriever cites.

`tags` are `["security", "solana", "anchor", <class>]`. These strings live in
`dike-lang-anchor`, where domain vocabulary belongs.

### The test that keeps it honest

```rust
#[test]
fn catalog_covers_exactly_the_detector_vocabulary() { /* both directions */ }
```

The catalog's class set and `all_detectors()`' class set must be equal. Adding a
seventh detector without a catalog entry fails this test; leaving a stale entry
behind after removing a detector fails it too. That is the Rule 6 answer to
"what change would make this fail".

## 5. CLI wiring

- `config::Format` gains `Sarif`.
- `config::RunConfig` gains `base_dir: PathBuf`.
- `main.rs` gains `--base-dir`, defaulting to `std::env::current_dir()`.
- `commands/analyze.rs` renders with
  `report.render_sarif(&dike_lang_anchor::rules::catalog(), &cfg.base_dir)`.

`dike-cli` remains the only place core and Anchor meet (Rule 2). Core never
learns the catalog exists; the Anchor crate never learns SARIF exists beyond the
`RuleDoc` shape it fills.

## 6. `action.yml`

At the repository root, so consumers write `uses: Soulrealz/Dike-Analyzer@<ref>`.

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | — (required) | Program directory to analyze |
| `sarif-file` | `dike.sarif` | Where the SARIF is written |
| `category` | `dike` | Code-scanning category, so dike's alerts do not collide with another tool's |
| `upload` | `true` | Upload to code scanning. `false` writes the file and stops |

### Outputs

| Output | Meaning |
|---|---|
| `sarif-file` | Path to the written SARIF, for a caller that wants to upload it themselves |

### Steps

```yaml
runs:
  using: composite
  steps:
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
      with:
        workspaces: ${{ github.action_path }}
    - name: Build dike
      shell: bash
      run: cargo install --path "${{ github.action_path }}/crates/dike-cli" --locked
    - name: Analyze
      shell: bash
      run: dike analyze "${{ inputs.path }}" --format sarif --out "${{ inputs.sarif-file }}"
    - name: Upload
      if: inputs.upload == 'true'
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: ${{ inputs.sarif-file }}
        category: ${{ inputs.category }}
```

**Why `--path ${{ github.action_path }}` and not `--git`.** `github.action_path`
is the consumer's already-checked-out copy of the action source at whatever ref
they pinned. Building from it means the binary is exactly the version they
asked for, needs no `ref` input to keep in sync with the `uses:` line, and
fetches nothing over the network. `--locked` makes the build use the committed
`Cargo.lock`.

The analyze step runs with the runner's working directory at
`$GITHUB_WORKSPACE`, so `--base-dir` is left at its default and the emitted URIs
are workspace-relative, which is what `upload-sarif` expects.

### Documented consumer requirements

- `permissions: security-events: write` on the calling job, or the upload fails
  with a permissions error that does not explain itself.
- `actions/checkout` before the action, since it analyzes the working tree.
- A note that the first run builds from source and takes several minutes, and
  that `Swatinem/rust-cache` makes subsequent runs fast.
- The severity/protection-rule note from §2.

## 7. CI in this repository

A new `action-smoke` job in `.github/workflows/ci.yml`, `needs: check`:

1. `actions/checkout`
2. the local action via `uses: ./`, with `path:
   tests/fixtures/programs/leaky_vault`, `upload: false`
3. assertions on the produced file: it parses as JSON, `$schema` and `version`
   are present, `runs[0].results` is non-empty, and the rule IDs include
   all five of `missing-signer`, `missing-owner-check`,
   `missing-authority-binding`, `pda-validation-gap` and `unchecked-arithmetic`

**Why `upload: false`.** `leaky_vault` is deliberately vulnerable. Uploading its
SARIF would file permanent code-scanning alerts against this repository's own
Security tab for a fixture nobody intends to fix, and every contributor would
then have to learn to ignore them. Leaving the upload step unexercised in CI is
the lesser cost; the upload path is a four-line `uses:` of a Microsoft-
maintained action, and the consumer example in the README covers it.

The job runs the action against a fixture with findings, not a clean one. A
smoke test over `vault` would pass against a renderer that emits an empty
document.

## 8. Testing

### Renderer, in `dike-core`

| Test | What change makes it fail |
|---|---|
| Level and `security-severity` for all five severities | any edit to the pinned map |
| Render twice, compare bytes | reintroducing a clock or a `HashMap` iteration |
| Relativization: relative path, absolute under base, absolute outside base | dropping any of the three branches |
| Separator normalization to `/` | emitting native separators |
| `partialFingerprints` present and equal to `finding.id` | dropping fingerprints |
| Two reports differing only in `location.line` produce the same fingerprint | putting the line into the ID |
| Only referenced rules emitted, in catalog order, deduplicated | emitting the full catalog, or one rule per result |
| Two results of the same class share a `ruleIndex` | duplicating rule entries |
| Zero findings → valid document with `results: []` and `rules: []` | panicking or emitting `null` |
| Diagnostics become `toolExecutionNotifications` | dropping the invocations block |
| `executionSuccessful` is `true` with findings present | wiring findings into the exit story |
| `helpUri` omitted, not `null`, when `help_uri` is `None` | serializing `Option` naively |

### Catalog, in `dike-lang-anchor`

The both-directions completeness test from §4.

### CLI, in `dike-cli`

`analyze --format sarif` over `tests/fixtures/programs/leaky_vault` parses as
JSON and carries the **seven** results that fixture is known to produce
(verified 2026-09-19), across **five** distinct classes:

| Class | Handler | Line |
|---|---|---:|
| `missing-signer` | `withdraw` | 110 |
| `missing-owner-check` | `set_admin` | 118 |
| `missing-owner-check` | `withdraw` | 110 |
| `missing-authority-binding` | `set_fee` | 125 |
| `pda-validation-gap` | `deposit` | 92 |
| `unchecked-arithmetic` | `deposit` | 30 |
| `unchecked-arithmetic` | `withdraw` | 44 |

Seven results against five rules is the case that catches a renderer emitting
one rule per result instead of deduplicating: `rules` must have five entries and
the two `missing-owner-check` results must share a `ruleIndex`.

### Gates

All four from Rule 7, plus `cargo test -p dike-core --test seam` specifically —
`sarif.rs` is a new file in core and the seam test is the reason its design
keeps every class name out of it.

## 9. Documentation required by the rules

**`docs/PROJECT_CONTEXT.md`** (Rule 1): `report/sarif.rs` in the core tree,
`rules.rs` in the Anchor tree, `action.yml` in the folder structure, the new
`--format sarif` and `--base-dir` flags, the new CI job, and a
"Quirks & constraint-driven decisions" entry recording the severity-mapping
tension and why faithful mapping won.

**`README.md`**: a consumer workflow example, the `permissions` requirement, and
the protection-rule note.

**`learning/`** (Rule 10): `part-04-report.md` tours
`report/{mod,markdown,json}.rs` and gains a third renderer; `part-10-cli.md`
traces `dike analyze` from argument to rendered report and gains a format and a
flag. Both change in the same commit.

## 10. Risks

- **The action cannot be tested outside GitHub.** `uses: ./` in CI is the only
  real exercise it gets, and the upload step is not exercised at all. The first
  consumer will find anything wrong with the upload wiring. Accepted: the
  alternative is fixture alerts in this repo's Security tab forever.
- **`cargo install --locked` on every run.** Cold, that is several minutes. The
  cache keyed on `github.action_path` should make it near-free afterwards, but
  cache behaviour for a path outside the consumer's workspace is worth watching
  on the first real use.
- **GitHub's threshold defaults may change.** The README note names a setting
  in someone else's product. It will need checking when it goes stale.
