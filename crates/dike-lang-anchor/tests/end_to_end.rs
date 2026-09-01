use dike_core::analyzer::{Analyzer, SourceFile, SourceTree};
use std::path::{Path, PathBuf};

fn fixture() -> SourceTree {
    SourceTree::load(Path::new("../../tests/fixtures/programs/vault")).unwrap()
}

#[test]
fn clean_fixture_produces_a_low_noise_floor() {
    let result = dike_lang_anchor::AnchorAnalyzer.analyze(&fixture());
    // The fixture is written correctly and Phase 3 verified repeatedly that
    // it produces zero findings of any severity — pin that exact number, not
    // just "no Critical", so a detector that starts emitting Info-level
    // noise on clean code has to change this assertion consciously rather
    // than sliding under a pre-weakened bound.
    assert!(
        result.findings.is_empty(),
        "expected zero findings on the clean fixture (the noise floor), got: {:#?}",
        result.findings
    );
    assert!(
        !result.findings.iter().any(|f| f.severity == dike_core::Severity::Critical),
        "critical finding on the clean fixture: {:#?}",
        result.findings
    );
}

/// The deliberately vulnerable counterpart to the clean fixture.
///
/// It exists so both tracks can be exercised against code that *should*
/// produce findings — the clean fixture proves the noise floor, and this one
/// proves the detectors still fire on a whole program rather than on
/// in-memory mutations of a correct one. Also the Track 2 fixture: a run that
/// finds nothing on it is a regression, not a clean bill of health.
fn leaky_fixture() -> SourceTree {
    SourceTree::load(Path::new("../../tests/fixtures/programs/leaky_vault")).unwrap()
}

#[test]
fn the_vulnerable_fixture_produces_findings_in_every_class_it_was_written_for() {
    let result = dike_lang_anchor::AnchorAnalyzer.analyze(&leaky_fixture());
    let classes: Vec<&str> = result.findings.iter().map(|f| f.class.as_str()).collect();
    for expected in [
        "missing-signer",
        "missing-owner-check",
        "missing-authority-binding",
        "unchecked-arithmetic",
    ] {
        assert!(
            classes.contains(&expected),
            "the fixture was written to trigger `{expected}`; got: {classes:?}"
        );
    }
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.class.as_str() == "missing-signer" && f.location.handler == "withdraw"),
        "the headline defect is the unsigned authority on `withdraw`: {:#?}",
        result.findings
    );
}

#[test]
fn the_vulnerable_fixture_is_never_built() {
    // Fixture programs are parsed as text. A Cargo.toml appearing here would
    // make `cargo test` at the workspace root try to compile a program that
    // deliberately does not compile.
    assert!(
        !Path::new("../../tests/fixtures/programs/leaky_vault/Cargo.toml").exists(),
        "fixture programs must not be buildable crates"
    );
}

/// Mutates `Withdraw`'s `admin: Signer<'info>` (tests/fixtures/programs/vault/src/lib.rs)
/// down to `AccountInfo<'info>`, removing its signer-ness.
///
/// Why this account: `Withdraw::admin` has no `#[account(...)]` attribute at
/// all, so once it stops being a `Signer` it also becomes an unchecked
/// wrapper with nothing (`address =`, `owner =`, `seeds`) pinning its
/// identity — `missing-owner-check` legitimately fires on it too, alongside
/// `missing-signer`. This test only asserts the `missing-signer` finding is
/// present on `admin`; it does not assert an exact finding count, since a
/// second, unrelated-but-correct detector firing is not a defect.
///
/// None of the fixture's `require!` calls mention `admin` or `is_signer` at
/// all (they check `amount`, `vault.amount`), and there is no
/// `#[access_control]` on `withdraw`, so the injected finding is not
/// suppressed by `detectors::suppression::apply` — verified by this test
/// actually passing rather than failing for an unrelated reason.
#[test]
fn injecting_a_missing_signer_produces_that_finding_on_the_mutated_account() {
    let mut tree = fixture();
    let mut replacements = 0;
    for f in &mut tree.files {
        let before = f.text.clone();
        f.text = f.text.replacen(
            "pub admin: Signer<'info>,\n\n    pub token_program: Program<'info, Token>,",
            "pub admin: AccountInfo<'info>,\n\n    pub token_program: Program<'info, Token>,",
            1,
        );
        if f.text != before {
            replacements += 1;
        }
    }
    assert_eq!(
        replacements, 1,
        "mutation did not apply — the fixture text this test targets has drifted"
    );

    let result = dike_lang_anchor::AnchorAnalyzer.analyze(&tree);
    assert!(
        result.findings.iter().any(|f| f.class.as_str() == "missing-signer"
            && f.location.handler == "withdraw"
            && f.evidence.contains("`admin`")),
        "expected a missing-signer finding on `admin` in `withdraw`, got: {:#?}",
        result.findings
    );
}

/// Fix round 1, Item 2: the previous version of this test compared two runs
/// over the *clean* vault fixture, which produces zero findings — it
/// asserted `[] == []`, proving nothing about `rank`'s stability, and
/// nothing at all about tie-break ordering, which is exactly the fragile
/// part (Task 3 needed two fix rounds to make ranking order-independent
/// when `rank_score` ties).
///
/// This mutates the fixture (same in-memory technique as
/// `injecting_a_missing_signer_produces_that_finding_on_the_mutated_account`
/// above) three ways to produce several findings of DIFFERING and of EQUAL
/// rank score, then asserts the two runs are identical on the full finding
/// vectors:
///
/// - `Withdraw::admin` downgraded from `Signer` to `AccountInfo`: fires both
///   `missing-signer` (rank_score = Critical.weight() 1.0 * confidence 0.90
///   = 0.90) and `missing-owner-check` (rank_score = High.weight() 0.75 *
///   confidence 0.75 = 0.5625) on the same account/handler — two DIFFERING
///   scores.
/// - `deposit`'s `checked_add` and `withdraw`'s `checked_sub` are each
///   replaced with a bare operator, producing an `unchecked-arithmetic`
///   finding (rank_score = Medium.weight() 0.5 * confidence 0.35 = 0.175) in
///   EACH handler. These two findings TIE exactly on rank_score AND
///   severity, so their relative order is decided by the `handler_id`
///   tiebreaker in `dike_core::merge::rank`.
///
/// What this test DOES prove: the whole pipeline is free of accidental
/// nondeterminism — an added `HashMap` iteration, a thread, a clock — on a
/// realistic multi-finding input that includes a rank tie.
///
/// What it does NOT prove, stated plainly so nobody mistakes it: it feeds
/// the SAME input in the SAME order twice, and Rust's sort is deterministic
/// and stable on unchanged input, so this would still pass if the
/// `handler_id` tiebreaker were deleted outright. Order-INDEPENDENCE — that
/// two different input orderings converge on one output — is proven where
/// the comparator lives, by `dike_core::merge`'s own
/// `ranking_breaks_ties_by_handler_id` and
/// `same_track_duplicate_order_independence` tests. Do not weaken those on
/// the assumption that this end-to-end test covers them.
#[test]
fn analysis_is_byte_stable_across_runs() {
    let mut tree = fixture();
    let mut applied = [false; 3];
    for f in &mut tree.files {
        let before = f.text.clone();
        f.text = f.text.replacen(
            "pub admin: Signer<'info>,\n\n    pub token_program: Program<'info, Token>,",
            "pub admin: AccountInfo<'info>,\n\n    pub token_program: Program<'info, Token>,",
            1,
        );
        if f.text != before {
            applied[0] = true;
        }

        let before = f.text.clone();
        f.text = f.text.replacen(
            "vault.amount = vault.amount.checked_add(amount).ok_or(VaultError::Overflow)?;",
            "vault.amount = vault.amount + amount;",
            1,
        );
        if f.text != before {
            applied[1] = true;
        }

        let before = f.text.clone();
        f.text = f.text.replacen(
            "vault.amount = vault.amount.checked_sub(amount).ok_or(VaultError::Overflow)?;",
            "vault.amount = vault.amount - amount;",
            1,
        );
        if f.text != before {
            applied[2] = true;
        }
    }
    assert_eq!(
        applied,
        [true, true, true],
        "one or more mutations did not apply — the fixture text this test targets has drifted"
    );

    let a = dike_lang_anchor::AnchorAnalyzer.analyze(&tree).findings;
    let b = dike_lang_anchor::AnchorAnalyzer.analyze(&tree).findings;

    // Sanity: this really does produce multiple findings, including a
    // genuine rank-score tie — otherwise this test would be no better than
    // the vacuous version it replaces.
    assert!(
        a.iter().any(|f| f.class.as_str() == "missing-signer"),
        "expected a missing-signer finding: {:#?}",
        a
    );
    assert!(
        a.iter().any(|f| f.class.as_str() == "missing-owner-check"),
        "expected a missing-owner-check finding: {:#?}",
        a
    );
    let arithmetic: Vec<_> =
        a.iter().filter(|f| f.class.as_str() == "unchecked-arithmetic").collect();
    assert_eq!(
        arithmetic.len(),
        2,
        "expected an unchecked-arithmetic finding in both deposit and withdraw: {:#?}",
        arithmetic
    );
    assert!(
        (arithmetic[0].rank_score() - arithmetic[1].rank_score()).abs() < 1e-6,
        "the two unchecked-arithmetic findings must tie on rank_score for this test to actually \
         exercise tie-break ordering: {:#?}",
        arithmetic
    );

    assert_eq!(
        a, b,
        "analysis (including rank-score tie-break order) must be byte-stable across runs over \
         identical input"
    );
}

/// Fix round 1, Item 1: nothing previously proved suppression is wired into
/// `analyze_program` (as opposed to `detectors::suppression::apply`, which
/// every other suppression test calls directly). A reviewer mutated
/// `analyze_program` to bypass suppression entirely
/// (`let (kept, dropped) = (raw, Vec::new());`) and the full suite — 133
/// tests — still passed, because no test went through `analyze_program`
/// itself.
///
/// This uses a scenario the reviewer already proved suppressible: an
/// `UncheckedAccount` (`mint`) that would trip `missing-owner-check`, paired
/// with a `require!(ctx.accounts.mint.key() == expected_mint, ...)`
/// identity check naming that account — the exact idiom
/// `equality_to_key_suppresses` (via `detectors::suppression::apply`)
/// recognizes.
///
/// Goes through `analyze_program`, not `AnchorAnalyzer::analyze`: the latter
/// discards the `suppressed` field entirely (see `analyze_program`'s doc
/// comment on `AnchorAnalyzer`), so it cannot show suppression happened —
/// only that a finding is absent, which is also what "the detector never
/// fired" would look like.
#[test]
fn suppression_is_applied_through_analyze_program() {
    let tree = SourceTree {
        root: PathBuf::from("."),
        files: vec![SourceFile {
            path: PathBuf::from("src/lib.rs"),
            text: r#"
                #[program]
                pub mod vault {
                    pub fn withdraw(ctx: Context<Withdraw>, expected_mint: Pubkey) -> Result<()> {
                        require!(ctx.accounts.mint.key() == expected_mint, VaultError::WrongMint);
                        Ok(())
                    }
                }
                #[derive(Accounts)]
                pub struct Withdraw<'info> {
                    pub authority: Signer<'info>,
                    pub mint: UncheckedAccount<'info>,
                }
            "#
            .into(),
        }],
    };

    let analysis = dike_lang_anchor::analyze_program(&tree);

    assert!(
        !analysis.result.findings.iter().any(|f| f.class.as_str() == "missing-owner-check"
            && f.evidence.contains("`mint`")),
        "the require!(mint.key() == expected_mint) check should have suppressed \
         missing-owner-check on `mint`, but it survived into `findings`: {:#?}",
        analysis.result.findings
    );

    assert!(
        !analysis.suppressed.is_empty(),
        "analyze_program's `suppressed` list must be non-empty — the finding above was \
         withheld, not simply never generated"
    );
    assert!(
        analysis.suppressed.iter().any(|(f, reason)| f.class.as_str() == "missing-owner-check"
            && f.evidence.contains("`mint`")
            && !reason.is_empty()),
        "suppressed must contain the missing-owner-check finding on `mint` paired with a \
         non-empty reason: {:#?}",
        analysis.suppressed
    );
}
