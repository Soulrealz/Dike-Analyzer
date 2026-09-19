//! Documentation for the Anchor vulnerability vocabulary.
//!
//! `dike-core` defines the `RuleDoc` shape and deliberately knows none of
//! these classes (CLAUDE.md Rule 2); this is where the domain words live. The
//! wording is drawn from the detectors' own evidence strings, so a reader who
//! sees an annotation and then reads the detector finds the same explanation
//! twice rather than two that have drifted apart.
//!
//! Every `help_uri` below is already a source in `corpus/sources.toml`: the
//! catalog cites what the retriever cites.

use crate::detectors::{
    MISSING_AUTHORITY_BINDING, MISSING_OWNER_CHECK, MISSING_SIGNER, PDA_VALIDATION_GAP,
    REMOVED_GUARD, UNCHECKED_ARITHMETIC,
};
use dike_core::report::RuleDoc;

const SEALEVEL: &str = "https://github.com/coral-xyz/sealevel-attacks/tree/master/programs";

fn rule(id: &str, short: &str, full: &str, help_uri: &str) -> RuleDoc {
    RuleDoc {
        id: id.to_string(),
        short_description: short.to_string(),
        full_description: full.to_string(),
        help_uri: Some(help_uri.to_string()),
        tags: vec!["security".into(), "solana".into(), "anchor".into(), id.to_string()],
    }
}

/// The six documented classes, in `detectors::all_detectors()` order.
///
/// The order is load-bearing: `RuleDoc`s are emitted in catalog order and
/// `ruleIndex` is positional, so reordering this list reorders every
/// consumer's rule array.
pub fn catalog() -> Vec<RuleDoc> {
    vec![
        rule(
            MISSING_SIGNER,
            "A privileged account is not required to sign",
            "An account the program treats as privileged is declared without a `Signer<'info>` type, a `signer` constraint, or an `address =` pin. Nothing requires the transaction to be signed by it, so any caller may pass an arbitrary account in its place and act with its authority.",
            &format!("{SEALEVEL}/0-signer-authorization"),
        ),
        rule(
            MISSING_OWNER_CHECK,
            "An account's owning program is never checked",
            "The account is declared as a raw wrapper, for which Anchor performs neither an owner check nor a discriminator check. Nothing else (`address =`, `owner =`, `seeds`, or a manual `constraint = ...` pinning its identity) constrains it either, so an attacker may substitute an account of the right shape owned by a program they control.",
            &format!("{SEALEVEL}/2-owner-checks"),
        ),
        rule(
            MISSING_AUTHORITY_BINDING,
            "A signer is never bound to the account it claims authority over",
            "A handler takes both a state account and an authority, but nothing ties the two together — no `has_one`, no `constraint = ...` comparing them, no seed derivation over the authority. The signature proves who sent the transaction and not what they are entitled to touch, so any valid signer may operate on anyone's account.",
            &format!("{SEALEVEL}/1-account-data-matching"),
        ),
        rule(
            PDA_VALIDATION_GAP,
            "A derived address is validated inconsistently across handlers",
            "The same account type is derived with `seeds` in one accounts struct and accepted without derivation in another. The handler that skips the derivation accepts any account of that type, which makes the constraint the other handlers enforce reachable around rather than through.",
            &format!("{SEALEVEL}/7-bump-seed-canonicalization"),
        ),
        rule(
            UNCHECKED_ARITHMETIC,
            "Arithmetic on account state can wrap",
            "A handler performs arithmetic on persisted balances or counters using operators that wrap in release builds rather than the checked, saturating or `require!`-guarded forms. An attacker who can drive a value past a boundary changes state the program believes is impossible.",
            "https://neodyme.io/en/blog/solana_common_pitfalls/",
        ),
        rule(
            REMOVED_GUARD,
            "A guard the surrounding code implies is absent",
            "A constraint that the rest of the program's shape implies should be present is missing from this declaration — a field its siblings bind, or an authority-shaped account nothing pins. Reported at lower confidence than the classes above: the evidence is the surrounding code's own pattern rather than a structural rule.",
            "https://www.anchor-lang.com/docs/references/account-constraints",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::all_detectors;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_covers_exactly_the_detector_vocabulary() {
        // Both directions. A seventh detector with no entry fails this; a
        // stale entry left behind after removing a detector fails it too.
        let documented: BTreeSet<String> = catalog().into_iter().map(|r| r.id).collect();
        let detected: BTreeSet<String> =
            all_detectors().iter().map(|d| d.class().to_string()).collect();
        assert_eq!(documented, detected);
    }

    #[test]
    fn every_entry_is_populated_and_ordered_like_the_detectors() {
        let cat = catalog();
        let detected: Vec<String> =
            all_detectors().iter().map(|d| d.class().to_string()).collect();
        let documented: Vec<String> = cat.iter().map(|r| r.id.clone()).collect();
        assert_eq!(documented, detected, "catalog order must match all_detectors()");
        for rule in &cat {
            assert!(!rule.short_description.is_empty(), "{} has no short description", rule.id);
            assert!(!rule.full_description.is_empty(), "{} has no full description", rule.id);
            assert!(rule.help_uri.is_some(), "{} has no help uri", rule.id);
            assert!(rule.tags.contains(&"security".to_string()), "{} is not tagged", rule.id);
        }
    }
}
