//! Ground truth for the differential eval harness.
//!
//! A `MutationLabel` is what a mutation operator *claims* it injected into an
//! otherwise-clean program: a class string, a severity, and a source location.
//! The harness compares it against what an analyzer actually reported.
//!
//! It lives in `dike-core` rather than in a language crate because the harness
//! consumes it and `dike-core` can never depend on a language crate. Nothing
//! here names a language: the class is a free string, exactly as `VulnClass`
//! is, for the same reason (D6).

use crate::finding::Severity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One injected defect, labelled by the operator that made the edit.
///
/// The label is emitted at the edit site, never inferred afterwards, so ground
/// truth is exact rather than guessed (spec §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationLabel {
    /// Stable across runs for the same operator and site — the harness keys
    /// history on it, so it must not move when unrelated mutants appear.
    pub id: String,
    /// The class an analyzer is expected to report. Compared against
    /// `VulnClass::as_str`.
    pub class: String,
    pub severity: Severity,
    pub file: PathBuf,
    /// The line the operator rewrote, 1-based. Never 0 (invariant 9).
    pub line: u32,
    /// The enclosing instruction handler — the unit at which findings are
    /// compared (D5).
    pub handler: String,
    /// The operator's `name()`. Carried so a per-operator recall breakdown
    /// needs no second pass over the mutation engine.
    pub operator: String,
}

impl MutationLabel {
    /// The same key `Location::handler_id` produces, so a label and a finding
    /// can be matched without either side knowing the other's type.
    pub fn handler_id(&self) -> String {
        format!("{}::{}", self.file.display(), self.handler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Location;

    /// The whole point of the type is that it lines up with a `Finding`'s
    /// location. If either side changes its key format, this goes red.
    #[test]
    fn a_label_and_a_location_agree_on_the_handler_key() {
        let label = MutationLabel {
            id: "abc".into(),
            class: "some-class".into(),
            severity: Severity::High,
            file: PathBuf::from("src/lib.rs"),
            line: 12,
            handler: "withdraw".into(),
            operator: "some_operator".into(),
        };
        let location = Location {
            file: PathBuf::from("src/lib.rs"),
            line: 99, // deliberately different: the key must not read the line
            handler: "withdraw".into(),
        };
        assert_eq!(label.handler_id(), location.handler_id());
    }
}
