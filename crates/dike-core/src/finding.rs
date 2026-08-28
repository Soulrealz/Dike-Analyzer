use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Intrinsic to the vulnerability class — never a statement about how sure we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Ranking weights (D2). Pinned — the eval harness compares runs across time.
    pub fn weight(self) -> f32 {
        match self {
            Severity::Critical => 1.0,
            Severity::High => 0.75,
            Severity::Medium => 0.5,
            Severity::Low => 0.25,
            Severity::Info => 0.1,
        }
    }
}

/// A vulnerability class label. Deliberately a string newtype, not an enum:
/// class vocabularies are language-specific and live in the language crates (D6).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VulnClass(String);

impl VulnClass {
    pub fn new(s: impl Into<String>) -> Self {
        VulnClass(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Track {
    Static,
    Llm,
    Corroborated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: u32,
    /// Enclosing instruction handler. The unit at which findings are compared (D5).
    pub handler: String,
}

impl Location {
    pub fn handler_id(&self) -> String {
        format!("{}::{}", self.file.display(), self.handler)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Citation {
    pub doc_id: String,
    pub source_url: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub class: VulnClass,
    pub severity: Severity,
    /// How sure this *instance* is real. Track 1: a per-detector constant.
    /// Track 2: model-reported, clamped and down-weighted (D3).
    pub confidence: f32,
    pub track: Track,
    pub location: Location,
    pub evidence: String,
    pub citations: Vec<Citation>,
}

impl Finding {
    /// Dedupe/corroboration key: handler granularity + class, never the span (D5).
    pub fn merge_key(&self) -> (String, VulnClass) {
        (self.location.handler_id(), self.class.clone())
    }

    pub fn rank_score(&self) -> f32 {
        self.severity.weight() * self.confidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn finding(class: &str, sev: Severity, conf: f32, handler: &str) -> Finding {
        Finding {
            id: String::new(),
            class: VulnClass::new(class),
            severity: sev,
            confidence: conf,
            track: Track::Static,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                handler: handler.to_string(),
            },
            evidence: "evidence".into(),
            citations: vec![],
        }
    }

    #[test]
    fn severity_weights_are_ordered_and_pinned() {
        assert_eq!(Severity::Critical.weight(), 1.0);
        assert_eq!(Severity::High.weight(), 0.75);
        assert_eq!(Severity::Medium.weight(), 0.5);
        assert_eq!(Severity::Low.weight(), 0.25);
        assert_eq!(Severity::Info.weight(), 0.1);
        assert!(Severity::Critical > Severity::Info);
    }

    #[test]
    fn rank_score_is_severity_times_confidence() {
        let f = finding("missing-signer", Severity::High, 0.8, "withdraw");
        assert!((f.rank_score() - 0.6).abs() < 1e-6);
    }

    #[test]
    fn merge_key_is_handler_and_class_not_span() {
        let mut a = finding("missing-signer", Severity::High, 0.9, "withdraw");
        let mut b = finding("missing-signer", Severity::Medium, 0.4, "withdraw");
        b.location.line = 412; // wildly different span, same handler
        a.location.line = 10;
        assert_eq!(a.merge_key(), b.merge_key());
    }

    #[test]
    fn handler_id_joins_file_and_handler() {
        let f = finding("missing-signer", Severity::High, 0.8, "withdraw");
        assert_eq!(f.location.handler_id(), "src/lib.rs::withdraw");
    }
}
