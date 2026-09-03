pub mod finding;
pub mod analyzer;
pub mod eval;
pub mod http;
pub mod llm;
pub mod merge;
pub mod report;
pub mod retrieval;

pub use finding::{Citation, Finding, Location, Severity, Track, VulnClass};
pub use analyzer::{
    AnalysisResult, Analyzer, Diagnostic, DiagnosticKind, SourceFile, SourceTree, UnitCoverage,
};
pub use eval::MutationLabel;
pub use report::{Coverage, Report, RunMetadata, TrackFindings};
pub use llm::{LlmClient, LlmError, LlmRequest};
pub use retrieval::{
    chunk_by_finding, corpus_hash, is_grounded, load_manifest, Document, HybridRetriever,
    RetrievalHit, Retrieve, Source, SourceKind,
};
