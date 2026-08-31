//! Retrieval corpus: document model, manifest loading, chunking, and hashing.
//!
//! This module builds the offline corpus of vulnerability write-ups used by
//! the retrieval-grounded track. It knows nothing about any particular
//! blockchain or smart-contract framework — it operates on plain text,
//! headings, and finding-ID-shaped boundaries.

pub mod bm25;
pub mod dense;
pub mod document;
pub mod fetch;
pub mod store;

pub use bm25::Bm25Index;
pub use dense::{Embedder, OllamaEmbedder};
pub use document::{chunk_by_finding, corpus_hash, load_manifest, Document, Source, SourceKind};
pub use fetch::{extract_archive, fetch_source, html_to_text, load_cached, FetchOutcome};
pub use store::{StoreError, VectorStore};
