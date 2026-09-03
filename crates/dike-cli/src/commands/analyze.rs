use crate::config::{Format, RunConfig};
use anyhow::Context;
use dike_core::analyzer::{Analyzer, SourceTree};
use dike_core::llm::OllamaClient;
use dike_core::retrieval::{load_cached, load_manifest, HybridRetriever, OllamaEmbedder};
use dike_lang_anchor::llm_analyzer::LlmAnalyzer;

/// Build Track 2, or explain why it is not running.
///
/// Every failure here is a *degraded* run, never a tool failure: a missing
/// index or an unbuildable client still leaves a complete Track 1 report, and
/// exiting non-zero would contradict Rule 4.
pub(crate) fn build_llm_analyzer(cfg: &RunConfig) -> Option<LlmAnalyzer> {
    if !cfg.index_dir.exists() {
        eprintln!(
            "dike: no corpus index at {}; run `dike corpus index` first. Running Track 1 only.",
            cfg.index_dir.display()
        );
        return None;
    }
    let sources = match load_manifest(std::path::Path::new(crate::commands::corpus::MANIFEST_PATH))
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("dike: corpus manifest unreadable ({e:#}); running Track 1 only.");
            return None;
        }
    };
    let docs = match load_cached(&sources, std::path::Path::new(crate::commands::corpus::CACHE_DIR))
    {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => {
            eprintln!("dike: corpus cache is empty; run `dike corpus fetch`. Running Track 1 only.");
            return None;
        }
        Err(e) => {
            eprintln!("dike: corpus cache unreadable ({e:#}); running Track 1 only.");
            return None;
        }
    };
    let embedder = match OllamaEmbedder::new(&cfg.ollama_host, &cfg.embed_model) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("dike: could not build the embedder ({e}); running Track 1 only.");
            return None;
        }
    };
    let retriever = match HybridRetriever::open(&cfg.index_dir, docs, Box::new(embedder)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dike: could not open the corpus index ({e:#}); running Track 1 only.");
            return None;
        }
    };
    let client = match OllamaClient::new(&cfg.ollama_host, &cfg.model) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dike: could not build the model client ({e}); running Track 1 only.");
            return None;
        }
    };
    Some(LlmAnalyzer::new(
        Box::new(client),
        Box::new(retriever),
        cfg.top_k,
    ))
}

pub fn run(cfg: RunConfig) -> anyhow::Result<()> {
    let tree = SourceTree::load(&cfg.root)
        .with_context(|| format!("reading {}", cfg.root.display()))?;

    let analysis = dike_lang_anchor::analyze_program(&tree);
    let coverage_extra = (analysis.handlers, analysis.suppressed.len());

    let llm = if cfg.llm { build_llm_analyzer(&cfg) } else { None };
    // Recorded whenever Track 2 was *configured*, which is not the same as
    // "it answered": an unreachable model still leaves its name here, and
    // the `TrackSkipped` diagnostic plus `units examined: 0/N` is what tells
    // a reader it never ran. A Track-1-only run records neither, so an empty
    // Track 2 section with no model named means "not attempted".
    let (model, corpus_hash) = match &llm {
        Some(a) => (Some(a.client.name()), Some(a.retriever.corpus_hash())),
        None => (None, None),
    };
    let llm_analyzer: Option<&dyn Analyzer> = llm.as_ref().map(|a| a as &dyn Analyzer);
    let static_analyzer = dike_lang_anchor::AnchorAnalyzer;
    let report = crate::pipeline::run(
        &tree,
        &static_analyzer,
        llm_analyzer,
        model,
        corpus_hash,
        coverage_extra,
    );

    let rendered = match cfg.format {
        Format::Md => report.render_markdown(),
        Format::Json => report.render_json()?,
    };
    match cfg.out {
        Some(path) => std::fs::write(&path, rendered)
            .with_context(|| format!("writing {}", path.display()))?,
        None => println!("{rendered}"),
    }
    Ok(()) // exit 0 even with findings — triage, not a gate
}
