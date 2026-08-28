use crate::config::{Format, RunConfig};
use anyhow::Context;
use dike_core::analyzer::{Analyzer, SourceTree};

pub fn run(cfg: RunConfig) -> anyhow::Result<()> {
    let tree = SourceTree::load(&cfg.root)
        .with_context(|| format!("reading {}", cfg.root.display()))?;

    let analysis = dike_lang_anchor::analyze_program(&tree);
    let coverage_extra = (analysis.handlers, analysis.suppressed.len());

    // Phase 6 wires Track 2; until then the LLM slot stays unset rather than
    // fed a placeholder analyzer, so the report's empty Track 2 section
    // means "not run yet", not "ran and found nothing".
    if cfg.llm {
        eprintln!("dike: --llm requested but Track 2 is not wired up yet; running Track 1 only");
    }
    let llm_analyzer: Option<&dyn Analyzer> = None;
    let static_analyzer = dike_lang_anchor::AnchorAnalyzer;
    let report =
        crate::pipeline::run(&tree, &static_analyzer, llm_analyzer, None, None, coverage_extra);

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
