use anyhow::Context;
use dike_core::analyzer::SourceTree;

/// Debug command: parses a program directory and prints its IR as pretty JSON.
pub fn run(path: std::path::PathBuf) -> anyhow::Result<()> {
    let tree = SourceTree::load(&path).with_context(|| format!("reading {}", path.display()))?;
    let outcome = dike_lang_anchor::parser::parse_tree(&tree);
    println!("{}", serde_json::to_string_pretty(&outcome.program)?);
    for d in &outcome.diagnostics {
        eprintln!("warn: {:?} {}", d.kind, d.message);
    }
    Ok(())
}
