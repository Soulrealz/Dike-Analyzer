//! The eval series: one `EvalSummary` per run, appended to a JSON array.
//!
//! The harness exists to answer "did that change help?", which is a question
//! about two runs, not one. That makes the file itself load-bearing: a run
//! that silently fails to append, or one that overwrites the series, turns
//! every later comparison into a guess.

use super::metrics::EvalSummary;
use anyhow::{bail, Context};
use std::path::Path;

/// Reads `path` as a JSON array, pushes `summary`, and writes it back
/// pretty-printed.
///
/// Refuses a missing file rather than starting a fresh series: the history is
/// committed to the repository, so its absence means a wrong path or a lost
/// file, and silently creating an empty one would erase the comparison the
/// caller was about to make.
///
/// The write goes through a temporary file and a rename, the same way
/// the corpus manifest rewrite does — an interrupted append would otherwise
/// leave a truncated array and destroy every prior run.
pub fn append_history(path: &Path, summary: &EvalSummary) -> anyhow::Result<()> {
    if !path.is_file() {
        bail!(
            "{} does not exist; initialize it to `[]` before recording a run",
            path.display()
        );
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut runs: Vec<serde_json::Value> = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a JSON array of runs", path.display()))?;

    runs.push(serde_json::to_value(summary)?);
    let rendered = serde_json::to_string_pretty(&runs)? + "\n";

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&temp, rendered).with_context(|| format!("writing {}", temp.display()))?;
    std::fs::rename(&temp, path)
        .with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Every run in the series, oldest first.
pub fn read_history(path: &Path) -> anyhow::Result<Vec<EvalSummary>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}
