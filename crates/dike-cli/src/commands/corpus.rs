//! `dike corpus fetch`: pull every source in `corpus/sources.toml` into
//! `corpus/cache`, reporting per-source status and a summary.
//!
//! `index` and `query` (BM25 search over the fetched corpus) and `hash`
//! (print the corpus hash) land in Task 18 — this file is deliberately
//! fetch-only for now.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use dike_core::http::HttpClient;
use dike_core::retrieval::{fetch_source, load_manifest, FetchOutcome};

const MANIFEST_PATH: &str = "corpus/sources.toml";
const CACHE_DIR: &str = "corpus/cache";
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Run `dike corpus fetch [--update-hashes] [--verify]`.
pub fn fetch(update_hashes: bool, verify: bool) -> anyhow::Result<()> {
    let manifest_path = PathBuf::from(MANIFEST_PATH);
    let cache_dir = PathBuf::from(CACHE_DIR);

    let mut sources = load_manifest(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let http = HttpClient::new(FETCH_TIMEOUT)
        .map_err(|e| anyhow::anyhow!("building HTTP client: {e}"))?;

    let mut fetched = 0usize;
    let mut unchanged = 0usize;
    let mut changed = 0usize;
    let mut new_hashes: HashMap<String, String> = HashMap::new();

    for source in &mut sources {
        let outcome = fetch_source(&http, source, &cache_dir)
            .with_context(|| format!("fetching source {}", source.id))?;
        match outcome {
            FetchOutcome::Fetched { hash } => {
                println!("fetched   {}", source.id);
                fetched += 1;
                new_hashes.insert(source.id.clone(), hash);
            }
            FetchOutcome::Unchanged => {
                println!("unchanged {}", source.id);
                unchanged += 1;
            }
            FetchOutcome::Changed { old, new } => {
                println!(
                    "CHANGED   {} (recorded {old}, fetched {new})",
                    source.id
                );
                changed += 1;
                new_hashes.insert(source.id.clone(), new);
            }
        }
    }

    println!(
        "summary: {} source(s): {fetched} fetched, {unchanged} unchanged, {changed} changed",
        sources.len()
    );

    if update_hashes && !new_hashes.is_empty() {
        rewrite_manifest_hashes(&manifest_path, &new_hashes)
            .with_context(|| format!("updating {}", manifest_path.display()))?;
    }

    if verify && changed > 0 {
        anyhow::bail!(
            "corpus verify failed: {changed} source(s) changed since sources.toml was last hashed"
        );
    }

    Ok(())
}

/// Rewrite `sha256` and `retrieved` for the sources named in `new_hashes`,
/// in place, leaving every other line (including the commented-out entries
/// and their explanatory prose) untouched. A full TOML round-trip through
/// `toml::to_string` would drop those comments, which is why this walks the
/// file as text instead.
fn rewrite_manifest_hashes(path: &Path, new_hashes: &HashMap<String, String>) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    let mut out = String::with_capacity(text.len());
    let mut current_id: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let mut wrote = false;
        if !trimmed.starts_with('#') {
            if let Some(rest) = trimmed.strip_prefix("id") {
                if let Some(id) = parse_toml_string_assignment(rest) {
                    current_id = Some(id);
                }
            } else if let Some(rest) = trimmed.strip_prefix("sha256") {
                if parse_toml_string_assignment(rest).is_some() {
                    if let Some(hash) = current_id.as_ref().and_then(|id| new_hashes.get(id)) {
                        out.push_str(&format!("sha256 = \"{hash}\"\n"));
                        wrote = true;
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("retrieved") {
                if parse_toml_string_assignment(rest).is_some()
                    && current_id
                        .as_ref()
                        .is_some_and(|id| new_hashes.contains_key(id))
                {
                    out.push_str(&format!("retrieved = \"{today}\"\n"));
                    wrote = true;
                }
            }
        }
        if !wrote {
            out.push_str(line);
            out.push('\n');
        }
    }

    write_atomically(path, &out)
}

/// Write `contents` to `path` atomically: write to a temp file in the same
/// directory, then `rename` over the original. `std::fs::write` truncates
/// the target before writing, so a crash mid-write would otherwise leave a
/// truncated `corpus/sources.toml` — a committed file the user owns. A
/// rename within the same directory (and therefore the same filesystem) is
/// atomic, so readers only ever see the old or the new content, never a
/// partial write.
fn write_atomically(path: &Path, contents: &str) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp_path = dir.join(tmp_name);

    std::fs::write(&tmp_path, contents)
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} to {}", tmp_path.display(), path.display()))?;
    Ok(())
}

/// Given the text after a bare TOML key (e.g. `" = \"sealevel-attacks\""`),
/// return the quoted string value if this really is a `key = "value"` line.
fn parse_toml_string_assignment(after_key: &str) -> Option<String> {
    let rest = after_key.trim_start().strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // A manifest fixture, NEVER the repo's real `corpus/sources.toml`.
    // Deliberately gives "alpha" and "beta" the *same* `sha256` value so a
    // rewrite scoped incorrectly (by value instead of by the preceding
    // `id = "..."` line) would be caught: updating "alpha" must not also
    // touch "beta" just because their hashes matched.
    // Also includes a commented-out third entry, sharing that same
    // duplicate hash and an `id` that collides with "alpha", to prove
    // commented-out `sha256`/`retrieved` lines are never rewritten
    // regardless of what `id` precedes them.
    const FIXTURE: &str = r#"[[source]]
id = "alpha"
kind = "page"
url = "https://example.invalid/a"
title = "Alpha"
license = "L"
retrieved = "2026-01-01"
sha256 = "dupe-hash"
class_tags = []

[[source]]
id = "beta"
kind = "page"
url = "https://example.invalid/b"
title = "Beta"
license = "L"
retrieved = "2026-01-01"
sha256 = "dupe-hash"
class_tags = []

# Commented out pending curation; do not touch on rewrite.
# [[source]]
# id = "alpha"
# kind = "page"
# url = "https://example.invalid/commented"
# title = "Commented"
# license = "L"
# retrieved = "2026-01-01"
# sha256 = "dupe-hash"
# class_tags = []
"#;

    /// Write `FIXTURE` into a fresh tempdir and return `(dir, path)` so the
    /// tempdir isn't dropped (and deleted) while `path` is still in use.
    fn fixture_copy() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sources.toml");
        std::fs::write(&path, FIXTURE).unwrap();
        (dir, path)
    }

    #[test]
    fn rewrite_updates_only_the_id_scoped_source() {
        let (_dir, path) = fixture_copy();
        let mut new_hashes = HashMap::new();
        new_hashes.insert("alpha".to_string(), "fresh-hash".to_string());

        rewrite_manifest_hashes(&path, &new_hashes).unwrap();
        let out = std::fs::read_to_string(&path).unwrap();

        // alpha's sha256 was updated...
        assert!(out.contains("sha256 = \"fresh-hash\""), "got:\n{out}");
        // ...and beta's untouched duplicate-hash entry survives unchanged,
        // proving the rewrite is scoped by the preceding `id`, not by
        // matching the hash value itself.
        let beta_block = out.split("id = \"beta\"").nth(1).unwrap();
        let beta_sha_line = beta_block.lines().find(|l| l.trim_start().starts_with("sha256")).unwrap();
        assert_eq!(beta_sha_line.trim(), "sha256 = \"dupe-hash\"", "got:\n{out}");
    }

    #[test]
    fn rewrite_bumps_retrieved_only_for_updated_sources() {
        let (_dir, path) = fixture_copy();
        let mut new_hashes = HashMap::new();
        new_hashes.insert("alpha".to_string(), "fresh-hash".to_string());

        rewrite_manifest_hashes(&path, &new_hashes).unwrap();
        let out = std::fs::read_to_string(&path).unwrap();

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let alpha_block = out.split("id = \"alpha\"").nth(1).unwrap();
        let alpha_retrieved = alpha_block
            .lines()
            .find(|l| l.trim_start().starts_with("retrieved"))
            .unwrap();
        assert_eq!(alpha_retrieved.trim(), format!("retrieved = \"{today}\""), "got:\n{out}");

        let beta_block = out.split("id = \"beta\"").nth(1).unwrap();
        let beta_retrieved = beta_block
            .lines()
            .find(|l| l.trim_start().starts_with("retrieved"))
            .unwrap();
        assert_eq!(beta_retrieved.trim(), "retrieved = \"2026-01-01\"", "got:\n{out}");
    }

    #[test]
    fn rewrite_never_touches_commented_out_entries() {
        let (_dir, path) = fixture_copy();
        let mut new_hashes = HashMap::new();
        // "alpha" also names the commented-out entry's id; if scoping were
        // done by id text alone (ignoring the leading '#'), this would
        // wrongly rewrite the commented block too.
        new_hashes.insert("alpha".to_string(), "fresh-hash".to_string());

        rewrite_manifest_hashes(&path, &new_hashes).unwrap();
        let out = std::fs::read_to_string(&path).unwrap();

        assert!(
            out.contains("# sha256 = \"dupe-hash\""),
            "commented-out sha256 line must be untouched, got:\n{out}"
        );
        assert!(
            out.contains("# retrieved = \"2026-01-01\""),
            "commented-out retrieved line must be untouched, got:\n{out}"
        );
    }

    #[test]
    fn rewrite_preserves_comments_and_untouched_lines_verbatim() {
        let (_dir, path) = fixture_copy();
        let mut new_hashes = HashMap::new();
        new_hashes.insert("alpha".to_string(), "fresh-hash".to_string());

        rewrite_manifest_hashes(&path, &new_hashes).unwrap();
        let out = std::fs::read_to_string(&path).unwrap();

        assert!(out.contains("# Commented out pending curation; do not touch on rewrite."));
        assert!(out.contains("url = \"https://example.invalid/a\""));
        assert!(out.contains("class_tags = []"));
    }

    #[test]
    fn rewrite_is_atomic_and_leaves_no_temp_file_behind() {
        let (dir, path) = fixture_copy();
        let mut new_hashes = HashMap::new();
        new_hashes.insert("alpha".to_string(), "fresh-hash".to_string());

        rewrite_manifest_hashes(&path, &new_hashes).unwrap();

        // Only the manifest itself remains in the directory; the temp file
        // used for the atomic write-then-rename was cleaned up by the
        // rename (which moves, not copies).
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("sources.toml")], "got: {entries:?}");
    }
}
