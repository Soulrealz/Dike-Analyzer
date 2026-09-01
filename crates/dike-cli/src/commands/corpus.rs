//! The `dike corpus` subcommands.
//!
//! - `fetch` pulls every source in `corpus/sources.toml` into `corpus/cache`.
//! - `index` builds the hybrid retrieval index from the cached text.
//! - `query` searches it and reports whether the result is grounded.
//! - `hash` prints the corpus hash that goes into a report's metadata.
//!
//! `index` and `query` are the only commands in this project that need a
//! live embedding model. Each one's work is split into an inner function
//! taking explicit paths and a `Box<dyn Embedder>`, so the wiring is
//! testable against a stub with nothing running; the public wrappers supply
//! the repo paths and an `OllamaEmbedder`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use dike_core::http::HttpClient;
use dike_core::retrieval::{
    corpus_hash, fetch_source, is_grounded, load_cached, load_manifest, Document, Embedder,
    FetchOutcome, HybridRetriever, OllamaEmbedder, Retrieve,
};

pub const MANIFEST_PATH: &str = "corpus/sources.toml";
pub const CACHE_DIR: &str = "corpus/cache";
pub const INDEX_DIR: &str = "corpus/index";
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Default Ollama host. A default, never a constant baked into the library:
/// `OllamaEmbedder` takes host and model as parameters (D26), and this is
/// the one place a default lives.
pub const DEFAULT_OLLAMA_HOST: &str = "http://localhost:11434";
/// Default embedding model: BGE-small-en v1.5, the model the user chose.
///
/// The bare name `bge-small-en-v1.5` is NOT resolvable — it is a Hugging
/// Face model with no entry in Ollama's own library, so `ollama pull
/// bge-small-en-v1.5` fails with "file does not exist". The `hf.co/...`
/// form is how Ollama pulls it, and it is the string the vector store
/// records as the index's model, so it must match exactly or a later query
/// is refused as a mismatch.
pub const DEFAULT_EMBED_MODEL: &str = "hf.co/CompendiumLabs/bge-small-en-v1.5-gguf";

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
            FetchOutcome::Changed { old, new, old_bytes, new_bytes } => {
                println!(
                    "CHANGED   {} (recorded {old}, fetched {new}, {})",
                    source.id,
                    describe_size_change(old_bytes, new_bytes)
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

/// Describe a cached source's size change in words.
///
/// A living corpus repository is *expected* to change between fetches —
/// that is the point of re-fetching. What needs a human is the change that
/// went the wrong way: a source that lost most of its text usually means
/// the fetch captured an error page, not that the maintainers deleted their
/// findings.
fn describe_size_change(old_bytes: usize, new_bytes: usize) -> String {
    match old_bytes {
        0 => format!("{new_bytes} bytes, nothing cached before"),
        old if new_bytes > old => format!("grew {} bytes", new_bytes - old),
        old if new_bytes == old => "same size, different content".to_string(),
        old => format!(
            "SHRANK {} bytes — check the fetch before accepting it",
            old - new_bytes
        ),
    }
}

/// Load the cached corpus named by the manifest.
///
/// An empty corpus is an error rather than an empty index: every later
/// command would otherwise succeed while silently retrieving nothing.
fn load_corpus(manifest_path: &Path, cache_dir: &Path) -> anyhow::Result<Vec<Document>> {
    let sources = load_manifest(manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let docs = load_cached(&sources, cache_dir)
        .with_context(|| format!("reading cached corpus from {}", cache_dir.display()))?;
    if docs.is_empty() {
        anyhow::bail!(
            "no cached corpus in {} — run `dike corpus fetch` first",
            cache_dir.display()
        );
    }
    Ok(docs)
}

/// Run `dike corpus index`.
pub fn index(rebuild: bool, embed_model: &str, ollama_host: &str) -> anyhow::Result<()> {
    let embedder = OllamaEmbedder::new(ollama_host, embed_model)
        .map_err(|e| anyhow::anyhow!("building the embedder: {e}"))?;
    let summary = index_at(
        Path::new(INDEX_DIR),
        Path::new(MANIFEST_PATH),
        Path::new(CACHE_DIR),
        rebuild,
        Box::new(embedder),
    )?;
    println!("{summary}");
    Ok(())
}

/// Build the index at `index_dir` and return the line to print.
///
/// `--rebuild` deletes the index directory first. Without it a build still
/// replaces every document it is given, but IDs that have since left the
/// corpus survive in the vector store — `rebuild` is how those go away.
fn index_at(
    index_dir: &Path,
    manifest_path: &Path,
    cache_dir: &Path,
    rebuild: bool,
    embedder: Box<dyn Embedder>,
) -> anyhow::Result<String> {
    let docs = load_corpus(manifest_path, cache_dir)?;
    if rebuild && index_dir.exists() {
        std::fs::remove_dir_all(index_dir)
            .with_context(|| format!("removing {}", index_dir.display()))?;
    }
    let model = embedder.model_name();
    let retriever = HybridRetriever::build(index_dir, &docs, embedder)?;
    Ok(format!(
        "indexed {} document(s) into {} (embedding model: {}, corpus hash: {})",
        docs.len(),
        index_dir.display(),
        model,
        retriever.corpus_hash()
    ))
}

/// Run `dike corpus query`.
pub fn query(text: &str, top_k: usize, embed_model: &str, ollama_host: &str) -> anyhow::Result<()> {
    let embedder = OllamaEmbedder::new(ollama_host, embed_model)
        .map_err(|e| anyhow::anyhow!("building the embedder: {e}"))?;
    let rendered = query_at(
        Path::new(INDEX_DIR),
        Path::new(MANIFEST_PATH),
        Path::new(CACHE_DIR),
        text,
        top_k,
        Box::new(embedder),
    )?;
    print!("{rendered}");
    Ok(())
}

/// Search the index and render the result.
///
/// Scores are printed at fixed precision so two runs over one corpus are
/// diffable (Rule 5). A leg that did not return a document prints `-`, which
/// is how a sparse-only run — the embedder being down — is visible rather
/// than looking like a corpus with nothing in it.
fn query_at(
    index_dir: &Path,
    manifest_path: &Path,
    cache_dir: &Path,
    text: &str,
    top_k: usize,
    embedder: Box<dyn Embedder>,
) -> anyhow::Result<String> {
    let docs = load_corpus(manifest_path, cache_dir)?;
    if !index_dir.exists() {
        anyhow::bail!(
            "no index at {} — run `dike corpus index` first",
            index_dir.display()
        );
    }
    let retriever = HybridRetriever::open(index_dir, docs, embedder)?;
    let hits = retriever.search(text, top_k)?;

    let mut out = String::new();
    for hit in &hits {
        out.push_str(&format!(
            "{:.4}  {}  {}  dense={} bm25={}\n",
            hit.rrf_score,
            hit.document.id,
            hit.document.title,
            render_score(hit.dense_score),
            render_score(hit.bm25_score),
        ));
    }
    if hits.is_empty() {
        out.push_str("no hits\n");
    }
    out.push_str(&format!("grounded: {}\n", is_grounded(&hits)));
    Ok(out)
}

fn render_score(score: Option<f32>) -> String {
    match score {
        Some(s) => format!("{s:.4}"),
        None => "-".to_string(),
    }
}

/// Run `dike corpus hash`: print the corpus hash for embedding in reports.
pub fn hash() -> anyhow::Result<()> {
    let docs = load_corpus(Path::new(MANIFEST_PATH), Path::new(CACHE_DIR))?;
    println!("{}", corpus_hash(&docs));
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
    let tmp_path = tmp_path_for(path)?;

    std::fs::write(&tmp_path, contents)
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} to {}", tmp_path.display(), path.display()))?;
    Ok(())
}

/// Compute the temp-file path [`write_atomically`] writes to before
/// renaming over `path`. Pulled out as its own function so the
/// same-directory invariant it must hold — a `rename` across filesystems is
/// not atomic and fails at runtime — can be tested directly rather than
/// only inferred from reading the rename call.
fn tmp_path_for(path: &Path) -> anyhow::Result<PathBuf> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    Ok(dir.join(tmp_name))
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
    use dike_core::http::HttpError;

    /// A deterministic bag-of-words hashing embedder: no network, no model,
    /// but real cosines, so a dense-leg assertion means something.
    struct StubEmbedder;

    impl Embedder for StubEmbedder {
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, HttpError> {
            Ok(texts
                .iter()
                .map(|t| {
                    let mut v = vec![0.0f32; 32];
                    for word in t.split(|c: char| !c.is_alphanumeric() && c != '_') {
                        if word.is_empty() {
                            continue;
                        }
                        let bucket = word
                            .to_lowercase()
                            .bytes()
                            .fold(7u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
                        v[(bucket as usize) % 32] += 1.0;
                    }
                    v
                })
                .collect())
        }
        fn model_name(&self) -> String {
            "stub-hashing-32".to_string()
        }
    }

    /// Stands in for "the embedding model is not running".
    struct DeadEmbedder;

    impl Embedder for DeadEmbedder {
        fn embed(&self, _texts: &[String]) -> Result<Vec<Vec<f32>>, HttpError> {
            Err(HttpError::Unavailable("connection refused".into()))
        }
        fn model_name(&self) -> String {
            "dead".to_string()
        }
    }

    /// A manifest plus a cache directory, entirely inside a tempdir. Nothing
    /// here touches the repo's real corpus or the network.
    fn corpus_fixture(entries: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("sources.toml");
        let cache = dir.path().join("cache");
        let index = dir.path().join("index");
        std::fs::create_dir_all(&cache).unwrap();

        let mut toml = String::new();
        for (id, text) in entries {
            toml.push_str(&format!(
                "[[source]]\nid = \"{id}\"\nkind = \"page\"\nurl = \"https://example.invalid/{id}\"\ntitle = \"{id}\"\nlicense = \"L\"\nretrieved = \"2026-01-01\"\nsha256 = \"\"\nclass_tags = []\n\n"
            ));
            std::fs::write(cache.join(format!("{id}.txt")), text).unwrap();
        }
        std::fs::write(&manifest, toml).unwrap();
        (dir, manifest, cache, index)
    }

    #[test]
    fn index_at_reports_the_document_count_and_the_corpus_hash() {
        let (_d, manifest, cache, index) = corpus_fixture(&[
            ("alpha", "# Missing owner validation\nThe handler never checks the owner."),
            ("beta", "# Unchecked arithmetic\nThe balance wraps on overflow."),
        ]);
        let summary =
            index_at(&index, &manifest, &cache, false, Box::new(StubEmbedder)).unwrap();
        let docs = load_corpus(&manifest, &cache).unwrap();
        assert!(summary.contains(&format!("indexed {} document(s)", docs.len())), "{summary}");
        assert!(summary.contains(&corpus_hash(&docs)), "{summary}");
        assert!(summary.contains("stub-hashing-32"), "{summary}");
    }

    #[test]
    fn index_at_refuses_an_empty_cache_with_an_actionable_message() {
        // A manifest listing a source whose text was never fetched: this is
        // the state a fresh clone is in, and indexing nothing would leave
        // every later command succeeding while retrieving nothing.
        let (_d, manifest, cache, index) =
            corpus_fixture(&[("alpha", "# Missing owner validation\nno owner check")]);
        std::fs::remove_file(cache.join("alpha.txt")).unwrap();
        let err = index_at(&index, &manifest, &cache, false, Box::new(StubEmbedder)).unwrap_err();
        assert!(
            format!("{err:#}").contains("dike corpus fetch"),
            "the error must say what to run: {err:#}"
        );
    }

    #[test]
    fn index_at_survives_a_dead_embedder_so_the_corpus_is_still_searchable() {
        let (_d, manifest, cache, index) =
            corpus_fixture(&[("alpha", "# Missing owner validation\nno owner check")]);
        index_at(&index, &manifest, &cache, false, Box::new(DeadEmbedder)).unwrap();
        let out = query_at(&index, &manifest, &cache, "owner", 5, Box::new(DeadEmbedder)).unwrap();
        assert!(out.contains("dense=-"), "a missing dense leg is visible: {out}");
        assert!(out.contains("grounded: true"), "BM25 alone still grounds: {out}");
    }

    #[test]
    fn query_at_renders_a_score_line_per_hit_and_a_grounded_line() {
        // Renders shape, not verdict: whether a stub embedder's cosines
        // clear DENSE_GROUNDING_THRESHOLD is a property of the stub, and
        // asserting `grounded: true` here would make a recalibration of the
        // real threshold fail a rendering test. The gate itself is covered
        // in `retrieval::rrf`.
        let (_d, manifest, cache, index) = corpus_fixture(&[
            ("alpha", "# Missing owner validation\nThe handler never checks the owner."),
            ("beta", "# Unchecked arithmetic\nThe balance wraps on overflow."),
        ]);
        index_at(&index, &manifest, &cache, false, Box::new(StubEmbedder)).unwrap();
        let out =
            query_at(&index, &manifest, &cache, "owner", 5, Box::new(StubEmbedder)).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.len() >= 2, "{out}");
        assert!(lines[0].contains("dense=") && lines[0].contains("bm25="), "{out}");
        let last = lines.last().copied().unwrap();
        assert!(
            last == "grounded: true" || last == "grounded: false",
            "the last line must be the grounding verdict, got: {out}"
        );
    }

    #[test]
    fn query_at_says_no_hits_rather_than_printing_only_a_grounded_line() {
        let (_d, manifest, cache, index) =
            corpus_fixture(&[("alpha", "# Missing owner validation\nno owner check")]);
        index_at(&index, &manifest, &cache, false, Box::new(StubEmbedder)).unwrap();
        // A dead embedder skips the dense leg, and a term in no document
        // returns nothing from BM25 either.
        let out = query_at(
            &index,
            &manifest,
            &cache,
            "zzzznotinanydocument",
            5,
            Box::new(DeadEmbedder),
        )
        .unwrap();
        assert!(out.contains("no hits"), "{out}");
        assert!(out.contains("grounded: false"), "{out}");
    }

    #[test]
    fn query_at_reports_a_missing_index_rather_than_failing_obscurely() {
        let (_d, manifest, cache, index) =
            corpus_fixture(&[("alpha", "# Missing owner validation\nno owner check")]);
        let err =
            query_at(&index, &manifest, &cache, "owner", 5, Box::new(StubEmbedder)).unwrap_err();
        assert!(
            err.to_string().contains("dike corpus index"),
            "the error must say what to run: {err}"
        );
    }

    #[test]
    fn rebuild_drops_vectors_for_documents_that_have_left_the_corpus() {
        // Observed in the store, not through `query`: a query cannot see a
        // stale row anyway, because hydration drops IDs the corpus no longer
        // has. That makes a query-level assertion here pass with or without
        // the flag -- it would prove hydration, not `--rebuild`. What the
        // flag actually governs is whether the row survives on disk.
        let (_d, manifest, cache, index) = corpus_fixture(&[
            ("alpha", "# Missing owner validation\nThe handler never checks the owner."),
            ("beta", "# Stale document\nzzzuniquetoken appears only here."),
        ]);
        index_at(&index, &manifest, &cache, false, Box::new(StubEmbedder)).unwrap();
        let store_path = index.join("vectors.db");
        assert_eq!(
            dike_core::retrieval::VectorStore::open(&store_path).unwrap().len().unwrap(),
            2
        );

        // "beta" leaves the corpus. Re-indexing without `--rebuild` leaves
        // its vector behind...
        std::fs::remove_file(cache.join("beta.txt")).unwrap();
        index_at(&index, &manifest, &cache, false, Box::new(StubEmbedder)).unwrap();
        assert_eq!(
            dike_core::retrieval::VectorStore::open(&store_path).unwrap().len().unwrap(),
            2,
            "without --rebuild the stale vector survives"
        );

        // ...and with it, the store is rebuilt from the corpus alone.
        index_at(&index, &manifest, &cache, true, Box::new(StubEmbedder)).unwrap();
        assert_eq!(
            dike_core::retrieval::VectorStore::open(&store_path).unwrap().len().unwrap(),
            1,
            "--rebuild must drop the vector whose document is gone"
        );
    }

    #[test]
    fn query_output_is_byte_identical_across_runs() {
        // Rule 5: the same corpus and the same query must be diffable.
        let (_d, manifest, cache, index) = corpus_fixture(&[
            ("alpha", "# Missing owner validation\nThe handler never checks the owner."),
            ("beta", "# Unchecked arithmetic\nThe balance wraps on overflow."),
        ]);
        index_at(&index, &manifest, &cache, false, Box::new(StubEmbedder)).unwrap();
        let first =
            query_at(&index, &manifest, &cache, "owner", 5, Box::new(StubEmbedder)).unwrap();
        for _ in 0..3 {
            let again =
                query_at(&index, &manifest, &cache, "owner", 5, Box::new(StubEmbedder)).unwrap();
            assert_eq!(first, again);
        }
    }

    #[test]
    fn a_missing_score_renders_as_a_dash_not_as_zero() {
        // `dense=0.0000` would read as "the model scored this zero", which
        // is a different claim from "the dense leg did not run".
        assert_eq!(render_score(None), "-");
        assert_eq!(render_score(Some(0.0)), "0.0000");
    }

    /// The repo's real manifest. Lives in this crate, not in `dike-core`:
    /// asserting on a source *by name* means naming Solana-specific
    /// vocabulary, which `dike-core/tests/seam.rs` rejects in string
    /// literals as well as identifiers. The CLI is where the two worlds
    /// meet, so this is the right side of the seam for it.
    fn real_manifest() -> Vec<dike_core::retrieval::Source> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(MANIFEST_PATH);
        load_manifest(&path).unwrap()
    }

    #[test]
    fn the_large_repository_sources_are_path_filtered() {
        // Both were added specifically because they are big general-purpose
        // repositories whose Markdown is mostly not corpus material: an
        // unfiltered entry would quietly pull in READMEs and changelogs,
        // and every other manifest test would still pass.
        for id in ["solana-security-standard", "solana-audit-taxonomy"] {
            let s = real_manifest()
                .into_iter()
                .find(|s| s.id == id)
                .unwrap_or_else(|| panic!("{id} missing from the manifest"));
            assert!(!s.include_paths.is_empty(), "{id} must be path-filtered");
        }
    }

    #[test]
    fn a_size_drop_between_fetches_is_called_out_and_growth_is_not() {
        // A living corpus repository is expected to grow between fetches.
        // The change that needs a human is the one that went backwards.
        assert!(describe_size_change(1000, 1200).contains("grew"));
        assert!(describe_size_change(1000, 400).contains("SHRANK"));
        assert!(describe_size_change(0, 400).contains("nothing cached before"));
        assert!(describe_size_change(1000, 1000).contains("same size"));
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        // Not the bare `bge-small-en-v1.5`: that name does not resolve on
        // Ollama, and a default that cannot be pulled makes `dike corpus
        // index` fail out of the box.
        assert_eq!(
            DEFAULT_EMBED_MODEL,
            "hf.co/CompendiumLabs/bge-small-en-v1.5-gguf"
        );
        assert_eq!(DEFAULT_OLLAMA_HOST, "http://localhost:11434");
    }


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

    // Scope note (round 2, item 2): `rewrite_leaves_no_temp_file_behind`
    // below only proves cleanup — it passes just as well against a naive
    // `std::fs::write(path, contents)`, which never creates a temp file in
    // the first place, so "no debris left over" is true either way and
    // does not exercise atomicity at all. Genuinely proving atomicity (that
    // a crash mid-write can never leave `path` truncated) needs fault
    // injection — killing the process between the write and the rename —
    // which isn't practical to do in-process from a `#[test]`. What *is*
    // practical and is tested here instead is the precondition atomicity
    // depends on: the temp file must land in the same directory (therefore
    // the same filesystem) as the target, since `rename` is only atomic
    // within one filesystem and a naive implementation using, say,
    // `std::env::temp_dir()` for the temp file would compile fine, pass a
    // "no debris" check, and then fail (or silently stop being atomic) at
    // runtime the first time `corpus/` and the OS temp dir are on
    // different filesystems.
    #[test]
    fn rewrite_leaves_no_temp_file_behind() {
        let (dir, path) = fixture_copy();
        let mut new_hashes = HashMap::new();
        new_hashes.insert("alpha".to_string(), "fresh-hash".to_string());

        rewrite_manifest_hashes(&path, &new_hashes).unwrap();

        // Only the manifest itself remains in the directory; the temp file
        // used for the write-then-rename was cleaned up by the rename
        // (which moves, not copies). This alone does not distinguish an
        // atomic write from `std::fs::write` — see the scope note above.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("sources.toml")], "got: {entries:?}");
    }

    #[test]
    fn write_atomically_places_its_temp_file_in_the_same_directory_as_the_target() {
        // A rename is only atomic within a single filesystem, so the temp
        // path must share a parent directory with the target. This is the
        // property a naive "write the temp file to the OS temp dir, then
        // rename into place" implementation would violate — it would still
        // leave no debris (the rename would either succeed by copying, on
        // some platforms, or fail outright), but it would not be a same-
        // filesystem atomic rename.
        let (_dir, path) = fixture_copy();
        let tmp_path = tmp_path_for(&path).unwrap();

        assert_eq!(
            tmp_path.parent(),
            path.parent(),
            "temp file must be in the same directory as the target for rename to be atomic"
        );
        assert_ne!(tmp_path, path, "temp file must not collide with the target path");
    }
}
