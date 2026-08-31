//! Corpus document model: sources, chunked documents, manifest loading,
//! chunking, and content hashing.

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The five vulnerability class tags a chunk's text may be tagged with,
/// beyond whatever tags it inherits from its [`Source`].
const CLASS_TAGS: [&str; 5] = [
    "missing-signer",
    "missing-owner-check",
    "missing-authority-binding",
    "pda-validation-gap",
    "unchecked-arithmetic",
];

/// How a [`Source`] was (or will be) fetched.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// A single fetched HTML page.
    #[default]
    Page,
    /// A downloaded archive (e.g. a tarball) containing multiple documents.
    Archive,
    /// Content that already lives in the repository (no network fetch).
    Local,
}

/// One entry in the corpus manifest (`corpus/sources.toml`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub url: String,
    pub title: String,
    pub license: String,
    pub retrieved: String,
    pub sha256: String,
    pub class_tags: Vec<String>,
    #[serde(default)]
    pub kind: SourceKind,
    /// For `Archive` sources: keep only entries under these paths, relative
    /// to the archive's top-level directory (a codeload tarball wraps
    /// everything in `<repo>-<ref>/`). Empty means keep everything, which
    /// is what a small single-purpose repository wants.
    ///
    /// This exists because a large repository's `.md` files are mostly not
    /// corpus material — a README, a changelog and issue templates would
    /// otherwise be indexed, embedded and cited alongside the rules.
    #[serde(default)]
    pub include_paths: Vec<String>,
}

/// A retrievable chunk of text derived from a [`Source`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub source_url: String,
    pub title: String,
    pub text: String,
    pub class_tags: Vec<String>,
}

/// The on-disk shape of `corpus/sources.toml`.
#[derive(Debug, Deserialize)]
struct Manifest {
    source: Vec<Source>,
}

/// Load and deserialize the corpus manifest at `path`.
pub fn load_manifest(path: &Path) -> anyhow::Result<Vec<Source>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading corpus manifest {}", path.display()))?;
    let manifest: Manifest = toml::from_str(&text)
        .with_context(|| format!("reading corpus manifest {}", path.display()))?;
    Ok(manifest.source)
}

/// A blake3 digest over the sorted `id:content-hash` pairs of `docs`, so the
/// result is independent of fetch/iteration order but changes whenever any
/// document's id set or text changes.
pub fn corpus_hash(docs: &[Document]) -> String {
    let mut lines: Vec<String> = docs
        .iter()
        .map(|doc| format!("{}:{}\n", doc.id, blake3::hash(doc.text.as_bytes()).to_hex()))
        .collect();
    lines.sort();
    blake3::hash(lines.concat().as_bytes()).to_hex().to_string()
}

/// Does `line` start a new chunk boundary: a Markdown heading (`#` through
/// `####`, followed by a space) or a finding-ID-shaped token such as
/// `OS-VLT-ADV-00` or `[OS-VLT-00]`?
fn is_boundary(line: &str) -> bool {
    is_markdown_heading(line) || is_finding_id(line)
}

fn is_markdown_heading(line: &str) -> bool {
    let bytes = line.as_bytes();
    let hashes = bytes.iter().take_while(|&&b| b == b'#').count();
    (1..=4).contains(&hashes) && bytes.get(hashes) == Some(&b' ')
}

/// Matches `^\[?[A-Z]{2,5}-[A-Z0-9-]*\d+\]?\b` by hand: an optional leading
/// `[`, 2-5 uppercase letters, a `-`, then any run of uppercase letters,
/// digits and `-` that contains at least one digit, then an optional `]`.
fn is_finding_id(line: &str) -> bool {
    let rest = line.strip_prefix('[').unwrap_or(line);

    let letters_end = rest
        .as_bytes()
        .iter()
        .take_while(|b| b.is_ascii_uppercase())
        .count();
    if !(2..=5).contains(&letters_end) {
        return false;
    }
    let rest = &rest[letters_end..];
    let Some(rest) = rest.strip_prefix('-') else {
        return false;
    };

    let mut saw_digit = false;
    let mut consumed = 0;
    for ch in rest.chars() {
        if ch.is_ascii_uppercase() || ch == '-' || ch.is_ascii_digit() {
            if ch.is_ascii_digit() {
                saw_digit = true;
            }
            consumed += ch.len_utf8();
        } else {
            break;
        }
    }
    if !saw_digit || consumed == 0 {
        return false;
    }

    // A word boundary follows: end of string, `]`, or a non-identifier char.
    let after = &rest[consumed..];
    after.is_empty()
        || after.starts_with(']')
        || !after.chars().next().unwrap().is_alphanumeric()
}

/// Split `raw_text` into per-finding [`Document`] chunks, inheriting tags
/// and identity from `source`. See the module docs for the boundary rules.
pub fn chunk_by_finding(source: &Source, raw_text: &str) -> Vec<Document> {
    if raw_text.trim().is_empty() {
        return Vec::new();
    }

    // Accumulate raw (title, text) fragments split at boundary lines.
    let mut fragments: Vec<(Option<String>, String)> = Vec::new();
    let mut current_title: Option<String> = None;
    let mut current_text = String::new();

    for line in raw_text.lines() {
        if is_boundary(line) {
            if !current_text.is_empty() {
                fragments.push((current_title.take(), std::mem::take(&mut current_text)));
            }
            current_title = Some(line.trim_start_matches('#').trim().to_string());
        }
        current_text.push_str(line);
        current_text.push('\n');
    }
    if !current_text.trim().is_empty() {
        fragments.push((current_title.take(), current_text));
    }

    // Merge chunks under 200 chars into their predecessor; if there is no
    // predecessor yet, hold the short fragment and merge the next
    // fragment(s) into it instead. The decision is about the *accumulated
    // pending chunk*, not each incoming fragment's own length: a pending
    // chunk keeps absorbing fragments (long or short) until its combined
    // length clears 200, at which point it is closed out and a fresh
    // pending chunk starts. This is what makes a short-first-fragment
    // merge forward into a following long fragment, and what stops an
    // already-long pending chunk from continuing to sweep up unrelated
    // short fragments that come after it.
    let mut merged: Vec<(Option<String>, String)> = Vec::new();
    let mut pending: Option<(Option<String>, String)> = None;
    for (title, text) in fragments {
        match &mut pending {
            Some(p) if p.1.trim().len() < 200 => {
                p.1.push_str(&text);
            }
            _ => {
                if let Some(done) = pending.take() {
                    merged.push(done);
                }
                pending = Some((title, text));
            }
        }
    }
    // A final pending chunk still under 200 with no successor to merge
    // into gets emitted as-is: there is nothing left to absorb it into,
    // and dropping it would silently lose content.
    if let Some(done) = pending {
        merged.push(done);
    }

    merged
        .into_iter()
        .enumerate()
        .map(|(index, (title, text))| {
            let lowered = text.to_lowercase();
            let mut class_tags = source.class_tags.clone();
            for tag in CLASS_TAGS {
                if lowered.contains(tag) {
                    class_tags.push(tag.to_string());
                }
            }
            class_tags.sort();
            class_tags.dedup();

            Document {
                id: format!("{}#{}", source.id, index),
                source_url: source.url.clone(),
                title: compose_title(&source.title, title.as_deref()),
                text,
                class_tags,
            }
        })
        .collect()
}

/// Build a chunk's title from its source and its own heading.
///
/// A chunk's heading alone is a terrible citation: real corpus documents
/// carry headings like "Mitigation Guidance", "Review Signals" or "See it in
/// code", and an auditor following a citation to "See it in code" learns
/// nothing about which rule or file it came from. The source title is what
/// supplies that context, so both are kept.
///
/// A heading that already starts with the source title is not repeated —
/// several sources title their opening chunk with the document title itself.
fn compose_title(source_title: &str, heading: Option<&str>) -> String {
    match heading {
        None => source_title.to_string(),
        Some(h) if h.trim().is_empty() => source_title.to_string(),
        Some(h) if h == source_title => source_title.to_string(),
        Some(h) => format!("{source_title} — {h}"),
    }
}

#[cfg(test)]
mod tests {
    // `crates/dike-core/tests/seam.rs` scans every non-comment line of this
    // file's string literals for Solana/Anchor vocabulary and fails the
    // build if any appears, even inside a test fixture. It is tempting to
    // make these fixtures "more realistic" by naming the Anchor types this
    // module's boundary-detection logic is ultimately meant to support —
    // don't. Paraphrase instead (as the existing fixtures already do).
    // Banned tokens: "anchor", "solana", "Signer<", "AccountInfo",
    // "UncheckedAccount", "has_one", "invoke_signed", "pubkey", "Pubkey",
    // "spl_".
    use super::*;

    fn src() -> Source {
        Source {
            id: "os-report".into(), url: "https://example.invalid/r".into(),
            title: "T".into(), license: "l".into(), retrieved: "2026-08-28".into(),
            sha256: "h".into(), class_tags: vec!["missing-signer".into()],
            kind: SourceKind::Page, include_paths: vec![],
        }
    }

    fn doc(id: &str, text: &str) -> Document {
        Document { id: id.into(), source_url: "u".into(), title: "t".into(),
                   text: text.into(), class_tags: vec![] }
    }

    #[test]
    fn manifest_round_trips_including_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sources.toml");
        std::fs::write(&path, r#"
[[source]]
id = "a"
kind = "archive"
url = "https://example.invalid/x.tar.gz"
title = "T"
license = "Apache-2.0"
retrieved = "2026-08-28"
sha256 = "deadbeef"
class_tags = ["missing-signer"]
"#).unwrap();
        let sources = load_manifest(&path).unwrap();
        assert_eq!(sources.len(), 1);
        assert!(matches!(sources[0].kind, SourceKind::Archive));
        assert_eq!(sources[0].class_tags, vec!["missing-signer".to_string()]);
    }

    fn real_manifest() -> Vec<Source> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("sources.toml");
        load_manifest(&path).unwrap()
    }

    #[test]
    fn a_chunk_title_carries_its_source_not_only_its_heading() {
        // The live corpus produced citations reading "Mitigation Guidance",
        // "Review Signals" and "See it in code" — headings that identify
        // nothing on their own. A citation has to say which document it
        // came from.
        assert_eq!(
            compose_title("Signer And Authority Enforcement", Some("Review Signals")),
            "Signer And Authority Enforcement — Review Signals"
        );
    }

    #[test]
    fn a_chunk_with_no_heading_falls_back_to_the_source_title() {
        assert_eq!(compose_title("Source", None), "Source");
        assert_eq!(compose_title("Source", Some("   ")), "Source");
    }

    #[test]
    fn a_heading_equal_to_the_source_title_is_not_doubled() {
        // Several sources open with a heading that repeats the document
        // title; "X — X" is noise in every citation that chunk appears in.
        assert_eq!(compose_title("Account Validation", Some("Account Validation")), "Account Validation");
    }

    #[test]
    fn chunk_titles_from_a_real_source_are_prefixed() {
        let source = src();
        let chunks = chunk_by_finding(
            &source,
            "## Review Signals\nA signal that is long enough to survive the minimum chunk \
             length rule applied when short fragments accumulate into their successor.",
        );
        assert!(
            chunks[0].title.starts_with(&source.title),
            "got: {}",
            chunks[0].title
        );
        assert!(chunks[0].title.contains("Review Signals"), "got: {}", chunks[0].title);
    }

    #[test]
    fn real_manifest_parses_and_has_six_active_sources() {
        // Three audit-report sources (ottersec/zellic/sec3) remain
        // commented out in corpus/sources.toml: they are PDF corpora and
        // the fetch pipeline reads no PDFs. The six active ones —
        // sealevel-attacks, neodyme-pitfalls, anchor-constraints,
        // notes-local, solana-security-standard, solana-audit-taxonomy —
        // must still parse cleanly.
        assert_eq!(real_manifest().len(), 6);
    }

    #[test]
    fn every_filtered_source_in_the_real_manifest_is_an_archive() {
        // `include_paths` only means anything for an archive: nothing reads
        // it on a page or a local source, so a filter set on one would look
        // like a scoping rule while silently doing nothing.
        for s in real_manifest() {
            if !s.include_paths.is_empty() {
                assert!(
                    matches!(s.kind, SourceKind::Archive),
                    "{} sets include_paths but is not an archive",
                    s.id
                );
            }
        }
    }

    #[test]
    fn no_active_source_is_missing_a_hash_field_or_a_title() {
        // Cheap manifest hygiene: every entry the fetcher will act on needs
        // an id, a url, a title and a licence recorded, because all four
        // reach either the cache path or a citation.
        for s in real_manifest() {
            assert!(!s.id.is_empty());
            assert!(!s.url.is_empty(), "{} has no url", s.id);
            assert!(!s.title.is_empty(), "{} has no title", s.id);
            assert!(!s.license.is_empty(), "{} has no licence", s.id);
        }
    }

    #[test]
    fn manifest_defaults_kind_to_page_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sources.toml");
        std::fs::write(&path, r#"
[[source]]
id = "a"
url = "https://example.invalid/x"
title = "T"
license = "l"
retrieved = "2026-08-28"
sha256 = ""
class_tags = []
"#).unwrap();
        assert!(matches!(load_manifest(&path).unwrap()[0].kind, SourceKind::Page));
    }

    #[test]
    fn corpus_hash_is_order_independent() {
        let (a, b) = (doc("a", "x"), doc("b", "y"));
        assert_eq!(corpus_hash(&[a.clone(), b.clone()]), corpus_hash(&[b, a]));
    }

    #[test]
    fn corpus_hash_changes_when_content_changes() {
        let a = doc("a", "x");
        let mut b = a.clone();
        b.text = "z".into();
        assert_ne!(corpus_hash(&[a]), corpus_hash(&[b]));
    }

    #[test]
    fn corpus_hash_changes_when_a_document_is_added() {
        let a = doc("a", "x");
        assert_ne!(corpus_hash(std::slice::from_ref(&a)), corpus_hash(&[a, doc("b", "y")]));
    }

    #[test]
    fn splits_on_finding_headings_not_token_counts() {
        let text = "\
# OS-VLT-ADV-00 Missing signer check
The withdraw instruction does not verify that the caller authorized the transaction,
so any account may drain the vault. Severity: Critical. Recommendation: require the
account type that enforces a transaction signature on the authority field.

# OS-VLT-ADV-01 Unchecked arithmetic
The deposit instruction adds to the stored balance without an overflow check, which
wraps silently in release builds. Recommendation: use the checked_add helper instead
of the bare addition operator so the overflow surfaces as an error.
";
        let chunks = chunk_by_finding(&src(), text);
        assert_eq!(chunks.len(), 2, "one chunk per finding heading");
        assert!(chunks[0].title.contains("OS-VLT-ADV-00"));
        assert!(chunks[0].text.contains("drain the vault"), "the body travels with its heading");
        assert!(!chunks[0].text.contains("OS-VLT-ADV-01"), "chunks do not bleed into each other");
        assert_eq!(chunks[0].id, "os-report#0");
        assert_eq!(chunks[1].id, "os-report#1");
        assert!(chunks[0].class_tags.contains(&"missing-signer".to_string()),
                "source tags are inherited");
    }

    #[test]
    fn extends_class_tags_from_chunk_text() {
        let text = format!("# F\n{}\nThis finding is an unchecked-arithmetic issue in the \
                            deposit path and the recommendation is to use checked math.",
                           "x".repeat(200));
        let chunks = chunk_by_finding(&src(), &text);
        assert!(chunks[0].class_tags.contains(&"unchecked-arithmetic".to_string()));
        assert!(chunks[0].class_tags.contains(&"missing-signer".to_string()),
                "inherited tags survive extension");
    }

    #[test]
    fn merges_fragments_shorter_than_200_chars() {
        let chunks = chunk_by_finding(&src(), "# A\nshort\n\n# B\nalso short\n");
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].text.contains("short") && chunks[0].text.contains("also short"),
                "the merged chunk must contain both fragments' text, not just the first");
    }

    #[test]
    fn short_first_fragment_merges_into_following_long_fragment() {
        // A short first chunk with no predecessor must still merge forward
        // into the next (long) fragment, not ship standalone as noise.
        let text = format!("# A\nshort\n\n# B\n{}\n", "y".repeat(250));
        let chunks = chunk_by_finding(&src(), &text);
        assert_eq!(chunks.len(), 1, "short leading fragment must merge into the following long one");
        assert!(chunks[0].text.contains("short"));
        assert!(chunks[0].text.contains(&"y".repeat(250)));
    }

    #[test]
    fn chain_of_short_fragments_accumulates_until_long_enough_then_resets() {
        // A and B are each individually short, but their combined length
        // clears the 200-char floor, so they should merge into ONE chunk
        // and stop accumulating there. C is short and comes after the
        // pending chunk has already cleared 200, so it must start a FRESH
        // pending chunk rather than being swept into the A+B pack; it then
        // merges forward into the long D fragment. Expected: two chunks,
        // [A+B] and [C+D] — not [A+B+C] and [D], which is what you get if
        // the merge decision keys off each incoming fragment's own length
        // instead of the accumulated pending chunk's length.
        let text = format!(
            "# A\n{}\n\n# B\n{}\n\n# C\nshort3\n\n# D\n{}\n",
            "a".repeat(90),
            "b".repeat(150),
            "d".repeat(250)
        );
        let chunks = chunk_by_finding(&src(), &text);
        assert_eq!(chunks.len(), 2, "A+B closes out at 200 chars; C+D is a separate chunk");
        assert!(chunks[0].text.contains(&"a".repeat(90)) && chunks[0].text.contains(&"b".repeat(150)));
        assert!(!chunks[0].text.contains("short3"), "C must not bleed into the already-closed A+B chunk");
        assert!(chunks[1].text.contains("short3") && chunks[1].text.contains(&"d".repeat(250)));
    }

    #[test]
    fn splits_on_bracketed_finding_ids_without_a_heading() {
        let body = "x".repeat(250);
        let text = format!("[OS-VLT-00] First\n{body}\n[OS-VLT-01] Second\n{body}\n");
        assert_eq!(chunk_by_finding(&src(), &text).len(), 2);
    }

    #[test]
    fn text_with_no_boundaries_yields_exactly_one_chunk() {
        let chunks = chunk_by_finding(&src(), &"a ".repeat(300));
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].id, "os-report#0");
    }

    #[test]
    fn empty_text_yields_no_chunks_and_does_not_panic() {
        assert!(chunk_by_finding(&src(), "").is_empty());
        assert!(chunk_by_finding(&src(), "   \n\n  ").is_empty());
    }
}
