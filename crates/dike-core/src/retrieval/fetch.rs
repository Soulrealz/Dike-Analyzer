//! Source fetching and normalization: HTML-to-text, archive extraction, the
//! change-detection policy (D21), and the on-disk fetch cache.

use std::io::Read;
use std::path::{Component, Path};

use anyhow::Context;
use sha2::{Digest, Sha256};

use crate::http::HttpClient;
use crate::retrieval::document::{chunk_by_finding, Document, Source, SourceKind};

/// Block-level HTML tags: a *closing* tag with one of these names becomes a
/// newline in the output; everything else (opening tags, inline tags) does
/// not, so inline runs stay on one line. `br` is exempted from the
/// closing-tag-only rule since it is conventionally self-closing.
const BLOCK_TAGS: &[&str] = &[
    "p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article",
    "header", "footer", "pre", "blockquote", "table", "ul", "ol",
];

/// Strip HTML tags and decode entities into plain text (D23).
///
/// `<script>`/`<style>` element *contents* are dropped, not merely their
/// tags, so page JavaScript never leaks into the corpus. Entities are
/// decoded last-to-first with `&amp;` decoded **last**: decoding it first
/// would turn a page's literal `&amp;lt;` into `<` (a double decode), since
/// the intermediate `&lt;` produced by an early `&amp;` pass would then be
/// caught by the `&lt;` pass.
pub fn html_to_text(html: &str) -> String {
    let chars: Vec<char> = html.chars().collect();
    let lower: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
    let n = chars.len();
    let mut out = String::with_capacity(html.len());
    let mut i = 0;

    let matches_at = |idx: usize, pat: &str| -> bool {
        let pat: Vec<char> = pat.chars().collect();
        idx + pat.len() <= n && lower[idx..idx + pat.len()] == pat[..]
    };
    fn find_subseq(chars: &[char], from: usize, pat: &str) -> Option<usize> {
        let pat: Vec<char> = pat.chars().collect();
        let n = chars.len();
        if from > n {
            return None;
        }
        (from..=n.saturating_sub(pat.len())).find(|&k| chars[k..k + pat.len()] == pat[..])
    }

    // Find the index of the `>` that closes the tag opened at `start` (where
    // `chars[start] == '<'`), tracking quote state so a `>` inside a
    // single- or double-quoted attribute value does not end the tag early.
    // Returns `None` if the tag is unterminated (no `>` before end of
    // input). Used both for ordinary tags and (for the opening delimiter
    // only) for `<script>`/`<style>`.
    let scan_tag_end = |start: usize| -> Option<usize> {
        let mut j = start + 1;
        let mut quote: Option<char> = None;
        while j < n {
            let c = chars[j];
            match quote {
                Some(q) => {
                    if c == q {
                        quote = None;
                    }
                }
                None => {
                    if c == '"' || c == '\'' {
                        quote = Some(c);
                    } else if c == '>' {
                        return Some(j);
                    }
                }
            }
            j += 1;
        }
        None
    };

    while i < n {
        if chars[i] != '<' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        // A `<` only starts a tag if the next character is ASCII-alphabetic,
        // `/`, or `!` (covers ordinary tags, closing tags, comments, and
        // doctype). Otherwise it's literal text — e.g. `a < b`.
        let next = chars.get(i + 1).copied();
        let starts_tag = matches!(next, Some(c) if c.is_ascii_alphabetic() || c == '/' || c == '!');
        if !starts_tag {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        if matches_at(i, "<!--") {
            // Comments are delimited by the literal string `-->`, not by
            // the next unquoted `>` — a comment body routinely contains a
            // bare `>` (e.g. `<!-- a > b -->`) that must not end it early.
            match find_subseq(&chars, i + 4, "-->") {
                Some(pos) => i = pos + 3,
                None => i = n,
            }
            continue;
        }

        if matches_at(i, "<script") || matches_at(i, "<style") {
            let close: Vec<char> = if matches_at(i, "<script") {
                "</script".chars().collect()
            } else {
                "</style".chars().collect()
            };
            let j = scan_tag_end(i).map(|p| p + 1).unwrap_or(n);

            let mut found = None;
            let mut k = j;
            while k + close.len() <= n {
                if lower[k..k + close.len()] == close[..] {
                    found = Some(k);
                    break;
                }
                k += 1;
            }
            i = match found {
                Some(pos) => scan_tag_end(pos).map(|p| p + 1).unwrap_or(n),
                None => n,
            };
            continue;
        }

        let j = scan_tag_end(i); // index of the closing '>', or None if unterminated
        let tag_body: String = chars[i + 1..j.unwrap_or(n)].iter().collect();
        let is_closing = tag_body.starts_with('/');
        let tag_name: String = tag_body
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if BLOCK_TAGS.contains(&tag_name.as_str()) && (is_closing || tag_name == "br") {
            out.push('\n');
        }
        i = j.map(|p| p + 1).unwrap_or(n);
    }

    let decoded = out
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&");

    let trimmed: String = decoded
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n");

    collapse_blank_line_runs(&trimmed)
}

/// Collapse runs of 3+ consecutive newlines down to 2.
fn collapse_blank_line_runs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = 0usize;
    for c in text.chars() {
        if c == '\n' {
            run += 1;
            if run <= 2 {
                out.push(c);
            }
        } else {
            run = 0;
            out.push(c);
        }
    }
    out
}

/// Is `path` untrusted-tarball-unsafe: absolute, or containing a `..`
/// component?
fn is_unsafe_archive_path(path: &str) -> bool {
    path.starts_with('/') || Path::new(path).components().any(|c| c == Component::ParentDir)
}

/// Decompress `gz` as a gzipped tar archive and return `(path, utf8 text)`
/// pairs for entries whose extension (without the dot) is in `keep_ext`.
///
/// Untrusted-input handling (spec §9, partial results beat no results):
/// entries with a path-traversal-shaped path are skipped, entries whose
/// bytes are not valid UTF-8 are skipped rather than failing the whole
/// archive, and the result is sorted by path for determinism.
pub fn extract_archive(gz: &[u8], keep_ext: &[&str]) -> anyhow::Result<Vec<(String, String)>> {
    let decoder = flate2::read::GzDecoder::new(gz);
    let mut archive = tar::Archive::new(decoder);
    let mut out = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();

        if is_unsafe_archive_path(&path) {
            continue;
        }
        let Some(ext) = Path::new(&path).extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !keep_ext.contains(&ext) {
            continue;
        }

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        if let Ok(text) = String::from_utf8(buf) {
            out.push((path, text));
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The result of [`fetch_source`], per the change policy (D21).
#[derive(Debug, Clone, PartialEq)]
pub enum FetchOutcome {
    /// First-ever fetch: the manifest's `sha256` was empty.
    Fetched { hash: String },
    /// The freshly fetched content hashes the same as the manifest.
    Unchanged,
    /// The freshly fetched content differs from the manifest's recorded
    /// hash. The new content is written to the cache regardless — three of
    /// the four active sources are live web pages that change weekly, so
    /// hard-failing on a mismatch would make the second-ever fetch an
    /// error.
    Changed { old: String, new: String },
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn fetch_local_markdown(root: &str) -> anyhow::Result<String> {
    let mut paths: Vec<_> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("md"))
        .map(|e| e.path().to_path_buf())
        .collect();
    paths.sort();

    let mut buf = String::new();
    for path in paths {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        buf.push_str(&format!("# {}\n{}\n\n", path.display(), content));
    }
    Ok(buf)
}

/// Fetch `s`, normalize it to plain text per its [`SourceKind`], write the
/// result to `cache_dir/<s.id>.txt`, and report how it compares to the
/// manifest's recorded hash.
pub fn fetch_source(http: &HttpClient, s: &Source, cache_dir: &Path) -> anyhow::Result<FetchOutcome> {
    let text = match s.kind {
        SourceKind::Page => {
            let bytes = http
                .get_bytes(&s.url)
                .map_err(|e| anyhow::anyhow!("fetching {}: {e}", s.url))?;
            html_to_text(&String::from_utf8_lossy(&bytes))
        }
        SourceKind::Archive => {
            let bytes = http
                .get_bytes(&s.url)
                .map_err(|e| anyhow::anyhow!("fetching {}: {e}", s.url))?;
            extract_archive(&bytes, &["rs", "md"])?
                .into_iter()
                .map(|(path, content)| format!("# {path}\n{content}\n\n"))
                .collect()
        }
        SourceKind::Local => fetch_local_markdown(&s.url)?,
    };

    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("creating cache dir {}", cache_dir.display()))?;
    let cache_path = cache_dir.join(format!("{}.txt", s.id));
    std::fs::write(&cache_path, &text)
        .with_context(|| format!("writing {}", cache_path.display()))?;

    let new_hash = sha256_hex(text.as_bytes());
    let outcome = if s.sha256.is_empty() {
        FetchOutcome::Fetched { hash: new_hash }
    } else if s.sha256 == new_hash {
        FetchOutcome::Unchanged
    } else {
        FetchOutcome::Changed { old: s.sha256.clone(), new: new_hash }
    };
    Ok(outcome)
}

/// Load every source's cached text (missing files are skipped, not an
/// error) and chunk each into [`Document`]s.
pub fn load_cached(sources: &[Source], cache_dir: &Path) -> anyhow::Result<Vec<Document>> {
    let mut docs = Vec::new();
    for s in sources {
        let path = cache_dir.join(format!("{}.txt", s.id));
        if !path.exists() {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        docs.extend(chunk_by_finding(s, &text));
    }
    Ok(docs)
}

#[cfg(test)]
mod tests {
    // `crates/dike-core/tests/seam.rs` scans every non-comment line of this
    // file's string literals for Solana/Anchor vocabulary and fails the
    // build if any appears, even inside a test fixture. These fixtures
    // describe fetching audit reports about a smart-contract platform;
    // paraphrase instead of naming the real framework/runtime types.
    // Banned tokens: "anchor", "solana", "Signer<", "AccountInfo",
    // "UncheckedAccount", "has_one", "invoke_signed", "pubkey", "Pubkey",
    // "spl_".
    use super::*;
    use crate::retrieval::{Source, SourceKind};

    fn page_source(id: &str) -> Source {
        Source {
            id: id.into(),
            url: "https://example.invalid/x".into(),
            title: "T".into(),
            license: "l".into(),
            retrieved: "2026-08-28".into(),
            sha256: "".into(),
            class_tags: vec![],
            kind: SourceKind::Page,
        }
    }

    fn build_test_tar_gz(files: &[(&str, &str)]) -> Vec<u8> {
        build_test_tar_gz_raw(
            &files
                .iter()
                .map(|(n, c)| (*n, c.as_bytes().to_vec()))
                .collect::<Vec<_>>(),
        )
    }

    // Writes the raw name bytes into the header directly (via `append`, not
    // `append_data`), bypassing `tar`'s own path validation. That validation
    // rejects `..`-containing paths at *write* time, which would make it
    // impossible to construct the very path-traversal fixture the
    // `extract_archive_rejects_path_traversal_entries` test below needs.
    fn build_test_tar_gz_raw(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            let name_bytes = name.as_bytes();
            header.as_old_mut().name[..name_bytes.len()].copy_from_slice(name_bytes);
            header.set_cksum();
            builder.append(&header, content.as_slice()).unwrap();
        }
        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn html_to_text_drops_script_and_style_contents() {
        let html = "<html><head><style>body{color:red}</style>\
                    <script>var x = 1; alert('hi');</script></head>\
                    <body><p>Real content here.</p></body></html>";
        let text = html_to_text(html);
        assert!(text.contains("Real content here."));
        assert!(!text.contains("color:red"), "style body must not enter the corpus");
        assert!(!text.contains("alert"), "script body must not enter the corpus");
    }

    #[test]
    fn html_to_text_separates_block_elements_with_newlines() {
        let text = html_to_text("<p>One</p><p>Two</p><li>Three</li>");
        assert!(text.contains("One\nTwo"), "got: {text:?}");
        assert!(text.contains("Three"));
    }

    #[test]
    fn html_to_text_keeps_inline_runs_on_one_line() {
        let text = html_to_text("<p>a <code>close_account</code> call</p>");
        assert!(text.contains("a close_account call"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_decodes_the_entities_that_matter() {
        let text = html_to_text(
            "<p>a &amp; b &lt;T&gt; &quot;q&quot; &#39;s&#39; x&nbsp;y &amp;lt;</p>",
        );
        assert!(text.contains("a & b <T> \"q\" 's' x y"), "got: {text:?}");
        // If `&amp;` were decoded FIRST instead of LAST, the literal
        // `&amp;lt;` in the source would become `&lt;` after the `&amp;`
        // pass, and then get caught by the (already-completed, in the wrong
        // order) `&lt;` pass, double-decoding it into `<`. Decoding `&amp;`
        // last means the `&lt;` produced by decoding `&amp;lt;` is never
        // revisited, so it must survive as the literal text `&lt;`.
        assert!(text.contains("&lt;"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_does_not_swallow_literal_less_than_and_greater_than() {
        // A `<` followed by a space is not a tag start (real HTML parsers
        // require the next char to be ASCII-alphabetic, `/`, or `!`), so
        // this whole sentence must survive intact.
        let text = html_to_text("a < b and c > d");
        assert_eq!(text, "a < b and c > d", "got: {text:?}");
    }

    #[test]
    fn html_to_text_does_not_leak_quoted_greater_than_from_attributes() {
        // The `>` inside the quoted `title` attribute must not end the tag
        // early; the real tag end is the final `>` after the closing quote.
        let text = html_to_text(r#"<a title="x>y">link text</a>"#);
        assert_eq!(text, "link text", "got: {text:?}");
    }

    #[test]
    fn html_to_text_ignores_greater_than_inside_html_comments() {
        let text = html_to_text("before <!-- a > b --> after");
        assert_eq!(text, "before  after", "got: {text:?}");
    }

    #[test]
    fn html_to_text_handles_single_quoted_attribute_values() {
        let text = html_to_text("<a href='x>y'>t</a>");
        assert_eq!(text, "t", "got: {text:?}");
    }

    #[test]
    fn html_to_text_keeps_literal_comparisons_on_both_sides() {
        let text = html_to_text("5 < 10 and 10 > 5");
        assert_eq!(text, "5 < 10 and 10 > 5", "got: {text:?}");
    }

    #[test]
    fn html_to_text_collapses_blank_line_runs() {
        let text = html_to_text("<p>a</p><div></div><div></div><p>b</p>");
        assert!(!text.contains("\n\n\n"), "got: {text:?}");
    }

    #[test]
    fn extract_archive_keeps_only_requested_extensions() {
        let gz = build_test_tar_gz(&[
            ("repo/a.rs", "fn main() {}"),
            ("repo/b.md", "# notes"),
            ("repo/c.png", "\u{0}binary"),
        ]);
        let out = extract_archive(&gz, &["rs", "md"]).unwrap();
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"repo/a.rs"));
        assert!(names.contains(&"repo/b.md"));
        assert!(!names.iter().any(|n| n.ends_with(".png")));
    }

    #[test]
    fn extract_archive_is_deterministically_ordered() {
        let gz = build_test_tar_gz(&[("repo/z.rs", "z"), ("repo/a.rs", "a")]);
        let out = extract_archive(&gz, &["rs"]).unwrap();
        assert_eq!(out[0].0, "repo/a.rs", "entries sort by path");
    }

    #[test]
    fn extract_archive_skips_non_utf8_without_failing_the_whole_archive() {
        let gz = build_test_tar_gz_raw(&[
            ("repo/good.rs", b"fn main() {}".to_vec()),
            ("repo/bad.rs", vec![0xff, 0xfe, 0xff]),
        ]);
        let out = extract_archive(&gz, &["rs"]).unwrap();
        assert_eq!(out.len(), 1, "partial results beat no results");
        assert_eq!(out[0].0, "repo/good.rs");
    }

    #[test]
    fn extract_archive_rejects_path_traversal_entries() {
        let gz = build_test_tar_gz(&[("../../etc/evil.rs", "pwn"), ("repo/ok.rs", "ok")]);
        let out = extract_archive(&gz, &["rs"]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "repo/ok.rs");
    }

    #[test]
    fn load_cached_returns_no_documents_when_the_cache_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_cached(&[page_source("a")], dir.path()).unwrap().is_empty());
    }

    #[test]
    fn load_cached_chunks_each_cached_file() {
        let dir = tempfile::tempdir().unwrap();
        let body = "x".repeat(250);
        std::fs::write(
            dir.path().join("a.txt"),
            format!("# F1 finding one\n{body}\n# F2 finding two\n{body}\n"),
        )
        .unwrap();
        let docs = load_cached(&[page_source("a")], dir.path()).unwrap();
        assert_eq!(docs.len(), 2);
        assert!(docs.iter().all(|d| d.id.starts_with("a#")));
    }

    // `#[ignore]` — needs the network. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn fetches_a_live_page_into_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let http = crate::http::HttpClient::new(std::time::Duration::from_secs(30)).unwrap();
        // Any stable, real docs page works here; this one is deliberately
        // unrelated to the corpus's actual sources (see the seam note atop
        // this test module) since this file may not name them.
        let s = Source {
            url: "https://doc.rust-lang.org/std/index.html".into(),
            ..page_source("live-docs-page")
        };
        let outcome = fetch_source(&http, &s, dir.path()).unwrap();
        assert!(matches!(outcome, FetchOutcome::Fetched { .. }));
        let text = std::fs::read_to_string(dir.path().join("live-docs-page.txt")).unwrap();
        assert!(text.len() > 1000, "a docs page should yield real text");
        assert!(!text.contains("<div"), "tags must not survive normalization");
    }
}
