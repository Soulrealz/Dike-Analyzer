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

/// Upper bound, in characters, on how far [`html_to_text`]'s tag scanner
/// will look for a closing `>` before giving up. A real HTML tag is never
/// remotely this long, so bounding the scan means an unterminated or
/// odd-parity quoted attribute costs at most one tag's worth of input —
/// never the remainder of the document (see the "Known gaps" note this
/// constant retires in `docs/PROJECT_CONTEXT.md`).
const MAX_TAG_SCAN: usize = 500;

/// Result of scanning forward from a malformed tag's `<` for the next raw
/// `>` or `<`, ignoring quote state. See `raw_scan` inside [`html_to_text`].
enum RawScan {
    /// A `>` was found first, at this index.
    Close(usize),
    /// A `<` was found first, at this index.
    Open(usize),
    /// Neither a `>` nor a `<` appears anywhere in the remainder.
    Neither,
}

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
    // Set after a heading marker is emitted, to swallow the whitespace
    // between `<h2>` and its text so the title lands on the marker's own
    // line. Without it, `<h2>\n  Title</h2>` produces a bare `## ` line and
    // the chunker takes the boundary but finds no title text on it.
    let mut skip_leading_ws = false;

    // A `<` only starts a tag if the next character is ASCII-alphabetic,
    // `/`, or `!` (covers ordinary tags, closing tags, comments, and
    // doctype) — otherwise it's literal text, e.g. `a < b`. Used both at
    // the top level (below) and, as of Round 6, inside `scan_tag_end`'s
    // quoted state, so the two can never drift apart.
    let is_tag_start = |c: char| c.is_ascii_alphabetic() || c == '/' || c == '!';

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
    // input) OR if no closing `>` turns up within `MAX_TAG_SCAN` characters
    // — the latter also covers an unterminated or odd-parity quote, which
    // would otherwise hold the scanner in "quoted" mode indefinitely and
    // swallow everything after it. Every `None` case is handled by the
    // caller as "not a tag after all" (see below), so bounding the scan
    // here is what keeps a malformed tag from costing more than itself.
    // Used both for ordinary tags and (for the opening delimiter only) for
    // `<script>`/`<style>`.
    // Round 5, Item 1: a `<` inside a quoted attribute value is often not
    // legal HTML at all — it's strong evidence of a second, unrelated
    // malformed opener whose own stray quote is about to collide with
    // (toggle off the quote state of) a later, real tag. Abandoning the
    // scan in that case (returning `None`) hands control to the `raw_scan`
    // fallback, which stops at the next `<` and resumes the outer loop
    // right there, so normal recognition (including the script/style
    // check) runs fresh on it. Without this, a flat (non-nesting) quote
    // tracker can be toggled back to "unquoted" by an even number of stray
    // quote characters from unrelated malformed openers, landing exactly on
    // a later real `<script>`/`<style>` tag's own `>` — which the malformed
    // tag's scan then consumes as its own close, resuming just past it and
    // inside the script/style body, so `<script`/`<style` is never matched
    // and the body leaks as ordinary text.
    //
    // Round 6, Item 1: but a literal `<` inside a quoted attribute value
    // IS legal HTML (`title="a < b"`), and the round-5 rule above fired on
    // it too, leaking a raw markup fragment (e.g. `< b">`) into extracted
    // text on well-formed input. The two cases are distinguishable by what
    // follows the `<`, using the exact same `is_tag_start` predicate the
    // top-level loop already uses to decide whether a `<` begins a tag at
    // all: a collision opener looks like `<b `, `<script>` — tag-like,
    // ASCII-alphabetic/`/`/`!` next — while a legitimate in-attribute `<`
    // is followed by a space or other ordinary content. Abandon the scan
    // (return `None`) only in the tag-like case; otherwise treat the `<` as
    // ordinary quoted content and keep scanning, so the round-5 collision
    // fix and this round's legal-`<` fix hold at the same time.
    let scan_tag_end = |start: usize| -> Option<usize> {
        let mut j = start + 1;
        let limit = n.min(start + 1 + MAX_TAG_SCAN);
        let mut quote: Option<char> = None;
        while j < limit {
            let c = chars[j];
            match quote {
                Some(q) => {
                    if c == q {
                        quote = None;
                    } else if c == '<'
                        && matches!(chars.get(j + 1).copied(), Some(nc) if is_tag_start(nc))
                    {
                        return None;
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

    // Fallback for when `scan_tag_end` gives up (cap exceeded, EOF, or an
    // odd-parity quote holding it open indefinitely): re-scan forward from
    // `start` (the `<`) ignoring quote state entirely, looking for whichever
    // comes first — the next raw `>` or the next raw `<`. Round 3 looked
    // only for `>`, which is wrong when a *later, real* tag's `>` is what
    // gets found: resuming just past it skips over that tag's own opening
    // delimiter (e.g. `<script`), so recognition never runs on it and,
    // for `<script>`/`<style>`, stripping mode is never entered — the exact
    // leak this scanner exists to prevent, just reached through the
    // fallback instead of around it. A `<` is far likelier to begin a real
    // tag than our malformed one, so when it comes first we hand control
    // back to the outer loop right there instead of past it.
    //
    // Returns `RawScan::Close(idx)` when a `>` is found before any `<`,
    // `RawScan::Open(idx)` when a `<` is found first (or the two coincide —
    // `>` cannot open a tag, so a `<` at the same position never happens,
    // but if some future change made ties possible, preferring `<` is the
    // safe choice), or `RawScan::Neither` when the remainder has no `>` and
    // no `<` at all.
    let raw_scan = |start: usize| -> RawScan {
        for (k, &c) in chars.iter().enumerate().skip(start + 1) {
            match c {
                '>' => return RawScan::Close(k),
                '<' => return RawScan::Open(k),
                _ => {}
            }
        }
        RawScan::Neither
    };

    while i < n {
        if chars[i] != '<' {
            if skip_leading_ws {
                if chars[i].is_whitespace() {
                    i += 1;
                    continue;
                }
                skip_leading_ws = false;
            }
            out.push(chars[i]);
            i += 1;
            continue;
        }

        // A `<` only starts a tag if the next character is ASCII-alphabetic,
        // `/`, or `!` (covers ordinary tags, closing tags, comments, and
        // doctype). Otherwise it's literal text — e.g. `a < b`.
        let next = chars.get(i + 1).copied();
        let starts_tag = matches!(next, Some(c) if is_tag_start(c));
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
            // If the opening `<script`/`<style` tag itself is malformed (no
            // closing `>` within the bound), do NOT fall through to the
            // literal-`<` path — that would walk the attributes *and the
            // entire script/style body* as ordinary text, silently
            // disabling script stripping for this element. Instead, fall
            // back to a raw scan (ignoring quotes) for whichever comes first,
            // the next `>` or the next `<`:
            //   - a `>` first is still the end of the opening tag, so
            //     script-stripping mode is entered from there as normal;
            //   - a `<` first more likely belongs to a real, later tag (see
            //     `raw_scan`'s doc comment) — resume the outer loop at that
            //     `<` so recognition runs on it fresh, rather than skipping
            //     past it and disabling stripping for whatever it is;
            //   - neither existing means there is no `>` at all, so (unlike
            //     the ordinary-tag path below) drop to end of input rather
            //     than guess: with no delimiter separating attributes from
            //     body, the undifferentiated remainder could be real
            //     JavaScript/CSS, and losing it beats leaking it.
            let open_end = match scan_tag_end(i) {
                Some(e) => e,
                None => match raw_scan(i) {
                    RawScan::Close(p) => p,
                    RawScan::Open(p) => {
                        i = p;
                        continue;
                    }
                    RawScan::Neither => {
                        i = n;
                        continue;
                    }
                },
            };
            let j = open_end + 1;

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

        // No closing '>' within the bound — either the tag is far longer
        // than any real tag, or its quote never resolved. Do NOT treat the
        // `<` as literal text and resume one character later by default:
        // that would leak the (possibly huge) tag interior — attributes,
        // base64 data-URI payloads, etc. — into the output. Instead, fall
        // back to a raw scan (ignoring quote state) for whichever comes
        // first, the next `>` or the next `<`:
        //   - a `>` first: drop everything from `<` through it, emitting
        //     nothing (unchanged from before).
        //   - a `<` first: that `<` is far likelier to begin a real tag
        //     than our malformed one (a genuine `<script>`, say, that would
        //     otherwise have its opening delimiter skipped past — see
        //     `raw_scan`'s doc comment). Resume the outer loop right there
        //     so normal recognition runs on it, emitting nothing for the
        //     skipped span.
        //   - neither: unlike the `<script>`/`<style>` path, there is no
        //     ambiguity to protect against here — with no `>` anywhere, this
        //     can't be a tag at all, so treat the `<` as literal text and
        //     resume one character later, recovering the trailing content
        //     instead of dropping it to EOF for no benefit.
        let Some(j) = scan_tag_end(i) else {
            match raw_scan(i) {
                RawScan::Close(p) => i = p + 1,
                RawScan::Open(p) => i = p,
                RawScan::Neither => {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            continue;
        };
        let tag_body: String = chars[i + 1..j].iter().collect();
        let is_closing = tag_body.starts_with('/');
        let tag_name: String = tag_body
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        // Headings become Markdown headings rather than bare text (D31).
        //
        // The chunker splits on Markdown headings and finding-ID tokens. A
        // fetched HTML page has neither once its tags are stripped, so a
        // whole page collapsed into ONE document: measured on the live
        // corpus, `anchor-constraints` was a single 11 KB chunk and
        // `neodyme-pitfalls` a single 23 KB chunk. A chunk that large
        // matches almost any query in its domain — it topped nearly every
        // search — and a citation pointing at it tells an auditor to go
        // read the page, which is precisely what citations exist to avoid.
        //
        // `h5`/`h6` render as four hashes because that is the deepest level
        // the chunker treats as a boundary; emitting five would silently
        // stop being a boundary at all.
        if let Some(level) = heading_level(&tag_name) {
            if is_closing {
                out.push('\n');
            } else {
                out.push('\n');
                for _ in 0..level {
                    out.push('#');
                }
                out.push(' ');
                skip_leading_ws = true;
            }
        } else if BLOCK_TAGS.contains(&tag_name.as_str()) && (is_closing || tag_name == "br") {
            out.push('\n');
        }
        i = j + 1;
    }

    // Documentation generators (MkDocs, Sphinx, Docusaurus) put a pilcrow
    // inside every heading as the anchor-link glyph, so stripped headings
    // arrive as `Example¶` and every citation carries the artefact. It is
    // decoration in generated docs and vanishingly rare in prose, so it is
    // dropped outright rather than only in headings.
    let out = out.replace('\u{00b6}', "");

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

/// The Markdown heading depth an HTML heading tag maps to, or `None`.
///
/// `h5` and `h6` map to 4: `chunk_by_finding` treats `#` through `####` as
/// boundaries and anything deeper as ordinary text.
fn heading_level(tag_name: &str) -> Option<usize> {
    match tag_name {
        "h1" => Some(1),
        "h2" => Some(2),
        "h3" => Some(3),
        "h4" => Some(4),
        "h5" | "h6" => Some(4),
        _ => None,
    }
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
pub fn extract_archive(
    gz: &[u8],
    keep_ext: &[&str],
    include_paths: &[String],
) -> anyhow::Result<Vec<(String, String)>> {
    let decoder = flate2::read::GzDecoder::new(gz);
    let mut archive = tar::Archive::new(decoder);
    let mut out = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();

        if is_unsafe_archive_path(&path) {
            continue;
        }
        if !is_included(&path, include_paths) {
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
    // A filter that matches nothing is a typo, not an empty repository. Left
    // unreported it would cache an empty file, index zero documents, and
    // leave every later command succeeding while retrieving nothing.
    if out.is_empty() && !include_paths.is_empty() {
        anyhow::bail!(
            "no archive entries matched include_paths {:?} — check the paths against the \
             repository layout (they are relative to the archive's top-level directory)",
            include_paths
        );
    }
    Ok(out)
}

/// Is this archive entry under one of `include_paths`?
///
/// An empty filter keeps everything. Otherwise the archive's top-level
/// directory is stripped first: a codeload tarball names every entry
/// `<repo>-<ref>/...`, so a filter written against the repository layout
/// (`content/rules/`) would match nothing at all if compared to the raw
/// entry path. That mismatch is silent — the fetch would succeed with an
/// empty corpus — which is why it has its own test.
fn is_included(path: &str, include_paths: &[String]) -> bool {
    if include_paths.is_empty() {
        return true;
    }
    let relative = path.split_once('/').map(|(_, rest)| rest).unwrap_or(path);
    include_paths.iter().any(|prefix| {
        let prefix = prefix.trim_start_matches('/');
        relative == prefix || relative.starts_with(prefix)
    })
}

/// The result of [`fetch_source`], per the change policy (D21).
#[derive(Debug, Clone, PartialEq)]
pub enum FetchOutcome {
    /// First-ever fetch: the manifest's `sha256` was empty.
    Fetched { hash: String },
    /// The freshly fetched content hashes the same as the manifest.
    Unchanged,
    /// The freshly fetched content differs from the manifest's recorded
    /// hash. The new content is written to the cache regardless — several
    /// active sources are live web pages or living repositories that change
    /// weekly, so hard-failing on a mismatch would make the second-ever
    /// fetch an error.
    ///
    /// `old_bytes` is the size of the previously cached text (0 when there
    /// was none) and `new_bytes` the size just written. The hashes say
    /// *that* a source changed; the sizes are what distinguishes "the
    /// repository added findings" from "the fetch broke and we cached a
    /// login page", and only the second needs a human.
    Changed {
        old: String,
        new: String,
        old_bytes: usize,
        new_bytes: usize,
    },
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
            extract_archive(&bytes, &["rs", "md"], &s.include_paths)?
                .into_iter()
                .map(|(path, content)| format!("# {path}\n{content}\n\n"))
                .collect()
        }
        SourceKind::Local => fetch_local_markdown(&s.url)?,
    };

    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("creating cache dir {}", cache_dir.display()))?;
    let cache_path = cache_dir.join(format!("{}.txt", s.id));
    // Read before the write below overwrites it.
    let old_bytes = std::fs::metadata(&cache_path)
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    std::fs::write(&cache_path, &text)
        .with_context(|| format!("writing {}", cache_path.display()))?;

    let new_hash = sha256_hex(text.as_bytes());
    let outcome = if s.sha256.is_empty() {
        FetchOutcome::Fetched { hash: new_hash }
    } else if s.sha256 == new_hash {
        FetchOutcome::Unchanged
    } else {
        FetchOutcome::Changed {
            old: s.sha256.clone(),
            new: new_hash,
            old_bytes,
            new_bytes: text.len(),
        }
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
            include_paths: vec![],
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
    fn a_heading_permalink_glyph_never_reaches_a_citation() {
        // Real corpus artefact: the fetched pitfalls page chunked into
        // sections titled `Example\u{00b6}`.
        let out = html_to_text("<h2>Example\u{00b6}</h2><p>Body.</p>");
        assert!(out.contains("## Example"), "got: {out:?}");
        assert!(!out.contains('\u{00b6}'), "got: {out:?}");
    }

    #[test]
    fn a_heading_becomes_a_markdown_heading_so_the_chunker_can_split_on_it() {
        // Measured defect (2026-08-31): with headings stripped to bare text,
        // a fetched page had no chunk boundaries at all and became ONE
        // document — 11 KB for the constraint reference, 23 KB for a blog
        // post. Those chunks topped nearly every search and cited a whole
        // page instead of a finding.
        let out = html_to_text("<h1>Title</h1><p>Body text.</p><h2>Second</h2><p>More.</p>");
        assert!(out.contains("# Title"), "got: {out:?}");
        assert!(out.contains("## Second"), "got: {out:?}");
    }

    #[test]
    fn a_heading_marker_starts_its_own_line_with_the_title_on_it() {
        // `chunk_by_finding` reads the `#` at byte 0 of a line and takes the
        // rest of that line as the chunk's title, so a marker stranded on a
        // line of its own yields a boundary with an empty title.
        let out = html_to_text("<p>Intro.</p>\n<h2>\n   Spaced Title\n</h2>\n<p>Body.</p>");
        assert!(
            out.lines().any(|l| l == "## Spaced Title"),
            "got: {out:?}"
        );
    }

    #[test]
    fn deep_headings_stay_at_the_deepest_level_the_chunker_recognises() {
        // Five hashes is not a boundary, so `h5` would silently stop
        // chunking rather than chunk more finely.
        let out = html_to_text("<h5>Deep</h5><h6>Deeper</h6>");
        assert!(out.contains("#### Deep"), "got: {out:?}");
        assert!(out.contains("#### Deeper"), "got: {out:?}");
        assert!(!out.contains("##### "), "got: {out:?}");
    }

    #[test]
    fn heading_text_itself_is_never_lost() {
        // The whitespace-skipping after a marker must not eat real text.
        let out = html_to_text("<h3>Bump Seed Canonicalization</h3>");
        assert!(out.contains("Bump Seed Canonicalization"), "got: {out:?}");
    }

    #[test]
    fn a_page_with_headings_chunks_into_more_than_one_document() {
        // The end-to-end property the change exists for, asserted through
        // the chunker rather than on the intermediate text.
        use crate::retrieval::document::{chunk_by_finding, Source, SourceKind};
        let html = format!(
            "<h2>First Section</h2><p>{}</p><h2>Second Section</h2><p>{}</p>",
            "alpha ".repeat(80),
            "beta ".repeat(80)
        );
        let text = html_to_text(&html);
        let source = Source {
            id: "s".into(),
            url: "https://example.invalid/p".into(),
            title: "T".into(),
            license: "l".into(),
            retrieved: "2026-08-31".into(),
            sha256: String::new(),
            class_tags: vec![],
            kind: SourceKind::Page,
            include_paths: vec![],
        };
        let chunks = chunk_by_finding(&source, &text);
        assert!(chunks.len() >= 2, "got {} chunk(s): {text:?}", chunks.len());
        assert!(
            chunks.iter().any(|c| c.title.contains("First Section")),
            "the heading must reach the citation: {:?}",
            chunks.iter().map(|c| &c.title).collect::<Vec<_>>()
        );
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
        let out = extract_archive(&gz, &["rs", "md"], &[]).unwrap();
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"repo/a.rs"));
        assert!(names.contains(&"repo/b.md"));
        assert!(!names.iter().any(|n| n.ends_with(".png")));
    }

    #[test]
    fn include_paths_are_matched_under_the_archives_top_level_directory() {
        // The trap this test exists for: a codeload tarball names every
        // entry `<repo>-<ref>/...`, but a filter is naturally written
        // against the repository layout (`content/rules/`). Comparing the
        // filter to the raw entry path matches nothing, and the failure is
        // silent — an empty corpus, not an error.
        let gz = build_test_tar_gz(&[
            ("repo-main/content/rules/SOL-001.md", "rule one"),
            ("repo-main/content/rules/SOL-002.md", "rule two"),
            ("repo-main/README.md", "readme"),
            ("repo-main/CHANGELOG.md", "changelog"),
        ]);
        let out = extract_archive(&gz, &["md"], &["content/rules/".to_string()]).unwrap();
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "repo-main/content/rules/SOL-001.md",
                "repo-main/content/rules/SOL-002.md"
            ]
        );
    }

    #[test]
    fn an_empty_include_paths_keeps_everything() {
        // The existing single-purpose sources have no filter and must keep
        // behaving exactly as before.
        let gz = build_test_tar_gz(&[("repo-main/a.md", "a"), ("repo-main/deep/b.md", "b")]);
        let out = extract_archive(&gz, &["md"], &[]).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn several_include_paths_are_ored_together() {
        let gz = build_test_tar_gz(&[
            ("repo-main/taxonomy/signer.md", "sig"),
            ("repo-main/reports/patterns.md", "pat"),
            ("repo-main/README.md", "readme"),
        ]);
        let out = extract_archive(
            &gz,
            &["md"],
            &["taxonomy/".to_string(), "reports/patterns.md".to_string()],
        )
        .unwrap();
        assert_eq!(out.len(), 2, "{out:?}");
    }

    #[test]
    fn an_include_path_matching_nothing_is_an_error_not_an_empty_corpus() {
        // A typo'd prefix would otherwise cache an empty file and leave
        // every later command succeeding while retrieving nothing.
        let gz = build_test_tar_gz(&[("repo-main/content/rules/SOL-001.md", "rule")]);
        let err = extract_archive(&gz, &["md"], &["contnet/rules/".to_string()]).unwrap_err();
        assert!(
            err.to_string().contains("include_paths"),
            "the error must name the filter: {err}"
        );
    }

    #[test]
    fn an_empty_archive_without_a_filter_is_still_not_an_error() {
        // Only a filter that matched nothing is a defect; an archive with
        // no files of interest and no filter stays a soft outcome, which is
        // what the per-entry tolerance elsewhere in this module assumes.
        let gz = build_test_tar_gz(&[("repo-main/logo.png", "not text")]);
        assert!(extract_archive(&gz, &["md"], &[]).unwrap().is_empty());
    }

    #[test]
    fn include_paths_still_cannot_smuggle_a_traversal_entry() {
        // The filter runs after the traversal guard, and must not become a
        // way around it.
        let gz = build_test_tar_gz_raw(&[(
            "repo-main/../../etc/passwd.md",
            b"root:x:0:0".to_vec(),
        )]);
        let err = extract_archive(&gz, &["md"], &["../".to_string()]).unwrap_err();
        assert!(err.to_string().contains("include_paths"), "{err}");
    }

    #[test]
    fn extract_archive_is_deterministically_ordered() {
        let gz = build_test_tar_gz(&[("repo/z.rs", "z"), ("repo/a.rs", "a")]);
        let out = extract_archive(&gz, &["rs"], &[]).unwrap();
        assert_eq!(out[0].0, "repo/a.rs", "entries sort by path");
    }

    #[test]
    fn extract_archive_skips_non_utf8_without_failing_the_whole_archive() {
        let gz = build_test_tar_gz_raw(&[
            ("repo/good.rs", b"fn main() {}".to_vec()),
            ("repo/bad.rs", vec![0xff, 0xfe, 0xff]),
        ]);
        let out = extract_archive(&gz, &["rs"], &[]).unwrap();
        assert_eq!(out.len(), 1, "partial results beat no results");
        assert_eq!(out[0].0, "repo/good.rs");
    }

    #[test]
    fn extract_archive_rejects_path_traversal_entries() {
        let gz = build_test_tar_gz(&[("../../etc/evil.rs", "pwn"), ("repo/ok.rs", "ok")]);
        let out = extract_archive(&gz, &["rs"], &[]).unwrap();
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

    // --- Item 1 (round 2): an unterminated/odd-parity quote must cost at
    // most the malformed tag it appears in, never the remainder of the
    // document. Pre-fix (quoted-mode with no bound), each of the four cases
    // below was observed by running them against the round-1 code:
    //
    //   html_to_text(r#"<a title="x> rest of doc here <b>bold</b>"#)
    //     -> ""
    //   html_to_text(r#"before <a title="never closes tail content here"#)
    //     -> "before"
    //   html_to_text(r#"<a title="odd><p>Real content</p>"#)
    //     -> ""
    //   html_to_text(r#"<a href="unterminated stray" more text <p>Real content</p>"#)
    //     -> "Real content"   (already survives pre-fix, kept below as a
    //        regression guard — see comment on that test)

    #[test]
    fn html_to_text_recovers_trailing_content_after_an_unterminated_quote() {
        // Round-1 bug: the opening `"` before `x` never finds its match, so
        // the scanner stayed in "quoted" mode for the rest of the input and
        // the whole document (including "bold") was lost, yielding "".
        let text = html_to_text(r#"<a title="x> rest of doc here <b>bold</b>"#);
        assert_ne!(text, "", "pre-fix this was empty: whole document swallowed");
        assert!(text.contains("rest of doc here"), "got: {text:?}");
        assert!(text.contains("bold"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_recovers_content_after_a_quote_unterminated_at_end_of_input() {
        // Round-1 bug: no closing quote ever appears before end-of-input,
        // so everything from the opening quote onward (here, the whole
        // "tail content here" clause) was dropped; pre-fix output was just
        // "before".
        //
        // Round 2 recovered "tail content here" by falling back to
        // literal-`<` (resume one char later). Round 3 replaced that with a
        // raw scan for the next `>` that, finding none here either, dropped
        // straight to end of input — losing "tail content here" again, which
        // is what this test's own name contradicted until now.
        //
        // Round 4 (Item 2) restores the Round-2 behavior, but only for
        // ordinary tags: this is a plain `<a>`, not `<script>`/`<style>`, so
        // there is no script/style body it could be mistaken for. With no
        // `>` anywhere, this cannot be real markup at all, so the `<` is
        // literal text and "tail content here" is unambiguously recoverable
        // prose. (The `<script>`/`<style>` path keeps the drop-to-EOF
        // behavior instead — see the comment at its `RawScan::Neither` arm.)
        let text = html_to_text(r#"before <a title="never closes tail content here"#);
        assert_eq!(text, "before <a title=\"never closes tail content here", "got: {text:?}");
        assert!(text.contains("tail content here"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_recovers_content_after_an_odd_quote_spanning_two_tags() {
        // Round-1 bug: a single unmatched `"` before `odd` put the scanner
        // in quoted mode; with no bound it stayed quoted through the *next*
        // tag's `<p>...</p>` too, so "Real content" itself was lost and
        // output was "".
        let text = html_to_text(r#"<a title="odd><p>Real content</p>"#);
        assert_ne!(text, "", "pre-fix this was empty");
        assert!(text.contains("Real content"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_keeps_trailing_content_when_a_balanced_odd_looking_tag_resyncs() {
        // This case's quotes are actually balanced (open before
        // "unterminated, close after "stray"), so this was never the
        // quoted-mode-forever bug — the scanner resyncs on the next
        // unquoted `>`, which happens to belong to the *following* `<p>`
        // tag. That silently drops "more text" (a separate, narrower
        // resync issue the task explicitly does not ask us to fix), but it
        // already preserves trailing real content both before and after
        // this change. Kept as a regression guard.
        let text = html_to_text(
            r#"<a href="unterminated stray" more text <p>Real content</p>"#,
        );
        assert_eq!(text, "Real content", "got: {text:?}");
    }

    #[test]
    fn html_to_text_bounds_the_scan_for_a_tag_far_longer_than_any_real_tag() {
        // A tag body far past MAX_TAG_SCAN with an unterminated quote must
        // not consume trailing real content either, exercising the cap
        // itself rather than only the unterminated-quote path.
        //
        // Round 2 asserted only `text.contains("after cap")`, which passes
        // even though ~1000 chars of `long_junk` leak into the output
        // verbatim (the round-2 fallback treated the unparseable `<` as
        // literal text and resumed one char later). Assert the junk is
        // ABSENT too, so this test can actually fail for the reason its
        // name claims.
        let long_junk = "x".repeat(MAX_TAG_SCAN * 2);
        let html = format!(r#"<a title="{long_junk}unterminated then <p>after cap</p>"#);
        let text = html_to_text(&html);
        assert!(text.contains("after cap"), "got: {text:?}");
        assert!(
            !text.contains(&"x".repeat(50)),
            "malformed tag interior leaked into output; got a {}-char string",
            text.len()
        );
    }

    #[test]
    fn html_to_text_does_not_leak_an_over_long_data_uri_image_tag() {
        // A base64 data-URI `<img>` easily exceeds MAX_TAG_SCAN. Pre-fix,
        // scan_tag_end gives up, the `<` is treated as literal text, and
        // the entire tag - src attribute and ~2000-char base64 payload
        // included - is emitted verbatim as text.
        let base64_payload = "A".repeat(2000);
        let html = format!(r#"<img src="data:image/png;base64,{base64_payload}">after"#);
        let text = html_to_text(&html);
        assert!(
            !text.contains(&"A".repeat(100)),
            "leaked base64 payload into output; got: {} chars",
            text.len()
        );
        assert!(text.contains("after"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_does_not_leak_an_attribute_heavy_div_tag() {
        // A `<div>` with enough attributes to exceed MAX_TAG_SCAN. Pre-fix,
        // all 30 `data-attr-N` attributes leak verbatim ahead of the real
        // content.
        let mut attrs = String::new();
        for k in 0..30 {
            attrs.push_str(&format!(r#" data-attr-{k}="value{k}""#));
        }
        let html = format!(r#"<div{attrs}>Real content</div>"#);
        let text = html_to_text(&html);
        assert!(!text.contains("data-attr-"), "got: {text:?}");
        assert!(text.contains("Real content"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_does_not_leak_an_over_long_script_open_tag_body() {
        // The serious case: a `<script>` tag whose opening delimiter alone
        // (nonce/integrity/crossorigin/query-string attributes, as real
        // analytics/tag-manager scripts carry) exceeds MAX_TAG_SCAN.
        // Pre-fix, scan_tag_end gives up on the OPENING tag, so the script
        // branch bails to the literal-`<` path entirely: script-stripping
        // mode is never entered, and the scanner walks both the attributes
        // and the full script body - including the payload here - as
        // ordinary prose. This is the "naive strip inlines the page's
        // JavaScript" failure the whole design exists to prevent.
        let mut attrs = String::new();
        for k in 0..40 {
            attrs.push_str(&format!(r#" data-x{k}="{}""#, "z".repeat(20)));
        }
        let html = format!(r#"<script{attrs}>alert('leaked secret code');</script>after"#);
        let text = html_to_text(&html);
        assert!(
            !text.contains("alert('leaked secret code')"),
            "script body leaked into output; got: {text:?}"
        );
        assert!(text.contains("after"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_does_not_leak_script_reached_through_a_malformed_tag_collision() {
        // Round 3's fallback (`raw_scan_gt`) resumes at the first raw `>`
        // anywhere after a malformed `<`, with no regard for what that `>`
        // belongs to. Here the malformed tag is `<div data-x="unterminated`
        // (the quote never closes), and the next raw `>` is the one that
        // closes the *real* `<script>` tag's opening delimiter. Resuming
        // just past that `>` skips over the `<script` prefix entirely, so
        // the script/style recognition check never runs on it and its body
        // is walked as ordinary text.
        let html = r#"<div data-x="unterminated<script>alert('leak minimal');</script>after"#;
        let text = html_to_text(html);
        assert!(
            !text.contains("alert"),
            "script body leaked into output; got: {text:?}"
        );
        assert!(
            !text.contains("leak minimal"),
            "script body leaked into output; got: {text:?}"
        );
        assert!(text.contains("after"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_does_not_leak_script_reached_through_a_cap_triggered_collision() {
        // Same collision as above, but the malformed tag's attribute is long
        // enough to blow MAX_TAG_SCAN, so this exercises the `scan_tag_end`
        // cap path (not just the odd-parity-quote path) hitting the same
        // fallback.
        let junk = "x".repeat(600);
        let html = format!(
            r#"<div data-x="unterminated{junk}<script>alert('leak cap');</script>after"#
        );
        let text = html_to_text(&html);
        assert!(
            !text.contains("alert"),
            "script body leaked into output; got: {} chars",
            text.len()
        );
        assert!(
            !text.contains("leak cap"),
            "script body leaked into output; got: {} chars",
            text.len()
        );
        assert!(text.contains("after"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_does_not_leak_style_reached_through_a_malformed_tag_collision() {
        // Same collision, proving the fix is not script-specific: `<style>`
        // must be recognized the same way.
        let html = r#"<div data-x="unterminated<style>body{color:red} /* leak style */</style>after"#;
        let text = html_to_text(html);
        assert!(
            !text.contains("color:red"),
            "style body leaked into output; got: {text:?}"
        );
        assert!(
            !text.contains("leak style"),
            "style body leaked into output; got: {text:?}"
        );
        assert!(text.contains("after"), "got: {text:?}");
    }

    #[test]
    fn html_to_text_handles_a_collision_with_an_ordinary_tag_sanely() {
        // The intervening `<` here begins an ordinary tag (`<p>`), not
        // script/style. Per Item 1, the scanner should resume at that `<`
        // and let normal tag recognition run on it, rather than skipping
        // past whatever `>` comes first. Nothing should leak, and the real
        // paragraph content should survive.
        let html = r#"<div data-x="unterminated<p>Real content</p>after"#;
        let text = html_to_text(html);
        assert!(!text.contains("unterminated"), "got: {text:?}");
        assert!(text.contains("Real content"), "got: {text:?}");
        assert!(text.contains("after"), "got: {text:?}");
    }

    // --- Round 5, Item 1: quote-parity collision in `scan_tag_end` -----
    //
    // Two malformed, unrelated attribute-openers whose stray quote
    // characters sum to an EVEN count toggle `scan_tag_end`'s flat
    // (non-nesting) quote tracker back to "unquoted" exactly at a later
    // real `<script>`/`<style>` tag's own `>`. The outer malformed tag's
    // scan then treats that `>` as its own close and resumes just past it —
    // inside the script/style body — so `matches_at(i, "<script")` never
    // fires and the body leaks as ordinary text. An ODD number of stray
    // quotes instead leaves the scanner unclosed, hitting the `None`
    // fallback (`raw_scan`) safely — which is why every prior round's
    // fixtures (all odd-parity) never caught this.

    #[test]
    fn html_to_text_does_not_leak_script_through_even_parity_quote_collision() {
        // Two stray `"` (one in `<a title="`, one in `<b title="`) is an
        // even count: the flat quote tracker started in `<a`'s scan sees
        // `"` (quote on), then `"` again from `<b title="` (quote off) —
        // right before the real `<script>`'s own closing `>`, so that `>`
        // reads as unquoted and ends the malformed `<a ...>` tag. The
        // scanner resumes just past it, inside the script body, and
        // `<script` is never matched.
        let html = r#"<a title="<b title="<script>alert('x')</script>"#;
        let text = html_to_text(html);
        assert!(
            !text.contains("alert('x')"),
            "script body leaked into output; got: {text:?}"
        );
    }

    #[test]
    fn html_to_text_does_not_leak_style_through_even_parity_quote_collision() {
        let html = r#"<a title="<b title="<style>body{color:red}</style>"#;
        let text = html_to_text(html);
        assert!(
            !text.contains("color:red"),
            "style body leaked into output; got: {text:?}"
        );
    }

    #[test]
    fn html_to_text_does_not_leak_script_through_three_way_even_parity_collision() {
        // Generalizes beyond two colliding openers: three malformed
        // attribute-openers (`<a t="`, `<b t="`, `<c t="`) each contribute
        // one stray `"`, and their sum is odd... except the *third* opener
        // (`<c t="`) is itself unclosed when the scan reaches `<script`, so
        // only the first two stray quotes have toggled the tracker by the
        // time `<script>`'s own `>` is reached — an even count at that
        // point, same as the two-opener case, and it still leaks pre-fix.
        let html = r#"<a t="<b t="<c t="<script>alert(2)</script>"#;
        let text = html_to_text(html);
        assert!(
            !text.contains("alert(2)"),
            "script body leaked into output; got: {text:?}"
        );
    }

    #[test]
    fn html_to_text_does_not_leak_script_through_even_parity_single_quote_collision() {
        // Same mechanism with single quotes instead of double quotes.
        let html = r#"<a title='<b title='<script>alert(4)</script>"#;
        let text = html_to_text(html);
        assert!(
            !text.contains("alert(4)"),
            "script body leaked into output; got: {text:?}"
        );
    }

    #[test]
    fn html_to_text_quote_parity_determines_whether_the_script_collision_leaks() {
        // The mechanism made explicit side by side: ONE stray quote
        // (odd parity) leaves `scan_tag_end` unclosed and hits the safe
        // `raw_scan` fallback; TWO stray quotes (even parity) toggle the
        // tracker back to "unquoted" right at the real `<script>`'s `>`,
        // so the malformed tag's scan succeeds and consumes it — the
        // fallback never runs, and the body leaks. Both must be clean
        // after the fix; only the even case leaked before it.
        let odd = r#"<a title="<script>alert('odd')</script>"#;
        let even = r#"<a title="<b title="<script>alert('even')</script>"#;

        let odd_text = html_to_text(odd);
        assert!(
            !odd_text.contains("alert('odd')"),
            "odd-parity case was already expected to be safe; got: {odd_text:?}"
        );

        let even_text = html_to_text(even);
        assert!(
            !even_text.contains("alert('even')"),
            "even-parity case is the collision this round fixes; got: {even_text:?}"
        );
    }

    // --- Round 6, Item 1: a legal `<` inside a quoted attribute value ---
    //
    // Round 5's rule (abandon the scan on ANY `<` seen while quoted) fixed
    // the collision case but also fired on legal HTML like
    // `title="a < b"`, leaking a raw markup fragment (`< b">`) into
    // extracted text. Pre-fix, verified by extracting this exact
    // `html_to_text` into a scratchpad binary and running it:
    //
    //   html_to_text(r#"<div title="a < b">content</div>"#)
    //     -> "< b\">content"
    //   html_to_text(r#"<span data-cond="x < y">visible</span>"#)
    //     -> "< y\">visible"
    //   html_to_text(r#"<div title="a < b"><script>alert('x')</script>after"#)
    //     -> "< b\">after"

    #[test]
    fn html_to_text_does_not_leak_a_legal_less_than_inside_a_quoted_attribute() {
        let text = html_to_text(r#"<div title="a < b">content</div>"#);
        assert!(
            !text.contains("< b\">"),
            "pre-fix leaked markup fragment; got: {text:?}"
        );
        assert_eq!(text, "content", "got: {text:?}");
    }

    #[test]
    fn html_to_text_does_not_leak_a_legal_less_than_inside_a_data_attribute() {
        let text = html_to_text(r#"<span data-cond="x < y">visible</span>"#);
        assert!(
            !text.contains("< y\">"),
            "pre-fix leaked markup fragment; got: {text:?}"
        );
        assert_eq!(text, "visible", "got: {text:?}");
    }

    #[test]
    fn html_to_text_still_abandons_scan_on_tag_like_less_than_double_quote() {
        // Round 5's collision fix must still hold: `<b` (letter after `<`)
        // is tag-like, so the scan still abandons and the script body
        // still does not leak.
        let text = html_to_text(r#"<a title="<b title="<script>alert('x')</script>"#);
        assert_eq!(text, "", "got: {text:?}");
    }

    #[test]
    fn html_to_text_still_abandons_scan_on_tag_like_less_than_single_quote() {
        let text = html_to_text(r#"<a title='<b title='<script>alert(4)</script>"#);
        assert_eq!(text, "", "got: {text:?}");
    }

    #[test]
    fn html_to_text_unaffected_quoted_greater_than_still_works() {
        let text = html_to_text(r#"<a title="x>y">link</a>"#);
        assert_eq!(text, "link", "got: {text:?}");
    }

    #[test]
    fn html_to_text_handles_legal_less_than_and_a_following_script_together() {
        // The combined case: a legal `<` inside a quoted attribute must not
        // leak a fragment, AND a genuine following `<script>` must still be
        // recognized and stripped — both properties at once.
        let text = html_to_text(r#"<div title="a < b"><script>alert('x')</script>after"#);
        assert!(
            !text.contains("< b\">"),
            "pre-fix leaked markup fragment; got: {text:?}"
        );
        assert!(!text.contains("alert('x')"), "script body leaked; got: {text:?}");
        assert_eq!(text, "after", "got: {text:?}");
    }
}
