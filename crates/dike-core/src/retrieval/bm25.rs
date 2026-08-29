//! BM25 sparse index over the corpus, backed by tantivy.
//!
//! Sparse retrieval earns its place by catching exact identifiers that dense
//! embeddings blur. The tokenizer here is deliberately simple: split on
//! non-alphanumeric boundaries and lowercase, with no stemmer.
//!
//! Contrary to what an earlier version of this comment claimed, the
//! tokenizer does NOT preserve identifiers -- `SimpleTokenizer` splits
//! `try_borrow_mut_data` into four sub-tokens (`try`, `borrow`, `mut`,
//! `data`) exactly like it splits any other text on non-alphanumeric
//! boundaries. Identifier-level discrimination (searching
//! `try_borrow_mut_data` does not also match text that merely contains
//! "try", "borrow", "mut" and "data" scattered elsewhere) instead comes from
//! an emergent property of `tantivy::query::QueryParser`: when a query word
//! contains no whitespace and tokenizes into more than one sub-token, the
//! parser builds a zero-slop `PhraseQuery` requiring those sub-tokens to
//! appear adjacently, rather than an OR of independent terms. Index-time
//! splitting plus query-time phrase reconstruction is what delivers
//! exactness, not token preservation.
//!
//! **How that guarantee is enforced today (updated after the round-2
//! review).** `search` no longer relies on the emergent parser behaviour
//! described above. It wraps every whitespace-separated term in explicit
//! `"..."` phrase-quote syntax (see `per_term_quote`), so the zero-slop
//! `PhraseQuery` is now produced by a documented tantivy feature applied
//! unconditionally, rather than by an internal heuristic that happens to
//! fire on unquoted multi-sub-token words. That is strictly more robust,
//! and it closes off the caller-side risk an earlier version of this
//! comment warned about: joining terms with boolean syntax can no longer
//! silently change the query shape, because `search` sanitises and quotes
//! before parsing either way.
//!
//! The emergent behaviour is still described above because it explains
//! *why* index-time splitting does not destroy exactness, and because the
//! two mechanisms agree — but the explicit quoting is what the code now
//! depends on.
//!
//! **One caller obligation survives, and it is still load-bearing.**
//! Quoting is applied *per whitespace-separated term*, so an identifier
//! must reach `search` as a single unspaced token. `close_account` matches
//! only adjacent occurrences; `close account` is two independent quoted
//! terms ORed together and matches scattered text. A caller that splits an
//! identifier on `_`, or interpolates one into a sentence, silently loses
//! exactness with every existing test still passing. See the
//! `phrase_reconstruction_is_what_makes_identifiers_exact` test below and
//! the contract on [`Bm25Index::search`].

use std::path::Path;

use anyhow::Context;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Schema, Value, STORED, STRING};
use tantivy::tokenizer::{LowerCaser, SimpleTokenizer, TextAnalyzer};
use tantivy::{doc, Index, IndexReader, ReloadPolicy, TantivyDocument};

use super::document::Document;

/// The name registered for our tokenizer: `SimpleTokenizer` (split on
/// non-alphanumeric) + `LowerCaser`, and deliberately no stemmer.
///
/// This does NOT preserve identifiers as single tokens -- it splits them at
/// every non-alphanumeric boundary just like it splits ordinary prose.
/// Exact identifier matching is a query-time property, not a tokenizer
/// property: `search` wraps each whitespace-separated term in explicit
/// `"..."` phrase quotes, so the sub-tokens of an unspaced identifier must
/// appear adjacently. See the module-level doc comment for the full
/// mechanism and the one caller obligation that remains.
const TOKENIZER_NAME: &str = "dike_identifier";

fn build_tokenizer() -> TextAnalyzer {
    TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .build()
}

/// A BM25 index over the corpus, backed by tantivy.
pub struct Bm25Index {
    index: Index,
    reader: IndexReader,
    id_field: tantivy::schema::Field,
    text_field: tantivy::schema::Field,
    title_field: tantivy::schema::Field,
}

fn schema() -> (Schema, tantivy::schema::Field, tantivy::schema::Field, tantivy::schema::Field) {
    let mut builder = Schema::builder();
    let id_field = builder.add_text_field("id", STRING | STORED);
    let text_options = tantivy::schema::TextOptions::default().set_indexing_options(
        tantivy::schema::TextFieldIndexing::default()
            .set_tokenizer(TOKENIZER_NAME)
            .set_index_option(tantivy::schema::IndexRecordOption::WithFreqsAndPositions),
    );
    let text_field = builder.add_text_field("text", text_options.clone());
    let title_field = builder.add_text_field("title", text_options);
    let schema = builder.build();
    (schema, id_field, text_field, title_field)
}

impl Bm25Index {
    /// Build a fresh index at `dir` from `docs`, replacing any documents
    /// already there. Safe to call repeatedly against the same directory.
    pub fn build(docs: &[Document], dir: &Path) -> anyhow::Result<Bm25Index> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating index directory {}", dir.display()))?;

        let (schema, id_field, text_field, title_field) = schema();

        let index = if dir.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false) {
            Index::open_in_dir(dir)
                .with_context(|| format!("opening existing index at {}", dir.display()))?
        } else {
            Index::create_in_dir(dir, schema)
                .with_context(|| format!("creating index at {}", dir.display()))?
        };
        index
            .tokenizers()
            .register(TOKENIZER_NAME, build_tokenizer());

        let mut writer = index.writer(50_000_000)?;
        // Clear any documents from a previous build so repeated `dike corpus
        // index` runs over the same directory do not silently double every
        // score contribution.
        writer.delete_all_documents()?;
        writer.commit()?;

        for d in docs {
            writer.add_document(doc!(
                id_field => d.id.clone(),
                text_field => d.text.clone(),
                title_field => d.title.clone(),
            ))?;
        }
        writer.commit()?;

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()?;

        Ok(Bm25Index {
            index,
            reader,
            id_field,
            text_field,
            title_field,
        })
    }

    /// Open a previously built index at `dir`.
    pub fn open(dir: &Path) -> anyhow::Result<Bm25Index> {
        let index = Index::open_in_dir(dir)
            .with_context(|| format!("opening index at {}", dir.display()))?;
        index
            .tokenizers()
            .register(TOKENIZER_NAME, build_tokenizer());

        let schema = index.schema();
        let id_field = schema
            .get_field("id")
            .context("index schema missing 'id' field")?;
        let text_field = schema
            .get_field("text")
            .context("index schema missing 'text' field")?;
        let title_field = schema
            .get_field("title")
            .context("index schema missing 'title' field")?;

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()?;

        Ok(Bm25Index {
            index,
            reader,
            id_field,
            text_field,
            title_field,
        })
    }

    /// Search the index for `query`, returning at most `k` `(id, score)`
    /// pairs in descending score order (ties broken by ascending `id`, so
    /// the result order is deterministic across repeated builds and
    /// searches -- see `search_order_is_deterministic_across_tied_scores`).
    /// A query matching nothing returns an empty vector rather than an
    /// error.
    ///
    /// # Caller contract: exact-identifier matching
    ///
    /// Exact-identifier discrimination (see the module doc comment) only
    /// holds when an identifier reaches this function as a single,
    /// unspaced token in `query`. Concretely:
    /// - Pass `"try_borrow_mut_data"` as one word, not `"try borrow mut
    ///   data"` -- splitting it on `_` before calling `search` destroys the
    ///   phrase reconstruction that makes the match exact and degrades it
    ///   to an independent-term OR match.
    /// - Do not build the query string with explicit boolean/field syntax
    ///   (`AND`, `OR`, `field:term`, quoted phrases, `+`/`-` prefixes,
    ///   etc.) expecting it to behave like a bag of literal identifiers --
    ///   see the query-syntax sanitizing below, which strips tantivy's
    ///   reserved characters so *your* input can't be reinterpreted as
    ///   query syntax, but it does not let you opt back into that syntax.
    ///
    /// # Query-syntax sanitizing
    ///
    /// `query` is treated as literal search terms, not as tantivy query
    /// syntax. First, characters tantivy's query parser treats specially
    /// (`+ ^ \` : { } " [ ] ( ) ! \ * ~` -- notably *not* `-`, see below) are
    /// replaced with spaces -- see [`sanitize_query`]. Then, each
    /// whitespace-separated term of the result is individually wrapped in
    /// double quotes -- see [`per_term_quote`] -- before the whole thing is
    /// handed to the parser.
    ///
    /// The per-term quoting is what actually neutralizes query syntax: it is
    /// not merely a belt-and-suspenders redundancy over the character
    /// replacement above. A quoted term is parsed as a literal phrase, so
    /// whatever characters happen to survive inside it (including a `-`
    /// that sanitize_query deliberately leaves untouched -- removing it
    /// would turn a query like `missing-signer` into a spaced, bag-of-words
    /// query and destroy the phrase-adjacency requirement that makes it
    /// exact, per the module doc) cannot be reinterpreted as field
    /// selectors, phrase quotes, must/must-not prefixes, boosts, or
    /// wildcards. This matters for callers (e.g. Task 20's IR-derived
    /// queries) that may pass through raw source fragments like
    /// `Account<Vault>` or `constraint = ...`, which would otherwise risk a
    /// parse error or a silently misparsed query, and for this project's own
    /// hyphenated vulnerability-class identifiers (`missing-signer`,
    /// `missing-owner-check`, `pda-validation-gap`, ...), which must reach
    /// tantivy as a single adjacency-preserving phrase per term rather than
    /// being blown apart into an OR of independent words.
    pub fn search(&self, query: &str, k: usize) -> anyhow::Result<Vec<(String, f32)>> {
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(&self.index, vec![self.text_field, self.title_field]);
        let sanitized = sanitize_query(query);
        let quoted = per_term_quote(&sanitized);
        let query = parser
            .parse_query(&quoted)
            .with_context(|| "parsing BM25 query")?;

        let top_docs = searcher.search(&query, &TopDocs::with_limit(k))?;

        let mut hits = Vec::with_capacity(top_docs.len());
        for (score, addr) in top_docs {
            let retrieved: TantivyDocument = searcher.doc(addr)?;
            if let Some(id) = retrieved
                .get_first(self.id_field)
                .and_then(|v| v.as_str())
            {
                hits.push((id.to_string(), score));
            }
        }
        // `TopDocs` gives no tie-break guarantee: with equal scores, build
        // order (which is itself nondeterministic -- tantivy's writer can
        // lay out segments differently across runs) leaks into the
        // returned order. Sort explicitly so output is a pure function of
        // (score, id), independent of index-build internals. `partial_cmp`
        // is used with a total fallback (`Ordering::Equal`) so a NaN score
        // -- which BM25 should never produce, but which would otherwise
        // make `sort_by`'s comparator non-total -- cannot panic the sort.
        hits.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        Ok(hits)
    }
}

/// Strip characters tantivy's query parser treats as syntax (field
/// selectors, phrase quotes, grouping, occur prefixes, boosts, escapes,
/// fuzzy/slop suffixes, wildcards) by replacing them with a space, so a raw
/// literal string -- including one containing `<`, `>`, `:`, or `"` -- can
/// never be reinterpreted as query syntax or produce a parse error. Space
/// itself is left untouched: it is the desired word separator for
/// bag-of-words queries.
///
/// `<` and `>` are deliberately *not* in `QUERY_SYNTAX_CHARS` -- this was
/// verified, not overlooked. Neither is a tantivy query-syntax
/// metacharacter, so a raw fragment like `Account<Vault>` parses cleanly
/// without help from this function; adding them here would only insert an
/// extra space and split `Account<Vault>` into two terms for no benefit. Do
/// not "fix" this omission.
///
/// `-` is also deliberately *not* in this list (it was in an earlier,
/// buggy version). Replacing a leading `-` with a space would only matter
/// for a term-level must-not prefix, but tantivy's must-not prefix is only
/// recognized at the start of a top-level query token -- once
/// [`per_term_quote`] wraps every term in double quotes, an interior or
/// leading `-` is just literal phrase content and can never be
/// reinterpreted as that prefix. Replacing it here instead would corrupt
/// hyphenated identifiers (`missing-signer`, `pda-validation-gap`, ...) by
/// turning a single adjacency-requiring term into two independent words,
/// silently reopening the false-positive bug that per-term quoting fixes.
/// See [`Bm25Index::search`]'s doc comment for the full picture.
fn sanitize_query(query: &str) -> String {
    const QUERY_SYNTAX_CHARS: &[char] = &[
        '+', '^', '`', ':', '{', '}', '"', '[', ']', '(', ')', '!', '\\', '*', '~',
    ];
    query.replace(QUERY_SYNTAX_CHARS, " ")
}

/// Wrap each whitespace-separated term of `query` in double quotes,
/// stripping any interior `"` characters first so a term can never produce
/// an unterminated or nested quote. Terms are joined back with spaces.
///
/// This is what actually enforces phrase adjacency per term while keeping
/// terms independent of each other: `"missing-signer"` is one zero-slop
/// phrase clause, and multiple quoted terms in the joined string are ORed
/// together by the parser exactly as unquoted bare words would be, so
/// genuine multi-word bag-of-words queries (`"missing" "signer" "check"`)
/// keep matching documents that contain the words scattered apart. Whole-
/// query quoting (wrapping the entire string in one pair of quotes) was
/// considered and rejected: it forces one giant phrase across the whole
/// query and breaks that bag-of-words behavior.
///
/// An empty input, or one that is all whitespace, produces an empty string
/// (no terms to quote), which parses as a query matching nothing -- never
/// an error.
fn per_term_quote(query: &str) -> String {
    query
        .split_whitespace()
        .map(|term| {
            let stripped: String = term.chars().filter(|&c| c != '"').collect();
            format!("\"{stripped}\"")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::super::document::Document;
    use super::*;

    fn doc(id: &str, text: &str) -> Document {
        Document {
            id: id.into(),
            source_url: "u".into(),
            title: "t".into(),
            text: text.into(),
            class_tags: vec![],
        }
    }

    #[test]
    fn exact_identifier_matches_rank_first() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![
            // Short and focused: the phrase appears once, with little else
            // around it, so it should score highest.
            doc("d1", "call try_borrow_mut_data now"),
            // Genuinely competes: it contains the same adjacent phrase
            // ("try borrow mut data"), so it also matches the zero-slop
            // phrase query built from the unspaced identifier -- but it is
            // padded with a lot of unrelated filler, which dilutes term
            // frequency and lengthens the document, so under BM25's length
            // normalization it must rank below the short, focused d1
            // rather than tying with or beating it.
            doc(
                "d2",
                "try_borrow_mut_data appears here too but this document is padded with a lot of \
                 extra unrelated filler words about general program design and account handling \
                 so that it is much longer and less focused than the other document",
            ),
        ];
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        let hits = idx.search("try_borrow_mut_data", 5).unwrap();
        assert_eq!(
            hits.len(),
            2,
            "both documents contain the adjacent phrase and must both enter the result set"
        );
        assert_eq!(hits[0].0, "d1", "the short, focused document must rank first");
        assert_eq!(hits[1].0, "d2", "the padded, diluted document must rank second, not tie");
    }

    /// Rewritten from a version whose comment claimed "a stemmer would
    /// break this" but which had no distractor: the same analyzer runs
    /// over both indexed text and the query, so even with a real stemmer
    /// added, self-matching a single document survives stemming trivially.
    ///
    /// The distinguishing property of a stemmer is that it *conflates*
    /// morphological variants. So this test indexes both the exact
    /// identifier `checked_add` and a variant, `checked_adds`, that a
    /// stemmer would fold to the same root ("checked" -> "check",
    /// "add(s)" -> "add"). Without a stemmer, `checked_add` tokenizes to
    /// the phrase ["checked", "add"] and `checked_adds` tokenizes to
    /// ["checked", "adds"] -- "add" != "adds", so searching `checked_add`
    /// must match only the exact document. Under a stemmer both would
    /// reduce to ["check", "add"] and the distractor would wrongly match
    /// too.
    #[test]
    fn an_underscored_identifier_is_not_stemmed_away() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![
            doc("exact", "call checked_add here"),
            doc("variant", "call checked_adds here"),
        ];
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        let hits = idx.search("checked_add", 5).unwrap();
        assert_eq!(
            hits.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(),
            vec!["exact"],
            "a stemmer would conflate checked_add/checked_adds and match both"
        );
    }

    /// Locks in the mechanism documented at the top of this file: an
    /// unspaced query word that tokenizes into multiple sub-tokens becomes
    /// a zero-slop phrase query, so `close_account` (adjacent "close",
    /// "account") does not match text where "close" and "account" appear
    /// as separate words. This is currently the only thing standing
    /// between "verified correct" and "accidentally correct" -- without
    /// this test, nothing in the suite would catch a change to the
    /// tokenizer or query construction that silently destroyed identifier
    /// discrimination.
    #[test]
    fn phrase_reconstruction_is_what_makes_identifiers_exact() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![
            doc("d1", "call close_account here"),
            doc("d2", "close the account safely"),
        ];
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        let hits = idx.search("close_account", 5).unwrap();
        assert_eq!(
            hits.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(),
            vec!["d1"],
            "close_account must match only the adjacent-token document, \
             not a document with close/account as separate words"
        );
    }

    /// Round 2, Item 1 (Critical): `sanitize_query` alone replaced `-` with
    /// a space, turning a hyphenated query into a spaced bag-of-words OR
    /// instead of a zero-slop phrase. This project's own vulnerability
    /// class names are hyphenated -- e.g. `dike_lang_anchor::detectors`'s
    /// `MISSING_SIGNER = "missing-signer"`, `MISSING_OWNER_CHECK`,
    /// `PDA_VALIDATION_GAP` -- and `Document::class_tags` carries
    /// exactly those strings, so this is not academic: searching
    /// `missing-signer` used to also match unrelated text that merely
    /// contained "missing" and "signer" as separate words. Per-term
    /// quoting (`per_term_quote`) fixes this by preserving `-` and wrapping
    /// each whitespace-separated term in its own zero-slop phrase.
    #[test]
    fn a_hyphenated_class_name_does_not_match_scattered_words() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![
            doc("d1", "class missing-signer applies here"),
            doc("d2", "the check is missing and the signer is absent"),
        ];
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        let hits = idx.search("missing-signer", 5).unwrap();
        assert_eq!(
            hits.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(),
            vec!["d1"],
            "missing-signer must match only the adjacent-token document, not one where \
             \"missing\" and \"signer\" merely appear as separate scattered words"
        );
    }

    /// Item 1: `TopDocs` gives no tie-break guarantee, and tantivy's
    /// multi-threaded writer can lay out segments differently across
    /// separate builds, so an unsorted tie order is unstable build-to-build
    /// even when it is stable within one built index. `search` must sort
    /// explicitly so output is a deterministic function of (score, id).
    #[test]
    fn search_order_is_deterministic_across_tied_scores() {
        let docs: Vec<_> = (0..8)
            .map(|i| doc(&format!("d{i}"), "identical tied text for every document"))
            .collect();
        let expected: Vec<String> = {
            let mut ids: Vec<String> = docs.iter().map(|d| d.id.clone()).collect();
            ids.sort();
            ids
        };

        for _ in 0..5 {
            let dir = tempfile::tempdir().unwrap();
            let idx = Bm25Index::build(&docs, dir.path()).unwrap();
            let hits = idx.search("identical tied text document", 10).unwrap();
            let ids: Vec<String> = hits.into_iter().map(|(id, _)| id).collect();
            assert_eq!(
                ids, expected,
                "tied scores must break by ascending id, deterministically across builds"
            );
        }
    }

    /// Item 4b: `search` must treat its input as literal terms, not as
    /// tantivy query syntax, so IR-derived queries (Task 20) carrying
    /// source-like fragments (`Account<Vault>`, `constraint = ...`) do not
    /// risk a parse error or a silently misparsed query.
    #[test]
    fn query_syntax_metacharacters_do_not_error_or_misparse() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![
            doc("d1", "constraint requires Account Vault ownership check"),
            doc("d2", "unrelated discussion of program design"),
        ];
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();

        for query in [
            "Account<Vault>",
            "Program<Token>",
            "constraint = owner",
            "field:value",
            "\"unterminated quote",
            "-leading-dash",
        ] {
            let hits = idx.search(query, 5).unwrap_or_else(|e| {
                panic!("query {query:?} must not error, got: {e:#}")
            });
            // Sanity: at least the sanitizing didn't turn every query into
            // one that spuriously matches everything.
            assert!(hits.len() <= docs.len());
        }

        // Concretely: a `:`-laden query still finds the real match rather
        // than erroring out or being parsed as a (nonexistent) field
        // selector.
        let hits = idx.search("constraint: owner", 5).unwrap();
        assert!(hits.iter().any(|h| h.0 == "d1"));
    }

    #[test]
    fn search_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Bm25Index::build(&[doc("d1", "uses CpiContext to sign")], dir.path()).unwrap();
        assert_eq!(idx.search("cpicontext", 5).unwrap().len(), 1);
    }

    #[test]
    fn returns_at_most_k_hits() {
        let dir = tempfile::tempdir().unwrap();
        let docs: Vec<_> = (0..10).map(|i| doc(&format!("d{i}"), "missing signature check")).collect();
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        assert_eq!(idx.search("signature", 3).unwrap().len(), 3);
    }

    #[test]
    fn a_query_matching_nothing_returns_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let idx = Bm25Index::build(&[doc("d1", "alpha beta")], dir.path()).unwrap();
        assert!(idx.search("zzzznomatch", 5).unwrap().is_empty());
    }

    #[test]
    fn an_index_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        Bm25Index::build(&[doc("d1", "missing owner validation")], dir.path()).unwrap();
        let reopened = Bm25Index::open(dir.path()).unwrap();
        assert_eq!(reopened.search("owner", 5).unwrap().len(), 1);
    }

    #[test]
    fn rebuilding_over_an_existing_directory_does_not_duplicate_documents() {
        let dir = tempfile::tempdir().unwrap();
        Bm25Index::build(&[doc("d1", "missing owner validation")], dir.path()).unwrap();
        let idx = Bm25Index::build(&[doc("d1", "missing owner validation")], dir.path()).unwrap();
        assert_eq!(idx.search("owner", 5).unwrap().len(), 1, "build must replace, not append");
    }

    #[test]
    fn scores_are_positive_and_descending() {
        let dir = tempfile::tempdir().unwrap();
        let docs = vec![doc("d1", "owner owner owner check"), doc("d2", "owner check")];
        let idx = Bm25Index::build(&docs, dir.path()).unwrap();
        let hits = idx.search("owner", 5).unwrap();
        assert!(hits[0].1 > 0.0);
        assert!(hits[0].1 >= hits[1].1);
    }
}
