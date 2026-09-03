//! Every mutant of a clean fixture program must still be parseable Rust.
//!
//! The operators edit source text, and the way they fail is by corrupting an
//! attribute list — a dangling comma, an unbalanced bracket, an item removed
//! without its separator. A mutant that does not parse never reaches the
//! analyzer, so the eval harness would score it as a silent miss rather than
//! as the tooling bug it is. This is a cheap stand-in for Task 24's compile
//! gate: it cannot prove Anchor accepts the program, but it catches every
//! defect the text surgery here is capable of producing.

use dike_core::analyzer::SourceTree;
use dike_lang_anchor::mutations::all_operators;

#[test]
fn every_mutant_of_the_clean_fixture_still_parses() {
    let root = std::path::Path::new("../../tests/fixtures/programs/vault");
    let tree = SourceTree::load(root).expect("clean fixture");
    let program = dike_lang_anchor::parser::parse_tree(&tree).program;

    let mut total = 0;
    for op in all_operators() {
        for mutant in op.apply(&program, &tree) {
            total += 1;
            let (path, text) = &mutant.files[0];
            if let Err(err) = syn::parse_file(text) {
                panic!(
                    "{} produced unparseable Rust in {} at line {}: {err}\n{text}",
                    op.name(),
                    path.display(),
                    mutant.label.line,
                );
            }
        }
    }
    // A silent zero would make this assert nothing at all.
    assert!(total >= 12, "only {total} mutants; the operators stopped firing");
}

/// The mutants must differ from each other, not just from the clean program:
/// two operators writing the same file would make one of them unscoreable.
#[test]
fn no_two_mutants_of_the_clean_fixture_are_identical() {
    let root = std::path::Path::new("../../tests/fixtures/programs/vault");
    let tree = SourceTree::load(root).expect("clean fixture");
    let program = dike_lang_anchor::parser::parse_tree(&tree).program;

    let mut texts: Vec<String> = all_operators()
        .iter()
        .flat_map(|op| op.apply(&program, &tree))
        .map(|m| m.files[0].1.clone())
        .collect();
    let count = texts.len();
    texts.sort();
    texts.dedup();
    assert_eq!(texts.len(), count, "two mutants carry the same source text");
}
