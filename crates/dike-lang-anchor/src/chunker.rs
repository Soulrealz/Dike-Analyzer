//! Handler chunking and derived retrieval queries.
//!
//! A [`HandlerUnit`] is the smallest self-contained review unit (spec §6):
//! one handler's body, its accounts struct, and every state struct that
//! struct actually references. Anything more pads the model's context window
//! with code that cannot be part of the answer.
//!
//! **The query is derived, never raw source (spec §7).** Raw Rust embeds
//! poorly; a description of behaviour embeds well. The clause that carries
//! the most retrieval signal is the *absent* one — audit findings are
//! written about what was missing, not about what was there.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dike_core::analyzer::SourceTree;

use crate::ir::{AccountDecl, AccountsStruct, Constraint, Handler, Program, StateStruct, Wrapper};

/// One handler with everything needed to review it, plus the query that
/// retrieves corpus material about it.
#[derive(Debug, Clone, PartialEq)]
pub struct HandlerUnit {
    pub handler_name: String,
    pub file: PathBuf,
    pub line: u32,
    pub source: String,
    pub query: String,
}

/// Build one unit per handler in `program`.
pub fn chunk(program: &Program, tree: &SourceTree) -> Vec<HandlerUnit> {
    program
        .instructions
        .iter()
        .map(|handler| {
            let accounts = program.accounts_for(handler);
            HandlerUnit {
                handler_name: handler.name.clone(),
                file: handler.file.clone(),
                line: handler.line,
                source: assemble_source(program, handler, accounts, tree),
                query: derive_query(program, handler, accounts),
            }
        })
        .collect()
}

/// Handler body + accounts struct + referenced state structs, in that order.
///
/// A piece whose file is missing from the tree, or whose line range does not
/// fit the file, is emitted as nothing rather than panicking: a unit missing
/// its state struct is still reviewable, and partial results beat no results
/// (invariant 6).
fn assemble_source(
    program: &Program,
    handler: &Handler,
    accounts: Option<&AccountsStruct>,
    tree: &SourceTree,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(slice_lines(tree, &handler.file, handler.line, handler.end_line));
    if let Some(a) = accounts {
        parts.push(slice_lines(tree, &a.file, a.line, a.end_line));
        for state in referenced_state_structs(program, a) {
            parts.push(slice_lines(tree, &state.file, state.line, state.end_line));
        }
    }
    parts.retain(|p| !p.is_empty());
    parts.join("\n\n")
}

/// The state structs an accounts struct actually names, ordered by name and
/// deduplicated.
///
/// "References" means: appears as the inner type of an `Account` or
/// `InterfaceAccount` wrapper. A `Program<Token>` names a program, not state,
/// and pulling in every state struct in the crate would waste the context
/// window on code that cannot be part of the answer.
fn referenced_state_structs<'p>(
    program: &'p Program,
    accounts: &AccountsStruct,
) -> Vec<&'p StateStruct> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for decl in &accounts.decls {
        match &decl.wrapper {
            Wrapper::Account(inner) | Wrapper::InterfaceAccount(inner) => {
                names.insert(inner.as_str());
            }
            _ => {}
        }
    }
    names
        .into_iter()
        .filter_map(|n| program.state_structs.get(n))
        .collect()
}

/// Lines `[line, end_line]` of `path`'s text in `tree`, or `""`.
///
/// Lines are 1-based — that is what `proc-macro2`'s `span-locations`
/// produces — so a `line` of 0 (the "no attribute" sentinel elsewhere in the
/// IR) yields nothing rather than silently reading from the top of the file.
fn slice_lines(tree: &SourceTree, path: &PathBuf, line: u32, end_line: u32) -> String {
    if line == 0 || end_line < line {
        return String::new();
    }
    let Some(file) = tree.files.iter().find(|f| &f.path == path) else {
        return String::new();
    };
    let start = (line - 1) as usize;
    let take = (end_line - line + 1) as usize;
    let picked: Vec<&str> = file.text.lines().skip(start).take(take).collect();
    picked.join("\n")
}

/// Describe a handler in words, for retrieval.
///
/// **Every identifier reaches the sparse index as a single unspaced token**,
/// and that is a caller obligation, not a nicety: `Bm25Index::search` quotes
/// each whitespace-separated term into a zero-slop phrase, so an identifier
/// split across a space stops matching exactly, with every existing test
/// still passing. Hence wrappers render as `Account of Vault` rather than
/// `Account<Vault>` — the latter tokenises to the adjacent pair
/// `account vault`, which fails to match a corpus document written
/// `Account<'info, Vault>` (tokens `account info vault`). Splitting them into
/// separate terms keeps both `Account` and `Vault` matchable on their own.
///
/// Clause order is fixed, and empty clauses are omitted rather than printed
/// with an empty tail (Rule 5: the same handler must always produce the same
/// query).
pub fn derive_query(
    program: &Program,
    handler: &Handler,
    accounts: Option<&AccountsStruct>,
) -> String {
    let mut clauses: Vec<String> = Vec::new();

    let account_count = accounts.map(|a| a.decls.len()).unwrap_or(0);
    clauses.push(format!(
        "Solana Anchor instruction {} with {} accounts.",
        handler.name, account_count
    ));

    if let Some(accounts) = accounts {
        let types = account_type_clause(&accounts.decls);
        if !types.is_empty() {
            clauses.push(format!("Account types: {types}."));
        }
        let present = present_constraint_clause(&accounts.decls);
        if !present.is_empty() {
            clauses.push(format!("Present constraints: {present}."));
        }
        if let Some(absent) = absent_constraint_clause(&accounts.decls) {
            clauses.push(format!("Absent on unchecked accounts: {absent}."));
        }
    }

    let ops = operations_clause(handler);
    if !ops.is_empty() {
        clauses.push(format!("Operations: {ops}."));
    }

    if let Some(accounts) = accounts {
        for state in referenced_state_structs(program, accounts) {
            if state.fields.is_empty() {
                continue;
            }
            let fields: Vec<&str> = state.fields.iter().map(|(n, _)| n.as_str()).collect();
            clauses.push(format!(
                "State struct {} has field {}.",
                state.name,
                fields.join(", ")
            ));
        }
    }

    clauses.join(" ")
}

/// Wrapper renderings, sorted and deduplicated.
fn account_type_clause(decls: &[AccountDecl]) -> String {
    let rendered: BTreeSet<String> = decls.iter().map(|d| render_wrapper(&d.wrapper)).collect();
    rendered.into_iter().collect::<Vec<_>>().join(", ")
}

/// A wrapper in words. No lifetimes, no angle brackets — see `derive_query`.
fn render_wrapper(w: &Wrapper) -> String {
    match w {
        Wrapper::Signer => "Signer".to_string(),
        Wrapper::Account(inner) => format!("Account of {inner}"),
        Wrapper::InterfaceAccount(inner) => format!("InterfaceAccount of {inner}"),
        Wrapper::UncheckedAccount => "UncheckedAccount".to_string(),
        Wrapper::AccountInfo => "AccountInfo".to_string(),
        Wrapper::Program(inner) => format!("Program of {inner}"),
        Wrapper::SystemAccount => "SystemAccount".to_string(),
        Wrapper::Sysvar(inner) => format!("Sysvar of {inner}"),
        Wrapper::Other(name) => name.clone(),
    }
}

fn constraint_name(c: &Constraint) -> &'static str {
    match c {
        Constraint::Mut => "mut",
        Constraint::Init => "init",
        Constraint::InitIfNeeded => "init_if_needed",
        Constraint::Close(_) => "close",
        Constraint::Seeds(_) => "seeds",
        Constraint::Bump(_) => "bump",
        Constraint::HasOne(_) => "has_one",
        Constraint::Owner(_) => "owner",
        Constraint::Address(_) => "address",
        Constraint::SignerAttr => "signer",
        Constraint::Raw(_) => "constraint",
    }
}

fn present_constraint_clause(decls: &[AccountDecl]) -> String {
    let present: BTreeSet<&str> = decls
        .iter()
        .flat_map(|d| d.constraints.iter())
        .map(constraint_name)
        .collect();
    present.into_iter().collect::<Vec<_>>().join(", ")
}

/// The validation constraints that appear on *no* unchecked declaration.
///
/// `None` when the struct has no unchecked declarations at all: "nothing is
/// missing from a set that does not exist" is a different statement from
/// "these are missing", and printing the second would put a false signal
/// into the query for every well-typed handler.
fn absent_constraint_clause(decls: &[AccountDecl]) -> Option<String> {
    let unchecked: Vec<&AccountDecl> = decls.iter().filter(|d| d.is_unchecked()).collect();
    if unchecked.is_empty() {
        return None;
    }
    let present: BTreeSet<&str> = unchecked
        .iter()
        .flat_map(|d| d.constraints.iter())
        .map(constraint_name)
        .collect();
    let absent: Vec<&str> = ["owner", "address", "seeds", "signer"]
        .into_iter()
        .filter(|c| !present.contains(c))
        .collect();
    if absent.is_empty() {
        None
    } else {
        Some(absent.join(", "))
    }
}

/// What the handler body does, in words.
fn operations_clause(handler: &Handler) -> String {
    let mut ops: Vec<String> = Vec::new();
    if handler.body.calls.iter().any(|c| c.is_cpi) {
        ops.push("cross-program invocation".to_string());
    }
    if !handler.body.state_writes.is_empty() {
        ops.push("state mutation".to_string());
    }
    let unchecked_ops: BTreeSet<&str> = handler
        .body
        .arithmetic
        .iter()
        .filter(|a| !a.checked)
        .map(|a| arith_word(&a.op))
        .collect();
    for op in unchecked_ops {
        ops.push(format!("unchecked {op}"));
    }
    if !handler.body.checks.is_empty() {
        ops.push("imperative checks present".to_string());
    }
    ops.join(", ")
}

/// An operator in words. An unrecognised operator degrades to "arithmetic"
/// rather than leaking a punctuation token into the query.
fn arith_word(op: &str) -> &'static str {
    match op {
        "+" | "add" => "addition",
        "-" | "sub" => "subtraction",
        "*" | "mul" => "multiplication",
        "/" | "div" => "division",
        _ => "arithmetic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dike_core::analyzer::SourceFile;

    const SRC: &str = r#"
#[program]
pub mod vault {
    use super::*;
    pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.amount = v.amount - amount;
        let cpi_ctx = CpiContext::new(a, b);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }
}
#[account]
pub struct Vault { pub admin: Pubkey, pub amount: u64 }
#[derive(Accounts)]
pub struct W<'info> {
    pub authority: UncheckedAccount<'info>,
    #[account(mut, has_one = admin)]
    pub vault: Account<'info, Vault>,
}
"#;

    fn tree_for(src: &str) -> SourceTree {
        SourceTree {
            root: PathBuf::from("."),
            files: vec![SourceFile {
                path: PathBuf::from("lib.rs"),
                text: src.to_string(),
            }],
        }
    }

    fn parse_for(src: &str) -> Program {
        crate::parser::parse_tree(&tree_for(src)).program
    }

    fn chunk_for(src: &str) -> Vec<HandlerUnit> {
        let tree = tree_for(src);
        chunk(&crate::parser::parse_tree(&tree).program, &tree)
    }

    fn derive_query_for(src: &str) -> String {
        let program = parse_for(src);
        let handler = &program.instructions[0];
        derive_query(&program, handler, program.accounts_for(handler))
    }

    #[test]
    fn query_describes_behavior_and_never_quotes_raw_rust() {
        let q = derive_query_for(SRC);
        assert!(q.contains("withdraw"), "{q}");
        assert!(
            q.contains("UncheckedAccount"),
            "wrapper types are the retrieval signal: {q}"
        );
        assert!(q.contains("cross-program invocation"), "{q}");
        assert!(
            q.contains("unchecked"),
            "unchecked arithmetic is described in words: {q}"
        );
        assert!(!q.contains("ctx.accounts"), "the query is a description, not source");
        assert!(!q.contains("->"), "no Rust syntax: {q}");
        assert!(!q.contains('{'), "no Rust syntax: {q}");
    }

    #[test]
    fn query_names_absent_constraints_not_only_present_ones() {
        let q = derive_query_for(SRC);
        let absent = q.split("Absent").nth(1).expect("an Absent clause exists");
        assert!(
            absent.contains("owner") || absent.contains("address") || absent.contains("seeds"),
            "audit findings are written about what is missing; got: {q}"
        );
    }

    #[test]
    fn query_is_deterministic() {
        assert_eq!(derive_query_for(SRC), derive_query_for(SRC));
    }

    #[test]
    fn query_survives_an_unresolvable_accounts_struct() {
        let program = parse_for(
            r#"
#[program]
pub mod p { pub fn go(ctx: Context<Elsewhere>) -> Result<()> { Ok(()) } }
"#,
        );
        let h = program.handler("go").unwrap();
        let q = derive_query(&program, h, None);
        assert!(q.contains("go"), "{q}");
        assert!(!q.is_empty(), "an unresolvable context degrades, it does not vanish");
    }

    #[test]
    fn unit_includes_accounts_struct_and_referenced_state_structs() {
        let units = chunk_for(SRC);
        assert_eq!(units.len(), 1);
        assert!(units[0].source.contains("pub fn withdraw"), "the handler body");
        assert!(units[0].source.contains("pub struct W"), "its accounts struct");
        assert!(
            units[0].source.contains("pub struct Vault"),
            "the referenced state struct"
        );
    }

    #[test]
    fn unit_does_not_include_unreferenced_state_structs() {
        let units = chunk_for(&format!(
            "{SRC}\n#[account]\npub struct Unrelated {{ pub x: u64 }}\n"
        ));
        assert!(
            !units[0].source.contains("Unrelated"),
            "padding the unit with irrelevant structs wastes the context window"
        );
    }

    #[test]
    fn unit_line_points_at_the_handler_not_the_file_start() {
        let units = chunk_for(SRC);
        assert!(units[0].line > 1);
        assert_eq!(units[0].handler_name, "withdraw");
    }

    #[test]
    #[ignore = "scratch: prints the derived queries for the repo fixtures"]
    fn print_fixture_queries() {
        let tree = SourceTree::load(std::path::Path::new("../../tests/fixtures/programs/vault")).unwrap();
        for u in chunk(&crate::parser::parse_tree(&tree).program, &tree) {
            println!("=== {} ===\n{}\n", u.handler_name, u.query);
        }
    }

    #[test]
    fn a_program_with_no_handlers_yields_no_units() {
        assert!(chunk_for("pub fn not_a_handler() {}").is_empty());
    }

    // --- added beyond the plan -------------------------------------------

    #[test]
    fn every_identifier_reaches_the_query_as_a_single_unspaced_token() {
        // The caller obligation `Bm25Index::search` documents: it quotes each
        // whitespace-separated term into a zero-slop phrase, so an identifier
        // broken across a space silently stops matching exactly while every
        // existing test still passes. This is the first real caller.
        let src = SRC.replace("withdraw", "close_account");
        let q = derive_query_for(&src);
        assert!(
            q.split_whitespace().any(|t| t.trim_end_matches([',', '.']) == "close_account"),
            "the handler name must survive as one token: {q}"
        );
        assert!(
            q.split_whitespace().any(|t| t.trim_end_matches([',', '.']) == "Vault"),
            "a state type must survive as one token: {q}"
        );
    }

    #[test]
    fn a_wrapper_never_renders_with_angle_brackets() {
        // `Account<Vault>` tokenises to the adjacent pair `account vault`,
        // which does not match a document written `Account<'info, Vault>`
        // (`account info vault`). Rendering the two as separate terms keeps
        // each matchable on its own.
        let q = derive_query_for(SRC);
        assert!(!q.contains('<'), "{q}");
        assert!(!q.contains('>'), "{q}");
        assert!(!q.contains("'info"), "no lifetimes in the query: {q}");
        assert!(q.contains("Account of Vault"), "{q}");
    }

    #[test]
    fn a_fully_checked_struct_gets_no_absent_clause() {
        // "Nothing is missing from a set that does not exist" is a different
        // statement from "these are missing". A handler with no unchecked
        // accounts must not carry a false absence signal into retrieval.
        let src = r#"
#[program]
pub mod p {
    pub fn go(ctx: Context<G>) -> Result<()> { Ok(()) }
}
#[derive(Accounts)]
pub struct G<'info> {
    pub authority: Signer<'info>,
}
"#;
        let q = derive_query_for(src);
        assert!(!q.contains("Absent"), "{q}");
    }

    #[test]
    fn an_unchecked_account_that_is_pinned_reports_only_what_is_missing() {
        let src = r#"
#[program]
pub mod p {
    pub fn go(ctx: Context<G>) -> Result<()> { Ok(()) }
}
#[derive(Accounts)]
pub struct G<'info> {
    #[account(owner = token_program.key())]
    pub thing: UncheckedAccount<'info>,
}
"#;
        let q = derive_query_for(src);
        let absent = q.split("Absent").nth(1).expect("an Absent clause exists");
        assert!(!absent.contains("owner"), "owner is present here: {q}");
        assert!(absent.contains("seeds"), "seeds really is absent: {q}");
    }

    #[test]
    fn clause_order_is_fixed_so_two_runs_are_diffable() {
        // Rule 5. Sets are iterated through `BTreeSet`, and the clauses
        // themselves are pushed in a fixed order; a `HashSet` anywhere here
        // would make the query vary between runs of the same binary.
        let q = derive_query_for(SRC);
        let instruction = q.find("Solana Anchor instruction").unwrap();
        let types = q.find("Account types:").unwrap();
        let present = q.find("Present constraints:").unwrap();
        let absent = q.find("Absent on unchecked accounts:").unwrap();
        let ops = q.find("Operations:").unwrap();
        let state = q.find("State struct").unwrap();
        assert!(instruction < types, "{q}");
        assert!(types < present, "{q}");
        assert!(present < absent, "{q}");
        assert!(absent < ops, "{q}");
        assert!(ops < state, "{q}");
    }

    #[test]
    fn a_handler_whose_file_is_missing_from_the_tree_degrades_to_an_empty_source() {
        // Invariant 6: partial results beat no results. A unit with no
        // source text is still a unit with a query.
        let program = parse_for(SRC);
        let empty_tree = SourceTree {
            root: PathBuf::from("."),
            files: vec![],
        };
        let units = chunk(&program, &empty_tree);
        assert_eq!(units.len(), 1);
        assert!(units[0].source.is_empty());
        assert!(!units[0].query.is_empty(), "the query does not depend on the tree");
    }

    #[test]
    fn an_out_of_range_line_span_does_not_panic() {
        let tree = tree_for("fn short() {}\n");
        assert_eq!(slice_lines(&tree, &PathBuf::from("lib.rs"), 50, 60), "");
        assert_eq!(slice_lines(&tree, &PathBuf::from("lib.rs"), 0, 3), "");
        assert_eq!(slice_lines(&tree, &PathBuf::from("nope.rs"), 1, 2), "");
    }

    #[test]
    fn the_unit_source_is_the_handler_first_then_its_context() {
        // Order matters for the prompt: the model should read the code under
        // review before the declarations it refers to.
        let units = chunk_for(SRC);
        let s = &units[0].source;
        assert!(s.find("pub fn withdraw").unwrap() < s.find("pub struct W").unwrap(), "{s}");
    }

    #[test]
    fn a_checked_arithmetic_handler_is_not_described_as_unchecked() {
        let src = r#"
#[program]
pub mod p {
    pub fn go(ctx: Context<G>, amount: u64) -> Result<()> {
        let x = amount.checked_sub(1).unwrap();
        Ok(())
    }
}
#[derive(Accounts)]
pub struct G<'info> {
    pub authority: Signer<'info>,
}
"#;
        let q = derive_query_for(src);
        assert!(!q.contains("unchecked"), "{q}");
    }

    #[test]
    fn two_handlers_yield_two_units_each_with_its_own_query() {
        let src = r#"
#[program]
pub mod p {
    pub fn alpha(ctx: Context<G>) -> Result<()> { Ok(()) }
    pub fn beta(ctx: Context<G>) -> Result<()> { Ok(()) }
}
#[derive(Accounts)]
pub struct G<'info> {
    pub authority: Signer<'info>,
}
"#;
        let units = chunk_for(src);
        assert_eq!(units.len(), 2);
        assert_ne!(units[0].query, units[1].query);
        assert!(units[0].query.contains("alpha"), "{}", units[0].query);
        assert!(units[1].query.contains("beta"), "{}", units[1].query);
    }
}
