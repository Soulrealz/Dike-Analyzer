pub mod accounts;
pub mod body;
pub mod program;
pub mod symbols;

pub use accounts::parse_accounts_struct;
#[allow(unused_imports)]
pub(crate) use accounts::{parse_constraints, parse_wrapper};

use crate::ir::{Program, StateStruct};
use dike_core::analyzer::{Diagnostic, DiagnosticKind, SourceTree};
use std::path::Path;
use symbols::SymbolTable;
use syn::spanned::Spanned;

pub struct ParseOutcome {
    pub program: Program,
    pub diagnostics: Vec<Diagnostic>,
    pub files_parsed: usize,
}

pub fn parse_tree(tree: &SourceTree) -> ParseOutcome {
    let mut symbols = SymbolTable::default();
    let mut handlers = Vec::new();
    let mut diagnostics = Vec::new();
    let mut files_parsed = 0;

    for file in &tree.files {
        let parsed = match syn::parse_file(&file.text) {
            Ok(p) => p,
            Err(err) => {
                // Partial results beat no results.
                diagnostics.push(Diagnostic {
                    file: Some(file.path.clone()),
                    kind: DiagnosticKind::ParseFailure,
                    message: err.to_string(),
                });
                continue;
            }
        };
        files_parsed += 1;
        visit_items(&parsed.items, &file.path, &mut symbols, &mut handlers);
    }

    diagnostics.extend(std::mem::take(&mut symbols.diagnostics));
    handlers.sort_by(|a, b| a.name.cmp(&b.name)); // determinism

    ParseOutcome {
        program: Program {
            instructions: handlers,
            accounts_structs: symbols.accounts_structs,
            state_structs: symbols.state_structs,
        },
        diagnostics,
        files_parsed,
    }
}

fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

fn derives(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("derive")
            && a.parse_nested_meta(|m| {
                if m.path.is_ident(name) {
                    Err(m.error("found"))
                } else {
                    Ok(())
                }
            })
            .is_err()
    })
}

/// Recurses into inline modules — real programs nest `#[program]` inside `pub mod`.
fn visit_items(
    items: &[syn::Item],
    file: &Path,
    symbols: &mut SymbolTable,
    handlers: &mut Vec<crate::ir::Handler>,
) {
    for item in items {
        match item {
            syn::Item::Mod(m) => {
                if has_attr(&m.attrs, "program") {
                    handlers.extend(program::parse_handlers(m, file));
                }
                if let Some((_, inner)) = &m.content {
                    visit_items(inner, file, symbols, handlers);
                }
            }
            syn::Item::Struct(s) => {
                if derives(&s.attrs, "Accounts") {
                    symbols.insert_accounts(accounts::parse_accounts_struct(s, file), file);
                } else if has_attr(&s.attrs, "account") {
                    let fields = match &s.fields {
                        syn::Fields::Named(named) => named
                            .named
                            .iter()
                            .map(|f| {
                                let ty = &f.ty;
                                (
                                    f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default(),
                                    quote::quote!(#ty).to_string(),
                                )
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    symbols.insert_state(
                        StateStruct {
                            name: s.ident.to_string(),
                            fields,
                            file: file.to_path_buf(),
                            line: s.span().start().line as u32,
                            end_line: s.span().end().line as u32,
                        },
                        file,
                    );
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dike_core::analyzer::{DiagnosticKind, SourceFile, SourceTree};
    use std::path::PathBuf;

    fn tree(files: &[(&str, &str)]) -> SourceTree {
        SourceTree {
            root: PathBuf::from("."),
            files: files
                .iter()
                .map(|(p, t)| SourceFile {
                    path: PathBuf::from(p),
                    text: (*t).to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn binds_handlers_to_accounts_structs_across_files() {
        let t = tree(&[
            (
                "src/lib.rs",
                r#"
                #[program]
                pub mod vault {
                    use super::*;
                    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> { Ok(()) }
                    pub fn deposit(ctx: Context<Deposit>) -> Result<()> { Ok(()) }
                }
            "#,
            ),
            (
                "src/contexts.rs",
                r#"
                #[derive(Accounts)]
                pub struct Withdraw<'info> { pub authority: Signer<'info> }
                #[derive(Accounts)]
                pub struct Deposit<'info> { pub payer: Signer<'info> }
            "#,
            ),
            (
                "src/state.rs",
                r#"
                #[account]
                pub struct Vault { pub admin: Pubkey, pub amount: u64 }
            "#,
            ),
        ]);
        let out = parse_tree(&t);
        assert_eq!(out.program.instructions.len(), 2);
        let w = out.program.handler("withdraw").unwrap();
        assert_eq!(w.context_ty, "Withdraw");
        assert_eq!(w.args.len(), 1);
        assert_eq!(w.args[0].name, "amount");
        assert!(out.program.accounts_for(w).is_some());
        assert!(out.program.state_structs.contains_key("Vault"));
        assert_eq!(out.files_parsed, 3);
    }

    #[test]
    fn a_broken_file_is_skipped_not_fatal() {
        let t = tree(&[
            ("src/broken.rs", "pub fn oops( {"),
            (
                "src/lib.rs",
                r#"
                #[program]
                pub mod vault {
                    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
                }
            "#,
            ),
        ]);
        let out = parse_tree(&t);
        assert_eq!(out.program.instructions.len(), 1);
        assert_eq!(out.files_parsed, 1);
        assert!(out
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::ParseFailure));
    }

    #[test]
    fn duplicate_symbol_names_keep_the_first_and_warn() {
        let t = tree(&[
            (
                "src/a.rs",
                "#[derive(Accounts)]\npub struct Withdraw<'info> { pub a: Signer<'info> }",
            ),
            (
                "src/b.rs",
                "#[derive(Accounts)]\npub struct Withdraw<'info> { pub b: Signer<'info> }",
            ),
        ]);
        let out = parse_tree(&t);
        let s = out.program.accounts_structs.get("Withdraw").unwrap();
        assert!(s.decl("a").is_some());
        assert!(out
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::Ambiguity));
    }

    #[test]
    fn handlers_are_found_in_nested_modules() {
        let t = tree(&[(
            "src/lib.rs",
            r#"
            pub mod outer {
                #[program]
                pub mod vault {
                    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
                }
            }
        "#,
        )]);
        assert_eq!(parse_tree(&t).program.instructions.len(), 1);
    }

    #[test]
    fn private_helper_taking_context_is_not_a_handler() {
        let t = tree(&[(
            "src/lib.rs",
            r#"
            #[program]
            pub mod vault {
                pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
                fn assert_can_withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
            }
        "#,
        )]);
        let out = parse_tree(&t);
        assert_eq!(out.program.instructions.len(), 1);
        assert!(out.program.handler("withdraw").is_some());
        assert!(out.program.handler("assert_can_withdraw").is_none());
    }

    #[test]
    fn program_nested_two_levels_deep_is_still_found() {
        let t = tree(&[(
            "src/lib.rs",
            r#"
            pub mod outer {
                pub mod inner {
                    #[program]
                    pub mod vault {
                        pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }
                    }
                }
            }
        "#,
        )]);
        let out = parse_tree(&t);
        assert_eq!(out.program.instructions.len(), 1);
        assert!(out.program.handler("withdraw").is_some());
    }

    #[test]
    fn account_struct_with_no_named_fields_yields_empty_fields_no_panic() {
        let t = tree(&[(
            "src/state.rs",
            r#"
                #[account]
                pub struct Marker;
                #[account]
                pub struct Pair(pub u64, pub u64);
            "#,
        )]);
        let out = parse_tree(&t);
        let marker = out.program.state_structs.get("Marker").unwrap();
        assert!(marker.fields.is_empty());
        assert_eq!(marker.line, 2);
        assert!(marker.end_line >= marker.line);
        let pair = out.program.state_structs.get("Pair").unwrap();
        assert!(pair.fields.is_empty());
    }

    #[test]
    fn accounts_derive_is_detected_regardless_of_order_among_multiple_derives() {
        let t = tree(&[(
            "src/contexts.rs",
            r#"
                #[derive(Accounts, Clone)]
                pub struct Withdraw<'info> { pub authority: Signer<'info> }
                #[derive(Clone, Accounts)]
                pub struct Deposit<'info> { pub payer: Signer<'info> }
            "#,
        )]);
        let out = parse_tree(&t);
        assert!(out.program.accounts_structs.contains_key("Withdraw"));
        assert!(out.program.accounts_structs.contains_key("Deposit"));
    }
}
