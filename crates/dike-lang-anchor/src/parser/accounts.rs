use crate::ir::{AccountDecl, AccountsStruct, Constraint, Wrapper};
use std::path::Path;
use syn::spanned::Spanned;

/// Parses a `#[derive(Accounts)]` struct into the IR.
///
/// `line`/`end_line` are populated from the struct item's span (not just the
/// synthesized fields) so a later task can slice the original source text
/// between them to rebuild source for an LLM prompt without losing comments
/// or `/// CHECK:` docs that `quote`-based reconstruction would drop.
pub fn parse_accounts_struct(item: &syn::ItemStruct, file: &Path) -> AccountsStruct {
    let mut decls = Vec::new();
    if let syn::Fields::Named(named) = &item.fields {
        for field in &named.named {
            let name = field
                .ident
                .as_ref()
                .map(|i| i.to_string())
                .unwrap_or_default();
            let (wrapper, boxed, optional) = parse_wrapper(&field.ty);
            let account_attr = field
                .attrs
                .iter()
                .find(|a| a.path().is_ident("account"));
            let (attr_line, attr_end_line) = account_attr
                .map(|a| (a.span().start().line as u32, a.span().end().line as u32))
                .unwrap_or((0, 0));
            // Use the identifier's own span, not `field.span()` — the latter
            // includes the field's outer attributes (e.g. `#[account(...)]`),
            // which would make `line` point at the attribute instead of the
            // `pub name: Type` declaration. `field.ident` is always `Some`
            // inside `Fields::Named`; fall back to the field's own span only
            // in the unreachable case where it isn't.
            let decl_line = field
                .ident
                .as_ref()
                .map(|i| i.span().start().line as u32)
                .unwrap_or_else(|| field.span().start().line as u32);
            decls.push(AccountDecl {
                name,
                wrapper,
                boxed,
                optional,
                constraints: parse_constraints(&field.attrs),
                line: decl_line,
                attr_line,
                attr_end_line,
            });
        }
    }
    AccountsStruct {
        name: item.ident.to_string(),
        file: file.to_path_buf(),
        decls,
        line: item.span().start().line as u32,
        end_line: item.span().end().line as u32,
    }
}

/// Recursively unwraps `Box<..>` and `Option<..>` before classifying (D8).
pub(crate) fn parse_wrapper(ty: &syn::Type) -> (Wrapper, bool, bool) {
    fn outer_segment(ty: &syn::Type) -> Option<&syn::PathSegment> {
        match ty {
            syn::Type::Path(p) => p.path.segments.last(),
            syn::Type::Reference(r) => outer_segment(&r.elem),
            _ => None,
        }
    }
    fn first_type_arg(seg: &syn::PathSegment) -> Option<&syn::Type> {
        if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
            args.args.iter().find_map(|a| match a {
                syn::GenericArgument::Type(t) => Some(t),
                _ => None,
            })
        } else {
            None
        }
    }
    /// Anchor's account wrappers carry `<'info, T>`; T is the last type argument.
    fn last_type_arg_name(seg: &syn::PathSegment) -> String {
        if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
            for arg in args.args.iter().rev() {
                if let syn::GenericArgument::Type(syn::Type::Path(p)) = arg {
                    if let Some(s) = p.path.segments.last() {
                        return s.ident.to_string();
                    }
                }
            }
        }
        String::new()
    }

    let Some(seg) = outer_segment(ty) else {
        return (Wrapper::Other(String::new()), false, false);
    };
    match seg.ident.to_string().as_str() {
        "Box" => {
            let inner = first_type_arg(seg);
            let (w, _, opt) = inner
                .map(parse_wrapper)
                .unwrap_or((Wrapper::Other("Box".into()), false, false));
            (w, true, opt)
        }
        "Option" => {
            let inner = first_type_arg(seg);
            let (w, boxed, _) = inner
                .map(parse_wrapper)
                .unwrap_or((Wrapper::Other("Option".into()), false, false));
            (w, boxed, true)
        }
        "Signer" => (Wrapper::Signer, false, false),
        "Account" => (Wrapper::Account(last_type_arg_name(seg)), false, false),
        "InterfaceAccount" => (
            Wrapper::InterfaceAccount(last_type_arg_name(seg)),
            false,
            false,
        ),
        "UncheckedAccount" => (Wrapper::UncheckedAccount, false, false),
        "AccountInfo" => (Wrapper::AccountInfo, false, false),
        "Program" => (Wrapper::Program(last_type_arg_name(seg)), false, false),
        "SystemAccount" => (Wrapper::SystemAccount, false, false),
        "Sysvar" => (Wrapper::Sysvar(last_type_arg_name(seg)), false, false),
        other => (Wrapper::Other(other.to_string()), false, false),
    }
}

/// Anything unrecognized becomes `Raw` rather than being dropped — a lost
/// constraint is a false positive later.
pub(crate) fn parse_constraints(attrs: &[syn::Attribute]) -> Vec<Constraint> {
    let mut out = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("account") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            let key = meta
                .path
                .get_ident()
                .map(|i| i.to_string())
                .unwrap_or_default();

            // If this meta item has a `= value` part, capture the raw tokens
            // of the value up to (but not including) the next top-level comma,
            // without consuming them from the real stream yet — that happens
            // below once the key has been classified.
            let value = || -> String {
                let fork = meta.input.fork();
                if fork.parse::<syn::Token![=]>().is_err() {
                    return String::new();
                }
                let mut tokens = proc_macro2::TokenStream::new();
                while !fork.is_empty() && !fork.peek(syn::Token![,]) {
                    match fork.parse::<proc_macro2::TokenTree>() {
                        Ok(tt) => tokens.extend(std::iter::once(tt)),
                        Err(_) => break,
                    }
                }
                tokens.to_string()
            };

            match key.as_str() {
                "mut" => out.push(Constraint::Mut),
                "init" => out.push(Constraint::Init),
                "init_if_needed" => out.push(Constraint::InitIfNeeded),
                "signer" => out.push(Constraint::SignerAttr),
                "close" => out.push(Constraint::Close(value())),
                "seeds" => out.push(Constraint::Seeds(value())),
                "bump" => {
                    let v = value();
                    out.push(Constraint::Bump(Some(v).filter(|v| !v.is_empty())))
                }
                "has_one" => {
                    // `has_one = admin` — take the identifier, ignore any trailing
                    // `@ ErrorCode::X` so the target name stays clean.
                    let raw = value();
                    let target = raw
                        .trim_start_matches('=')
                        .split('@')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    out.push(Constraint::HasOne(target));
                }
                "owner" => out.push(Constraint::Owner(value())),
                "address" => out.push(Constraint::Address(value())),
                _ => {
                    // `value()` returns "" for a bare flag like `zero` or
                    // `close` with no `=`. Keep the `=` separator only when
                    // there is a value, so e.g. `constraint = vault.amount >
                    // 0` reads as `"constraint = vault . amount > 0"` and
                    // `zero` reads as `"zero"` — never glued together with no
                    // separator (that previously produced unparseable text
                    // like `"constraintvault . amount > 0"`, which is what a
                    // later suppression pass and detectors match against).
                    let v = value();
                    let text = if v.is_empty() {
                        key.clone()
                    } else {
                        format!("{key} = {v}")
                    };
                    out.push(Constraint::Raw(text));
                }
            }

            // Consume the rest of this meta item (the `= value` part, if any)
            // from the real stream so `parse_nested_meta` can advance past the
            // comma to the next item. `value()` above only forked the input to
            // peek at it without consuming. A value can span multiple token
            // trees (`crate::ID`, `vault.amount > 0`), so consume token trees
            // one at a time until the next top-level comma or end of input.
            if meta.input.peek(syn::Token![=]) {
                let _ = meta.input.parse::<syn::Token![=]>();
                while !meta.input.is_empty() && !meta.input.peek(syn::Token![,]) {
                    let _ = meta.input.parse::<proc_macro2::TokenTree>();
                }
            }
            Ok(())
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Constraint, Wrapper};
    use std::path::Path;

    fn parse(src: &str) -> crate::ir::AccountsStruct {
        let file: syn::File = syn::parse_str(src).unwrap();
        let item = file
            .items
            .iter()
            .find_map(|i| match i {
                syn::Item::Struct(s) => Some(s),
                _ => None,
            })
            .unwrap();
        parse_accounts_struct(item, Path::new("src/lib.rs"))
    }

    #[test]
    fn parses_wrappers_including_box_and_option_and_interface() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub authority: Signer<'info>,
                pub vault: Box<Account<'info, Vault>>,
                pub mint: InterfaceAccount<'info, Mint>,
                pub maybe: Option<Account<'info, Config>>,
                /// CHECK: manual
                pub raw: UncheckedAccount<'info>,
                pub sys: Program<'info, System>,
            }
        "#,
        );
        assert_eq!(s.name, "Withdraw");
        assert_eq!(s.decl("authority").unwrap().wrapper, Wrapper::Signer);
        let vault = s.decl("vault").unwrap();
        assert_eq!(vault.wrapper, Wrapper::Account("Vault".into()));
        assert!(vault.boxed);
        assert_eq!(
            s.decl("mint").unwrap().wrapper,
            Wrapper::InterfaceAccount("Mint".into())
        );
        let maybe = s.decl("maybe").unwrap();
        assert_eq!(maybe.wrapper, Wrapper::Account("Config".into()));
        assert!(maybe.optional);
        assert_eq!(s.decl("raw").unwrap().wrapper, Wrapper::UncheckedAccount);
        assert_eq!(
            s.decl("sys").unwrap().wrapper,
            Wrapper::Program("System".into())
        );
    }

    #[test]
    fn parses_constraints() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut, has_one = admin, seeds = [b"vault", admin.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
                #[account(init, payer = admin, space = 8 + 32)]
                pub fresh: Account<'info, Vault>,
                #[account(mut, close = admin, constraint = vault.amount > 0)]
                pub closing: Account<'info, Vault>,
                #[account(signer)]
                pub legacy: AccountInfo<'info>,
                #[account(address = crate::ID)]
                pub pinned: AccountInfo<'info>,
            }
        "#,
        );
        let vault = s.decl("vault").unwrap();
        assert!(vault.constraints.contains(&Constraint::Mut));
        assert_eq!(vault.has_one_targets(), vec!["admin".to_string()]);
        assert!(vault.has_seeds() && vault.has_bump());
        assert!(s.decl("fresh").unwrap().is_init());
        let closing = s.decl("closing").unwrap();
        assert!(closing
            .constraints
            .iter()
            .any(|c| matches!(c, Constraint::Close(_))));
        assert!(closing
            .constraints
            .iter()
            .any(|c| matches!(c, Constraint::Raw(_))));
        assert!(s.decl("legacy").unwrap().enforces_signer());
        assert!(s.decl("pinned").unwrap().is_address_pinned());
    }

    #[test]
    fn raw_constraint_text_keeps_a_separator_between_key_and_value() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(constraint = vault.amount > 0)]
                pub closing: Account<'info, Vault>,
                #[account(zero)]
                pub fresh: Account<'info, Vault>,
            }
        "#,
        );
        let closing = s.decl("closing").unwrap();
        let raw = closing
            .constraints
            .iter()
            .find_map(|c| match c {
                Constraint::Raw(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(raw, "constraint = vault . amount > 0");

        let fresh = s.decl("fresh").unwrap();
        let raw_no_value = fresh
            .constraints
            .iter()
            .find_map(|c| match c {
                Constraint::Raw(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(raw_no_value, "zero");
    }

    #[test]
    fn double_nested_box_option_unwraps_to_the_inner_account() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub vault: Box<Option<Account<'info, Vault>>>,
            }
        "#,
        );
        let vault = s.decl("vault").unwrap();
        assert_eq!(vault.wrapper, Wrapper::Account("Vault".into()));
        assert!(vault.boxed);
        assert!(vault.optional);
    }

    #[test]
    fn two_has_one_constraints_on_one_field_are_both_kept() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(has_one = admin, has_one = mint)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        let vault = s.decl("vault").unwrap();
        assert_eq!(
            vault.has_one_targets(),
            vec!["admin".to_string(), "mint".to_string()]
        );
    }

    #[test]
    fn account_and_cfg_attributes_coexist_on_one_field() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                #[cfg(feature = "x")]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        let vault = s.decl("vault").unwrap();
        assert!(vault.constraints.contains(&Constraint::Mut));
        assert_eq!(vault.wrapper, Wrapper::Account("Vault".into()));
    }

    #[test]
    fn sysvar_and_system_account_wrappers_are_recognized() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub rent: Sysvar<'info, Rent>,
                pub sys: SystemAccount<'info>,
            }
        "#,
        );
        assert_eq!(
            s.decl("rent").unwrap().wrapper,
            Wrapper::Sysvar("Rent".into())
        );
        assert_eq!(s.decl("sys").unwrap().wrapper, Wrapper::SystemAccount);
    }

    #[test]
    fn records_the_declaration_line() {
        let s = parse("#[derive(Accounts)]\npub struct W<'info> {\n    pub a: Signer<'info>,\n}");
        assert_eq!(s.decl("a").unwrap().line, 3);
    }

    #[test]
    fn records_the_attribute_span_for_a_multi_line_account_attribute() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(
                    mut,
                    has_one = admin,
                    seeds = [b"vault"],
                    bump
                )]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        let vault = s.decl("vault").unwrap();
        assert_ne!(vault.attr_line, vault.attr_end_line);
        // `line` is derived from the field identifier's own span, which never
        // absorbs the attribute above it (see
        // `field_ident_span_excludes_the_attribute` below), so it lands after
        // the whole multi-line attribute, not at its start.
        assert_ne!(vault.attr_line, vault.line);
        assert!(vault.attr_end_line >= vault.attr_line);
        assert!(vault.line > vault.attr_end_line);
    }

    #[test]
    fn attribute_span_is_zero_when_field_has_no_account_attribute() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub authority: Signer<'info>,
            }
        "#,
        );
        let authority = s.decl("authority").unwrap();
        assert_eq!(authority.attr_line, 0);
        assert_eq!(authority.attr_end_line, 0);
    }

    /// Empirically pins whether `syn`'s `Spanned` impl for `Ident` (the field
    /// name) includes the field's outer attributes in its span. `line` is
    /// derived from `field.ident`'s span specifically because an identifier's
    /// span is its own token and never absorbs sibling attribute tokens —
    /// unlike `field.span()`, which does include them. If a future `syn`
    /// upgrade changes that, this test fails loudly instead of every
    /// wrapper-type finding's line number silently pointing at the wrong
    /// line.
    #[test]
    fn field_ident_span_excludes_the_attribute() {
        let s = parse(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        let vault = s.decl("vault").unwrap();
        // Line 1 is the blank line right after the raw-string opener; the
        // `#[account(mut)]` line is line 4 and `pub vault: ...` is line 5.
        assert_eq!(vault.attr_line, 4);
        assert_eq!(
            vault.line, 5,
            "field.ident's span now appears to include the attribute — \
             AccountDecl.line semantics changed; update callers/report text \
             accordingly"
        );
    }
}
