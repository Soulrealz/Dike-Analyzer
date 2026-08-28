use crate::ir::{Arg, Handler};
use std::path::Path;
use syn::spanned::Spanned;

/// Extracts the `T` from `Context<'info, T>` / `Context<T>`.
pub(crate) fn context_type_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != "Context" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    args.args.iter().rev().find_map(|a| match a {
        syn::GenericArgument::Type(syn::Type::Path(tp)) => {
            tp.path.segments.last().map(|s| s.ident.to_string())
        }
        _ => None,
    })
}

/// Every `pub fn` in a `#[program]` module whose first argument is a `Context<T>`.
///
/// `line`/`end_line` are populated from the function item's span (not just the
/// synthesized fields) so a later task can slice the original source text
/// between them to rebuild source for an LLM prompt without losing comments.
pub(crate) fn parse_handlers(module: &syn::ItemMod, file: &Path) -> Vec<Handler> {
    let Some((_, items)) = &module.content else {
        return Vec::new();
    };
    let mut handlers = Vec::new();
    for item in items {
        let syn::Item::Fn(f) = item else { continue };
        if !matches!(f.vis, syn::Visibility::Public(_)) {
            // Only `pub fn` inside `#[program]` become Anchor instructions;
            // a private helper that happens to take `Context<T>` first is not
            // user-reachable and must not be recorded as one.
            continue;
        }
        let mut inputs = f.sig.inputs.iter();
        let Some(syn::FnArg::Typed(first)) = inputs.next() else {
            continue;
        };
        let Some(context_ty) = context_type_name(&first.ty) else {
            continue;
        };

        let args = inputs
            .filter_map(|a| match a {
                syn::FnArg::Typed(t) => Some(Arg {
                    name: match &*t.pat {
                        syn::Pat::Ident(i) => i.ident.to_string(),
                        other => quote::quote!(#other).to_string(),
                    },
                    ty: {
                        let ty = &t.ty;
                        quote::quote!(#ty).to_string()
                    },
                }),
                _ => None,
            })
            .collect();

        handlers.push(Handler {
            name: f.sig.ident.to_string(),
            file: file.to_path_buf(),
            line: f.span().start().line as u32,
            end_line: f.span().end().line as u32,
            args,
            context_ty,
            body: crate::parser::body::summarize_body(f),
        });
    }
    handlers
}
