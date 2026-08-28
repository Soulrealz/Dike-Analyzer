use crate::ir::{ArithOp, CallSite, CheckKind, HandlerBody, ImperativeCheck, StateWrite};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

#[derive(Default)]
struct BodyVisitor {
    body: HandlerBody,
    /// local variable name -> account name it was bound to via `&ctx.accounts.<name>` /
    /// `&mut ctx.accounts.<name>`. Populated in textual visitation order, so a later
    /// `let x = ...` naturally shadows an earlier one — this is a heuristic, not a real
    /// scope model: a name rebound to something unrelated inside a nested block will
    /// incorrectly "leak" that shadow to code after the block that uses the outer binding.
    /// Acceptable for a triage IR; not sound for a real borrow checker.
    aliases: HashMap<String, String>,
}

/// Collect every identifier in a token stream. The suppression pass intersects
/// these with real account names — doing it here would need scope we don't have.
fn identifiers(tokens: &proc_macro2::TokenStream) -> Vec<String> {
    let mut out = Vec::new();
    for t in tokens.clone() {
        match t {
            proc_macro2::TokenTree::Ident(i) => out.push(i.to_string()),
            proc_macro2::TokenTree::Group(g) => out.extend(identifiers(&g.stream())),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `ctx.accounts.vault.amount` -> Some("vault"); also resolves through `aliases`,
/// so `v.amount` -> Some("vault") when `v` was bound to `&ctx.accounts.vault`.
fn resolve_account_root(expr: &syn::Expr, aliases: &HashMap<String, String>) -> Option<String> {
    let mut names = Vec::new();
    let mut cur = expr;
    loop {
        match cur {
            syn::Expr::Field(f) => {
                if let syn::Member::Named(id) = &f.member {
                    names.push(id.to_string());
                }
                cur = &f.base;
            }
            syn::Expr::Path(p) => {
                names.push(p.path.segments.last()?.ident.to_string());
                break;
            }
            syn::Expr::MethodCall(m) => cur = &m.receiver,
            _ => return None,
        }
    }
    names.reverse(); // ["ctx", "accounts", "vault", "amount"]
    if names.len() >= 3 && names[0] == "ctx" && names[1] == "accounts" {
        return Some(names[2].clone());
    }
    names.first().and_then(|first| aliases.get(first)).cloned()
}

/// The identifier a `let` binding names, unwrapping a `Pat::Type` annotation
/// (`let v: &Vault = ...`) down to the bare `Pat::Ident`.
fn pat_ident_name(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(i) => Some(i.ident.to_string()),
        syn::Pat::Type(t) => pat_ident_name(&t.pat),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for BodyVisitor {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        // Compound assignment (`+=` etc.) parses as `Expr::Binary`, not `Expr::Assign`,
        // in syn 2.x — it must be recognized as both unchecked arithmetic AND a
        // state write, or `ctx.accounts.vault.amount += amount;` is invisible to both.
        let (op, is_compound_assign) = match node.op {
            syn::BinOp::Add(_) => ("+", false),
            syn::BinOp::Sub(_) => ("-", false),
            syn::BinOp::Mul(_) => ("*", false),
            syn::BinOp::Div(_) => ("/", false),
            syn::BinOp::AddAssign(_) => ("+=", true),
            syn::BinOp::SubAssign(_) => ("-=", true),
            syn::BinOp::MulAssign(_) => ("*=", true),
            syn::BinOp::DivAssign(_) => ("/=", true),
            _ => {
                visit::visit_expr_binary(self, node);
                return;
            }
        };
        let line = node.span().start().line as u32;
        self.body.arithmetic.push(ArithOp {
            op: op.to_string(),
            line,
            checked: false,
        });
        if is_compound_assign {
            if let Some(account) = resolve_account_root(&node.left, &self.aliases) {
                self.body.state_writes.push(StateWrite { account, line });
            }
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if name.starts_with("checked_")
            || name.starts_with("saturating_")
            || name.starts_with("wrapping_")
        {
            self.body.arithmetic.push(ArithOp {
                op: name.clone(),
                line: node.span().start().line as u32,
                checked: true,
            });
        }
        self.body.calls.push(CallSite {
            name,
            line: node.span().start().line as u32,
            is_cpi: false,
        });
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let name = {
            let f = &node.func;
            quote::quote!(#f).to_string().replace(' ', "")
        };
        let is_cpi = name.ends_with("invoke")
            || name.ends_with("invoke_signed")
            || name.contains("CpiContext")
            || node
                .args
                .iter()
                .any(|a| quote::quote!(#a).to_string().contains("CpiContext"));
        self.body.calls.push(CallSite {
            name,
            line: node.span().start().line as u32,
            is_cpi,
        });
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let kind = match name.as_str() {
            "require" => Some(CheckKind::Require),
            "require_eq" | "require_neq" | "require_gt" | "require_gte" => Some(CheckKind::RequireEq),
            "require_keys_eq" | "require_keys_neq" => Some(CheckKind::RequireKeysEq),
            _ => None,
        };
        if let Some(kind) = kind {
            self.body.checks.push(ImperativeCheck {
                kind,
                referenced_accounts: identifiers(&node.tokens),
                text: node.tokens.to_string(),
                line: node.span().start().line as u32,
            });
        }
        visit::visit_macro(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(account) = resolve_account_root(&node.left, &self.aliases) {
            self.body.state_writes.push(StateWrite {
                account,
                line: node.span().start().line as u32,
            });
        }
        visit::visit_expr_assign(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        // Alias ONLY `let x = &ctx.accounts.y` / `let x = &mut ctx.accounts.y` (or a
        // chain through an existing alias). Anything else — e.g.
        // `let k = ctx.accounts.vault.key();` — must NOT bind `k` to the account: that
        // local holds a `Pubkey`, not the account, and writes through it are not state
        // writes to the account.
        if let Some(name) = pat_ident_name(&node.pat) {
            if let Some(init) = &node.init {
                if let syn::Expr::Reference(r) = init.expr.as_ref() {
                    if let Some(account) = resolve_account_root(&r.expr, &self.aliases) {
                        self.aliases.insert(name, account);
                    }
                }
            }
        }
        visit::visit_local(self, node);
    }
}

pub fn summarize_body(f: &syn::ItemFn) -> HandlerBody {
    let mut v = BodyVisitor::default();
    for attr in &f.attrs {
        if attr.path().is_ident("access_control") {
            let tokens = match &attr.meta {
                syn::Meta::List(l) => l.tokens.clone(),
                _ => proc_macro2::TokenStream::new(),
            };
            v.body.checks.push(ImperativeCheck {
                kind: CheckKind::AccessControl,
                referenced_accounts: identifiers(&tokens),
                text: tokens.to_string(),
                line: attr.span().start().line as u32,
            });
        }
    }
    v.visit_block(&f.block);
    v.body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::CheckKind;

    fn body(src: &str) -> crate::ir::HandlerBody {
        let f: syn::ItemFn = syn::parse_str(src).unwrap();
        summarize_body(&f)
    }

    #[test]
    fn detects_unchecked_and_checked_arithmetic() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                let a = ctx.accounts.vault.amount - amount;
                let c = ctx.accounts.vault.amount.checked_add(amount).unwrap();
                Ok(())
            }
        "#);
        assert!(b.arithmetic.iter().any(|a| !a.checked && a.op == "-"));
        assert!(b.arithmetic.iter().any(|a| a.checked));
    }

    #[test]
    fn detects_cpi_calls() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>) -> Result<()> {
                let cpi = CpiContext::new(ctx.accounts.token_program.to_account_info(), accs);
                token::transfer(cpi, 1)?;
                invoke_signed(&ix, &accounts, signers)?;
                Ok(())
            }
        "#);
        assert!(b.calls.iter().any(|c| c.is_cpi));
        assert!(b.calls.iter().any(|c| c.name.contains("invoke_signed")));
    }

    #[test]
    fn detects_imperative_checks_and_their_identifiers() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>) -> Result<()> {
                require_keys_eq!(ctx.accounts.vault.admin, ctx.accounts.authority.key());
                require!(amount > 0, ErrorCode::Zero);
                Ok(())
            }
        "#);
        assert_eq!(b.checks.len(), 2);
        let keys_eq = b.checks.iter().find(|c| c.kind == CheckKind::RequireKeysEq).unwrap();
        assert!(keys_eq.referenced_accounts.contains(&"authority".to_string()));
        assert!(keys_eq.referenced_accounts.contains(&"vault".to_string()));
    }

    /// `text` preserves punctuation that `referenced_accounts` (via
    /// `identifiers()`) discards, so a consumer can distinguish an identity
    /// comparison from a value comparison. Documented rather than
    /// over-fitted: proc-macro2's `TokenStream::to_string()` spaces
    /// punctuation out (`vault.admin` renders as `vault . admin`, and a
    /// call's parens render as ` (` / `)`), so this only asserts substring
    /// containment, not an exact rendering.
    #[test]
    fn imperative_check_text_preserves_punctuation() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>) -> Result<()> {
                require_keys_eq!(ctx.accounts.vault.key(), ctx.accounts.authority.key());
                Ok(())
            }
        "#);
        let keys_eq = b.checks.iter().find(|c| c.kind == CheckKind::RequireKeysEq).unwrap();
        assert!(keys_eq.text.contains("key"));
        assert!(keys_eq.text.contains('('));
    }

    #[test]
    fn detects_access_control_attribute() {
        let b = body(r#"
            #[access_control(only_admin(&ctx))]
            pub fn withdraw(ctx: Context<W>) -> Result<()> { Ok(()) }
        "#);
        assert!(b.checks.iter().any(|c| c.kind == CheckKind::AccessControl));
    }

    #[test]
    fn detects_state_writes_through_ctx_accounts() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>) -> Result<()> {
                ctx.accounts.vault.amount = 0;
                Ok(())
            }
        "#);
        assert_eq!(b.state_writes.len(), 1);
        assert_eq!(b.state_writes[0].account, "vault");
    }

    #[test]
    fn detects_state_writes_through_a_mut_ref_alias() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.amount = vault.amount.checked_add(amount).unwrap();
                Ok(())
            }
        "#);
        assert_eq!(b.state_writes.len(), 1);
        assert_eq!(b.state_writes[0].account, "vault");
    }

    #[test]
    fn a_local_bound_to_a_field_value_is_not_treated_as_an_account_alias() {
        let b = body(r#"
            pub fn withdraw(ctx: Context<W>) -> Result<()> {
                let k = ctx.accounts.vault.key();
                k.log();
                Ok(())
            }
        "#);
        assert!(b.state_writes.is_empty());
    }

    #[test]
    fn detects_compound_assignment_as_unchecked_arithmetic_and_a_state_write() {
        let b = body(r#"
            pub fn deposit(ctx: Context<D>, amount: u64) -> Result<()> {
                ctx.accounts.vault.amount += amount;
                Ok(())
            }
        "#);
        assert!(b.arithmetic.iter().any(|a| !a.checked && a.op == "+="));
        assert_eq!(b.state_writes.len(), 1);
        assert_eq!(b.state_writes[0].account, "vault");
    }
}
