use crate::ir::{ArithOp, CallSite, CheckKind, HandlerBody, ImperativeCheck, StateWrite};
use std::collections::{BTreeSet, HashMap};
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
    /// local variable name -> the set of accounts whose value flows into it.
    ///
    /// Distinct from `aliases`, which answers "is this local *the* account" for
    /// state-write attribution. This answers "which accounts' values are inside
    /// this local", which is a union and not a single name: a `Transfer { .. }`
    /// struct literal carries three at once.
    ///
    /// A `HashMap` is safe here despite Rule 5 because it is only ever looked
    /// up by key and never iterated; the accumulator that reaches the IR is the
    /// `BTreeSet` below.
    taint: HashMap<String, BTreeSet<String>>,
    /// Accounts seen flowing into a value-moving sink. A `BTreeSet` so the IR
    /// field is sorted and deduplicated by construction, with no later sort to
    /// forget (Rule 5).
    reaches_sink: BTreeSet<String>,
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

/// Calls that move value. Domain vocabulary, and therefore in
/// `dike-lang-anchor` and never in `dike-core` (Rule 2).
///
/// Matched on the LAST path segment, so `transfer`, `token::transfer`,
/// `anchor_spl::token::transfer` and `system_program::transfer` all count
/// without enumerating the module paths people actually write.
///
/// `CpiContext::new` and `new_with_signer` are deliberately absent. They are
/// intermediate constructors: taint flows *through* them into the `transfer`
/// that consumes them, and treating the constructor as the sink would report a
/// handler that builds a context and never invokes it. For the same reason
/// `CallSite::is_cpi` cannot serve as the sink predicate — it is already true
/// for `CpiContext::new`.
const VALUE_SINKS: [&str; 4] = ["transfer", "transfer_checked", "burn", "mint_to"];

fn is_value_sink(path: &str) -> bool {
    let last = path.rsplit("::").next().unwrap_or(path);
    VALUE_SINKS.contains(&last)
}

/// Whether an assignment target is a native lamport balance:
/// `**a.try_borrow_mut_lamports()?` or `**b.lamports.borrow_mut()`. Lamport
/// movement is not a CPI at all, so the sink set above never sees it.
fn is_lamports_target(expr: &syn::Expr) -> bool {
    let text: String = quote::quote!(#expr)
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    text.contains("lamports") && text.contains("borrow_mut")
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

/// Which accounts' values flow into `expr`.
///
/// Three propagation forms, which is everything the fixtures and the
/// `sealevel-attacks` set need: a `let`-bound local, a struct literal, and a
/// method or function call, whose taint is the union of its receiver's and its
/// arguments'. The wrapper expressions below (`&x`, `*x`, `(x)`, `x?`,
/// `x as T`, tuples, arrays, binaries) carry taint through unchanged; they are
/// not propagation rules so much as the absence of a barrier.
///
/// Deliberately NOT handled: loops, branches, and calls into other functions in
/// the crate. Nothing in scope needs them, and each would make the result
/// depend on evaluation order this visitor does not model.
fn expr_taint(
    expr: &syn::Expr,
    aliases: &HashMap<String, String>,
    taint: &HashMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    // A `ctx.accounts.X...` chain, or a local aliased to one, is a source and
    // needs no further descent.
    if let Some(account) = resolve_account_root(expr, aliases) {
        out.insert(account);
        return out;
    }
    // Not `let mut`: it mutates only its `out` argument, never a capture, and
    // this build denies warnings.
    let union = |e: &syn::Expr, out: &mut BTreeSet<String>| {
        out.extend(expr_taint(e, aliases, taint));
    };
    match expr {
        syn::Expr::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                if let Some(t) = taint.get(&seg.ident.to_string()) {
                    out.extend(t.iter().cloned());
                }
            }
        }
        syn::Expr::Struct(s) => {
            for f in &s.fields {
                union(&f.expr, &mut out);
            }
            if let Some(rest) = &s.rest {
                union(rest, &mut out);
            }
        }
        syn::Expr::MethodCall(m) => {
            union(&m.receiver, &mut out);
            for a in &m.args {
                union(a, &mut out);
            }
        }
        syn::Expr::Call(c) => {
            for a in &c.args {
                union(a, &mut out);
            }
        }
        syn::Expr::Reference(r) => union(&r.expr, &mut out),
        syn::Expr::Unary(u) => union(&u.expr, &mut out),
        syn::Expr::Paren(p) => union(&p.expr, &mut out),
        syn::Expr::Group(g) => union(&g.expr, &mut out),
        syn::Expr::Try(t) => union(&t.expr, &mut out),
        syn::Expr::Cast(c) => union(&c.expr, &mut out),
        syn::Expr::Field(f) => union(&f.base, &mut out),
        syn::Expr::Index(i) => {
            union(&i.expr, &mut out);
            union(&i.index, &mut out);
        }
        syn::Expr::Binary(b) => {
            union(&b.left, &mut out);
            union(&b.right, &mut out);
        }
        syn::Expr::Array(a) => {
            for e in &a.elems {
                union(e, &mut out);
            }
        }
        syn::Expr::Tuple(t) => {
            for e in &t.elems {
                union(e, &mut out);
            }
        }
        _ => {}
    }
    out
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
            // Native lamport movement: `**a.lamports.borrow_mut() -= n`. Both
            // sides are recorded — the drained account and the credited one are
            // each moving value, and Rule 3 favours reporting both.
            if is_lamports_target(&node.left) {
                self.reaches_sink
                    .extend(expr_taint(&node.left, &self.aliases, &self.taint));
                self.reaches_sink
                    .extend(expr_taint(&node.right, &self.aliases, &self.taint));
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
        if is_value_sink(&name) {
            self.reaches_sink
                .extend(expr_taint(&node.receiver, &self.aliases, &self.taint));
            for a in &node.args {
                self.reaches_sink
                    .extend(expr_taint(a, &self.aliases, &self.taint));
            }
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
        if is_value_sink(&name) {
            for a in &node.args {
                self.reaches_sink
                    .extend(expr_taint(a, &self.aliases, &self.taint));
            }
        }
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

    /// A guard written as plain Rust rather than as an Anchor macro.
    ///
    /// `if !ctx.accounts.authority.is_signer { return Err(...) }` is the same
    /// assertion as `require!(ctx.accounts.authority.is_signer, ...)`, and it
    /// is how the Anchor authors' own reference set writes its fixes. Only
    /// macro calls were recorded as checks until 2026-09-19, so the
    /// suppression pass could not see any of them: measured over
    /// `coral-xyz/sealevel-attacks`, dike reported identical findings on the
    /// `insecure` and `secure` variants of six categories out of eleven.
    ///
    /// Only an `if` whose taken branch *rejects* counts. A branch that merely
    /// does something is not a guard, and treating it as one would let any
    /// mention of an account silence a finding about it — the dangerous
    /// direction for the one pass that deletes findings.
    ///
    /// The condition's text is recorded as written, negation included. The
    /// suppression pass matches on substrings such as `X.is_signer` and
    /// `X.key()` rather than evaluating the condition, and an `if` that
    /// rejects asserts the negation of its condition, so the two line up:
    /// `if !x.is_signer { return Err }` asserts `x.is_signer`, exactly as
    /// `require!(x.is_signer)` does.
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if branch_rejects(&node.then_branch) {
            let cond = &node.cond;
            let tokens = quote::quote!(#cond);
            self.body.checks.push(ImperativeCheck {
                kind: CheckKind::ManualIf,
                referenced_accounts: identifiers(&tokens),
                text: tokens.to_string(),
                line: node.span().start().line as u32,
            });
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        // The plain-`=` spelling of the lamport sink above. Compound assignment
        // does not reach here — in syn 2.x it parses as `Expr::Binary`.
        if is_lamports_target(&node.left) {
            self.reaches_sink
                .extend(expr_taint(&node.left, &self.aliases, &self.taint));
            self.reaches_sink
                .extend(expr_taint(&node.right, &self.aliases, &self.taint));
        }
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
                        self.aliases.insert(name.clone(), account);
                    }
                }
                // Taint is broader than aliasing: a local holding a
                // `Transfer { .. }` is not any one account, but three accounts'
                // values are inside it. Replaces rather than merges — textual
                // order, later binding wins, as `aliases` above does.
                let t = expr_taint(&init.expr, &self.aliases, &self.taint);
                self.taint.insert(name, t);
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
    // A `BTreeSet` drains in sorted order, so the field is sorted and
    // deduplicated by construction (Rule 5).
    v.body.reaches_value_sink = v.reaches_sink.into_iter().collect();
    v.body
}

/// Whether a block rejects: returns an error, or panics.
///
/// Token-level on purpose. The shapes in the wild are `return Err(..)`,
/// `return err!(..)`, `Err(..)?`, and `panic!`/`unreachable!`, and enumerating
/// them structurally would be a longer list that still missed the next one.
fn branch_rejects(block: &syn::Block) -> bool {
    let text = quote::quote!(#block).to_string();
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("returnErr")
        || compact.contains("returnerr!")
        || compact.contains("Err(")
        || compact.contains("panic!")
        || compact.contains("unreachable!")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::CheckKind;

    fn body(src: &str) -> crate::ir::HandlerBody {
        let f: syn::ItemFn = syn::parse_str(src).unwrap();
        summarize_body(&f)
    }

    /// The canonical secure pattern from `coral-xyz/sealevel-attacks`, the
    /// Anchor authors' own reference set:
    ///
    /// ```ignore
    /// if !ctx.accounts.authority.is_signer {
    ///     return Err(ProgramError::MissingRequiredSignature);
    /// }
    /// ```
    ///
    /// Measured 2026-09-19 over all 35 of its programs: dike reported the same
    /// findings on the `insecure` and `secure` variants of six categories out
    /// of eleven, because the fix is written as a plain `if` and only macro
    /// calls were ever recorded as checks. `CheckKind::ManualIf` existed in the
    /// IR from the start with nothing producing it.
    #[test]
    fn a_manual_if_that_returns_an_error_is_a_check() {
        let b = body(r#"
            pub fn log_message(ctx: Context<LogMessage>) -> ProgramResult {
                if !ctx.accounts.authority.is_signer {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                Ok(())
            }
        "#);
        let check = b
            .checks
            .iter()
            .find(|c| c.kind == CheckKind::ManualIf)
            .expect("the guard was not recorded as a check");
        assert!(
            check.referenced_accounts.iter().any(|a| a == "authority"),
            "{:?}",
            check.referenced_accounts
        );
        assert!(check.text.contains("is_signer"), "{}", check.text);
        assert!(check.line > 0);
    }

    /// An `if` that does not reject is not a guard. Recording it would let any
    /// branch mentioning an account silence a finding about that account,
    /// which is the dangerous direction for a pass that deletes findings.
    #[test]
    fn a_manual_if_that_does_not_reject_is_not_a_check() {
        let b = body(r#"
            pub fn log_message(ctx: Context<LogMessage>) -> ProgramResult {
                if ctx.accounts.authority.is_signer {
                    msg!("signed");
                }
                Ok(())
            }
        "#);
        assert!(
            !b.checks.iter().any(|c| c.kind == CheckKind::ManualIf),
            "{:?}",
            b.checks
        );
    }

    /// The other spelling of rejection, and the one older Anchor code uses.
    #[test]
    fn a_manual_if_that_calls_err_is_a_check() {
        let b = body(r#"
            pub fn settle(ctx: Context<Settle>) -> Result<()> {
                if ctx.accounts.vault.admin != ctx.accounts.admin.key() {
                    return err!(VaultError::Unauthorized);
                }
                Ok(())
            }
        "#);
        assert!(b.checks.iter().any(|c| c.kind == CheckKind::ManualIf), "{:?}", b.checks);
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

    /// The three-hop shape from `tests/fixtures/programs/vault`, lines 22-28:
    /// account -> struct literal -> local -> call argument -> sink. A rule that
    /// reads only `token::transfer`'s own argument tokens sees `cpi_ctx` and
    /// `amount` and nothing else.
    ///
    /// Breaks if: struct-literal propagation is dropped, `let` propagation is
    /// dropped, argument propagation is dropped, or `transfer` leaves the sink
    /// set.
    #[test]
    fn taint_reaches_a_sink_through_a_struct_literal_a_local_and_a_cpi_context() {
        let b = body(r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                let cpi_accounts = Transfer {
                    from: ctx.accounts.depositor_token_account.to_account_info(),
                    to: ctx.accounts.vault_token_account.to_account_info(),
                    authority: ctx.accounts.depositor.to_account_info(),
                };
                let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                token::transfer(cpi_ctx, amount)?;
                Ok(())
            }
        "#);
        for want in ["depositor", "depositor_token_account", "token_program", "vault_token_account"] {
            assert!(
                b.reaches_value_sink.iter().any(|a| a == want),
                "{want} missing from {:?}",
                b.reaches_value_sink
            );
        }
    }

    /// The other half of the shape-insensitivity claim: the same accounts
    /// inlined into the sink call, with no local at all. `leaky_vault` writes
    /// the first shape and `sealevel-attacks/5-arbitrary-cpi` writes this one;
    /// a rule that treated them differently would be keying on code shape.
    ///
    /// Breaks if: propagation is implemented only over `let` bindings.
    #[test]
    fn taint_reaches_an_inlined_sink_with_no_local_binding() {
        let b = body(r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                token::transfer(
                    CpiContext::new(
                        ctx.accounts.token_program.to_account_info(),
                        Transfer {
                            from: ctx.accounts.depositor_token_account.to_account_info(),
                            to: ctx.accounts.vault_token_account.to_account_info(),
                            authority: ctx.accounts.depositor.to_account_info(),
                        },
                    ),
                    amount,
                )?;
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.iter().any(|a| a == "vault_token_account"), "{:?}", b.reaches_value_sink);
        assert!(b.reaches_value_sink.iter().any(|a| a == "depositor_token_account"), "{:?}", b.reaches_value_sink);
    }

    /// An account the handler only writes state on does not reach a value
    /// sink. If this field meant "every account the handler mentions" it would
    /// carry no information and the detector reading it would fire on
    /// everything.
    ///
    /// Breaks if: taint is seeded from every `ctx.accounts.X` in the body
    /// rather than from the ones that flow into a sink.
    #[test]
    fn an_account_that_only_takes_a_state_write_does_not_reach_a_sink() {
        let b = body(r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                ctx.accounts.config.counter = amount;
                let cpi_accounts = Transfer {
                    from: ctx.accounts.source.to_account_info(),
                    to: ctx.accounts.dest.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts), amount)?;
                Ok(())
            }
        "#);
        assert!(!b.reaches_value_sink.iter().any(|a| a == "config"), "{:?}", b.reaches_value_sink);
        assert!(b.reaches_value_sink.iter().any(|a| a == "source"), "{:?}", b.reaches_value_sink);
    }

    /// `CpiContext::new` and `new_with_signer` are intermediate constructors,
    /// not sinks. A handler that builds one and never invokes it moves no
    /// value.
    ///
    /// Breaks if: `CpiContext` joins the sink set, or if `CallSite::is_cpi` is
    /// reused as the sink predicate — `is_cpi` is already true for
    /// `CpiContext::new`, which is exactly why it cannot serve here.
    #[test]
    fn building_a_cpi_context_without_invoking_it_is_not_a_sink() {
        let b = body(r#"
            pub fn deposit(ctx: Context<Deposit>) -> Result<()> {
                let cpi_accounts = Transfer {
                    from: ctx.accounts.source.to_account_info(),
                    to: ctx.accounts.dest.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                let _unused = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.is_empty(), "{:?}", b.reaches_value_sink);
    }

    /// Rule 5. Two sinks touching overlapping accounts must not produce
    /// duplicates or source-order output; `dike ir` prints this field and the
    /// eval harness compares runs byte for byte.
    ///
    /// Breaks if: the accumulator becomes a `Vec` filled by `push`, or a
    /// `HashSet`.
    #[test]
    fn reaches_value_sink_is_sorted_and_deduplicated() {
        let b = body(r#"
            pub fn sweep(ctx: Context<Sweep>, amount: u64) -> Result<()> {
                token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), Transfer {
                    from: ctx.accounts.zeta.to_account_info(),
                    to: ctx.accounts.alpha.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                }), amount)?;
                token::burn(CpiContext::new(ctx.accounts.token_program.to_account_info(), Burn {
                    mint: ctx.accounts.alpha.to_account_info(),
                    from: ctx.accounts.zeta.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                }), amount)?;
                Ok(())
            }
        "#);
        let mut sorted = b.reaches_value_sink.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(b.reaches_value_sink, sorted, "{:?}", b.reaches_value_sink);
        assert!(b.reaches_value_sink.iter().any(|a| a == "alpha"));
        assert!(b.reaches_value_sink.iter().any(|a| a == "zeta"));
    }

    /// Native lamport movement, which uses no CPI at all. Compound assignment
    /// parses as `Expr::Binary` in syn 2.x rather than `Expr::Assign` — the
    /// same trap `visit_expr_binary` already documents — so the sink has to be
    /// recognized in both places.
    ///
    /// Breaks if: the `lamports` / `borrow_mut` assignment sink is dropped, or
    /// hooked only into `visit_expr_assign`.
    #[test]
    fn a_lamports_borrow_mut_assignment_is_a_sink() {
        let b = body(r#"
            pub fn drain(ctx: Context<Drain>, amount: u64) -> Result<()> {
                **ctx.accounts.recipient.lamports.borrow_mut() += amount;
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.iter().any(|a| a == "recipient"), "{:?}", b.reaches_value_sink);
    }

    /// Flow-insensitive, textual order, later binding wins — the same
    /// heuristic `aliases` already documents. Pinned so the choice reads as a
    /// decision rather than an accident.
    ///
    /// Breaks if: `let` taint is merged into the existing entry instead of
    /// replacing it.
    #[test]
    fn a_rebound_local_replaces_its_earlier_taint() {
        let b = body(r#"
            pub fn shift(ctx: Context<Shift>, amount: u64) -> Result<()> {
                let accs = Transfer {
                    from: ctx.accounts.first.to_account_info(),
                    to: ctx.accounts.dest.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                let accs = Transfer {
                    from: ctx.accounts.second.to_account_info(),
                    to: ctx.accounts.dest.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                };
                token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), accs), amount)?;
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.iter().any(|a| a == "second"), "{:?}", b.reaches_value_sink);
        assert!(!b.reaches_value_sink.iter().any(|a| a == "first"), "{:?}", b.reaches_value_sink);
    }

    /// A method-call sink, the spelling hand-rolled wrappers use. Matching is
    /// on the LAST path segment so `transfer`, `token::transfer` and
    /// `anchor_spl::token::transfer` all count without enumerating module
    /// paths.
    ///
    /// Breaks if: only `syn::ExprCall` is hooked and `ExprMethodCall` is not.
    #[test]
    fn a_method_call_sink_is_matched_on_its_name() {
        let b = body(r#"
            pub fn go(ctx: Context<Go>, amount: u64) -> Result<()> {
                ctx.accounts.helper.mint_to(ctx.accounts.recipient.to_account_info(), amount)?;
                Ok(())
            }
        "#);
        assert!(b.reaches_value_sink.iter().any(|a| a == "recipient"), "{:?}", b.reaches_value_sink);
    }
}
