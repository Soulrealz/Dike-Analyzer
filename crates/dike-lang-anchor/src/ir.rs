use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Program {
    pub instructions: Vec<Handler>,
    pub accounts_structs: BTreeMap<String, AccountsStruct>,
    pub state_structs: BTreeMap<String, StateStruct>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Handler {
    pub name: String,
    pub file: PathBuf,
    pub line: u32,
    pub end_line: u32,
    pub args: Vec<Arg>,
    pub context_ty: String,
    pub body: HandlerBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Arg {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HandlerBody {
    pub calls: Vec<CallSite>,
    pub arithmetic: Vec<ArithOp>,
    pub checks: Vec<ImperativeCheck>,
    pub state_writes: Vec<StateWrite>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallSite {
    pub name: String,
    pub line: u32,
    pub is_cpi: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArithOp {
    pub op: String,
    pub line: u32,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CheckKind {
    Require,
    RequireKeysEq,
    RequireEq,
    AccessControl,
    ManualIf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImperativeCheck {
    pub kind: CheckKind,
    pub referenced_accounts: Vec<String>,
    /// Raw token text of the check's arguments, as `TokenStream::to_string()`
    /// renders it. Punctuation-preserving, unlike `referenced_accounts`, so a
    /// consumer can tell an identity comparison from a value comparison.
    /// Note proc-macro2 spaces punctuation: `vault.admin` renders `vault . admin`.
    pub text: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateWrite {
    pub account: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AccountsStruct {
    pub name: String,
    pub file: PathBuf,
    pub decls: Vec<AccountDecl>,
    pub line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountDecl {
    pub name: String,
    pub wrapper: Wrapper,
    pub boxed: bool,
    pub optional: bool,
    pub constraints: Vec<Constraint>,
    /// Line of the field's own `pub name: Type` declaration — always that
    /// line, never the `#[account(...)]` attribute above it, because this is
    /// derived from the field identifier's span, which never absorbs sibling
    /// attribute tokens (pinned by
    /// `parser::accounts::tests::field_ident_span_excludes_the_attribute`).
    ///
    /// Two location fields exist on this struct because they answer
    /// different questions for a detector: **wrapper-type findings** — a
    /// missing signer, an unchecked account, a wrong `Account<>` type — point
    /// at `line`, because that is the line a human would actually edit to fix
    /// the type. **Constraint findings** — a missing `has_one`, a seeds/bump
    /// gap, an absent `mut` — point at `attr_line`/`attr_end_line` instead,
    /// since the fix lives inside the `#[account(...)]` guard, not on the
    /// field's type line.
    pub line: u32,
    /// First line of this field's `#[account(...)]` attribute, or 0 if it has none.
    ///
    /// `Constraint` carries no location of its own (adding one to every variant
    /// would turn a plain enum into a struct-with-kind and break every
    /// detector's `matches!(c, Constraint::X(_))` pattern). This bounded
    /// attribute span is the cheaper alternative: a later mutation-testing
    /// stage that needs to delete a specific constraint (e.g. `has_one =
    /// admin`) from source text searches within `[attr_line, attr_end_line]`
    /// rather than the whole declaration, which can be wrong when the
    /// attribute spans multiple physical lines.
    pub attr_line: u32,
    /// Last line of this field's `#[account(...)]` attribute, or 0 if it has none.
    pub attr_end_line: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Wrapper {
    Signer,
    Account(String),
    InterfaceAccount(String),
    UncheckedAccount,
    AccountInfo,
    Program(String),
    SystemAccount,
    Sysvar(String),
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Constraint {
    Mut,
    Init,
    InitIfNeeded,
    Close(String),
    Seeds(String),
    Bump(Option<String>),
    HasOne(String),
    Owner(String),
    Address(String),
    SignerAttr,
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateStruct {
    pub name: String,
    pub fields: Vec<(String, String)>,
    pub file: PathBuf,
    pub line: u32,
    pub end_line: u32,
}

impl AccountDecl {
    /// D7: either the typed wrapper or the legacy attribute satisfies a signer check.
    pub fn enforces_signer(&self) -> bool {
        matches!(self.wrapper, Wrapper::Signer)
            || self.constraints.iter().any(|c| matches!(c, Constraint::SignerAttr))
    }

    /// Anchor performs no owner or discriminator validation on these.
    pub fn is_unchecked(&self) -> bool {
        matches!(self.wrapper, Wrapper::UncheckedAccount | Wrapper::AccountInfo)
    }

    pub fn has_one_targets(&self) -> Vec<String> {
        self.constraints
            .iter()
            .filter_map(|c| match c {
                Constraint::HasOne(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn has_seeds(&self) -> bool {
        self.constraints.iter().any(|c| matches!(c, Constraint::Seeds(_)))
    }

    pub fn has_bump(&self) -> bool {
        self.constraints.iter().any(|c| matches!(c, Constraint::Bump(_)))
    }

    pub fn is_init(&self) -> bool {
        self.constraints
            .iter()
            .any(|c| matches!(c, Constraint::Init | Constraint::InitIfNeeded))
    }

    /// Any explicit key/owner pin, which substitutes for type-based validation.
    pub fn is_address_pinned(&self) -> bool {
        self.constraints
            .iter()
            .any(|c| matches!(c, Constraint::Address(_) | Constraint::Owner(_)))
    }
}

impl Program {
    pub fn handler(&self, name: &str) -> Option<&Handler> {
        self.instructions.iter().find(|h| h.name == name)
    }

    /// The accounts struct bound to a handler's `Context<T>` type parameter.
    pub fn accounts_for(&self, handler: &Handler) -> Option<&AccountsStruct> {
        self.accounts_structs.get(&handler.context_ty)
    }
}

impl AccountsStruct {
    pub fn decl(&self, name: &str) -> Option<&AccountDecl> {
        self.decls.iter().find(|d| d.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(name: &str, wrapper: Wrapper, constraints: Vec<Constraint>) -> AccountDecl {
        AccountDecl {
            name: name.into(),
            wrapper,
            boxed: false,
            optional: false,
            constraints,
            line: 1,
            attr_line: 0,
            attr_end_line: 0,
        }
    }

    #[test]
    fn signer_wrapper_and_signer_attribute_are_distinct_but_both_recognized() {
        // D7: `Signer<'info>` and `#[account(signer)]` are different IR shapes.
        let typed = decl("authority", Wrapper::Signer, vec![]);
        let legacy = decl("authority", Wrapper::AccountInfo, vec![Constraint::SignerAttr]);
        assert!(typed.enforces_signer());
        assert!(legacy.enforces_signer());
        assert!(!decl("authority", Wrapper::AccountInfo, vec![]).enforces_signer());
    }

    #[test]
    fn unchecked_wrappers_are_identified() {
        assert!(decl("a", Wrapper::UncheckedAccount, vec![]).is_unchecked());
        assert!(decl("a", Wrapper::AccountInfo, vec![]).is_unchecked());
        assert!(!decl("a", Wrapper::Account("Vault".into()), vec![]).is_unchecked());
        assert!(!decl("a", Wrapper::InterfaceAccount("Mint".into()), vec![]).is_unchecked());
    }

    #[test]
    fn has_one_targets_are_readable() {
        let d = decl(
            "vault",
            Wrapper::Account("Vault".into()),
            vec![Constraint::HasOne("admin".into())],
        );
        assert_eq!(d.has_one_targets(), vec!["admin".to_string()]);
    }

    #[test]
    fn program_lookups_work() {
        let mut p = Program::default();
        p.instructions.push(Handler {
            name: "withdraw".into(),
            file: PathBuf::from("src/lib.rs"),
            line: 5,
            end_line: 10,
            args: vec![],
            context_ty: "Withdraw".into(),
            body: HandlerBody::default(),
        });
        assert!(p.handler("withdraw").is_some());
        assert!(p.handler("deposit").is_none());
    }
}
