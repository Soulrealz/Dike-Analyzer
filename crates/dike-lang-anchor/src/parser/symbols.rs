use crate::ir::{AccountsStruct, StateStruct};
use dike_core::analyzer::{Diagnostic, DiagnosticKind};
use std::collections::BTreeMap;
use std::path::Path;

/// One flat namespace keyed by bare type name (D10). Anchor context types are
/// referenced as `Context<Withdraw>` regardless of the module they live in, so
/// path-accurate resolution buys nothing here and costs a lot.
#[derive(Default)]
pub struct SymbolTable {
    pub accounts_structs: BTreeMap<String, AccountsStruct>,
    pub state_structs: BTreeMap<String, StateStruct>,
    pub diagnostics: Vec<Diagnostic>,
}

impl SymbolTable {
    pub fn insert_accounts(&mut self, s: AccountsStruct, file: &Path) {
        if let Some(existing) = self.accounts_structs.get(&s.name) {
            self.diagnostics.push(Diagnostic {
                file: Some(file.to_path_buf()),
                kind: DiagnosticKind::Ambiguity,
                message: format!(
                    "accounts struct `{}` also defined in {} — keeping the first",
                    s.name,
                    existing.file.display()
                ),
            });
            return;
        }
        self.accounts_structs.insert(s.name.clone(), s);
    }

    pub fn insert_state(&mut self, s: StateStruct, file: &Path) {
        if let Some(existing) = self.state_structs.get(&s.name) {
            self.diagnostics.push(Diagnostic {
                file: Some(file.to_path_buf()),
                kind: DiagnosticKind::Ambiguity,
                message: format!(
                    "state struct `{}` also defined in {} — keeping the first",
                    s.name,
                    existing.file.display()
                ),
            });
            return;
        }
        self.state_structs.insert(s.name.clone(), s);
    }
}
