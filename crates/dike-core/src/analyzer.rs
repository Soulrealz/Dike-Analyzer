use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct SourceTree {
    pub root: PathBuf,
    pub files: Vec<SourceFile>,
}

impl SourceTree {
    /// Read every `.rs` file under `root`. Never builds anything (Global Constraints).
    pub fn load(root: &Path) -> std::io::Result<SourceTree> {
        // A missing or non-directory root is a tool failure, not a partial result:
        // WalkDir would otherwise fold it into the same per-entry tolerance used
        // for unreadable files deep inside an otherwise-valid tree.
        if !root.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} is not a directory", root.display()),
            ));
        }
        let mut files = Vec::new();
        let walker = walkdir::WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                // Always include the root; filter subdirectories and files
                if e.path() == root {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                !(name == "target" || name.starts_with('.'))
            });
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                // An unreadable entry is a skipped file, not a failed run.
                Err(err) => {
                    tracing::warn!(%err, "skipping unreadable path");
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.path().extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let bytes = match std::fs::read(entry.path()) {
                Ok(b) => b,
                Err(err) => {
                    tracing::warn!(path = ?entry.path(), %err, "skipping unreadable file");
                    continue;
                }
            };
            files.push(SourceFile {
                path: entry.path().to_path_buf(),
                text: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path)); // determinism
        Ok(SourceTree { root: root.to_path_buf(), files })
    }

    /// Physical lines across all analyzed files. Denominator for the noise floor (D18).
    pub fn total_loc(&self) -> usize {
        self.files.iter().map(|f| f.text.lines().count()).sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    /// A file could not be parsed; it was skipped. Reported in coverage, never silent.
    ParseFailure,
    Skipped,
    /// Two symbols share a name across files; first-seen won (D10).
    Ambiguity,
    /// A whole track did not run (e.g. LLM unavailable). Degraded, not failed.
    TrackSkipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub file: Option<PathBuf>,
    pub kind: DiagnosticKind,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<Diagnostic>,
    pub files_analyzed: usize,
}

/// The extensibility seam. A Solidity port implements this and touches nothing else.
pub trait Analyzer {
    fn name(&self) -> &'static str;
    fn analyze(&self, tree: &SourceTree) -> AnalysisResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn load_errors_on_nonexistent_root() {
        let root = std::path::Path::new("/definitely/does/not/exist/dike-seam-probe");
        let err = SourceTree::load(root).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn load_on_empty_directory_returns_ok_with_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let tree = SourceTree::load(dir.path()).unwrap();
        assert!(tree.files.is_empty());
    }

    #[test]
    fn load_collects_rust_files_and_skips_target_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join("src/lib.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        fs::write(root.join("src/notes.md"), "# not rust").unwrap();
        fs::write(root.join("target/debug/build.rs"), "fn c() {}").unwrap();
        fs::write(root.join(".git/hook.rs"), "fn d() {}").unwrap();

        let tree = SourceTree::load(root).unwrap();

        assert_eq!(tree.files.len(), 1);
        assert!(tree.files[0].path.ends_with("src/lib.rs"));
        assert_eq!(tree.total_loc(), 2);
    }

    #[test]
    fn load_survives_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bad.rs"), [0xff, 0xfe, b'\n']).unwrap();
        let tree = SourceTree::load(dir.path()).unwrap();
        assert_eq!(tree.files.len(), 1);
    }

    #[test]
    fn load_returns_files_in_sorted_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("z_dir")).unwrap();
        fs::create_dir_all(root.join("a_dir")).unwrap();
        fs::create_dir_all(root.join("m_dir")).unwrap();

        // Create files in deliberately non-alphabetical order
        fs::write(root.join("z_dir/zebra.rs"), "fn z() {}").unwrap();
        fs::write(root.join("a_dir/apple.rs"), "fn a() {}").unwrap();
        fs::write(root.join("m_dir/mango.rs"), "fn m() {}").unwrap();

        let tree = SourceTree::load(root).unwrap();

        assert_eq!(tree.files.len(), 3);
        // Verify they're sorted by path
        let paths: Vec<_> = tree.files.iter().map(|f| f.path.clone()).collect();
        assert!(paths[0].ends_with("a_dir/apple.rs"));
        assert!(paths[1].ends_with("m_dir/mango.rs"));
        assert!(paths[2].ends_with("z_dir/zebra.rs"));
    }

    #[test]
    fn load_skips_unreadable_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let readable_path = root.join("readable.rs");
        let unreadable_path = root.join("unreadable.rs");

        fs::write(&readable_path, "fn readable() {}").unwrap();
        fs::write(&unreadable_path, "fn unreadable() {}").unwrap();

        // Make the file unreadable and probe whether permissions are actually enforced
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o000);
            let _ = fs::set_permissions(&unreadable_path, perms);

            // Probe: attempt to read the unreadable file directly.
            // This answers whether permissions are actually enforced in this environment.
            if fs::read(&unreadable_path).is_err() {
                // Permissions are enforced (not running as root on this filesystem).
                // Verify that load() skips the unreadable file.
                let tree = SourceTree::load(root).unwrap();
                assert_eq!(tree.files.len(), 1);
                assert!(tree.files[0].path.ends_with("readable.rs"));
            }
            // else: Running as root or on a filesystem that doesn't enforce DAC permissions.
            // In that case, even 0o000 files are readable here, so skip this assertion.

            // Restore permissions so cleanup works
            let perms = fs::Permissions::from_mode(0o644);
            let _ = fs::set_permissions(&unreadable_path, perms);
        }
        #[cfg(not(unix))]
        {
            // On non-Unix platforms, skip this test
        }
    }
}
