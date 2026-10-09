//! Shared helpers for the VexZygisk build tools.
//!
//! The two host tools (`ci-size-budget`, `make-update-json`) and the module
//! signer all used to be Python. They are small enough that what they share is
//! mostly about how they read a path and how they fail: the sizes are compared
//! against a path spelling that depends on the platform the build ran on, and a
//! missing file is an error the scripts are expected to survive.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Normalises a build-tree root the way the size budget did with
/// `rstrip("/\\")`: a trailing separator would otherwise turn the prefix test
/// into `build/` + `build/` and match nothing.
///
/// A root that is only separators normalises to empty, which is what the Python
/// did too - `"/".rstrip("/\\")` is `""`.
pub fn strip_trailing_sep(root: &str) -> &str {
    root.trim_end_matches(['/', '\\'])
}

/// True when `path` sits under one of `roots`, comparing whole path segments.
///
/// The Python compared `path.startswith(root + os.sep)`, which is a segment
/// test as long as both sides use the same separator. On Windows a build tree
/// spelled with forward slashes would not match a root spelled with backslashes,
/// so both spellings are accepted on either platform.
pub fn is_under_roots(path: &str, roots: &[&str]) -> bool {
    if roots.is_empty() {
        return true;
    }

    let normalise = |s: &str| s.replace('\\', "/");
    let path = normalise(path);

    roots.iter().any(|root| {
        let root = normalise(strip_trailing_sep(root));
        if root.is_empty() {
            return true;
        }

        path.starts_with(&root) && path.as_bytes().get(root.len()).is_some_and(|b| *b == b'/')
    })
}

/// File size in KiB, rounded down, which is the unit the budget is written in.
///
/// A file that cannot be stat'ed is reported as `None` rather than as zero: zero
/// would compare as "under budget" and quietly pass a build that has no such
/// binary at all.
pub fn size_kib(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len() / 1024)
}

/// Runs `git` and returns its stdout, or `None` when git is missing or the
/// command failed.
///
/// `make-update-json` needs three git answers and treats all three as advisory:
/// no tags yet, no commits, no HEAD - none of them are worth failing a release
/// over, so they degrade instead.
pub fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Collects the entries of a directory, sorted by name.
///
/// Every place the Python used `glob.glob` or `Path.rglob` walks directories in
/// filesystem order, which is not sorted on every filesystem; the update channel
/// and the signature both depend on a stable order, so the sort is made
/// explicit here rather than inherited.
pub fn sorted_children(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        Err(_) => return Vec::new(),
    };

    out.sort_by_key(|p| sort_key(p));
    out
}

/// The sort key the Python used for module paths: forward slashes regardless of
/// platform, so a Windows build and a Linux build produce the same order.
pub fn sort_key(path: &Path) -> String {
    sort_key_str(&path.to_string_lossy())
}

/// The same normalisation for something that is already a string.
///
/// A virtual name in the signature is a name rather than a path, so it cannot go
/// through `sort_key`; the two must agree, which is why this is the only place
/// the replacement happens.
pub fn sort_key_str(text: &str) -> String {
    text.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_separators_go() {
        assert_eq!(strip_trailing_sep("build/"), "build");
        assert_eq!(strip_trailing_sep("build\\"), "build");
        assert_eq!(strip_trailing_sep("build"), "build");
        assert_eq!(strip_trailing_sep("/"), "");
    }

    #[test]
    fn prefix_matches_whole_segments_only() {
        let roots = ["build"];
        // inside
        assert!(is_under_roots("build/out/x.zip", &roots));
        // a sibling whose name merely starts with the root
        assert!(!is_under_roots("builds/out/x.zip", &roots));
        // the root itself is not under itself, matching startswith(root + sep)
        assert!(!is_under_roots("build", &roots));
        // either separator on either platform
        assert!(is_under_roots("build\\out\\x.zip", &roots));
    }

    #[test]
    fn no_roots_means_everything() {
        assert!(is_under_roots("anything/at/all", &[]));
    }

    #[test]
    fn sort_key_normalises_separators() {
        assert_eq!(
            sort_key(Path::new(r"lib64\libzygisk.so")),
            "lib64/libzygisk.so"
        );
        assert_eq!(sort_key_str(r"lib64\libzygisk.so"), "lib64/libzygisk.so");
        assert_eq!(sort_key(Path::new("a/b")), sort_key_str("a/b"));
    }
}
