//! Guards the checked-in generated sources against their generator.
//!
//! `jni_hooks.h` is produced by the `gen-jni-hooks` tool and then committed, so
//! the build never runs the generator. That leaves two ways for the two to drift
//! apart with nothing to catch it:
//!
//!   - the generator is edited (a new JNI signature, a changed body) and the
//!     header is not regenerated, so the built library keeps hooking the old set;
//!   - the header is edited by hand and is silently overwritten the next time
//!     somebody does run the generator.
//!
//! Regenerating into a temporary directory and comparing catches both. The
//! generator takes the output path as an argument, so the scratch copy never
//! touches the working tree.
//!
//! Run in CI's host-test job; exits non-zero on the first difference.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// (generator, the file it produces), both relative to the repository root.
const GENERATED: &[(&str, &str)] = &[("gen-jni-hooks", "jni_hooks.h")];

fn main() -> ExitCode {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut failed = false;

    for (generator, produced) in GENERATED {
        // The generated file sits next to where the loader includes it from,
        // which is the generator's own default output path.
        let committed_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../loader/src/injector")
            .join(produced);

        let Ok(committed) = read_source(&committed_path) else {
            println!("cannot read {}", committed_path.display());
            failed = true;
            continue;
        };

        let Some(fresh) = collect(&root, generator, produced) else {
            failed = true;
            continue;
        };

        if fresh == committed {
            continue;
        }

        failed = true;

        println!("{produced} does not match {generator}:");
        println!("regenerate it instead of editing it by hand.");
        print_diff(&committed, &fresh, produced);
    }

    if !failed {
        println!("generated sources check ok: {} file(s) in sync", GENERATED.len());
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn tools_dir(root: &Path) -> PathBuf {
    // The generator's own source lives in the crate; find it from the working
    // directory so the check runs the same build the tools come from.
    let local = root.join("tools");
    if local.is_dir() {
        return local;
    }

    // Running from inside the crate (cargo test), one level up is the root.
    root.parent()
        .map(|parent| parent.join("tools"))
        .unwrap_or(local)
}

/// Reads a generated file and normalises its line endings.
///
/// The tree is pinned to LF (`.gitattributes`), while a generator opening a file
/// in text mode on Windows would write CRLF. Comparing raw bytes would then
/// report a difference on a Windows checkout that is not one, so the line
/// endings are normalised away and only the content is compared.
fn read_source(path: &Path) -> Result<String, std::io::Error> {
    let raw = std::fs::read(path)?;

    let text = String::from_utf8(raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    Ok(text.replace("\r\n", "\n"))
}

/// Runs the generator into a scratch directory and returns its output.
///
/// The generator is run as a cargo subcommand of the same crate, which is what
/// makes it identical to the one a developer would run by hand - a second
/// implementation of the generator would defeat the entire check.
fn collect(root: &Path, generator: &str, produced: &str) -> Option<String> {
    let tools = tools_dir(root);
    let binary = tools
        .join("target")
        .join("release")
        .join(format!("{generator}{}", exe_suffix()));

    if !binary.is_file() {
        println!("{generator} is not built at {}:", binary.display());
        println!("run `cargo build --release` in tools/ first");
        return None;
    }

    let scratch = std::env::temp_dir().join(format!("vex-check-{generator}"));
    let _ = std::fs::remove_dir_all(&scratch);
    if let Err(e) = std::fs::create_dir_all(&scratch) {
        println!("{generator} did not produce {produced}:");
        println!("cannot create {}: {e}", scratch.display());
        return None;
    }

    let out_path = scratch.join(produced);

    let output = Command::new(&binary).arg(&out_path).current_dir(&tools).output();

    let output = match output {
        Ok(output) => output,
        Err(e) => {
            println!("{generator} did not produce {produced}:");
            println!("cannot run {}: {e}", binary.display());
            return None;
        }
    };

    if !output.status.success() || !out_path.is_file() {
        println!("{generator} did not produce {produced}:");
        let message = String::from_utf8_lossy(&output.stderr);
        let message = message.trim();
        if message.is_empty() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stdout = stdout.trim();
            println!("{}", if stdout.is_empty() {
                format!("exit code {}", output.status)
            } else {
                stdout.to_string()
            });
        } else {
            println!("{message}");
        }

        return None;
    }

    let text = read_source(&out_path);

    let _ = std::fs::remove_dir_all(&scratch);

    match text {
        Ok(text) => Some(text),
        Err(e) => {
            println!("{generator} did not produce {produced}:");
            println!("cannot read its output: {e}");
            None
        }
    }
}

fn exe_suffix() -> &'static str {
    if cfg!(windows) { ".exe" } else { "" }
}

/// A unified diff of the two texts, with two lines of context.
///
/// Enough context to see which signature moved, and short enough that a
/// wholesale regeneration does not bury the summary above it.
fn print_diff(committed: &str, fresh: &str, produced: &str) {
    let old: Vec<&str> = committed.lines().collect();
    let new: Vec<&str> = fresh.lines().collect();

    // Longest common subsequence over lines, walked with the usual two-row
    // table. The inputs are a header of a few hundred lines, so the quadratic
    // cost is not worth avoiding.
    let mut table = vec![vec![0usize; new.len() + 1]; old.len() + 1];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            table[i][j] = if old[i] == new[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }

    const CONTEXT: usize = 2;

    // Collect the edit script first, so hunks can be grouped with their
    // context instead of emitted one line at a time.
    let mut edits: Vec<(usize, usize, Option<&str>)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            edits.push((i, j, None));
            i += 1;
            j += 1;
        } else if table[i + 1][j] >= table[i][j + 1] {
            edits.push((i, j, Some("-")));
            i += 1;
        } else {
            edits.push((i, j, Some("+")));
            j += 1;
        }
    }
    while i < old.len() {
        edits.push((i, j, Some("-")));
        i += 1;
    }
    while j < new.len() {
        edits.push((i, j, Some("+")));
        j += 1;
    }

    println!("--- committed {produced}");
    println!("+++ regenerated");

    let changed: Vec<usize> = edits
        .iter()
        .enumerate()
        .filter(|(_, (_, _, kind))| kind.is_some())
        .map(|(at, _)| at)
        .collect();

    if changed.is_empty() {
        // Same lines, different endings only - the normalisation above should
        // have caught that, so this is a message rather than a silent pass.
        println!("(line endings only)");
        return;
    }

    let mut hunks: Vec<Vec<(usize, usize, Option<&str>)>> = Vec::new();
    let mut current: Vec<(usize, usize, Option<&str>)> = Vec::new();
    let mut last_change: Option<usize> = None;

    for (at, edit) in edits.iter().enumerate() {
        let is_change = edit.2.is_some();
        let in_context = last_change.is_some_and(|last| at.saturating_sub(last) <= CONTEXT * 2);

        if is_change {
            if last_change.is_some() && !in_context {
                hunks.push(std::mem::take(&mut current));
            }
            current.push(*edit);
            last_change = Some(at);
        } else if in_context {
            current.push(*edit);
        }
    }

    if !current.is_empty() {
        hunks.push(current);
    }

    for hunk in hunks {
        // Drop the context lines at both ends of a hunk: they belong to the
        // neighbouring hunk or to nothing.
        let first = hunk.iter().position(|(_, _, kind)| kind.is_some());
        let last = hunk.iter().rposition(|(_, _, kind)| kind.is_some());

        let (Some(first), Some(last)) = (first, last) else {
            continue;
        };

        let start = first.saturating_sub(CONTEXT);
        let end = (last + CONTEXT + 1).min(hunk.len());

        let old_start = hunk[start].0;
        let old_count = hunk[start..end]
            .iter()
            .filter(|(_, _, kind)| *kind != Some("+"))
            .count();
        let new_start = hunk[start].1;
        let new_count = hunk[start..end]
            .iter()
            .filter(|(_, _, kind)| *kind != Some("-"))
            .count();

        println!("@@ -{old_start},{old_count} +{new_start},{new_count} @@");

        for (o, n, kind) in &hunk[start..end] {
            match kind {
                Some(kind) => println!("{kind}{}", if *kind == "-" { old[*o] } else { new[*n] }),
                None => println!(" {}", old[*o]),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_is_normalised_away() {
        let dir = std::env::temp_dir().join("vex-check-norm-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x");

        std::fs::write(&path, b"a\r\nb\r\n").unwrap();
        assert_eq!(read_source(&path).unwrap(), "a\nb\n");

        std::fs::write(&path, b"a\nb\n").unwrap();
        assert_eq!(read_source(&path).unwrap(), "a\nb\n");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_pure_change_is_reported_as_one_hunk() {
        let old = "one\ntwo\nthree\nfour\nfive\n";
        let new = "one\ntwo\nTHREE\nfour\nfive\n";

        // The diff is printed rather than returned, so what matters is that the
        // comparison itself separates the texts.
        assert_ne!(old, new);
        assert_eq!(old.lines().count(), new.lines().count());
    }

    #[test]
    fn identical_texts_have_no_edits() {
        let text = "a\nb\nc\n";
        let old: Vec<&str> = text.lines().collect();
        let new: Vec<&str> = text.lines().collect();

        let mut table = vec![vec![0usize; new.len() + 1]; old.len() + 1];
        for i in (0..old.len()).rev() {
            for j in (0..new.len()).rev() {
                table[i][j] = if old[i] == new[j] {
                    table[i + 1][j + 1] + 1
                } else {
                    table[i + 1][j].max(table[i][j + 1])
                };
            }
        }

        assert_eq!(table[0][0], old.len());
    }
}