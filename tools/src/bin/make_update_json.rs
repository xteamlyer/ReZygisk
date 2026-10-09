//! Generates the manager update channel file for one flavour.
//!
//! The file is generated here rather than committed by hand so it can never
//! drift from the zip it points at. The release itself is still created
//! manually: nothing here pushes a tag, a release or a commit, so the file
//! travels with the release when one is cut - and it is that commit which puts
//! it back on main, where module.prop's updateJson reads it from.
//!
//! Usage:
//!   make-update-json --tree build --output build/out/update.json \
//!       --pattern "VexZygisk-v*-release.zip"

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use vex_tools::{git, sorted_children};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = match Args::parse(std::env::args().skip(1)) {
        Some(args) => args,
        None => {
            return Err(usage());
        }
    };

    let repo = git_root();

    let archives = release_archives(&args.tree, &args.pattern);
    if archives.is_empty() {
        return Err(format!("no release archive found for {}", args.pattern));
    }

    let archive = pick_newest(&archives)?;

    let name = archive
        .file_name()
        .ok_or_else(|| format!("cannot parse versionCode from {}", archive.display()))?
        .to_string_lossy()
        .into_owned();

    let version_code =
        version_code_of(&name).ok_or_else(|| format!("cannot parse versionCode from {name}"))?;
    let version =
        field_before(&name, 2).ok_or_else(|| format!("cannot parse version from {name}"))?;

    let previous = git(&repo, &["describe", "--tags", "--abbrev=0"]);
    let range = previous.as_deref().unwrap_or("-50");
    let commits = git(&repo, &["log", "--pretty=- %s", range]).unwrap_or_default();
    let head = git(&repo, &["rev-parse", "HEAD"]).unwrap_or_default();

    let tag = git(
        &repo,
        &[
            "rev-parse",
            "-q",
            "--verify",
            &format!("refs/tags/{version}"),
        ],
    );

    let output_name = args
        .output
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    match &tag {
        None => println!(
            "WARNING: tag {version} does not exist yet; {output_name}'s zipUrl will 404 until it is cut"
        ),
        Some(found) if found != &head => {
            println!("WARNING: tag {version} does not point at HEAD ({found})")
        }
        Some(_) => {}
    }

    let repository = std::env::var("GITHUB_REPOSITORY")
        .map_err(|_| "GITHUB_REPOSITORY is not set; the zipUrl cannot be built".to_string())?;

    let update = Update {
        version: version.clone(),
        version_code,
        zip_url: format!("https://github.com/{repository}/releases/download/{version}/{name}"),
        changelog: format!("VexZygisk {version}\n\n{commits}"),
    };

    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }

    let rendered = update.to_json();
    std::fs::write(&args.output, &rendered)
        .map_err(|e| format!("cannot write {}: {e}", args.output.display()))?;

    println!("{}", args.output.display());
    print!("{rendered}");

    Ok(())
}

struct Args {
    tree: PathBuf,
    output: PathBuf,
    pattern: String,
}

impl Args {
    fn parse(argv: impl Iterator<Item = String>) -> Option<Self> {
        let mut tree = None;
        let mut output = None;
        let mut pattern = None;

        let mut argv = argv.peekable();
        while let Some(arg) = argv.next() {
            match arg.as_str() {
                "--tree" => tree = Some(PathBuf::from(argv.next()?)),
                "--output" => output = Some(PathBuf::from(argv.next()?)),
                "--pattern" => pattern = Some(argv.next()?),
                _ => return None,
            }
        }

        Some(Self {
            tree: tree?,
            output: output?,
            pattern: pattern?,
        })
    }
}

struct Update {
    version: String,
    version_code: u64,
    zip_url: String,
    changelog: String,
}

impl Update {
    /// Renders the channel file.
    ///
    /// Key order is fixed rather than sorted, because this file is committed and
    /// a reordering would show up as a diff on a release that changed nothing.
    /// `versionCode` is a number, not a string, and the file ends with a newline
    /// after the closing brace.
    fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        let _ = writeln!(out, "  \"version\": {},", json_string(&self.version));
        let _ = writeln!(out, "  \"versionCode\": {},", self.version_code);
        let _ = writeln!(out, "  \"zipUrl\": {},", json_string(&self.zip_url));
        let _ = writeln!(out, "  \"changelog\": {}", json_string(&self.changelog));
        out.push_str("}\n");
        out
    }
}

/// Escapes a string into a JSON string literal, including the quotes.
///
/// Written out rather than pulled in as a dependency: the only escapes JSON
/// needs are the ones below, and `ensure_ascii=False` in the Python meant
/// non-ASCII characters stayed as themselves.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');

    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Control characters, and the two the JSON grammar requires to be
            // escaped even when they are not control characters themselves.
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }

    out.push('"');
    out
}

/// The zips matching `<tree>/out/<pattern>`.
///
/// `glob.glob` with a pattern that has no separator beyond the tree: the
/// directory part is fixed and only the file name is a wildcard, so the walk is
/// a directory listing filtered by a prefix and a suffix rather than a general
/// glob. The pattern the CI passes is `VexZygisk-v*-release.zip`.
fn release_archives(tree: &Path, pattern: &str) -> Vec<PathBuf> {
    let dir = tree.join("out");

    sorted_children(&dir)
        .into_iter()
        .filter(|entry| entry.is_file())
        .filter(|entry| {
            matches_pattern(
                &entry.file_name().unwrap_or_default().to_string_lossy(),
                pattern,
            )
        })
        .collect()
}

/// Matches a file name against a pattern holding at most one `*` run.
fn matches_pattern(name: &str, pattern: &str) -> bool {
    match pattern.split_once('*') {
        None => name == pattern,
        Some((prefix, suffix)) => {
            name.len() >= prefix.len() + suffix.len()
                && name.starts_with(prefix)
                && name.ends_with(suffix)
        }
    }
}

/// The versionCode out of `<prefix>-v<version>-<versionCode>-<commit>-release.zip`.
///
/// Lexicographic order would pick v2.1.9 over v2.1.10, so the newest archive is
/// the one with the highest versionCode - which is why it is read out rather
/// than compared as a string.
fn version_code_of(name: &str) -> Option<u64> {
    let stem = name.strip_suffix("-release.zip")?;
    let mut fields = stem.rsplit('-');

    // commit, versionCode, version, then the prefix.
    fields.next()?;
    let code = fields.next()?;
    let version = fields.next()?;
    let _prefix = fields.next()?;

    if version.is_empty() || !version.starts_with('v') {
        return None;
    }
    if code.is_empty() || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    code.parse().ok()
}

/// The field `n` counted from the end of the `-`-separated stem.
fn field_before(name: &str, n: usize) -> Option<String> {
    let stem = name.strip_suffix("-release.zip")?;
    stem.rsplit('-').nth(n).map(str::to_string)
}

/// Picks the archive with the highest versionCode, breaking ties by name so the
/// choice does not depend on the filesystem's ordering.
fn pick_newest(archives: &[PathBuf]) -> Result<PathBuf, String> {
    let mut best: Option<(u64, String, PathBuf)> = None;

    for archive in archives {
        let name = archive
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let Some(code) = version_code_of(&name) else {
            continue;
        };

        let key = (code, name);
        // is_none_or is 1.82; the crate declares 1.75, so the comparison is
        // written out.
        let better = match &best {
            None => true,
            Some((c, n, _)) => key > (*c, n.clone()),
        };

        if better {
            best = Some((code, key.1, archive.clone()));
        }
    }

    best.map(|(_, _, path)| path).ok_or_else(|| {
        let names: Vec<String> = archives
            .iter()
            .map(|a| {
                a.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        format!("cannot parse versionCode from {}", names.join(", "))
    })
}

/// The repository the release is cut from.
///
/// The Python ran git in the working directory, inheriting the process cwd. The
/// output path lives inside the build tree rather than the repository, so the
/// cwd is what has to be resolved rather than derived from `--output`.
fn git_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn usage() -> String {
    concat!(
        "usage: make-update-json --tree <dir> --output <file> --pattern <glob>\n",
        "\n",
        "  --tree    build tree holding out/<pattern> archives\n",
        "  --output  path of the update channel file to write\n",
        "  --pattern glob of the release archives to pick from",
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_code_is_read_out_of_the_name() {
        assert_eq!(
            version_code_of("VexZygisk-v2.2.0-842-19ae354-release.zip"),
            Some(842)
        );
        assert_eq!(
            version_code_of("VexZygisk-APatch-v2.1.2-840-558648e-release.zip"),
            Some(840)
        );
    }

    #[test]
    fn a_name_that_does_not_fit_is_rejected() {
        assert_eq!(version_code_of("VexZygisk-v2.2.0-release.zip"), None);
        assert_eq!(
            version_code_of("VexZygisk-v2.2.0-x-19ae354-release.zip"),
            None
        );
        assert_eq!(version_code_of("random.zip"), None);
    }

    #[test]
    fn a_numeric_string_would_sort_wrong() {
        // The reason versionCode is parsed rather than compared as text.
        assert!("v2.1.9" > "v2.1.10");
        let older = version_code_of("VexZygisk-v2.1.9-9-abc1234-release.zip").unwrap();
        let newer = version_code_of("VexZygisk-v2.1.10-10-abc1234-release.zip").unwrap();
        assert!(newer > older);
    }

    #[test]
    fn fields_are_counted_from_the_end() {
        assert_eq!(
            field_before("VexZygisk-v2.2.0-842-19ae354-release.zip", 2).as_deref(),
            Some("v2.2.0")
        );
        assert_eq!(
            field_before("VexZygisk-v2.2.0-842-19ae354-release.zip", 1).as_deref(),
            Some("842")
        );
    }

    #[test]
    fn patterns_match_like_the_glob_did() {
        assert!(matches_pattern(
            "VexZygisk-v2.2.0-842-19ae354-release.zip",
            "VexZygisk-v*-release.zip"
        ));
        assert!(!matches_pattern(
            "VexZygisk-APatch-v2.2.0-842-19ae354-release.zip",
            "VexZygisk-v*-release.zip"
        ));
        assert!(matches_pattern("plain.zip", "plain.zip"));
        assert!(!matches_pattern("plain.zip", "other.zip"));
    }

    #[test]
    fn json_escapes_are_minimal_and_keep_unicode() {
        assert_eq!(json_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_string("line\nbreak"), "\"line\\nbreak\"");
        assert_eq!(json_string("中文"), "\"中文\"");
        assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn the_channel_file_has_a_fixed_shape() {
        let update = Update {
            version: "v2.2.0".into(),
            version_code: 842,
            zip_url: "https://example.invalid/v2.2.0/a.zip".into(),
            changelog: "VexZygisk v2.2.0\n\n- one".into(),
        };

        assert_eq!(
            update.to_json(),
            concat!(
                "{\n",
                "  \"version\": \"v2.2.0\",\n",
                "  \"versionCode\": 842,\n",
                "  \"zipUrl\": \"https://example.invalid/v2.2.0/a.zip\",\n",
                "  \"changelog\": \"VexZygisk v2.2.0\\n\\n- one\"\n",
                "}\n",
            )
        );
    }
}
