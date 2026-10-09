//! Guards the loader/daemon protocol against one-sided drift.
//!
//! The loader (loader/src/) and the daemon (zygiskd/src/) each implement their
//! half of the wire protocol, and merging their socket helpers into one shared
//! file is deliberately off the table: `read_string` alone has two intentional
//! semantics (malloc'd string on the loader, bounded buffer fill on the daemon).
//! What keeps them honest is this check - it parses both sides' headers and
//! asserts that the action enum, the process flag macros and the socket helper
//! surface stay identical.
//!
//! The flags matter as much as the actions and are the easiest to drift: they
//! are plain macros duplicated in both trees (`zygiskd/src/constants.h` and
//! `loader/src/injector/module.h`), so adding a bit to one side alone still
//! compiles and only shows up at runtime as a flag the other half never sets or
//! never reads.
//!
//! Run in CI's host-test job; exits non-zero on the first divergence.
//!
//! Written without a regex crate on purpose: every pattern here is a fixed
//! shape over identifiers and whitespace, and hand-rolled scanning keeps the
//! tool's dependency list to what the signer already needs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The files each half of the protocol is declared in.
const PATHS: &[(&str, &str)] = &[
    ("daemon actions", "zygiskd/src/constants.h"),
    ("loader actions", "loader/src/include/daemon.h"),
    ("daemon flags", "zygiskd/src/constants.h"),
    ("loader flags", "loader/src/injector/module.h"),
    ("daemon helpers", "zygiskd/src/utils.h"),
    ("loader helpers", "loader/src/include/socket_utils.h"),
];

fn main() -> ExitCode {
    // The paths below are relative to the repository root. Run from the crate
    // (cargo test) the working directory is tools/, so the root is one level up;
    // run from the repository the argument names it outright.
    let root = match std::env::args().nth(1) {
        Some(dir) => PathBuf::from(dir),
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

            if cwd.join("zygiskd").is_dir() {
                cwd
            } else {
                cwd.join("..")
            }
        }
    };

    match run(&root) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(root: &Path) -> Result<bool, String> {
    let daemon_actions_text = read(root, "daemon actions")?;
    let loader_actions_text = read(root, "loader actions")?;

    let daemon_actions = enum_members(&daemon_actions_text, "DaemonSocketAction")?;
    let loader_actions = enum_members(&loader_actions_text, "rezygiskd_actions")?;

    let mut failed = false;

    if daemon_actions != loader_actions {
        failed = true;

        println!("ACTION MISMATCH between the daemon and the loader:");

        for index in 0..daemon_actions.len().max(loader_actions.len()) {
            let daemon = daemon_actions.get(index).map(String::as_str).unwrap_or("(missing)");
            let loader = loader_actions.get(index).map(String::as_str).unwrap_or("(missing)");

            let marker = if daemon == loader { "  " } else { "! " };
            println!("{marker}{index:2}  daemon={daemon:24} loader={loader}");
        }
    }

    let daemon_flags = flag_values(&read(root, "daemon flags")?);
    let loader_flags = flag_values(&read(root, "loader flags")?);

    if daemon_flags != loader_flags {
        failed = true;

        println!("FLAG MISMATCH between the daemon and the loader:");

        let names: BTreeSet<&String> = daemon_flags.keys().chain(loader_flags.keys()).collect();
        for name in names {
            let daemon = daemon_flags.get(name).map(String::as_str).unwrap_or("(missing)");
            let loader = loader_flags.get(name).map(String::as_str).unwrap_or("(missing)");

            if daemon != loader {
                println!("! {name:26} daemon={daemon:14} loader={loader}");
            }
        }
    }

    let daemon_helpers = helper_names(&read(root, "daemon helpers")?);
    let loader_helpers = helper_names(&read(root, "loader helpers")?);

    if daemon_helpers != loader_helpers {
        failed = true;

        println!("HELPER MISMATCH between the daemon and the loader:");
        println!("  daemon only: {:?}", only_in(&daemon_helpers, &loader_helpers));
        println!("  loader only: {:?}", only_in(&loader_helpers, &daemon_helpers));
    }

    if !failed {
        println!(
            "protocol check ok: {} actions, {} flags, {} shared helpers",
            daemon_actions.len(),
            daemon_flags.len(),
            daemon_helpers.len()
        );
    }

    Ok(!failed)
}

/// The names present in `left` but not in `right`, in a stable order.
fn only_in(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).cloned().collect()
}

fn read(root: &Path, key: &str) -> Result<String, String> {
    let relative = PATHS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, path)| *path)
        .ok_or_else(|| format!("no path registered for {key}"))?;

    let full = root.join(relative);
    std::fs::read_to_string(&full).map_err(|e| format!("cannot read {}: {e}", full.display()))
}

/// The members of `enum <name> { ... }`, comments removed.
///
/// A member is whatever sits between commas with the `= value` part dropped;
/// an empty item is a trailing comma or a blank line, not a member.
fn enum_members(text: &str, name: &str) -> Result<Vec<String>, String> {
    let body = enum_body(text, name)
        .ok_or_else(|| format!("cannot find enum {name}"))?;

    let stripped = strip_comments(body);

    Ok(stripped
        .split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| item.split('=').next().unwrap_or(item).trim().to_string())
        .collect())
}

/// The text between an enum's braces.
///
/// The name has to be preceded by the `enum` keyword on a word boundary, or a
/// comment mentioning the type would match first. The end is the first closing
/// brace after the opening one, which is enough here: neither enum nests a struct
/// or another enum, so that is the end of the enum rather than of something
/// inside it.
fn enum_body<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let keyword = "enum";

    let mut from = 0;
    while let Some(at) = text[from..].find(keyword) {
        let keyword_at = from + at;
        let after = &text[keyword_at + keyword.len()..];

        // The type name has to be the next word, with any amount of space
        // between the keyword and it.
        let trimmed = after.trim_start();
        let skipped = after.len() - trimmed.len();

        let rest = match trimmed.strip_prefix(name) {
            Some(rest) => rest,
            None => {
                from = keyword_at + keyword.len();
                continue;
            }
        };

        // And then the body, with any space between the name and the brace.
        let body = match rest.trim_start().strip_prefix('{') {
            Some(body) => body,
            None => {
                from = keyword_at + keyword.len();
                continue;
            }
        };

        let _ = skipped;
        let close = body.find('}')?;
        return Some(&body[..close]);
    }

    None
}

/// Removes block and line comments, so a commented-out member is not read as
/// one and a comment cannot hide a brace.
///
/// A comment becomes a single space rather than nothing: `a/* x */b` has to stay
/// two tokens, and joining them would invent an identifier that was never there.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    'outer: while !rest.is_empty() {
        let bytes = rest.as_bytes();

        if bytes[0] == b'/' && bytes.len() > 1 {
            match bytes[1] {
                b'*' => {
                    // The block comment runs to its terminator; an unterminated
                    // one takes the rest of the text, which is what a C compiler
                    // does with it too.
                    match rest[2..].find("*/") {
                        Some(at) => {
                            out.push(' ');
                            rest = &rest[2 + at + 2..];
                            continue 'outer;
                        }
                        None => return out,
                    }
                }
                b'/' => {
                    // The line comment runs to the newline, which is kept so the
                    // two lines do not join.
                    match rest.find('\n') {
                        Some(at) => {
                            rest = &rest[at..];
                            continue 'outer;
                        }
                        None => return out,
                    }
                }
                _ => {}
            }
        }

        // One whole character, so multi-byte text survives.
        let ch = rest.chars().next().expect("rest is non-empty");
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }

    out
}

/// The `PROCESS_*` flag macros as name -> bit number.
///
/// Both sides define them as `(1u << n)`, so comparing the bit catches a
/// renumbering as well as a rename. The shape is anchored on that on purpose:
/// `PROCESS_NAME_MAX_LEN` shares the prefix but is a buffer length only the
/// daemon declares, and `PRIVATE_MASK` composes flags without being one, so
/// neither is a flag to compare.
fn flag_values(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    for line in text.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("#define") else {
            continue;
        };
        // `#define` has to be followed by whitespace, so a longer directive
        // like `#define_A` cannot match.
        if !rest.starts_with([' ', '\t']) {
            continue;
        }

        let rest = rest.trim_start();

        // The name runs to the next whitespace.
        let name_end = rest.find([' ', '\t']).unwrap_or(rest.len());
        let name = &rest[..name_end];
        if !name.starts_with("PROCESS_") || !is_identifier(name) {
            continue;
        }

        let value = rest[name_end..].trim_start();
        let Some(bit) = one_u_left_shift(value) else {
            continue;
        };

        out.insert(name.to_string(), bit.to_string());
    }

    out
}

/// The `n` in `(1u << n)`, if the text starts with exactly that shape.
///
/// Spacing is tolerated because both sides format it differently; anything else
/// is not a flag bit.
fn one_u_left_shift(text: &str) -> Option<u32> {
    let rest = text.strip_prefix('(')?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("1u")?;
    let rest = rest.trim_start().strip_prefix("<<")?;
    let rest = rest.trim_start();

    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }

    rest[..end].parse().ok()
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !text.as_bytes()[0].is_ascii_digit()
}

/// The wire helpers each side declares: the typed read/write families plus the
/// fd and string primitives.
///
/// `read_string` is excluded on purpose - its two signatures are intentional,
/// not drift.
fn helper_names(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();

    for kind in ["write", "read"] {
        for type_name in typed_family(text, kind) {
            names.insert(format!("{kind}_{type_name}"));
        }
    }

    for helper in ["write_fd", "read_fd", "write_string", "write_loop", "read_loop"] {
        if declares_function(text, helper) {
            names.insert(helper.to_string());
        }
    }

    names
}

/// The type names in `write_func(<type>)` and `write_func_def(<type>)`.
///
/// Both spellings are looked for because the loader declares the definition and
/// the daemon the prototype, or the other way round for some of them.
fn typed_family(text: &str, kind: &str) -> Vec<String> {
    let mut out = Vec::new();

    for suffix in ["_func", "_func_def"] {
        let needle = format!("{kind}{suffix}(");

        let mut from = 0;
        while let Some(at) = text[from..].find(&needle) {
            let mut index = from + at + needle.len();

            // The '(' may be followed by whitespace.
            while text[index..].starts_with([' ', '\t']) {
                index += 1;
            }

            let name_start = index;
            while index < text.len()
                && (text.as_bytes()[index].is_ascii_alphanumeric() || text.as_bytes()[index] == b'_')
            {
                index += 1;
            }

            if index > name_start {
                out.push(text[name_start..index].to_string());
            }

            from = index.max(from + at + needle.len());
        }
    }

    out
}

/// True when `name(` appears as a declaration or a call, on a word boundary.
///
/// The Python used `\bname\s*\(`; a name is matched after a character that
/// cannot be part of an identifier, which is what "word boundary" means for
/// identifiers.
fn declares_function(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();

    let mut from = 0;
    while let Some(at) = text[from..].find(name) {
        let start = from + at;
        let before_ok = start == 0 || {
            let previous = bytes[start - 1];
            !previous.is_ascii_alphanumeric() && previous != b'_'
        };

        let mut index = start + name.len();
        while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
            index += 1;
        }

        if before_ok && index < bytes.len() && bytes[index] == b'(' {
            return true;
        }

        from = start + name.len();
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_members_come_out_in_order() {
        let text = "enum rezygiskd_actions {\n  DAEMON_SOCKET_CONNECT,\n  DAEMON_SOCKET_PING,\n};\n";
        assert_eq!(
            enum_members(text, "rezygiskd_actions").unwrap(),
            vec!["DAEMON_SOCKET_CONNECT", "DAEMON_SOCKET_PING"]
        );
    }

    #[test]
    fn an_explicit_value_is_dropped() {
        let text = "enum e {\n  A,\n  B = 7,\n  C,\n};\n";
        assert_eq!(enum_members(text, "e").unwrap(), vec!["A", "B", "C"]);
    }

    #[test]
    fn comments_are_not_members() {
        let text = "enum e {\n  A,\n  // B,\n  /* C, */\n  D,\n};\n";
        assert_eq!(enum_members(text, "e").unwrap(), vec!["A", "D"]);
    }

    #[test]
    fn a_trailing_comma_is_not_an_empty_member() {
        let text = "enum e {\n  A,\n  B,\n};\n";
        assert_eq!(enum_members(text, "e").unwrap(), vec!["A", "B"]);
    }

    #[test]
    fn a_name_mentioned_in_a_comment_is_not_the_enum() {
        let text = "/* enum rezygiskd_actions { FAKE, } */\nenum rezygiskd_actions { REAL, };\n";
        assert_eq!(enum_members(text, "rezygiskd_actions").unwrap(), vec!["REAL"]);
    }

    #[test]
    fn a_missing_enum_is_an_error_not_a_panic() {
        assert!(enum_members("struct s {};", "nope").is_err());
    }

    #[test]
    fn only_bit_shift_flags_are_collected() {
        let text = concat!(
            "#define PROCESS_PID (1u << 0)\n",
            "#define PROCESS_DENYLISTED (1u << 1)\n",
            // Not a bit: a length and a mask.
            "#define PROCESS_NAME_MAX_LEN 256\n",
            "#define PRIVATE_MASK (PROCESS_PID | PROCESS_DENYLISTED)\n",
        );

        let flags = flag_values(text);

        assert_eq!(flags.get("PROCESS_PID").map(String::as_str), Some("0"));
        assert_eq!(flags.get("PROCESS_DENYLISTED").map(String::as_str), Some("1"));
        assert_eq!(flags.len(), 2);
    }

    #[test]
    fn a_renumbered_flag_is_caught() {
        let daemon = flag_values("#define PROCESS_PID (1u << 0)\n");
        let loader = flag_values("#define PROCESS_PID (1u << 5)\n");
        assert_ne!(daemon, loader);
    }

    #[test]
    fn spacing_inside_the_shift_is_tolerated() {
        assert_eq!(one_u_left_shift("(1u<<3)"), Some(3));
        assert_eq!(one_u_left_shift("( 1u << 3 )"), Some(3));
        assert_eq!(one_u_left_shift("(1u  <<  12)"), Some(12));
    }

    #[test]
    fn a_different_left_hand_side_is_not_a_bit() {
        assert_eq!(one_u_left_shift("(2u << 3)"), None);
        assert_eq!(one_u_left_shift("(1u >> 3)"), None);
        assert_eq!(one_u_left_shift("1u << 3"), None);
        assert_eq!(one_u_left_shift("(1u << )"), None);
    }

    #[test]
    fn both_helper_spellings_are_found() {
        let text = "void write_func(int *);\nvoid write_func_def(long *);\nint read_func(char *);\n";
        let names = helper_names(text);

        assert!(names.contains("write_int"));
        assert!(names.contains("write_long"));
        assert!(names.contains("read_char"));
    }

    #[test]
    fn the_primitives_are_found_only_when_declared() {
        let with = helper_names("void write_fd(int);\nvoid write_string(int);\n");
        let without = helper_names("int read_fd(int);\n");

        assert!(with.contains("write_fd"));
        assert!(with.contains("write_string"));
        assert!(without.contains("read_fd"));
        assert!(!without.contains("write_fd"));
    }

    #[test]
    fn a_name_embedded_in_another_is_not_a_declaration() {
        // `my_write_fd(` must not count as `write_fd(`.
        assert!(!declares_function("int my_write_fd(int);", "write_fd"));
        assert!(declares_function("int write_fd(int);", "write_fd"));
        assert!(declares_function("write_fd (int);", "write_fd"));
    }

    #[test]
    fn comment_stripping_keeps_the_braces_balanced() {
        // A comment leaves a space, so the tokens either side stay separate.
        assert_eq!(strip_comments("a /* } */ b"), "a   b");
        assert_eq!(strip_comments("a // }\nb"), "a \nb");
        // An unterminated block comment takes the rest, as a compiler's does.
        assert_eq!(strip_comments("a /* unterminated"), "a ");
    }

    #[test]
    fn multi_byte_text_survives_comment_stripping() {
        // Pushing bytes one at a time would mangle anything above ASCII.
        assert_eq!(strip_comments("/* 中文 */ ok"), "  ok");
        assert_eq!(strip_comments("名字"), "名字");
    }
}