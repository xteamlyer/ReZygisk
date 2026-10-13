//! One line of a module's `zn_modules.txt`.
//!
//! The format is `<name=|path=><target> [companion] <library>`: what the line
//! selects on, an optional flag, and the library to load. Every line in every
//! installed module is read by the daemon once per request, out of a file the
//! module ships - which is to say out of text this code did not write and
//! cannot assume anything about.
//!
//! The C version this replaces answered three questions with one function that
//! allocated two strings, and every caller had to handle two failure paths that
//! were really "the allocation did not work" rather than "the line was no
//! good". Here the caller passes the buffers and the answers are written into
//! them: a name or a path that does not fit is a refusal, which is one thing to
//! handle and the honest answer for a line nobody can act on.

use core::ffi::{c_char, CStr};

/// The prefix that says whether the target is a process name or a path.
const PREFIX_LEN: usize = 5;

/// The two spellings of the module id in a library path, longest first so the
/// braced one is answered before the bare one can match a prefix of it.
const MODULE_ID_BRACED: &[u8] = b"${moduleId}";
const MODULE_ID_BARE: &[u8] = b"$moduleId";

/// How many whitespace-separated tokens one line may have. The format needs
/// three and the C version stopped at eight; a line with more is read as its
/// first eight, which is what that version did with it too.
const MAX_TOKENS: usize = 8;

/// `isspace` in the C locale, spelled out: `is_ascii_whitespace` leaves out the
/// vertical tab, and a line that used one as a separator would parse
/// differently here than it did there.
#[inline]
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

#[derive(Clone, Copy)]
struct Token<'a> {
    bytes: &'a [u8],
}

const EMPTY: Token<'static> = Token { bytes: &[] };

/// The whitespace-separated tokens of a line, at most `MAX_TOKENS` of them.
struct Tokens<'a> {
    items: [Token<'a>; MAX_TOKENS],
    count: usize,
}

fn tokenize(line: &[u8]) -> Tokens<'_> {
    let mut tokens = Tokens {
        items: [EMPTY; MAX_TOKENS],
        count: 0,
    };

    let mut cursor = 0usize;

    while cursor < line.len() && tokens.count < MAX_TOKENS {
        while cursor < line.len() && is_space(line[cursor]) {
            cursor += 1;
        }

        if cursor >= line.len() {
            break;
        }

        let start = cursor;
        while cursor < line.len() && !is_space(line[cursor]) {
            cursor += 1;
        }

        tokens.items[tokens.count] = Token {
            bytes: &line[start..cursor],
        };
        tokens.count += 1;
    }

    tokens
}

/// Writes `value` and a terminator into `out`, or answers false when it does
/// not fit. The NUL is part of what has to fit: a truncated path is a path to
/// something else.
unsafe fn write_cstr(out: *mut c_char, capacity: usize, value: &[u8]) -> bool {
    if value.len() + 1 > capacity {
        return false;
    }

    // SAFETY: the caller passes a buffer of `capacity` bytes, and the length
    //         check above is what makes the copies stay inside it.
    unsafe {
        core::ptr::copy_nonoverlapping(value.as_ptr(), out as *mut u8, value.len());
        *out.add(value.len()) = 0;
    }

    true
}

/// Writes the library path a line asked for, and answers false when it does not
/// fit.
///
/// A relative library is relative to the module's own directory, which is what
/// makes the per-module switches mean anything - the same join the C version
/// built with a `malloc` and an `snprintf`.
///
/// Both spellings of the module id stand for the directory's *name* rather than
/// its path, which is the name the root solution knows the module by. Neither
/// used to be expanded, so a manifest that wrote one resolved to a literal file
/// name that cannot exist and the module silently never loaded - the same class
/// of failure as a target that names a process this build never injects.
///
/// The expansion happens before the absolute test, exactly as the reference
/// does it. A placeholder expands to a name, so it can never turn a relative
/// path into an absolute one, and the test stays answerable from the raw token.
unsafe fn write_lib_path(out: *mut c_char, capacity: usize, dir: &[u8], value: &[u8],
                         module_name: &[u8]) -> bool {
    let dst = out as *mut u8;
    let mut at: usize = 0;

    if value.first() != Some(&b'/') {
        if dir.len() + 1 > capacity {
            return false;
        }

        // SAFETY: the check above sized the directory and the separator.
        unsafe {
            core::ptr::copy_nonoverlapping(dir.as_ptr(), dst, dir.len());
            *dst.add(dir.len()) = b'/';
        }

        at = dir.len() + 1;
    }

    let mut cursor = 0usize;

    while cursor < value.len() {
        let rest = &value[cursor..];

        let expanded = if rest.starts_with(MODULE_ID_BRACED) {
            Some((module_name, MODULE_ID_BRACED.len()))
        } else if rest.starts_with(MODULE_ID_BARE) {
            Some((module_name, MODULE_ID_BARE.len()))
        } else {
            None
        };

        // SAFETY: every write is bounded by `capacity`, and the answer is false
        //         rather than a truncation - a half-written path is a path to
        //         something else.
        unsafe {
            match expanded {
                Some((name, skip)) => {
                    if at + name.len() > capacity {
                        return false;
                    }

                    core::ptr::copy_nonoverlapping(name.as_ptr(), dst.add(at), name.len());
                    at += name.len();
                    cursor += skip;
                }
                None => {
                    if at + 1 > capacity {
                        return false;
                    }

                    *dst.add(at) = value[cursor];
                    at += 1;
                    cursor += 1;
                }
            }
        }
    }

    if at + 1 > capacity {
        return false;
    }

    // SAFETY: the terminator is inside the buffer the check above sized.
    unsafe {
        *dst.add(at) = 0;
    }

    true
}

/// Splits one `zn_modules.txt` line into the answers the daemon needs.
///
/// Writes the target into `out_target` (`out_target_cap` bytes) and the library
/// path into `out_lib` (`out_lib_cap`), both NUL-terminated, and answers false
/// when the line cannot be read or does not fit - which is the same "skip this
/// line" the callers already handled.
///
/// # Safety
///
/// `line` and `module_dir` are NUL-terminated strings. The four output pointers
/// are valid: two `bool` and two buffers of the capacities passed with them.
#[no_mangle]
pub unsafe extern "C" fn vexcore_zn_parse_line(
    line: *const c_char,
    module_dir: *const c_char,
    out_is_name: *mut bool,
    out_companion: *mut bool,
    out_target: *mut c_char,
    out_target_cap: usize,
    out_lib: *mut c_char,
    out_lib_cap: usize,
) -> bool {
    if line.is_null()
        || module_dir.is_null()
        || out_is_name.is_null()
        || out_companion.is_null()
        || out_target.is_null()
        || out_lib.is_null()
    {
        return false;
    }

    // SAFETY: NUL-terminated, per the contract above.
    let (line, module_dir) = unsafe {
        (
            CStr::from_ptr(line).to_bytes(),
            CStr::from_ptr(module_dir).to_bytes(),
        )
    };

    let tokens = tokenize(line);

    // INFO: A line needs a target and a library; anything shorter says nothing.
    if tokens.count < 2 {
        return false;
    }

    let first = tokens.items[0].bytes;

    let is_name = if first.len() > PREFIX_LEN && first.starts_with(b"name=") {
        true
    } else if first.len() > PREFIX_LEN && first.starts_with(b"path=") {
        false
    } else {
        return false;
    };

    let target = &first[PREFIX_LEN..];

    // INFO: `companion` is a flag and not a position. It is recognised wherever
    //       it sits between the target and the library, and the library is the
    //       last token that is not a flag. Reading the library as "the last
    //       token" gave a manifest that wrote the flag after it a library path
    //       of the literal string "companion" - a module that silently never
    //       loaded.
    let mut library_index = tokens.count - 1;
    while library_index > 1 && tokens.items[library_index].bytes == b"companion" {
        library_index -= 1;
    }

    // INFO: What is left there has to be a library rather than another flag: a
    //       line of nothing but flags after the target says nothing.
    if tokens.items[library_index].bytes == b"companion" {
        return false;
    }

    let library = tokens.items[library_index].bytes;

    // INFO: Every other occurrence of the flag is a flag, wherever it sits -
    //       before the library, after it, or in both places at once.
    let mut companion = false;
    for index in 1..tokens.count {
        if index != library_index && tokens.items[index].bytes == b"companion" {
            companion = true;
        }
    }

    // INFO: The name the root solution knows the module by: the last component
    //       of the directory the manifest was read from. This is what the two
    //       placeholders in a library path stand for.
    let mut name_at = 0usize;
    for (index, &byte) in module_dir.iter().enumerate() {
        if byte == b'/' {
            name_at = index + 1;
        }
    }

    // SAFETY: the write is bounded by the capacity passed alongside the buffer,
    //         and answers false rather than truncating.
    let written = unsafe {
        write_cstr(out_target, out_target_cap, target)
            && write_lib_path(out_lib, out_lib_cap, module_dir, library,
                              &module_dir[name_at..])
    };

    if !written {
        return false;
    }

    // SAFETY: the caller passed pointers to one `bool` each.
    unsafe {
        *out_is_name = is_name;
        *out_companion = companion;
    }

    true
}
