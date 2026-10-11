//! Tests for the lookups.
//!
//! Run on the build host with `cargo test`, which is also why the crate is
//! built with `std` here and without it everywhere else.
//!
//! The tables are synthetic: the point is not to parse a real file, it is to
//! pin down what the two lookups answer for the shapes a file can hand them -
//! a name the filter excludes, a name the bucket holds but the chain does not,
//! a name offset that points past its own string table. Those are the cases
//! the C versions answered with a paragraph of hand-written checks, and the
//! cases a device only ever shows as "the module did not load".

use core::ffi::CStr;

// INFO: Only `cfg(test)` builds use these: the crate itself is `no_std`.
use std::ffi::CString;

use crate::hash::{vexcore_elf_hash, vexcore_gnu_hash};
use crate::lookup::{vexcore_elf_lookup, vexcore_gnu_lookup, Elf64Sym};

/// Appends `name` NUL-terminated and answers its offset, which is how a string
/// table is built.
fn push(table: &mut Vec<u8>, name: &[u8]) -> u32 {
    let offset = table.len() as u32;
    table.extend_from_slice(name);
    table.push(0);

    offset
}

/// A defined function symbol, the only kind either test needs.
fn function(st_name: u32, st_value: u64) -> Elf64Sym {
    Elf64Sym {
        st_name,
        st_info: 0x12, // STB_GLOBAL << 4 | STT_FUNC
        st_other: 0,
        st_shndx: 1,
        st_value,
        st_size: 0,
    }
}

const ALPHA_VALUE: u64 = 0x1000;
const BETA_VALUE: u64 = 0x2000;

/// A symbol table with one undefined entry, then alpha and beta.
fn symbols(dynstr: &mut Vec<u8>) -> Vec<Elf64Sym> {
    let alpha = push(dynstr, b"alpha");
    let beta = push(dynstr, b"beta");

    vec![
        Elf64Sym {
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: 0,
            st_size: 0,
        },
        function(alpha, ALPHA_VALUE),
        function(beta, BETA_VALUE),
    ]
}

fn cstr(name: &'static CStr) -> *const core::ffi::c_char {
    name.as_ptr()
}

#[test]
fn hashes_match_the_reference_implementation() {
    // Values from the C these replace, so a port that is off by a bit is
    // caught here rather than by a symbol that silently does not resolve.
    let cases: &[(&CStr, u32, u32)] = &[
        (c"", 0x0000_0000, 0x0000_1505),
        (c"a", 0x0000_0061, 0x0002_b606),
        (c"main", 0x0007_37fe, 0x7c9a_7f6a),
        (c"alpha", 0x0068_36e1, 0x0f17_6c2b),
        (c"beta", 0x0006_8ca1, 0x7c94_89a1),
        (c"__cxa_finalize", 0x0bea_6495, 0x6dce_65d0),
    ];

    for (name, elf, gnu) in cases {
        assert_eq!(vexcore_elf_hash(cstr(name)), *elf, "elf hash of {:?}", name);
        assert_eq!(vexcore_gnu_hash(cstr(name)), *gnu, "gnu hash of {:?}", name);
    }
}

#[test]
fn gnu_lookup_answers_the_address_of_a_hashed_symbol() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));
    let shift2 = 5u32;

    // The filter and the table the linker would have built for one symbol
    // starting at index 1, as the last entry of its chain.
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> shift2) % 64)),];
    let bucket = [1u32];
    let chain = [alpha_hash | 1];

    let mut sym_type = 0u8;

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            shift2,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            &mut sym_type,
        )
    };

    assert_eq!(found, ALPHA_VALUE);
    assert_eq!(sym_type, 0x2, "STT_FUNC");
}

#[test]
fn gnu_lookup_refuses_a_name_the_filter_excludes() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));
    let beta_hash = vexcore_gnu_hash(cstr(c"beta"));

    // The filter only has room for alpha's bits, which is the whole point of
    // it: beta is answered without touching the bucket or the chain.
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> 5) % 64)),];
    let bucket = [1u32];
    let chain = [alpha_hash | 1];

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            5,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"beta"),
            beta_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0);
}

#[test]
fn gnu_lookup_refuses_a_name_the_chain_does_not_hold() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));

    // The filter and the bucket are alpha's, the name asked for is not: the
    // hash half of the comparison passes and the name half is what has to
    // reject it, which is the case a bucket collision takes.
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> 5) % 64)),];
    let bucket = [1u32];
    let chain = [alpha_hash | 1];

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            5,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"beta"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0);
}

#[test]
fn gnu_lookup_refuses_a_bucket_index_past_the_symbols() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> 5) % 64)),];
    // One past the end of the table, which a malformed image can name.
    let bucket = [syms.len() as u32];
    let chain = [alpha_hash | 1];

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            5,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0, "an out-of-range bucket index was followed");
}

#[test]
fn elf_lookup_answers_the_address_of_a_chained_symbol() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_elf_hash(cstr(c"alpha"));
    let bucket = [1u32];
    // Index 1 is alpha, and its chain entry ends the walk.
    let chain = [0u32, 0];

    let mut sym_type = 0u8;

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            &mut sym_type,
        )
    };

    assert_eq!(found, ALPHA_VALUE);
    assert_eq!(sym_type, 0x2, "STT_FUNC");
}

#[test]
fn elf_lookup_walks_the_chain_and_then_gives_up() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    // The bucket names alpha, whose chain entry names beta: the miss is on the
    // first link and the hit on the second. An index of zero would end the walk
    // before it started - that is what STN_UNDEF means - so the chain has to
    // start at a real symbol for this to test anything.
    let bucket = [1u32];
    let chain = [0u32, 2, 0];

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"beta"),
            vexcore_elf_hash(cstr(c"beta")),
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, BETA_VALUE, "the second link of the chain was not reached");

    // And a name the chain does not hold runs out of links.
    let missing = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"gamma"),
            vexcore_elf_hash(cstr(c"gamma")),
            core::ptr::null_mut(),
        )
    };

    assert_eq!(missing, 0);
}

#[test]
fn a_name_offset_past_its_string_table_is_a_miss() {
    let mut dynstr = Vec::new();
    let mut syms = symbols(&mut dynstr);

    // Past the end of the string table, which is what a corrupt image has.
    syms[1].st_name = dynstr.len() as u32;

    let alpha_hash = vexcore_elf_hash(cstr(c"alpha"));
    let bucket = [1u32];
    let chain = [0u32, 0];

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0, "an offset past the string table was read");

    // The same offset through the GNU path: the bloom filter has to be built
    // to let this one through, so the miss is the string table's doing.
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> 5) % 64)),];
    let gnu_bucket = [1u32];
    let gnu_chain = [alpha_hash | 1];

    let gnu_found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            5,
            bloom.as_ptr(),
            gnu_bucket.as_ptr(),
            gnu_chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(gnu_found, 0, "an offset past the string table was read");
}

#[test]
fn a_symbol_that_is_not_defined_here_is_never_the_answer() {
    let mut dynstr = Vec::new();
    let mut syms = symbols(&mut dynstr);

    // The name matches, the definition is elsewhere.
    syms[1].st_shndx = 0;

    let alpha_hash = vexcore_elf_hash(cstr(c"alpha"));
    let bucket = [1u32];
    let chain = [0u32, 0];

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0);
}

#[test]
fn empty_tables_are_refused_without_being_read() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let null_sym: *const Elf64Sym = core::ptr::null();
    let null_u8: *const u8 = core::ptr::null();
    let null_u32: *const u32 = core::ptr::null();

    let by_gnu = unsafe {
        vexcore_gnu_lookup(
            null_sym, 0, null_u8, 0, 0, 0, 0, 0, core::ptr::null(), null_u32, null_u32,
            cstr(c"alpha"), 0, core::ptr::null_mut(),
        )
    };
    assert_eq!(by_gnu, 0);

    let by_elf = unsafe {
        vexcore_elf_lookup(
            null_sym, 0, null_u8, 0, 0, null_u32, null_u32,
            cstr(c"alpha"), 0, core::ptr::null_mut(),
        )
    };
    assert_eq!(by_elf, 0);

    // The hash of a name that is not there still has to be computable: the
    // caller hashes before it looks.
    let _ = vexcore_gnu_hash(cstr(c"gamma"));
    let _ = syms.len();
}

/// The answers one parsed line is expected to produce, or "refused".
#[derive(Debug, PartialEq)]
enum Parsed {
    Refused,
    Line {
        is_name: bool,
        companion: bool,
        target: String,
        library: String,
    },
}

fn parse(line: &CStr, module_dir: &CStr) -> Parsed {
    let mut is_name = false;
    let mut companion = false;
    let mut target = [0i8; 256];
    let mut library = [0i8; 256];

    let ok = unsafe {
        crate::vexcore_zn_parse_line(
            line.as_ptr(),
            module_dir.as_ptr(),
            &mut is_name,
            &mut companion,
            target.as_mut_ptr(),
            target.len(),
            library.as_mut_ptr(),
            library.len(),
        )
    };

    if !ok {
        return Parsed::Refused;
    }

    let read = |buf: &[i8]| -> String {
        let bytes: Vec<u8> = buf.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect();
        String::from_utf8(bytes).expect("ascii")
    };

    Parsed::Line {
        is_name,
        companion,
        target: read(&target),
        library: read(&library),
    }
}

const MODULE_DIR: &CStr = c"/data/adb/modules/example";

#[test]
fn a_name_line_names_a_process_and_a_relative_library() {
    assert_eq!(
        parse(c"name=com.example.app lib64/libexample.so", MODULE_DIR),
        Parsed::Line {
            is_name: true,
            companion: false,
            target: "com.example.app".to_string(),
            // The relative library is relative to the module's own directory,
            // which is what makes the per-module switches mean anything.
            library: "/data/adb/modules/example/lib64/libexample.so".to_string(),
        }
    );
}

#[test]
fn a_path_line_keeps_an_absolute_library_as_it_is() {
    assert_eq!(
        parse(c"path=/system/bin/app_process64 /data/local/tmp/lib.so", MODULE_DIR),
        Parsed::Line {
            is_name: false,
            companion: false,
            target: "/system/bin/app_process64".to_string(),
            library: "/data/local/tmp/lib.so".to_string(),
        }
    );
}

#[test]
fn the_companion_flag_is_read_between_the_target_and_the_library() {
    // INFO: The flag is looked for strictly between the target and the library,
    //       and the library is the last token - so a line that puts "companion"
    //       at the end sets no flag and hands "companion" back as the library.
    //
    //       That is what the C version did with the same line, and it is pinned
    //       here rather than corrected: this change moves the parser, it does
    //       not change what a module's file means. Anything that reads the flag
    //       as a position instead wants a change of its own, with the module
    //       documents to go with it.
    assert_eq!(
        parse(c"name=com.example.app companion lib64/lib.so", MODULE_DIR),
        Parsed::Line {
            is_name: true,
            companion: true,
            target: "com.example.app".to_string(),
            library: "/data/adb/modules/example/lib64/lib.so".to_string(),
        },
        "the flag before the library is read"
    );

    assert_eq!(
        parse(c"name=com.example.app lib64/lib.so companion", MODULE_DIR),
        Parsed::Line {
            is_name: true,
            companion: false,
            target: "com.example.app".to_string(),
            library: "/data/adb/modules/example/companion".to_string(),
        },
        "the flag after the library is not, and the last token is the library"
    );
}

#[test]
fn tabs_and_runs_of_spaces_separate_like_any_whitespace() {
    assert_eq!(
        parse(c"  name=x\t\tlib.so  ", MODULE_DIR),
        Parsed::Line {
            is_name: true,
            companion: false,
            target: "x".to_string(),
            library: "/data/adb/modules/example/lib.so".to_string(),
        }
    );
}

#[test]
fn lines_that_say_nothing_are_refused() {
    for line in [
        c"",                              // empty
        c"   \t ",                        // whitespace only
        c"# a comment",                   // one token
        c"name=",                         // a prefix and nothing else
        c"name=x",                        // a target but no library
        c"com.example.app lib.so",        // no prefix
        c"lib=com.example.app lib.so",    // a prefix this format does not have
        c"path=",                         // a prefix and nothing else
    ] {
        assert_eq!(parse(line, MODULE_DIR), Parsed::Refused, "line {:?}", line);
    }
}

#[test]
fn a_target_that_does_not_fit_is_refused_rather_than_cut() {
    // 300 characters of target: longer than the 256-byte buffer the test uses,
    // and a truncated target would be a different process's name.
    let long = format!("name={} lib.so", "a".repeat(300));
    let line = CString::new(long).expect("no interior NUL");

    assert_eq!(parse(&line, MODULE_DIR), Parsed::Refused);
}
