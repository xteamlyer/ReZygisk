//! Symbol lookup through the two hash tables an ELF image may carry.
//!
//! Both functions answer the same question - given a name and the hash of that
//! name, what is the symbol's address - and both are ports of the C they
//! replace, including the fallbacks. The differences that are not mechanical
//! are the ones worth reading for:
//!
//! * every table is turned into a slice once, at the top, instead of being
//!   indexed with a bounds check written out at each access;
//! * a name is compared only after its offset has been found inside the string
//!   table it points into, so a bad offset is a miss and not a `strcmp` that
//!   walks off the end of the mapping (which is what the C version could do -
//!   it checked the offset against the section size first, and this does the
//!   same thing, by way of `get`);
//! * the chain arrays are read through the raw pointer with the same bound the
//!   C used, not through a slice, because their length is not recorded anywhere
//!   in the image - the GNU one is walked by an index the bucket supplies and
//!   the SysV one by a value the previous entry supplies. A slice built with a
//!   guessed length would be a promise this code cannot keep.

use core::ffi::{c_char, CStr};

use crate::slice_ext::table;

/// One entry of a 64-bit ELF symbol table, field for field.
///
/// The layout matters more than usual here: these are the bytes the file
/// supplied, read directly, and the C side hands over a pointer into the
/// mapped image. Only the 64-bit shape exists in this tree - the build has a
/// single architecture, arm64-v8a.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

/// A symbol with no section is a reference to be resolved elsewhere, not a
/// definition, so it is never what a lookup is asking for.
const SHN_UNDEF: u16 = 0;

/// The end of a SysV hash chain.
const STN_UNDEF: u32 = 0;

/// `ELF_ST_TYPE`, which is the low nibble of `st_info`.
#[inline]
fn symbol_type(st_info: u8) -> u8 {
    st_info & 0xf
}

/// Whether this symbol defines `name`.
///
/// The order is the C one: a symbol that is not defined here is skipped before
/// its name is looked at, and the offset has to land inside the string table
/// before anything is compared.
#[inline]
fn defines(sym: &Elf64Sym, strings: &[u8], name: &[u8]) -> bool {
    if sym.st_shndx == SHN_UNDEF {
        return false;
    }

    let Some(rest) = strings.get(sym.st_name as usize..) else {
        return false;
    };
    let Some(end) = rest.iter().position(|&byte| byte == 0) else {
        return false;
    };

    &rest[..end] == name
}

/// The GNU hash lookup, `.gnu.hash`.
///
/// The bloom word is a filter, not a check: a bit set there says "maybe", and
/// the bucket and chain that follow are what actually decide. A miss costs one
/// table read, which is the whole reason the filter exists.
///
/// # Safety
///
/// Every pointer and count comes from the C side and has to describe tables
/// inside one mapped image: `dynsym` of `dynsym_count` entries, `dynstr` of
/// `dynstr_size` bytes, `bloom` of `gnu_bloom_size` words, `bucket` of
/// `gnu_nbucket` entries, and a `chain` array at least as long as the space
/// between `gnu_symndx` and the end of `dynsym`. `name` is NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn vexcore_gnu_lookup(
    dynsym: *const Elf64Sym,
    dynsym_count: usize,
    dynstr: *const u8,
    dynstr_size: usize,
    gnu_nbucket: u32,
    gnu_symndx: u32,
    gnu_bloom_size: u32,
    gnu_shift2: u32,
    bloom: *const usize,
    bucket: *const u32,
    chain: *const u32,
    name: *const c_char,
    hash: u32,
    sym_type: *mut u8,
) -> u64 {
    // INFO: The zero bucket count is not only a "no table" marker: it is what
    //       the modulo below would divide by.
    if gnu_nbucket == 0 || gnu_bloom_size == 0 || name.is_null() {
        return 0;
    }

    // SAFETY: the caller's contract, restated per table.
    let Some(syms) = (unsafe { table(dynsym, dynsym_count) }) else {
        return 0;
    };
    let Some(strings) = (unsafe { table(dynstr, dynstr_size) }) else {
        return 0;
    };
    let Some(bloom) = (unsafe { table(bloom, gnu_bloom_size as usize) }) else {
        return 0;
    };
    let Some(buckets) = (unsafe { table(bucket, gnu_nbucket as usize) }) else {
        return 0;
    };
    if chain.is_null() {
        return 0;
    }

    // SAFETY: NUL-terminated, as the C ABI it replaces requires.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();

    const BLOOM_BITS: u32 = usize::BITS;

    // INFO: `wrapping_shr` and not `>>`: a malformed header can put a shift
    //       count at or past the width, and the C version left that to the
    //       hardware, which masks it. Rust would panic on it in a debug build
    //       and this code has to mean the same thing in both.
    let bloom_index = (hash as usize / BLOOM_BITS as usize) % bloom.len();
    let mask = (1usize << (hash % BLOOM_BITS))
        | (1usize << (hash.wrapping_shr(gnu_shift2) % BLOOM_BITS));

    if (mask & bloom[bloom_index]) != mask {
        return 0;
    }

    let mut sym_index = buckets[(hash % gnu_nbucket) as usize];

    // INFO: The bucket names an entry inside the hashed range, and the count is
    //       the one recorded when the table was walked - taken from the image
    //       rather than recomputed, because that one already guards a zero
    //       entry size.
    if sym_index < gnu_symndx || sym_index as usize >= syms.len() {
        return 0;
    }

    loop {
        // SAFETY: the index is inside the hashed range, which is inside the
        //         symbol table, and the chain has one entry per symbol from
        //         `gnu_symndx` onwards.
        let chain_value = unsafe { *chain.add((sym_index - gnu_symndx) as usize) };

        let sym = &syms[sym_index as usize];

        // INFO: The hash is the cheap half of the comparison and comes first,
        //       so a bucket collision does not pay for the name walk.
        if ((chain_value ^ hash) >> 1) == 0 && defines(sym, strings, name) {
            if !sym_type.is_null() {
                // SAFETY: the caller passes a pointer to one byte or null.
                unsafe { *sym_type = symbol_type(sym.st_info) };
            }

            return sym.st_value;
        }

        // INFO: The low bit says whether this was the last entry of the chain.
        if chain_value & 1 != 0 {
            break;
        }

        // INFO: `checked_add` and a `usize` compare: an index that would wrap
        //       is out of range for the table, in either width.
        sym_index = match sym_index.checked_add(1) {
            Some(next) if (next as usize) < syms.len() => next,
            _ => break,
        };
    }

    0
}

/// The SysV hash lookup, `.hash`.
///
/// # Safety
///
/// As above, for the tables this one reads: `dynsym` of `dynsym_count`
/// entries, `dynstr` of `dynstr_size` bytes, `bucket` of `nbucket` entries,
/// and a `chain` array indexed by the values `bucket` and `chain` supply -
/// which the format bounds by the number of dynamic symbols. `name` is
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn vexcore_elf_lookup(
    dynsym: *const Elf64Sym,
    dynsym_count: usize,
    dynstr: *const u8,
    dynstr_size: usize,
    nbucket: u32,
    bucket: *const u32,
    chain: *const u32,
    name: *const c_char,
    hash: u32,
    sym_type: *mut u8,
) -> u64 {
    if nbucket == 0 || name.is_null() {
        return 0;
    }

    // SAFETY: the caller's contract, restated per table.
    let Some(syms) = (unsafe { table(dynsym, dynsym_count) }) else {
        return 0;
    };
    let Some(strings) = (unsafe { table(dynstr, dynstr_size) }) else {
        return 0;
    };
    let Some(buckets) = (unsafe { table(bucket, nbucket as usize) }) else {
        return 0;
    };
    if chain.is_null() {
        return 0;
    }

    // SAFETY: NUL-terminated, as the C ABI it replaces requires.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();

    let mut index = buckets[(hash % nbucket) as usize];

    // INFO: A chain entry can name itself or a predecessor - the format has
    //       no other progress guarantee - so the walk is capped at one entry
    //       per symbol and a cyclic chain is a miss rather than a hang. The
    //       GNU walk needs no such cap: its index only ever moves forward.
    let mut steps = syms.len() as isize;

    while index != STN_UNDEF {
        // INFO: The chain has one entry per dynamic symbol, so the symbol count
        //       bounds both walks - the same check the C version made, in the
        //       same place.
        if index as usize >= syms.len() || steps == 0 {
            break;
        }
        steps -= 1;

        let sym = &syms[index as usize];

        if defines(sym, strings, name) {
            if !sym_type.is_null() {
                // SAFETY: the caller passes a pointer to one byte or null.
                unsafe { *sym_type = symbol_type(sym.st_info) };
            }

            return sym.st_value;
        }

        // SAFETY: as above - the value is an index into the same chain.
        index = unsafe { *chain.add(index as usize) };
    }

    0
}
