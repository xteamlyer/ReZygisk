//! The two hash functions the ELF format defines for symbol tables.
//!
//! Both are ported bit for bit from the C they replace, because they are not
//! a private detail: a lookups' first step is to hash the name the caller
//! asked for and index a table the linker built with the same function. One
//! bit of difference and the lookup silently misses.

use core::ffi::c_char;

/// The SysV hash, `Elf_Hash` in the reference implementation.
///
/// The C version this replaces walks a `const char *` and adds each byte as
/// `unsigned char`, so a name with a byte above 0x7f hashes the same here.
#[no_mangle]
pub extern "C" fn vexcore_elf_hash(name: *const c_char) -> u32 {
    if name.is_null() {
        return 0;
    }

    let mut h: u32 = 0;
    let mut cursor = name;

    // SAFETY: the caller passes a NUL-terminated string. That is the same
    //         assumption the C function made, and the only one either of them
    //         can make about a name - the length is not passed, by design,
    //         because the ABI it serves has no length either.
    unsafe {
        while *cursor != 0 {
            // INFO: The shift drops the high bits, which is the point of the
            //       algorithm rather than an accident, so the arithmetic that
            //       would otherwise be a debug assertion is written to wrap.
            h = (h << 4).wrapping_add(*cursor as u8 as u32);

            let g = h & 0xf000_0000;
            if g != 0 {
                h ^= g >> 24;
            }

            h &= !g;

            cursor = cursor.add(1);
        }
    }

    h
}

/// The GNU hash, `dl_new_hash` in glibc and the one `.gnu.hash` is built with.
#[no_mangle]
pub extern "C" fn vexcore_gnu_hash(name: *const c_char) -> u32 {
    if name.is_null() {
        return 5381;
    }

    let mut h: u32 = 5381;
    let mut cursor = name;

    // SAFETY: NUL-terminated, as above.
    unsafe {
        while *cursor != 0 {
            h = (h << 5).wrapping_add(h).wrapping_add(*cursor as u8 as u32);

            cursor = cursor.add(1);
        }
    }

    h
}
