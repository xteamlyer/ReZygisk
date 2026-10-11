//! Finding the GOT slot a symbol's PLT entry jumps through.
//!
//! The linker writes, for every imported function, a relocation that names the
//! symbol and the slot its address will be stored in. Reading that pair back out
//! is what lets a hook rewrite one word instead of a function body: the PLT
//! entry keeps working, and only its target changes. YukiSU's own hook uses the
//! same trick for the same reason.
//!
//! This is a port of `find_jump_slot_got_offset` in loader/src/ptracer/utils.c.
//! The structure is the C one - read a header, walk the program headers to find
//! the dynamic table, walk the dynamic table to find the relocation and symbol
//! tables, walk the relocations comparing names - with two things that are not
//! mechanical:
//!
//! * every read is checked for the exact number of bytes it asked for, and a
//!   short read ends the walk rather than leaving a half-filled structure to be
//!   interpreted;
//! * nothing is allocated. The C version `calloc`ed the program headers and the
//!   dynamic section before reading them, which is a whole class of failure the
//!   caller has to handle on a path that only ever wants to walk them once -
//!   the entries are read one at a time into a local instead. It costs a few
//!   more `pread` calls on a path that runs once per process.

use core::ffi::{c_char, c_void};
use core::mem::size_of;

/// `PT_LOAD`, a segment that is mapped from the file.
const PT_LOAD: u32 = 1;

/// `PT_DYNAMIC`, the table of what the dynamic linker has to fix up.
const PT_DYNAMIC: u32 = 2;

/// The `d_tag` values this walk needs, from `<elf.h>`.
const DT_PLTRELSZ: i64 = 2;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_REL: i64 = 17;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;

/// `R_AARCH64_JUMP_SLOT`: the relocation a PLT entry's GOT slot is stored in.
/// The build has one architecture, so the one constant is the whole story.
const R_AARCH64_JUMP_SLOT: u32 = 1026;

const ELFCLASS64: u8 = 2;

const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];

const O_RDONLY: i32 = 0;
const O_CLOEXEC: i32 = 0o2000000;

const SEEK_END: i32 = 2;

/// A name longer than this is not compared: the linker does not emit symbol
/// names anywhere near this long, and a truncated one simply fails the
/// comparison - which is the same way the C version answered, and the reason
/// the buffer is fixed rather than allocated.
const NAME_MAX: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Dyn {
    d_tag: i64,
    d_un: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

/// A pair of `u64`, which is what both `Elf64_Rel` and the head of
/// `Elf64_Rela` are: the extra addend a Rela carries is not read, because the
/// walk only needs the offset and the info word.
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Rel {
    r_offset: u64,
    r_info: u64,
}

extern "C" {
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn lseek(fd: i32, offset: i64, whence: i32) -> i64;
    fn pread64(fd: i32, buf: *mut c_void, count: usize, offset: i64) -> isize;
}

/// Reads `size_of::<T>()` bytes at `offset`, or nothing.
#[inline]
unsafe fn read_at<T>(fd: i32, offset: i64) -> Option<T> {
    let mut value = core::mem::MaybeUninit::<T>::uninit();

    // SAFETY: the buffer is exactly the size of `T`, so a full read fills it
    //         and a short one is rejected before `assume_init`.
    let got = unsafe { pread64(fd, value.as_mut_ptr() as *mut c_void, size_of::<T>(), offset) };
    if got != size_of::<T>() as isize {
        return None;
    }

    // SAFETY: the read above filled every byte.
    Some(unsafe { value.assume_init() })
}

/// The file offset a virtual address maps to, through whichever `PT_LOAD`
/// segment contains it.
unsafe fn vaddr_to_offset(fd: i32, ehdr: &Elf64Ehdr, vaddr: u64) -> Option<i64> {
    for index in 0..ehdr.e_phnum as u64 {
        // SAFETY: the entry is at an offset derived from the header's own
        //         table location; a read past the end answers `None`.
        let phdr: Elf64Phdr = unsafe { read_at(fd, (ehdr.e_phoff + index * ehdr.e_phentsize as u64) as i64) }?;

        if phdr.p_type != PT_LOAD {
            continue;
        }

        let end = phdr.p_vaddr.checked_add(phdr.p_filesz)?;
        if vaddr < phdr.p_vaddr || vaddr >= end {
            continue;
        }

        return Some(phdr.p_offset as i64 + (vaddr - phdr.p_vaddr) as i64);
    }

    None
}

/// The name at `st_name` in the string table at `strtab`, or nothing when the
/// offset is past the end of the file.
unsafe fn symbol_name(fd: i32, strtab_off: i64, st_name: u32) -> Option<[u8; NAME_MAX]> {
    let mut name = [0u8; NAME_MAX];

    // SAFETY: one byte less than the buffer, so the terminator the comparison
    //         relies on is always a real zero even when the read fills it.
    let got = unsafe { pread64(fd, name.as_mut_ptr() as *mut c_void, NAME_MAX - 1, strtab_off + st_name as i64) };
    if got <= 0 {
        return None;
    }

    Some(name)
}

/// Whether the NUL-terminated `candidate` equals `wanted`.
fn names_equal(candidate: &[u8; NAME_MAX], wanted: &[u8]) -> bool {
    let end = candidate.iter().position(|&byte| byte == 0).unwrap_or(NAME_MAX);

    &candidate[..end] == wanted
}

/// The walk, with the descriptor already open.
unsafe fn scan(fd: i32, wanted: &[u8], out_bias: *mut u64, out_got_off: *mut u64) -> bool {
    // SAFETY: `read_at` answers `None` rather than filling a short read.
    let Some(ehdr) = (unsafe { read_at::<Elf64Ehdr>(fd, 0) }) else {
        return false;
    };

    if ehdr.e_ident[..4] != ELFMAG || ehdr.e_ident[4] != ELFCLASS64 || ehdr.e_phnum == 0 {
        return false;
    }

    let mut min_vaddr = u64::MAX;
    let mut dyn_vaddr = 0u64;
    let mut dyn_size = 0u64;

    for index in 0..ehdr.e_phnum as u64 {
        // SAFETY: as in `vaddr_to_offset`.
        let Some(phdr) = (unsafe { read_at::<Elf64Phdr>(fd, (ehdr.e_phoff + index * ehdr.e_phentsize as u64) as i64) }) else {
            return false;
        };

        if phdr.p_type == PT_LOAD && phdr.p_vaddr < min_vaddr {
            min_vaddr = phdr.p_vaddr;
        }

        if phdr.p_type == PT_DYNAMIC {
            dyn_vaddr = phdr.p_vaddr;
            dyn_size = phdr.p_filesz;
        }
    }

    if dyn_vaddr == 0 || dyn_size == 0 || min_vaddr == u64::MAX {
        return false;
    }

    let Some(dyn_off) = (unsafe { vaddr_to_offset(fd, &ehdr, dyn_vaddr) }) else {
        return false;
    };

    let mut jmprel = 0u64;
    let mut pltrelsz = 0u64;
    let mut pltrel = 0u64;
    let mut symtab = 0u64;
    let mut strtab = 0u64;

    let entries = dyn_size / size_of::<Elf64Dyn>() as u64;
    for index in 0..entries {
        // SAFETY: as above; a table that runs past the end ends the walk.
        let Some(entry) = (unsafe { read_at::<Elf64Dyn>(fd, dyn_off + (index * size_of::<Elf64Dyn>() as u64) as i64) }) else {
            return false;
        };

        match entry.d_tag {
            DT_JMPREL => jmprel = entry.d_un,
            DT_PLTRELSZ => pltrelsz = entry.d_un,
            DT_PLTREL => pltrel = entry.d_un,
            DT_SYMTAB => symtab = entry.d_un,
            DT_STRTAB => strtab = entry.d_un,
            _ => {}
        }
    }

    if jmprel == 0 || pltrelsz == 0 || symtab == 0 || strtab == 0 || (pltrel != DT_REL as u64 && pltrel != DT_RELA as u64) {
        return false;
    }

    // SAFETY: each conversion walks the program headers and answers `None` when
    //         the address is not in a segment the file maps.
    let (Some(rel_off), Some(sym_off), Some(str_off)) = (unsafe {
        (
            vaddr_to_offset(fd, &ehdr, jmprel),
            vaddr_to_offset(fd, &ehdr, symtab),
            vaddr_to_offset(fd, &ehdr, strtab),
        )
    }) else {
        return false;
    };

    // INFO: `DT_PLTREL` says which of the two relocation shapes the table
    //       holds; both begin with the same two words, which is all this walk
    //       reads.
    let entry_size = size_of::<Elf64Rel>() as u64;
    let count = pltrelsz / entry_size;

    for index in 0..count {
        // SAFETY: a relocation past the end of the file ends the walk.
        let Some(rel) = (unsafe { read_at::<Elf64Rel>(fd, rel_off + (index * entry_size) as i64) }) else {
            break;
        };

        // INFO: `ELF64_R_TYPE` and `ELF64_R_SYM`, inlined: the low half of the
        //       info word is the type and the high half is the symbol index.
        let r_type = (rel.r_info & 0xffff_ffff) as u32;
        let sym_index = rel.r_info >> 32;

        if r_type != R_AARCH64_JUMP_SLOT {
            continue;
        }

        // SAFETY: a symbol index past the end of the file ends the walk.
        let Some(sym) = (unsafe { read_at::<Elf64Sym>(fd, sym_off + (sym_index * size_of::<Elf64Sym>() as u64) as i64) }) else {
            break;
        };

        if sym.st_name == 0 {
            continue;
        }

        // SAFETY: reading a name only ever answers, or nothing when the offset
        //         is past the end of the file.
        let Some(name) = (unsafe { symbol_name(fd, str_off, sym.st_name) }) else {
            break;
        };

        if !names_equal(&name, wanted) {
            continue;
        }

        // SAFETY: the caller passed pointers to two `u64`, per the ABI.
        unsafe {
            *out_bias = min_vaddr;
            *out_got_off = rel.r_offset;
        }

        return true;
    }

    false
}

/// The address a symbol's PLT entry jumps through, as `(bias, got_offset)`.
///
/// `bias` is the image's lowest load address and `got_offset` is the
/// relocation's `r_offset`; the caller adds the two to a mapped base, which is
/// what the C version documented by handing back the same pair.
///
/// # Safety
///
/// `path` and `symbol` are NUL-terminated strings, `out_bias` and
/// `out_got_off` are valid pointers to `u64`, and all four stay valid for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn vexcore_got_offset(
    path: *const c_char,
    symbol: *const c_char,
    out_bias: *mut u64,
    out_got_off: *mut u64,
) -> bool {
    if path.is_null() || symbol.is_null() || out_bias.is_null() || out_got_off.is_null() {
        return false;
    }

    // SAFETY: NUL-terminated, per the contract above.
    let wanted = unsafe { core::ffi::CStr::from_ptr(symbol) }.to_bytes();

    // SAFETY: NUL-terminated, and the flags are plain constants.
    let fd = unsafe { open(path, O_RDONLY | O_CLOEXEC) };
    if fd < 0 {
        return false;
    }

    // INFO: A file too short to hold a header cannot be walked, and asking the
    //       descriptor its size is cheaper than finding out one read at a time.
    let size = unsafe { lseek(fd, 0, SEEK_END) };
    if size < size_of::<Elf64Ehdr>() as i64 {
        unsafe { close(fd) };

        return false;
    }

    let found = unsafe { scan(fd, wanted, out_bias, out_got_off) };

    unsafe { close(fd) };

    found
}
