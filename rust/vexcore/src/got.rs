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
//!   interpreted; every offset is assembled with checked arithmetic and has to
//!   name a byte the image actually has, so a header field that tries to move a
//!   read outside the file answers "not found" instead of wrapping into some
//!   other part of it;
//! * nothing is allocated. The C version `calloc`ed the program headers and the
//!   dynamic section before reading them, which is a whole class of failure the
//!   caller has to handle on a path that only ever wants to walk them once -
//!   the entries are read one at a time into a local instead. It costs a few
//!   more `pread` calls on a path that runs once per process.
//!
//! The byte source is behind the [`Image`] trait: the device build reads a
//! descriptor, and the host suite supplies an in-memory image, so the whole
//! walk is compiled - and pinned by tests - on a workstation too. That matters
//! because the walk used to be excluded from the host build, which is how a
//! relocation-stride bug lived here unseen.

use core::mem::size_of;

/* INFO: The symbol shape is lookup.rs's: it is #[repr(C)] over bytes a file
         supplied and re-exported for the C ABI, and a second private copy
         here would only be a chance for the two to drift apart. */
use crate::lookup::Elf64Sym;

/// `PT_LOAD`, a segment that is mapped from the file.
const PT_LOAD: u32 = 1;

/// `PT_DYNAMIC`, the table of what the dynamic linker has to fix up.
const PT_DYNAMIC: u32 = 2;

/// The `d_tag` values this walk needs, from `<elf.h>`.
const DT_NULL: i64 = 0;
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

/// `EI_DATA` must say little-endian: the fields below are read as the bytes
/// this target lays them out in, and a big-endian image would hand back
/// plausible-looking garbage rather than a refusal.
const ELFDATA2LSB: u8 = 1;

/// `e_phnum` uses this value to mean "the count is somewhere else", and
/// finding it would take the section headers this walk never reads.
const PN_XNUM: u16 = 0xffff;

const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];

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

/// A pair of `u64`, which is what both `Elf64_Rel` and the head of
/// `Elf64_Rela` are: the extra addend a Rela carries is not read, because the
/// walk only needs the offset and the info word. The *stride* between entries
/// is the two shapes' real difference - see [`RELA_ENTRY_SIZE`].
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Rel {
    r_offset: u64,
    r_info: u64,
}

/// `sizeof(Elf64_Rela)`: a JMPREL table flagged `DT_RELA` strides 24 bytes,
/// and walking it by 16 reads every third entry's addend as the next entry's
/// header - which is to say, it never finds roughly two thirds of the
/// imported symbols. `DT_REL` strides 16.
const RELA_ENTRY_SIZE: u64 = 24;
const REL_ENTRY_SIZE: u64 = 16;

/// The byte source a walk reads through.
///
/// Production wraps an open descriptor; the host suite hands over memory, so
/// the parsing logic is compiled and exercised on a workstation instead of
/// only on the device target.
pub(crate) trait Image {
    /// Reads up to `len` bytes into `buf` at `offset` and answers how many:
    /// a short read is the end of the file and not an error - the name window
    /// below reads a fixed 255 bytes wherever the name sits, and a name near
    /// the end of a real library's string table legitimately runs past it.
    /// Zero means nothing was read: past the end, or a read that failed.
    ///
    /// The buffer may be uninitialized memory the caller intends to fill -
    /// nothing here may read it, only the image's own bytes may be written
    /// into it.
    fn pread_max(&self, offset: i64, buf: *mut u8, len: usize) -> usize;

    /// The length of the image; offsets are validated against it before they
    /// are used, so a header field pointing past the end is refused up front.
    fn len(&self) -> i64;
}

#[cfg(not(test))]
mod sys {
    use super::Image;
    use core::ffi::{c_char, c_void};

    const O_RDONLY: i32 = 0;
    const O_CLOEXEC: i32 = 0o2000000;
    const SEEK_END: i32 = 2;

    extern "C" {
        fn open(path: *const c_char, flags: i32, ...) -> i32;
        fn close(fd: i32) -> i32;
        fn lseek(fd: i32, offset: i64, whence: i32) -> i64;
        fn pread64(fd: i32, buf: *mut c_void, count: usize, offset: i64) -> isize;
    }

    /// The descriptor the device build walks.
    pub(super) struct FileImage {
        fd: i32,
        size: i64,
    }

    impl FileImage {
        /// Opens `path` and asks its length, or answers nothing.
        pub(super) fn open(path: *const c_char) -> Option<FileImage> {
            // SAFETY: NUL-terminated per the caller's contract, and the flags
            //         are plain constants.
            let fd = unsafe { open(path, O_RDONLY | O_CLOEXEC) };
            if fd < 0 {
                return None;
            }

            // INFO: Asking the descriptor its size is cheaper than finding out
            //       one read at a time, and a size below zero says the seek -
            //       and so the walk - cannot work.
            let size = unsafe { lseek(fd, 0, SEEK_END) };
            if size < 0 {
                // SAFETY: the descriptor above is ours and open.
                unsafe { close(fd) };

                return None;
            }

            Some(FileImage { fd, size })
        }
    }

    impl Drop for FileImage {
        fn drop(&mut self) {
            // SAFETY: the descriptor is ours, and closing twice cannot happen:
            //         `drop` runs exactly once.
            unsafe { close(self.fd) };
        }
    }

    impl Image for FileImage {
        fn pread_max(&self, offset: i64, buf: *mut u8, len: usize) -> usize {
            // SAFETY: the buffer is the caller's, writable for `len` bytes,
            //         and untouched beyond whatever the read reports.
            let got = unsafe { pread64(self.fd, buf as *mut c_void, len, offset) };

            if got < 0 {
                0
            } else {
                got as usize
            }
        }

        fn len(&self) -> i64 {
            self.size
        }
    }
}

#[cfg(test)]
mod host {
    use super::Image;

    /// An image held in memory, which is what the host suite walks.
    pub(crate) struct MemImage(pub Vec<u8>);

    impl Image for MemImage {
        fn pread_max(&self, offset: i64, buf: *mut u8, len: usize) -> usize {
            if offset < 0 {
                return 0;
            }

            let Ok(start) = usize::try_from(offset) else {
                return 0;
            };
            let Some(available) = self.0.len().checked_sub(start) else {
                return 0;
            };

            // INFO: A short answer is the end of the image and not an error,
            //       the same way a pread on a file answers fewer bytes than
            //       were asked for at its end.
            let n = available.min(len);
            if n == 0 {
                return 0;
            }

            // SAFETY: `buf` is writable for `len` bytes and `n` is at most
            //         that; the source is `n` bytes of the image.
            unsafe { core::ptr::copy_nonoverlapping(self.0.as_ptr().add(start), buf, n) };

            n
        }

        fn len(&self) -> i64 {
            self.0.len() as i64
        }
    }
}

#[cfg(test)]
pub(crate) use host::MemImage;

/// A file offset `base + delta` that stays inside the image, or nothing.
///
/// Every field of a header is a raw file value, so every sum built from one
/// goes through here: an addend too large for the address space, or a sum
/// past the end of the file, is a malformed table and not a different valid
/// offset that happens to be nearby.
#[inline]
fn offset_within(img: &dyn Image, base: i64, delta: u64) -> Option<i64> {
    if delta > i64::MAX as u64 {
        return None;
    }

    let end = base.checked_add(delta as i64)?;
    if end < 0 || end >= img.len() {
        return None;
    }

    Some(end)
}

/// Reads `size_of::<T>()` bytes at `offset`, or nothing.
///
/// `T` has to be `Copy`: the read fills every byte, padding included, before
/// it is interpreted, which is only sound for plain data.
#[inline]
fn read_at<T: Copy>(img: &dyn Image, offset: i64) -> Option<T> {
    let mut value = core::mem::MaybeUninit::<T>::uninit();

    // SAFETY: the buffer is exactly the size of `T`, so only a read that
    //         fills it entirely may go on to `assume_init`.
    let got = img.pread_max(offset, value.as_mut_ptr() as *mut u8, size_of::<T>());
    if got != size_of::<T>() {
        return None;
    }

    // SAFETY: the read above filled every byte.
    Some(unsafe { value.assume_init() })
}

/// Walks the program headers, handing each to `visit`; answers false when the
/// header table itself cannot be read through.
///
/// `ehdr` has already passed validation, so the table location is arithmetic
/// on trusted shapes - but each entry's offset is still checked against the
/// image length before it is read.
fn for_each_phdr(img: &dyn Image, ehdr: &Elf64Ehdr, mut visit: impl FnMut(&Elf64Phdr)) -> bool {
    if ehdr.e_phoff > i64::MAX as u64 {
        return false;
    }
    let base = ehdr.e_phoff as i64;

    for index in 0..ehdr.e_phnum as u64 {
        // SAFETY: the entry's offset is checked against the image length; a
        //         read past the end answers `None` and ends the walk.
        let Some(offset) = offset_within(img, base, index * ehdr.e_phentsize as u64) else {
            return false;
        };
        let Some(phdr) = read_at::<Elf64Phdr>(img, offset) else {
            return false;
        };

        visit(&phdr);
    }

    true
}

/// The file offset a virtual address maps to, through whichever `PT_LOAD`
/// segment contains it.
fn vaddr_to_offset(img: &dyn Image, ehdr: &Elf64Ehdr, vaddr: u64) -> Option<i64> {
    let mut found = None;

    for_each_phdr(img, ehdr, |phdr| {
        if found.is_some() || phdr.p_type != PT_LOAD {
            return;
        }

        let Some(end) = phdr.p_vaddr.checked_add(phdr.p_filesz) else {
            return;
        };
        if vaddr < phdr.p_vaddr || vaddr >= end {
            return;
        }

        if let Some(offset) = phdr.p_offset.checked_add(vaddr - phdr.p_vaddr) {
            if offset <= i64::MAX as u64 {
                found = Some(offset as i64);
            }
        }
    });

    found
}

/// The name at `st_name` in the string table at `strtab`, or nothing when the
/// offset is past the end of the file.
///
/// The window is a fixed 255 bytes wherever the name sits, and a name near
/// the end of a real library's string table legitimately runs past the end of
/// the file: a short read is the normal answer there, and the bytes past it
/// stay the zeros the buffer began as - which is exactly the terminator the
/// comparison relies on.
fn symbol_name(img: &dyn Image, strtab_off: i64, st_name: u32) -> Option<[u8; NAME_MAX]> {
    let mut name = [0u8; NAME_MAX];

    let Some(offset) = offset_within(img, strtab_off, st_name as u64) else {
        return None;
    };

    let got = img.pread_max(offset, name.as_mut_ptr(), NAME_MAX - 1);
    if got == 0 {
        return None;
    }

    Some(name)
}

/// Whether the NUL-terminated `candidate` equals `wanted`.
fn names_equal(candidate: &[u8; NAME_MAX], wanted: &[u8]) -> bool {
    let end = candidate.iter().position(|&byte| byte == 0).unwrap_or(NAME_MAX);

    &candidate[..end] == wanted
}

/// The walk, over any [`Image`]. Crate-visible for the host suite, which
/// supplies its own image.
pub(crate) fn scan(img: &dyn Image, wanted: &[u8], out_bias: *mut u64, out_got_off: *mut u64) -> bool {
    let Some(ehdr) = read_at::<Elf64Ehdr>(img, 0) else {
        return false;
    };

    // INFO: The data-encoding and `e_phentsize` checks matter as much as the
    //       magic: a wrong endianness or a zero entry size makes every entry
    //       a misparse of the first one, and `PN_XNUM` hides a count this
    //       walk has no second place to read.
    if ehdr.e_ident[..4] != ELFMAG
        || ehdr.e_ident[4] != ELFCLASS64
        || ehdr.e_ident[5] != ELFDATA2LSB
        || ehdr.e_phnum == 0
        || ehdr.e_phnum == PN_XNUM
        || (ehdr.e_phentsize as usize) < size_of::<Elf64Phdr>()
    {
        return false;
    }

    let mut min_vaddr = u64::MAX;
    let mut dyn_vaddr = 0u64;
    let mut dyn_size = 0u64;

    if !for_each_phdr(img, &ehdr, |phdr| {
        if phdr.p_type == PT_LOAD && phdr.p_vaddr < min_vaddr {
            min_vaddr = phdr.p_vaddr;
        }

        if phdr.p_type == PT_DYNAMIC {
            dyn_vaddr = phdr.p_vaddr;
            dyn_size = phdr.p_filesz;
        }
    }) {
        return false;
    }

    if dyn_vaddr == 0 || dyn_size == 0 || min_vaddr == u64::MAX {
        return false;
    }

    let Some(dyn_off) = vaddr_to_offset(img, &ehdr, dyn_vaddr) else {
        return false;
    };

    let mut jmprel = 0u64;
    let mut pltrelsz = 0u64;
    let mut pltrel = 0u64;
    let mut symtab = 0u64;
    let mut strtab = 0u64;

    let entries = dyn_size / size_of::<Elf64Dyn>() as u64;
    for index in 0..entries {
        // SAFETY: a table that runs past the end ends the walk.
        let Some(offset) = offset_within(img, dyn_off, index * size_of::<Elf64Dyn>() as u64)
        else {
            return false;
        };
        let Some(entry) = read_at::<Elf64Dyn>(img, offset) else {
            return false;
        };

        // INFO: The table ends at its first `DT_NULL`; entries past it are
        //       padding, and treating them as live could overwrite a value an
        //       earlier real entry already set.
        if entry.d_tag == DT_NULL {
            break;
        }

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

    let (Some(rel_off), Some(sym_off), Some(str_off)) = (
        vaddr_to_offset(img, &ehdr, jmprel),
        vaddr_to_offset(img, &ehdr, symtab),
        vaddr_to_offset(img, &ehdr, strtab),
    ) else {
        return false;
    };

    // INFO: A translated address can only name a byte a segment maps, but a
    //       malformed one can still name a byte past the image; the extent
    //       arithmetic below reads `img.len()`, so the bounds are settled
    //       here.
    if sym_off < 0 || sym_off >= img.len() {
        return false;
    }

    // INFO: The dynamic linker lays `.dynsym` before `.dynstr`; the distance
    //       between them is therefore the symbol table's extent, which bounds
    //       the symbol index a relocation can name. A file that puts
    //       `.dynstr` first - or stretches an index past the string table -
    //       is answered with the rest of the file, which every table read
    //       below still checks against the image length.
    let sym_extent = if str_off > sym_off {
        (str_off - sym_off) as u64
    } else {
        (img.len() - sym_off) as u64
    };
    let sym_count_max = sym_extent / size_of::<Elf64Sym>() as u64;

    // INFO: `DT_PLTREL` says which of the two relocation shapes the table
    //       holds: both begin with the same two words, which is all this walk
    //       reads, but the distance between entries is 24 bytes for a Rela
    //       table and 16 for a Rel one.
    let entry_size = if pltrel == DT_RELA as u64 {
        RELA_ENTRY_SIZE
    } else {
        REL_ENTRY_SIZE
    };
    let count = pltrelsz / entry_size;

    for index in 0..count {
        // SAFETY: a relocation past the end of the file ends the walk.
        let Some(offset) = offset_within(img, rel_off, index * entry_size) else {
            break;
        };
        let Some(rel) = read_at::<Elf64Rel>(img, offset) else {
            break;
        };

        // INFO: `ELF64_R_TYPE` and `ELF64_R_SYM`, inlined: the low half of the
        //       info word is the type and the high half is the symbol index.
        let r_type = (rel.r_info & 0xffff_ffff) as u32;
        let sym_index = rel.r_info >> 32;

        if r_type != R_AARCH64_JUMP_SLOT {
            continue;
        }

        if sym_index >= sym_count_max {
            continue;
        }

        // SAFETY: a symbol index past the end of the file ends the walk.
        let Some(offset) = offset_within(
            img,
            sym_off,
            sym_index * size_of::<Elf64Sym>() as u64,
        ) else {
            break;
        };
        let Some(sym) = read_at::<Elf64Sym>(img, offset) else {
            break;
        };

        if sym.st_name == 0 {
            continue;
        }

        // SAFETY: reading a name only ever answers, or nothing when the offset
        //         is past the end of the file.
        let Some(name) = symbol_name(img, str_off, sym.st_name) else {
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
/// A symbol whose value happens to be `0` is indistinguishable from "not
/// found" - the C ABI this replaces had the same answer, and the callers
/// treat it as a miss.
///
/// # Safety
///
/// `path` and `symbol` are NUL-terminated strings, `out_bias` and
/// `out_got_off` are valid pointers to `u64`, and all four stay valid for the
/// duration of the call.
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn vexcore_got_offset(
    path: *const core::ffi::c_char,
    symbol: *const core::ffi::c_char,
    out_bias: *mut u64,
    out_got_off: *mut u64,
) -> bool {
    if path.is_null() || symbol.is_null() || out_bias.is_null() || out_got_off.is_null() {
        return false;
    }

    // SAFETY: NUL-terminated, per the contract above.
    let wanted = unsafe { core::ffi::CStr::from_ptr(symbol) }.to_bytes();

    // SAFETY: NUL-terminated, and the flags are plain constants.
    let Some(file) = sys::FileImage::open(path) else {
        return false;
    };

    // INFO: A file too short to hold a header cannot be walked; `FileImage`
    //       already asked the descriptor its size, and every read inside the
    //       walk is checked against it.
    if file.len() < size_of::<Elf64Ehdr>() as i64 {
        return false;
    }

    scan(&file, wanted, out_bias, out_got_off)
}
