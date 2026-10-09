//! Builds the synthetic ELF files the host tests run against.
//!
//! Each file is a minimal ELF whose only symbol table lives in a compressed
//! `.gnu_debugdata` section, which is what a stripped system library looks
//! like. Finding a symbol in it therefore exercises exactly one path: locating
//! the section, decompressing the XZ stream, and parsing the ELF that comes
//! out.
//!
//! Two layouts are produced because Android prepends a four byte CRC32 that the
//! GNU toolchain leaves out, and the loader has to cope with both:
//!
//!   <output>-plain.elf  raw XZ stream
//!   <output>-crc.elf    four byte CRC32 in front of the stream
//!
//! Usage: make-debugdata <output-prefix>

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// ELF constants, limited to what these files are made of.
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
/// e_ident[EI_VERSION], which is a byte, and e_version, which is a word - the
/// same constant in both places.
const EV_CURRENT: u32 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;

const STB_GLOBAL: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_OBJECT: u8 = 1;

const SHN_INDEX: u16 = 1;

/// The size of the ELF header, which always takes the first sixty four bytes.
const EHDR_SIZE: usize = 64;

/// The size of one 64-bit section header.
const SHDR_SIZE: usize = 64;

/// The size of one 64-bit symbol table entry.
const SYMENT: usize = 24;

/// The symbols the tests look up: (name, type, value, size).
///
/// The addresses are arbitrary but fixed, so the tests can assert on the exact
/// value rather than on "something non-zero".
const SYMBOLS: &[(&str, u8, u64, u64)] = &[
    ("zygote_probe_alpha", STT_FUNC, 0x1000, 0x40),
    ("zygote_probe_beta", STT_FUNC, 0x2000, 0x80),
    ("zygote_probe_object", STT_OBJECT, 0x3000, 0x10),
];

fn main() -> ExitCode {
    let Some(prefix) = std::env::args().nth(1) else {
        eprintln!("usage: make-debugdata <output-prefix>");
        return ExitCode::FAILURE;
    };

    let prefix = PathBuf::from(prefix);
    let inner = build_inner();

    let mut stream = Vec::new();
    if let Err(e) = lzma_rs::xz_compress(&mut Cursor::new(&inner), &mut stream) {
        eprintln!("cannot compress the inner ELF: {e}");
        return ExitCode::FAILURE;
    }

    // Android prepends the CRC32 of the uncompressed payload; the GNU toolchain
    // does not. Both layouts are fixtures, so both are written.
    let crc = crc32(&inner);

    for (suffix, payload) in [("-plain.elf", stream.clone()), ("-crc.elf", with_prefix(crc, &stream))] {
        let path = with_suffix(&prefix, suffix);

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        let outer = build_outer(&payload);

        if let Err(e) = std::fs::write(&path, &outer) {
            eprintln!("cannot write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }

        println!(
            "wrote {} ({} bytes, payload {})",
            path.display(),
            EHDR_SIZE + payload.len(),
            payload.len()
        );
    }

    ExitCode::SUCCESS
}

/// `path` with a suffix inserted before the file name's extension.
fn with_suffix(prefix: &Path, suffix: &str) -> PathBuf {
    let mut name = prefix
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(suffix);

    match prefix.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

/// The CRC32 variant: the checksum of the *uncompressed* payload in front of
/// the stream, little endian, which is what the loader is told to expect.
fn with_prefix(crc: u32, stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + stream.len());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(stream);
    out
}

/// CRC-32 as zlib defines it: reflected, polynomial 0xedb88320, final xor.
///
/// This is the checksum the loader compares against, so it has to be zlib's
/// variant and not the CRC-32/MPEG-2 one an LFSR would give.
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                0xedb88320 ^ (value >> 1)
            } else {
                value >> 1
            };
        }
        *entry = value;
    }

    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc = table[((crc ^ *byte as u32) & 0xff) as usize] ^ (crc >> 8);
    }

    crc ^ 0xffff_ffff
}

/// A string table starting with the mandatory empty string.
///
/// Returns the blob and each name's offset into it.
fn build_string_table(names: &[&str]) -> (Vec<u8>, Vec<usize>) {
    let mut blob = vec![0u8];
    let mut offsets = Vec::with_capacity(names.len());

    for name in names {
        offsets.push(blob.len());
        blob.extend_from_slice(name.as_bytes());
        blob.push(0);
    }

    (blob, offsets)
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// One section header, all ten fields.
fn shdr(name_offset: u32, kind: u32, offset: u64, size: u64, link: u32, entsize: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(SHDR_SIZE);
    push_u32(&mut out, name_offset);
    push_u32(&mut out, kind);
    push_u32(&mut out, 0); // sh_flags
    push_u32(&mut out, 0); // sh_addr
    push_u64(&mut out, offset);
    push_u64(&mut out, size);
    push_u32(&mut out, link);
    push_u32(&mut out, 0); // sh_info
    push_u64(&mut out, 1); // sh_addralign
    push_u64(&mut out, entsize);
    out
}

fn elf_header(shoff: u64, shnum: u16, shstrndx: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(EHDR_SIZE);

    // e_ident: the magic, the class and the endianness, then padding.
    out.extend_from_slice(b"\x7fELF");
    out.push(ELFCLASS64);
    out.push(ELFDATA2LSB);
    out.push(EV_CURRENT as u8);
    out.extend_from_slice(&[0u8; 9]);

    push_u16(&mut out, ET_EXEC);
    push_u16(&mut out, EM_X86_64);
    push_u32(&mut out, EV_CURRENT);
    push_u64(&mut out, 0); // e_entry
    push_u64(&mut out, 0); // e_phoff
    push_u64(&mut out, shoff);
    push_u32(&mut out, 0); // e_flags

    push_u16(&mut out, EHDR_SIZE as u16);
    push_u16(&mut out, 0); // e_phentsize
    push_u16(&mut out, 0); // e_phnum
    push_u16(&mut out, SHDR_SIZE as u16);
    push_u16(&mut out, shnum);
    push_u16(&mut out, shstrndx);

    out
}

/// The ELF that ends up compressed inside `.gnu_debugdata`.
///
/// It carries a `.symtab` with the probe symbols and nothing else: no program
/// headers, no other sections, which keeps it small enough to read as a fixture
/// while still being a valid ELF the loader can walk.
fn build_inner() -> Vec<u8> {
    let names: Vec<&str> = SYMBOLS.iter().map(|(name, ..)| *name).collect();
    let (strtab, offsets) = build_string_table(&names);

    // Index 0 is the reserved all-zero entry of every symbol table.
    let mut symtab = Vec::new();
    for _ in 0..6 {
        push_u32(&mut symtab, 0);
    }

    for (index, (_, kind, value, size)) in SYMBOLS.iter().enumerate() {
        let info = (STB_GLOBAL << 4) | kind;
        push_u32(&mut symtab, offsets[index] as u32);
        symtab.push(info);
        symtab.push(0); // st_other
        push_u16(&mut symtab, SHN_INDEX);
        push_u64(&mut symtab, *value);
        push_u64(&mut symtab, *size);
    }

    let section_names = [".symtab", ".strtab", ".shstrtab"];
    let (shstrtab, shstr_offsets) = build_string_table(&section_names);

    // Offsets are relative to the start of the file, so the header comes first.
    // Losing the header offset here shifts every section pointer and makes the
    // loader read symbols from the middle of the string table.
    let strtab_offset = EHDR_SIZE as u64;
    let symtab_offset = strtab_offset + strtab.len() as u64;
    let shstrtab_offset = symtab_offset + symtab.len() as u64;

    // The section header table sits right after the section contents.
    let shoff = EHDR_SIZE as u64 + (strtab.len() + symtab.len() + shstrtab.len()) as u64;

    let mut shdrs = shdr(0, SHT_NULL, 0, 0, 0, 0);
    shdrs.extend(shdr(
        shstr_offsets[0] as u32,
        SHT_SYMTAB,
        symtab_offset,
        symtab.len() as u64,
        2,
        SYMENT as u64,
    ));
    shdrs.extend(shdr(
        shstr_offsets[1] as u32,
        SHT_STRTAB,
        strtab_offset,
        strtab.len() as u64,
        0,
        0,
    ));
    shdrs.extend(shdr(
        shstr_offsets[2] as u32,
        SHT_STRTAB,
        shstrtab_offset,
        shstrtab.len() as u64,
        0,
        0,
    ));

    let mut out = elf_header(shoff, 4, 3);
    out.extend_from_slice(&strtab);
    out.extend_from_slice(&symtab);
    out.extend_from_slice(&shstrtab);
    out.extend_from_slice(&shdrs);
    out
}

/// A minimal ELF with a single, compressed `.gnu_debugdata` section.
fn build_outer(debugdata: &[u8]) -> Vec<u8> {
    let section_names = [".gnu_debugdata", ".shstrtab"];
    let (shstrtab, shstr_offsets) = build_string_table(&section_names);

    let debugdata_offset = EHDR_SIZE as u64;
    let shstrtab_offset = debugdata_offset + debugdata.len() as u64;
    let shoff = shstrtab_offset + shstrtab.len() as u64;

    let mut shdrs = shdr(0, SHT_NULL, 0, 0, 0, 0);
    shdrs.extend(shdr(
        shstr_offsets[0] as u32,
        SHT_PROGBITS,
        debugdata_offset,
        debugdata.len() as u64,
        0,
        0,
    ));
    shdrs.extend(shdr(
        shstr_offsets[1] as u32,
        SHT_STRTAB,
        shstrtab_offset,
        shstrtab.len() as u64,
        0,
        0,
    ));

    let mut out = elf_header(shoff, 3, 2);
    out.extend_from_slice(debugdata);
    out.extend_from_slice(&shstrtab);
    out.extend_from_slice(&shdrs);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_zlib() {
        // The values zlib.crc32 produces for these inputs, which is the
        // definition the loader checks against.
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xe8b7_be43);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414f_a339);
    }

    #[test]
    fn the_string_table_starts_with_an_empty_string() {
        let (blob, offsets) = build_string_table(&["a", "bb"]);

        assert_eq!(blob[0], 0);
        assert_eq!(offsets, vec![1, 3]);
        assert_eq!(blob, b"\0a\0bb\0");
    }

    #[test]
    fn the_inner_elf_is_the_shape_the_loader_walks() {
        let inner = build_inner();

        assert_eq!(&inner[..4], b"\x7fELF");
        assert_eq!(inner[4], ELFCLASS64);
        assert_eq!(inner[5], ELFDATA2LSB);

        // The header declares four sections and a section header table that
        // sits after the section contents, inside the file.
        let shoff = u64::from_le_bytes(inner[0x28..0x30].try_into().unwrap()) as usize;
        let shnum = u16::from_le_bytes(inner[0x3c..0x3e].try_into().unwrap()) as usize;
        let shstrndx = u16::from_le_bytes(inner[0x3e..0x40].try_into().unwrap()) as usize;

        assert_eq!(shnum, 4);
        assert_eq!(shstrndx, 3);
        assert!(shoff > EHDR_SIZE);
        assert_eq!(shoff + shnum * SHDR_SIZE, inner.len());
    }

    #[test]
    fn every_probe_symbol_is_in_the_inner_string_table() {
        let inner = build_inner();

        for (name, ..) in SYMBOLS {
            // The needle, so a name that is a prefix of another does not pass.
            assert!(
                inner
                    .windows(name.len() + 1)
                    .any(|w| w == format!("{name}\0").as_bytes()),
                "{name} is missing from the fixture"
            );
        }
    }

    #[test]
    fn the_symbol_table_starts_with_the_reserved_entry() {
        let inner = build_inner();

        // Find .symtab's offset and size out of the section header table.
        let shoff = u64::from_le_bytes(inner[0x28..0x30].try_into().unwrap()) as usize;
        let symtab_shdr = &inner[shoff + SHDR_SIZE..shoff + 2 * SHDR_SIZE];
        let offset = u64::from_le_bytes(symtab_shdr[0x18..0x20].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(symtab_shdr[0x20..0x28].try_into().unwrap()) as usize;

        assert_eq!(size, (SYMBOLS.len() + 1) * SYMENT);

        // The reserved entry is all zeroes.
        assert!(inner[offset..offset + SYMENT].iter().all(|b| *b == 0));

        // And each probe symbol carries the address the tests assert on.
        for (index, (_, _, value, sym_size)) in SYMBOLS.iter().enumerate() {
            let entry = &inner[offset + (index + 1) * SYMENT..offset + (index + 2) * SYMENT];
            assert_eq!(u64::from_le_bytes(entry[8..0x10].try_into().unwrap()), *value);
            assert_eq!(u64::from_le_bytes(entry[0x10..0x18].try_into().unwrap()), *sym_size);
        }
    }

    #[test]
    fn the_outer_elf_carries_the_payload_and_names_its_section() {
        let payload = b"not really xz".to_vec();
        let outer = build_outer(&payload);

        assert_eq!(&outer[..4], b"\x7fELF");

        let shoff = u64::from_le_bytes(outer[0x28..0x30].try_into().unwrap()) as usize;
        assert_eq!(u16::from_le_bytes(outer[0x3c..0x3e].try_into().unwrap()), 3);

        let first = &outer[shoff + SHDR_SIZE..shoff + 2 * SHDR_SIZE];
        let offset = u64::from_le_bytes(first[0x18..0x20].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(first[0x20..0x28].try_into().unwrap()) as usize;

        assert_eq!(offset, EHDR_SIZE);
        assert_eq!(size, payload.len() as usize);
        assert_eq!(&outer[offset..offset + payload.len()], &payload[..]);
    }

    #[test]
    fn the_crc_variant_puts_the_checksum_in_front() {
        let stream = b"stream".to_vec();
        let payload = with_prefix(0x1234_5678, &stream);

        assert_eq!(&payload[..4], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&payload[4..], &stream[..]);
    }

    #[test]
    fn a_suffix_lands_before_the_extension() {
        assert_eq!(
            with_suffix(Path::new("/tmp/out"), "-plain.elf"),
            PathBuf::from("/tmp/out-plain.elf")
        );
        // The prefix is a prefix, not a stem: nothing is stripped from it.
        assert_eq!(
            with_suffix(Path::new("/tmp/out.bin"), "-crc.elf"),
            PathBuf::from("/tmp/out.bin-crc.elf")
        );
        assert_eq!(with_suffix(Path::new("out"), "-plain.elf"), PathBuf::from("out-plain.elf"));
    }

    #[test]
    fn the_compressed_stream_decompresses_back_to_the_inner_elf() {
        let inner = build_inner();

        let mut stream = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(&inner), &mut stream).unwrap();

        // The XZ magic, so a change of container would be caught here rather
        // than by a test failing to decompress it.
        assert_eq!(&stream[..6], b"\xfd7zXZ\x00");

        let mut back = Vec::new();
        lzma_rs::xz_decompress(&mut Cursor::new(&stream), &mut back).unwrap();
        assert_eq!(back, inner);
    }
}