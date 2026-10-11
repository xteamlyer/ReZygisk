#ifndef VEXCORE_H
#define VEXCORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* INFO: The Rust half of the loader, as C sees it.
         Sources: rust/vexcore/src/{hash,lookup}.rs

         Only two things cross this line, and both are values rather than
         state: a name in, an address out, plus the tables the answer is
         searched in. Nothing on the other side allocates, owns a file
         descriptor, or keeps anything between calls - which is what makes the
         boundary safe to draw here. The `ElfImg` those tables belong to stays
         a C structure; the Rust side is told which tables to read and how long
         they are, so a change to that structure cannot silently change the
         meaning of a call. */

/* INFO: One entry of a 64-bit ELF symbol table, layed out the way the Rust
         `Elf64Sym` is. The image's own `.dynsym` is what is read through this,
         so the field order and widths are the file format's, not a choice
         made here. */
struct vexcore_symbol {
  uint32_t st_name;
  uint8_t st_info;
  uint8_t st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
};

/* INFO: Checked rather than assumed: this structure is reinterpreted over
         bytes that came out of a file, and a compiler that padded it
         differently from the other side would not fail to build - it would
         read the wrong fields and answer with the wrong address. */
_Static_assert(sizeof(struct vexcore_symbol) == 24, "vexcore_symbol must match the Rust Elf64Sym");

/* INFO: The SysV and GNU name hashes. A lookup starts by hashing the name it
         was asked for, and the answer has to be the same value the linker used
         when it built the table - one bit of difference and the lookup misses. */
uint32_t vexcore_elf_hash(const char *name);
uint32_t vexcore_gnu_hash(const char *name);

/* INFO: The two hash-table lookups. Each answers the symbol's `st_value`, or 0
         when the name is not in the table, and writes the symbol's type to
         `sym_type` on a hit.

         `dynstr_size` is the size of the string table the names live in: a
         symbol whose `st_name` points past it is a miss, not a string read
         that runs off the end of the mapping. The chain arrays have no
         recorded length and are read by the index the previous entry supplied,
         bounded by `dynsym_count` - the same bound the C implementation used. */
uintptr_t vexcore_gnu_lookup(const struct vexcore_symbol *dynsym, size_t dynsym_count,
                             const char *dynstr, size_t dynstr_size,
                             uint32_t gnu_nbucket, uint32_t gnu_symndx,
                             uint32_t gnu_bloom_size, uint32_t gnu_shift2,
                             const uintptr_t *bloom, const uint32_t *bucket,
                             const uint32_t *chain,
                             const char *name, uint32_t hash, unsigned char *sym_type);

uintptr_t vexcore_elf_lookup(const struct vexcore_symbol *dynsym, size_t dynsym_count,
                             const char *dynstr, size_t dynstr_size,
                             uint32_t nbucket, const uint32_t *bucket,
                             const uint32_t *chain,
                             const char *name, uint32_t hash, unsigned char *sym_type);

/* INFO: The address a symbol's PLT entry jumps through, as `(bias, got_offset)`:
         `bias` is the image's lowest load address and `got_offset` is the
         relocation's `r_offset`. False when the file has no such slot, which is
         also how a file that cannot be read answers. */
bool vexcore_got_offset(const char *path, const char *symbol,
                        uint64_t *out_bias, uint64_t *out_got_off);

#endif /* VEXCORE_H */
