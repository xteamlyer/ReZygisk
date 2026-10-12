#ifndef ZN_SPAWNER_H
#define ZN_SPAWNER_H

/* INFO: What identifies HyperOS's app spawner. It lives in a header because the
         whole Zygisk Next runtime of a boot hangs off the one question it
         answers, and because both answers are pure text and bytes - so the host
         test suite can hold them still (tests/host/test_zn_spawner.c) while the
         device cannot be asked.

         Getting it wrong is not a degraded feature, it is the other branch:
         entry() hands a process it does not recognise as the spawner to
         hook_functions(), and the JNI hooks are what crashed the spawner and
         left every application unable to start. So there are two answers and
         they are used where each one is the right one:

           - the image mapped at offset zero, which is what decides whether this
             process hosts the runtime at all (zn_hyos.h). It is the answer that
             survives a rename and an unreadable /proc/self/exe, and it is safe
             to ask in any process the ptracer reaches: execve replaces the
             address space, so an application that execs app_process64 no longer
             carries the spawner's image, and a process that merely forked from
             the spawner is never injected a second time.
           - the executable's own name, which only ever keeps a process out of
             the wrong branch: a process that is the spawner by name but whose
             image could not be inspected is still not a zygote, and the hooks
             installed for one are the crash above. It cannot arm the runtime -
             the hooks need the image identity the scan produces - so it is a
             guard and not a second way of finding the runtime.

         The image test is deliberately stricter than the name test: a mapping
         that happens to be named like the spawner is only the spawner if what is
         mapped really is an ELF for this ABI. */

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "misc.h"

#define ZN_SPAWNER_BASE_NAME "hyos_spawner"

/* INFO: The image has to be one this process could execute, and the ABI is the
         one this copy of the library was built for. `ElfW` already follows the
         ABI, so only the machine has to be spelled out. */
#if defined(__aarch64__)
  #define ZN_SPAWNER_ELF_MACHINE EM_AARCH64
#elif defined(__arm__)
  #define ZN_SPAWNER_ELF_MACHINE EM_ARM
#elif defined(__x86_64__)
  #define ZN_SPAWNER_ELF_MACHINE EM_X86_64
#else
  #define ZN_SPAWNER_ELF_MACHINE EM_NONE
#endif

/* INFO: A path whose last component is the spawner's file name, as a whole
         component: ".../bin/hyos_spawner" matches, ".../bin/xhyos_spawner" and
         ".../bin/hyos_spawner.old" do not, and neither does a bare file name
         with no directory in front of it - every caller passes a path the kernel
         produced, and both of them are absolute.

         The name is compared and not the directory on purpose: what the platform
         calls the file is the platform's business, and the one build that ships
         it from somewhere else should still be found. */
static inline bool zn_spawner_path_is_image(const char *path, size_t len) {
  static const char kBase[] = ZN_SPAWNER_BASE_NAME;
  const size_t base_len = sizeof(kBase) - 1;

  if (path == NULL) return false;
  if (len <= base_len) return false;
  if (path[len - base_len - 1] != '/') return false;

  return memcmp(path + len - base_len, kBase, base_len) == 0;
}

/* INFO: Whether a mapping's path names the spawner's image, with the
         " (deleted)" suffix the kernel appends to a file that was replaced while
         it was mapped dropped first: an OTA replaces the runtime image under a
         running system, and the suffix is part of the name, so a plain
         comparison would stop finding the runtime after one.

         This is the name half of the answer and nothing more. The bytes behind
         the mapping are the other half, and a caller that can read them asks
         zn_spawner_elf_is_image for it - which is what the injector does, since
         it is inside the process. A caller that cannot read them, like the
         monitor looking at somebody else's maps, has only this one to go on.

         The name is defined here once, and this is the only place that strips
         the suffix: three readers used to spell the same comparison out and one
         of them did not strip it at all, so a build whose runtime image had been
         replaced stopped recognising itself. */
static inline bool zn_spawner_map_is_spawner(const char *path) {
  if (path == NULL) return false;

  return zn_spawner_path_is_image(path, strip_deleted_suffix(path, strlen(path)));
}

/* INFO: Whether a mapping starts with the spawner's executable header.
         `available_size` is how much of the mapping may be read, and the caller
         is responsible for the mapping being readable at all: a PROT_NONE
         mapping is in the listing and must never be dereferenced.

         The header is copied out rather than read in place - nothing promises
         the address the caller passed is aligned for ElfW(Ehdr), and the
         .gnu_debugdata path in elf_util.c went to the same trouble for the same
         reason. */
static inline bool zn_spawner_elf_is_image(const unsigned char *image, size_t available_size) {
  if (image == NULL) return false;
  if (available_size < sizeof(ElfW(Ehdr))) return false;

  ElfW(Ehdr) header;
  memcpy(&header, image, sizeof(header));

  if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) return false;
  if (header.e_ident[EI_CLASS] != (sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32)) return false;
  if (header.e_ident[EI_DATA] != ELFDATA2LSB) return false;
  if (header.e_type != ET_DYN && header.e_type != ET_EXEC) return false;

  return header.e_machine == ZN_SPAWNER_ELF_MACHINE;
}

#endif /* ZN_SPAWNER_H */
