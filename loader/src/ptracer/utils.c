#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <inttypes.h>
#include <linux/limits.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "elf_util.h"

#include "utils.h"

/* INFO: The branch the CPU believes it took, kept in PSTATE bits 10-11. A value
         of 0b11 means the last branch was an indirect jump, and a BTI landing
         pad rejects that: see the two places that clear it before redirecting
         the tracee. */
#define AARCH64_PSTATE_BTYPE_MASK (3ull << 10)

ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len) {
  LOGV("write to remote addr %" PRIxPTR " size %zu", remote_addr, len);

  struct iovec local = {
    .iov_base = (void *)buf,
    .iov_len = len
  };

  struct iovec remote = {
    .iov_base = (void *)remote_addr,
    .iov_len = len
  };

  ssize_t l = process_vm_writev(pid, &local, 1, &remote, 1, 0);
  if (l == -1) PLOGE("process_vm_writev");
  else if ((size_t)l != len) LOGW("not fully written: %zu, expected %zu", l, len);

  return l;
}

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
  struct iovec local = {
    .iov_base = (void *)buf,
    .iov_len = len
  };

  struct iovec remote = {
    .iov_base = (void *)remote_addr,
    .iov_len = len
  };

  ssize_t l = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  if (l == -1) PLOGE("process_vm_readv");
  else if ((size_t)l != len) LOGW("not fully read: %zu, expected %zu", l, len);

  return l;
}

bool get_regs(int pid, struct user_regs_struct *regs) {
  struct iovec iov = {
    .iov_base = regs,
    .iov_len = sizeof(struct user_regs_struct)
  };

  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
    PLOGE("GETREGSET");

    return false;
  }

  return true;
}

bool set_regs(int pid, struct user_regs_struct *regs) {
  struct iovec iov = {
    .iov_base = regs,
    .iov_len = sizeof(struct user_regs_struct)
  };

  if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
    PLOGE("SETREGSET");

    return false;
  }

  return true;
}

/* INFO: strrchr but without modifying the string */
const char *position_after(const char *str, const char needle) {
  const char *positioned = strrchr(str, needle);
  return positioned ? positioned + 1 : str;
}

/* INFO: The "return address" handed to a remote call is deliberately picked
           from a non-executable mapping of the module: returning into it faults
           with SIGSEGV, which remote_call() recognizes as the end of the call.
           Do not "fix" the PROT_EXEC skip below, the fault is the mechanism. */
void *find_module_return_addr(struct maps_info *map, const char *suffix) {
  for (size_t i = 0; i < map->length; i++) {
    const struct map_entry  *m = &map->maps[i];
    const char *file_name;

    if (!m->path || (m->perms & PROT_EXEC)) continue;

    file_name = position_after(m->path, '/');
    if (strlen(file_name) < strlen(suffix) || strncmp(file_name, suffix, strlen(suffix)) != 0) continue;

    return (void *)m->start;
  }

  return NULL;
}

/* INFO: Locating a module is needed for two different things - its load base,
           and the file the local process mapped it from. Both live on the same
           maps entry, so the search sits here once and the two helpers below
           are thin wrappers over it.

           `file` may be a bare soname ("libdl.so") or the full path a maps
           entry carries ("/apex/com.android.runtime/lib64/bionic/libdl.so"),
           so a caller may hand over whichever spelling it holds.

           A maps path is normally the full location a library was loaded from,
           which is why the basename is compared and not the whole string. The
           comparison is exact on the basename rather than a prefix match: on
           Android "libdl.so" also appears as "libdl.so.1", and matching that
           would hand back the wrong image. */
static const struct map_entry *find_module_entry(const struct maps_info *map, const char *file) {
  for (size_t i = 0; i < map->length; i++) {
    const struct map_entry  *m = &map->maps[i];
    const char *base_name;

    if (!m->path || m->offset != 0) continue;

    base_name = position_after(m->path, '/');
    if (strcmp(base_name, file) != 0 && strcmp(m->path, file) != 0) continue;

    return m;
  }

  return NULL;
}

/* INFO: The symbol is looked up in the image the local process has `module`
           mapped from, and the path for that comes from the maps entry itself
           rather than from the name the caller used.

           That detail is the fix. A caller names a module by bare soname
           ("libdl.so"), and opening that string is a path lookup: open() knows
           nothing about the linker's namespaces, so it failed on every call,
           the image came back NULL and every symbol lookup returned NULL.
           dlopen_inject() could not resolve even dlopen itself, so the
           injection never started - and a release build compiles every log
           away, which is why it did so in silence.

           The local maps entry carries an absolute path, and that path is what
           gets opened. The offset found this way is the symbol's virtual
           address inside the image, which is what makes the remote address
           below valid: both processes run the same file, so the same offset
           lands on the same code.

           dlopen() by soname is the fallback, for a module that was mapped from
           something without a path on disk. */
void *find_func_addr(struct maps_info *local_info, struct maps_info *remote_info, const char *module, const char *func) {
  const struct map_entry *local_entry = find_module_entry(local_info, module);
  const struct map_entry *remote_entry = find_module_entry(remote_info, module);

  if (local_entry == NULL || remote_entry == NULL) {
    LOGE("module %s is not mapped in the %s", module, local_entry == NULL ? "tracer" : "target");

    return NULL;
  }

  uintptr_t local_base = (uintptr_t)local_entry->start;
  uintptr_t remote_base = (uintptr_t)remote_entry->start;
  uintptr_t offset = 0;

  if (local_entry->path != NULL) {
    ElfImg *mod = ElfImg_create(local_entry->path, (void *)local_base);

    if (mod != NULL) {
      ElfW(Addr) sym = getSymbAddress(mod, func);

      if (sym != 0) offset = (uintptr_t)sym - local_base;

      ElfImg_destroy(mod);
    }
  }

  if (offset == 0) {
    void *lib = dlopen(module, RTLD_NOW);

    if (lib != NULL) {
      uintptr_t sym = (uintptr_t)dlsym(lib, func);

      /* INFO: Only the handle is dropped. The libraries asked for here (libdl,
                 libc) are already resident, so the reference count never
                 reaches zero and the offset stays valid. */
      dlclose(lib);

      if (sym != 0) offset = sym - local_base;
    } else {
      LOGW("dlopen(%s) failed: %s", module, dlerror());
    }
  }

  if (offset == 0) {
    LOGE("failed to find symbol %s in %s", func, module);

    return NULL;
  }

  uintptr_t addr = remote_base + offset;

  LOGD("found remote %s!%s at %p (offset %#zx, local base %p, remote base %p)", module, func,
       (void *)addr, (size_t)offset, (void *)local_base, (void *)remote_base);

  return (void *)addr;
}

void align_stack(struct user_regs_struct *regs, long preserve) {
  /* INFO: ~0xf is a negative value, and REG_SP is unsigned,
             so we must cast REG_SP to signed type before subtracting
             then cast back to unsigned type.
  */
  regs->REG_SP = (uintptr_t)((intptr_t)(regs->REG_SP - preserve) & ~0xf);
}

uintptr_t remote_call(int pid, struct user_regs_struct *regs, uintptr_t func_addr, uintptr_t return_addr, long *args, size_t args_size) {
  align_stack(regs, 0);

  /* INFO: BTYPE so jumping into the callee is accepted by the CPU. The
             tracer intercepted the target on an indirect branch - the linker's
             jump to __libc_init through the poisoned GOT slot - which left
             BTYPE at 0b11 (indirect jump). Every bionic library on a BTI
             enabled device starts with a BTI landing pad that only accepts
             0b01 (direct call) or 0b10 (indirect call); arriving with 0b11
             makes the CPU treat the branch as a JOP attempt and raise SIGILL
             instead of running the function.

             Every remote call in this file clears it, whatever the branch is
             about to reach: an ordinary function here, a vDSO entry elsewhere. */
  regs->pstate &= ~AARCH64_PSTATE_BTYPE_MASK;

  LOGV("calling remote function %" PRIxPTR " args %zu", func_addr, args_size);

  for (size_t i = 0; i < args_size; i++) {
    LOGV("arg %p", (void *)args[i]);
  }

  for (size_t i = 0; i < args_size && i < 8; i++) {
    regs->regs[i] = args[i];
  }

  if (args_size > 8) {
    long remain = (args_size - 8) * sizeof(long);
    align_stack(regs, remain);

    write_proc(pid, (uintptr_t)regs->REG_SP, &args[8], remain);
  }

  regs->regs[30] = return_addr;
  regs->REG_IP = func_addr;

  if (!set_regs(pid, regs)) {
    LOGE("failed to set regs");

    return 0;
  }

  ptrace(PTRACE_CONT, pid, 0, 0);

  int status;
  wait_for_trace(pid, &status, __WALL);
  if (!get_regs(pid, regs)) {
    LOGE("failed to get regs after call");

    return 0;
  }

  if (WSTOPSIG(status) == SIGSEGV) {
    if ((uintptr_t)regs->REG_IP != return_addr) {
      LOGE("wrong return addr %p", (void *) regs->REG_IP);

      return 0;
    }

    return regs->REG_RET;
  } else {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("stopped by other reason %s at addr %p", status_str, (void *)regs->REG_IP);

    /* INFO: SIGILL here is almost always a BTI landing pad refusing the
               branch, which means the BTYPE clear above did not reach the CPU
               for this call. Say so outright: the generic message above reads
               like an unrelated stop and sends the reader hunting elsewhere. */
    if (WSTOPSIG(status) == SIGILL) {
      LOGE("remote call to %" PRIxPTR " raised SIGILL - branch target rejected (BTYPE %lu)",
           func_addr, (unsigned long)((regs->pstate >> 10) & 3));
    }
  }

  return 0;
}

int fork_dont_care() {
  pid_t pid = fork();

  if (pid < 0) {
    PLOGE("fork 1");
  } else if (pid == 0) {
    pid = fork();

    /* INFO: _exit, not exit: this intermediate fork still carries the
              tracer's stdio buffers, and flushing them here would duplicate
              the output the parent is about to produce. */
    if (pid < 0) {
      /* INFO: A second failure here used to fall through and hand -1 back to
                the caller. The caller only ever looks for 0, so that process
                did not exec the tracer and did not exit either: it carried on
                into the event loop as a second monitor, and every pass through
                it forked again. Nothing above it is left to report the failure
                to - the process that forked this one has already reaped it -
                so it ends here. */
      PLOGE("fork 2");

      _exit(1);
    } else if (pid > 0) {
      _exit(0);
    }
  } else {
    int status;
    waitpid(pid, &status, __WALL);
  }

  return pid;
}

#define TARGET_JUMP_SLOT R_AARCH64_JUMP_SLOT

#define ELFW_R_TYPE(info) ELF64_R_TYPE(info)
#define ELFW_R_SYM(info)  ELF64_R_SYM(info)
#define EXPECTED_ELFCLASS ELFCLASS64

bool elf_vaddr_to_off(const ElfW(Phdr) *phdr, int phnum, ElfW(Addr) vaddr, off_t *out_off) {
  for (int i = 0; i < phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;

    ElfW(Addr) seg_start = phdr[i].p_vaddr;
    ElfW(Addr) seg_end = phdr[i].p_vaddr + phdr[i].p_filesz;
    if (vaddr < seg_start || vaddr >= seg_end) continue;

    *out_off = (off_t)phdr[i].p_offset + (off_t)(vaddr - seg_start);

    return true;
  }

  return false;
}

bool find_jump_slot_got_offset(const char *elf_path, const char *symbol, uintptr_t *out_bias, uintptr_t *out_got_off) {
  int fd = -1;
  ElfW(Phdr) *phdr = NULL;
  ElfW(Dyn) *dyn = NULL;
  bool found = false;

  fd = open(elf_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    PLOGE("open ELF %s", elf_path);

    goto cleanup;
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(ElfW(Ehdr))) {
    LOGE("Failed to stat ELF %s", elf_path);

    goto cleanup;
  }

  ElfW(Ehdr) eh;
  if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) {
    LOGE("Failed to read ELF header");

    goto cleanup;
  }

  if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != EXPECTED_ELFCLASS || eh.e_phnum == 0) {
    LOGE("Invalid ELF header in %s", elf_path);

    goto cleanup;
  }

  phdr = calloc(eh.e_phnum, sizeof(ElfW(Phdr)));
  if (!phdr) {
    LOGE("Failed to allocate memory for program headers");

    goto cleanup;
  }

  if (pread(fd, phdr, sizeof(ElfW(Phdr)) * eh.e_phnum, eh.e_phoff) != (ssize_t)(sizeof(ElfW(Phdr)) * eh.e_phnum)) {
    LOGE("Failed to read program headers");

    goto cleanup;
  }

  ElfW(Addr) min_vaddr = (ElfW(Addr))-1;
  ElfW(Addr) dyn_vaddr = 0;
  ElfW(Word) dyn_size = 0;
  for (int i = 0; i < eh.e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD && phdr[i].p_vaddr < min_vaddr) min_vaddr = phdr[i].p_vaddr;
    if (phdr[i].p_type == PT_DYNAMIC) {
      dyn_vaddr = phdr[i].p_vaddr;
      dyn_size = phdr[i].p_filesz;
    }
  }

  if (!dyn_vaddr || !dyn_size || min_vaddr == (ElfW(Addr))-1) {
    LOGE("Failed to find dynamic section or PT_LOAD segments in %s", elf_path);

    goto cleanup;
  }

  off_t dyn_off = 0;
  if (!elf_vaddr_to_off(phdr, eh.e_phnum, dyn_vaddr, &dyn_off)) {
    LOGE("Failed to convert dynamic section virtual address to file offset in %s", elf_path);

    goto cleanup;
  }

  size_t dyn_count = dyn_size / sizeof(ElfW(Dyn));
  dyn = calloc(dyn_count, sizeof(ElfW(Dyn)));
  if (!dyn) {
    LOGE("Failed to allocate memory for dynamic section in %s", elf_path);

    goto cleanup;
  }

  if (pread(fd, dyn, dyn_count * sizeof(ElfW(Dyn)), dyn_off) != (ssize_t)(dyn_count * sizeof(ElfW(Dyn)))) {
    LOGE("Failed to read dynamic section in %s", elf_path);

    goto cleanup;
  }

  ElfW(Addr) jmprel = 0, symtab = 0, strtab = 0;
  ElfW(Word) pltrelsz = 0, pltrel = 0;
  for (size_t i = 0; i < dyn_count; i++) {
    switch (dyn[i].d_tag) {
      case DT_JMPREL: jmprel = dyn[i].d_un.d_ptr; break;
      case DT_PLTRELSZ: pltrelsz = dyn[i].d_un.d_val; break;
      case DT_PLTREL: pltrel = dyn[i].d_un.d_val; break;
      case DT_SYMTAB: symtab = dyn[i].d_un.d_ptr; break;
      case DT_STRTAB: strtab = dyn[i].d_un.d_ptr; break;
      default: break;
    }
  }

  if (!jmprel || !pltrelsz || !symtab || !strtab || !(pltrel == DT_REL || pltrel == DT_RELA)) {
    LOGE("Failed to find necessary dynamic entries in %s", elf_path);

    goto cleanup;
  }

  off_t rel_off = 0, sym_off = 0, str_off = 0;
  if (!elf_vaddr_to_off(phdr, eh.e_phnum, jmprel, &rel_off) ||
      !elf_vaddr_to_off(phdr, eh.e_phnum, symtab, &sym_off) ||
      !elf_vaddr_to_off(phdr, eh.e_phnum, strtab, &str_off)) {
    LOGE("Failed to convert virtual addresses to file offsets in %s", elf_path);

    goto cleanup;
  }

  size_t entsz = (pltrel == DT_REL) ? sizeof(ElfW(Rel)) : sizeof(ElfW(Rela));
  size_t count = pltrelsz / entsz;
  for (size_t i = 0; i < count; i++) {
    ElfW(Addr) r_offset = 0;
    ElfW(Word) r_info_type = 0;
    ElfW(Word) sym_index = 0;

    if (pltrel == DT_REL) {
      ElfW(Rel) rel;
      if (pread(fd, &rel, sizeof(rel), rel_off + (off_t)(i * sizeof(rel))) != (ssize_t)sizeof(rel)) {
        LOGE("Failed to read relocation entry at index %zu in %s", i, elf_path);

        break;
      }

      r_offset = rel.r_offset;
      r_info_type = ELFW_R_TYPE(rel.r_info);
      sym_index = ELFW_R_SYM(rel.r_info);
    } else {
      ElfW(Rela) rela;
      if (pread(fd, &rela, sizeof(rela), rel_off + (off_t)(i * sizeof(rela))) != (ssize_t)sizeof(rela)) {
        LOGE("Failed to read relocation entry at index %zu in %s", i, elf_path);

        break;
      }

      r_offset = rela.r_offset;
      r_info_type = ELFW_R_TYPE(rela.r_info);
      sym_index = ELFW_R_SYM(rela.r_info);
    }

    if (r_info_type != TARGET_JUMP_SLOT) continue;

    ElfW(Sym) sym;
    if (pread(fd, &sym, sizeof(sym), sym_off + (off_t)(sym_index * sizeof(sym))) != (ssize_t)sizeof(sym)) {
      LOGE("Failed to read symbol at index %zu in %s", (size_t)sym_index, elf_path);

      break;
    }

    if (sym.st_name == 0) continue;

    /* INFO: Sized for any realistic linker symbol; a truncated name simply
              fails the strcmp and is skipped. */
    char name[256] = { 0 };
    if (pread(fd, name, sizeof(name) - 1, str_off + (off_t)sym.st_name) <= 0) {
      LOGE("Failed to read symbol name at index %zu in %s", (size_t)sym_index, elf_path);

      break;
    }

    if (strcmp(name, symbol) != 0) continue;

    *out_bias = (uintptr_t)min_vaddr;
    *out_got_off = (uintptr_t)r_offset;

    found = true;

    break;
  }

  cleanup:
    free(dyn);
    free(phdr);
    if (fd != -1) close(fd);

    return found;
}

bool wait_linker_ready(int pid, uintptr_t *out_libc_init_resolved, uintptr_t *out_libc_init_got_slot) {
  char pid_str[11];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);

  struct maps_info *remote_map = parse_maps(pid_str);
  if (!remote_map) {
    LOGE("Failed to parse remote maps for pid %d", pid);

    return false;
  }

  bool found = false;
  for (size_t i = 0; i < remote_map->length; i++) {
    const struct map_entry *m = &remote_map->maps[i];
    if (!m->path || m->offset != 0 || !strstr(m->path, "app_process")) continue;

    uintptr_t bias = 0, got_off = 0;
    if (!find_jump_slot_got_offset(m->path, "__libc_init", &bias, &got_off)) {
      LOGD("Failed to find __libc_init in JMPREL of '%s'", m->path);

      free_maps(remote_map);

      return false;
    }

    *out_libc_init_got_slot = ((uintptr_t)m->start - bias) + got_off;

    found = true;

    break;
  }

  free_maps(remote_map);

  if (!found) {
    LOGE("Failed to find an app_process mapping for pid %d", pid);

    return false;
  }

  uintptr_t initial_value = 0;
  if (read_proc(pid, *out_libc_init_got_slot, &initial_value, sizeof(initial_value)) != sizeof(initial_value)) {
    LOGE("Failed to read initial value of __libc_init GOT slot at 0x%" PRIxPTR, *out_libc_init_got_slot);

    return false;
  }

  /* INFO: The loop below steps the target one syscall at a time until the
            linker writes the resolved address into the slot. That normally
            happens within the first few steps. If it does not, stepping
            forever would leave the target parked in ptrace-stop with the whole
            injection waiting on it, so the wait is bounded: the caller detaches
            and lets the process carry on without injection. */
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += 5;

  while (1) {
    uintptr_t current_value = 0;
    if (read_proc(pid, *out_libc_init_got_slot, &current_value, sizeof(current_value)) != sizeof(current_value)) {
      LOGE("Failed to read current value of __libc_init GOT slot at 0x%" PRIxPTR, *out_libc_init_got_slot);

      return false;
    }

    if (current_value != initial_value) {
      *out_libc_init_resolved = current_value;

      LOGI("Resolved __libc_init (0x%" PRIxPTR " -> 0x%" PRIxPTR ", pid %d)", initial_value, current_value, pid);

      return true;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec >= deadline.tv_sec) {
      LOGE("Timed out waiting for __libc_init to resolve in pid %d", pid);

      return false;
    }

    /* INFO: Step to the next syscall */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
      PLOGE("ptrace PTRACE_SYSCALL");

      return false;
    }

    int status = 0;
    if (!wait_for_ptrace_syscall_stop(pid, &status)) {
      LOGE("wait_for_ptrace_syscall_stop failed");

      return false;
    }
  }
}

bool ptrace_poke_uintptr(pid_t pid, uintptr_t addr, uintptr_t value) {
  /* INFO: Only whole-word slots are written (the GOT entry of __libc_init),
            so a plain POKEDATA at the address is enough; POKEDATA itself
            refuses unaligned addresses instead of corrupting the word. */
  errno = 0;
  if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)value) == -1) {
    PLOGE("ptrace pokedata at 0x%" PRIxPTR, addr);

    return false;
  }

  return true;
}

bool wait_for_ptrace_syscall_stop(int pid, int *status) {
  int step_retries = 0;
  while (1) {
    pid_t waited = waitpid(pid, status, __WALL);
    if (waited == -1) {
      if (errno == EINTR) continue;

      PLOGE("waitpid");

      return false;
    }

    if (waited != pid) continue;

    if (!WIFSTOPPED(*status)) {
      char status_str[64];
      parse_status(*status, status_str, sizeof(status_str));
      LOGE("Remote syscall stop is not ptrace-stop: %s", status_str);

      return false;
    }

    int stop_sig = WSTOPSIG(*status);
    int stop_event = (*status >> 16) & 0xff;
    bool is_syscall_stop = stop_event == 0 && (stop_sig == SIGTRAP || stop_sig == (SIGTRAP | 0x80));

    if ((stop_sig == SIGSTOP || stop_sig == SIGTRAP) && stop_event == PTRACE_EVENT_STOP) {
      if (step_retries++ >= 4) {
        char status_str[64];
        parse_status(*status, status_str, sizeof(status_str));
        LOGE("Remote syscall stuck in ptrace-stop: %s", status_str);

        return false;
      }

      LOGV("Remote syscall got pending ptrace-stop, retrying (retry %d)", step_retries);

      if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        PLOGE("PTRACE_SYSCALL retry");

        return false;
      }

      continue;
    }

    if (is_syscall_stop) return true;

    char status_str[64];
    parse_status(*status, status_str, sizeof(status_str));
    LOGE("Remote syscall unexpected stop: %s", status_str);

    return false;
  }
}

bool tracee_skip_syscall(int pid) {
  struct user_regs_struct regs;
  if (!get_regs(pid, &regs)) {
    LOGE("Failed to get seccomp regs");

    return false;
  }

  regs.REG_SYSNR = -1;
  if (!set_regs(pid, &regs)) {
    LOGE("Failed to set seccomp regs");

    return false;
  }

  /* INFO: Best effort — it might not work, don't fail for the SETREGSET */
  int sysnr = -1;
  struct iovec iov = {
    .iov_base = &sysnr,
    .iov_len = sizeof(int),
  };
  ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);

  return true;
}

void wait_for_trace(int pid, int *status, int flags) {
  while (1) {
    pid_t result = waitpid(pid, status, flags);
    if (result == -1) {
      if (errno == EINTR) continue;

      PLOGE("wait %d failed", pid);

      /* INFO: Hand the caller a synthetic "exited with 255" status so it can
                detect the failed wait instead of reading a stale status. */
      *status = W_EXITCODE(255, 0);

      return;
    }

    /* INFO: We'll fork there. This will signal SIGCHLD. We just ignore and continue
               to avoid blocking/not continuing. */
    if (WIFSTOPPED(*status) && WSTOPSIG(*status) == SIGCHLD) {
      LOGI("process %d stopped by SIGCHLD, continue", pid);

      ptrace(PTRACE_CONT, pid, 0, 0);

      continue;
    } else if (*status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
      /* INFO: If the syscall cannot be skipped, continuing would execute the
                trapped exit_group and the tracer holds EXITKILL — detach
                instead, which releases the tracee alive and lets the caller
                see the failure through the synthetic status. */
      if (!tracee_skip_syscall(pid)) {
        LOGE("Failed to skip the trapped syscall, detaching %d", pid);

        ptrace(PTRACE_DETACH, pid, 0, 0);

        *status = W_EXITCODE(255, 0);

        return;
      }

      ptrace(PTRACE_CONT, pid, 0, 0);

      continue;
    } else if (!WIFSTOPPED(*status)) {
      char status_str[64];
      parse_status(*status, status_str, sizeof(status_str));

      LOGE("process %d not stopped for trace: %s", pid, status_str);

      /* INFO: Return the status to the caller instead of killing the tracer */
      return;
    }

    return;
  }
}

void parse_status(int status, char *buf, size_t len) {
  snprintf(buf, len, "0x%x ", status);

  if (WIFEXITED(status)) {
    snprintf(buf + strlen(buf), len - strlen(buf), "exited with %d", WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    snprintf(buf + strlen(buf), len - strlen(buf), "signaled with %s(%d)", sigabbrev_np(WTERMSIG(status)), WTERMSIG(status));
  } else if (WIFSTOPPED(status)) {
    int stop_sig = WSTOPSIG(status);
    snprintf(buf + strlen(buf), len - strlen(buf), "stopped by signal %s (event: %s)", sigabbrev_np(stop_sig), parse_ptrace_event(status));
  } else {
    snprintf(buf + strlen(buf), len - strlen(buf), "unknown");
  }
}

int get_program(int pid, char *buf, size_t size) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/exe", pid);

  ssize_t sz = readlink(path, buf, size);
  if (sz == -1) {
    PLOGE("readlink /proc/%d/exe", pid);

    return -1;
  }

  if ((size_t)sz >= size) {
    LOGW("Program path truncated (%zd >= %zu)", sz, size);

    sz = size - 1;
  }

  sz = (ssize_t)strip_deleted_suffix(buf, (size_t)sz);

  buf[sz] = '\0';

  return 0;
}
