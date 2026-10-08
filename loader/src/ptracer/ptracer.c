#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <elf.h>
#include <unistd.h>

#define LOG_TAG "zygisk-injector"

#include "misc.h"
#include "utils.h"
#include "zygisk_paths.h"

#ifndef ALIGN_UP
  #define ALIGN_UP(x, a) (((x) + ((a)-1)) & ~((a)-1))
#endif

/* INFO: Load the injector into the target with the target's own linker.

           The previous path hand-mapped the library with CSOLoader, which
           mapped the PT_LOAD segments, applied the relocations and jumped to
           the entry — and nothing else. Two things a real linker does on top of
           that were therefore never done:

             - DT_INIT_ARRAY was never walked, so the five C++ global
               constructors of the bundled engines never ran. Dobby and LSPlt
               kept zeroed internal state, so hooks were accepted and then did
               nothing.
             - the object was never registered in the linker's soinfo list, so
               dl_iterate_phdr/dladdr could not see it from inside the target.
               That is what LSPosed probes when it reports "Zygisk Next API is
               unavailable" even though the library is plainly loaded.

           Letting the target's own linker do the load fixes both by
           construction rather than by imitation: it walks DT_INIT_ARRAY itself
           and publishes a soinfo. This mirrors what the reference
           implementation does, and it is why adding Dobby there required no
           change to its injection code at all. */
static bool dlopen_inject(int pid, struct user_regs_struct *regs, struct maps_info *map,
                          struct maps_info *local_map, const char *lib_path, void *return_addr) {
  void *dlopen_addr = find_func_addr(local_map, map, "libdl.so", "dlopen");
  if (!dlopen_addr) {
    LOGE("could not find dlopen in the target process");

    return false;
  }

  /* INFO: dlopen takes the path by pointer, so the string has to live in the
            target. It goes on the target's own stack, well below the frame the
            upcoming remote_call will use. */
  size_t path_len = strlen(lib_path) + 1;
  uintptr_t remote_path = regs->REG_SP - ALIGN_UP(path_len, 16);

  if (write_proc(pid, remote_path, lib_path, path_len) != (ssize_t)path_len) {
    LOGE("failed to write the library path into the target");

    return false;
  }

  regs->REG_SP = remote_path;

  long args[2] = {
    (long)remote_path,
    (long)RTLD_NOW
  };

  uintptr_t handle = remote_call(pid, regs, (uintptr_t)dlopen_addr, (uintptr_t)return_addr, args, 2);
  if (!handle) {
    /* INFO: Read dlerror's message out of the target. It is the only place the
              real reason (missing soname, bad ELF, denied namespace) shows up. */
    void *dlerror_addr = find_func_addr(local_map, map, "libdl.so", "dlerror");
    void *strlen_addr = find_func_addr(local_map, map, "libc.so", "strlen");

    if (dlerror_addr && strlen_addr) {
      uintptr_t msg = remote_call(pid, regs, (uintptr_t)dlerror_addr, (uintptr_t)return_addr, NULL, 0);

      if (msg) {
        long len_args[1] = { (long)msg };
        uintptr_t len = remote_call(pid, regs, (uintptr_t)strlen_addr, (uintptr_t)return_addr, len_args, 1);

        if (len > 0 && len < 512) {
          char err[513];

          if (read_proc(pid, msg, err, (size_t)len) == (ssize_t)len) {
            err[len] = '\0';
            LOGE("remote dlopen failed: %s", err);
          } else {
            LOGE("remote dlopen failed (could not read dlerror)");
          }
        }
      }
    }

    return false;
  }

  LOGI("remote dlopen succeeded, handle %p", (void *)handle);

  void *dlsym_addr = find_func_addr(local_map, map, "libdl.so", "dlsym");
  if (!dlsym_addr) {
    LOGE("could not find dlsym in the target process");

    return false;
  }

  /* INFO: "entry" is the injector's own export, the same symbol the manual
            loader used to resolve by hand. */
  static const char entry_sym[] = "entry";
  uintptr_t remote_entry_name = regs->REG_SP - ALIGN_UP(sizeof(entry_sym), 16);

  if (write_proc(pid, remote_entry_name, entry_sym, sizeof(entry_sym)) != (ssize_t)sizeof(entry_sym)) {
    LOGE("failed to write the entry symbol name into the target");

    return false;
  }

  regs->REG_SP = remote_entry_name;

  long dlsym_args[2] = {
    (long)handle,
    (long)remote_entry_name
  };

  uintptr_t entry = remote_call(pid, regs, (uintptr_t)dlsym_addr, (uintptr_t)return_addr, dlsym_args, 2);
  if (!entry) {
    LOGE("dlsym(\"entry\") failed in the target");

    return false;
  }

  LOGI("resolved injector entry at %p", (void *)entry);

  /* INFO: The entry keeps the (base, size) pair the manual loader used to hand
            it. With dlopen the mapping belongs to the linker, so the load bias
            is recovered from the target's own maps instead of from the manual
            layout the loader used to compute. dladdr is deliberately not used
            here: it would write a Dl_info into the *target's* memory, which
            this process cannot read back through remote_call.

            The maps have to be re-read: `map` predates the dlopen, so the
            object is not in it yet. */
  char pid_str[11];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);

  struct maps_info *post = parse_maps(pid_str);
  if (!post) {
    LOGE("failed to re-read the target maps after dlopen");

    return false;
  }

  uintptr_t base = 0;
  size_t size = 0;

  for (size_t i = 0; i < post->length; i++) {
    const struct map_entry *m = &post->maps[i];

    if (!m->path || m->offset != 0) continue;
    if (strcmp(m->path, lib_path) != 0) continue;

    base = (uintptr_t)m->start;

    break;
  }

  if (base) {
    /* INFO: The high end of the object is the topmost mapping of the same
              file; anything the linker placed below the base is its own
              bookkeeping and is not part of the image. */
    uintptr_t high = base;

    for (size_t i = 0; i < post->length; i++) {
      const struct map_entry *m = &post->maps[i];

      if (!m->path) continue;
      if (strcmp(m->path, lib_path) != 0) continue;

      size_t end = (size_t)m->start + m->end - m->start;

      if (end > high) high = end;
    }

    size = (size_t)(high - base);
  }

  free_maps(post);

  if (!base) {
    LOGE("could not find the injected library in the target maps after dlopen");

    return false;
  }

  LOGI("injected library base %p size %zu", (void *)base, size);

  long entry_args[2] = {
    (long)base,
    (long)size
  };

  remote_call(pid, regs, entry, (uintptr_t)return_addr, entry_args, 2);

  return (uintptr_t)regs->REG_IP == (uintptr_t)return_addr;
}

bool inject_on_main(int pid, const char *lib_path, uintptr_t libc_init_target, uintptr_t libc_init_got_slot) {
  LOGI("injecting %s to zygote %d via GOT hook", lib_path, pid);

  /* INFO: The GOT slot is poisoned with a guaranteed-unmapped address so the
            call to __libc_init faults and the tracer picks the process up. */
  uintptr_t break_addr = (uintptr_t)-16;
  if (!ptrace_poke_uintptr(pid, libc_init_got_slot, break_addr)) {
    LOGE("Failed to patch GOT slot with break_addr");

    return false;
  }

  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
    PLOGE("Failed to continue to GOT break");

    return false;
  }

  int status = 0;
  wait_for_trace(pid, &status, __WALL);

  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSEGV) {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("expected SIGSEGV on __libc_init GOT call, got: %s", status_str);

    return false;
  }

  struct user_regs_struct regs = { 0 };
  if (!get_regs(pid, &regs)) {
    LOGE("Failed to get regs after GOT break");

    return false;
  }

  /* Restore valid __libc_init pointer to RELRO GOT slot via PTRACE_POKEDATA fallback */
  if (!ptrace_poke_uintptr(pid, libc_init_got_slot, libc_init_target)) {
    LOGE("Failed to restore __libc_init GOT slot");

    return false;
  }

  struct user_regs_struct backup;
  memcpy(&backup, &regs, sizeof(regs));

  char pid_str[11];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);

  struct maps_info *map = parse_maps(pid_str);
  if (!map) {
    LOGE("Failed to parse remote maps after GOT break");

    return false;
  }

  struct maps_info *local_map = parse_maps("self");
  if (!local_map) {
    LOGE("Failed to parse local maps");

    free_maps(map);

    return false;
  }

  void *libc_return_addr = find_module_return_addr(map, "libc.so");

  if (!libc_return_addr) {
    LOGE("Failed to find a return address in the target");

    free_maps(local_map);
    free_maps(map);

    return false;
  }

  bool injected = dlopen_inject(pid, &regs, map, local_map, lib_path, libc_return_addr);

  free_maps(local_map);
  free_maps(map);

  if (!injected) {
    LOGE("Remote dlopen injection failed");

    backup.REG_IP = (long)libc_init_target;
    set_regs(pid, &backup);

    return false;
  }

  /* INFO: Restore from `backup`, not from `regs`: every remote call has been
             mutating `regs` (arguments, SP, and the BTYPE field remote_call
             clears), and the tracee has to resume with the register state it
             was interrupted in - the target validates its own BTI pad once it
             runs again. Only the instruction pointer is redirected, back to the
             real __libc_init now that the GOT slot holds it again. */
  backup.REG_IP = (long)libc_init_target;
  if (!set_regs(pid, &backup)) return false;

  LOGD("injection complete, instruction pointer reset to __libc_init (%p)", (void *)libc_init_target);

  return true;
}

#define WAIT_OR_DIE wait_for_trace(pid, &status, __WALL);
#define CONT_OR_DIE                           \
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) { \
    PLOGE("cont");                            \
                                              \
    return false;                             \
  }

bool trace_zygote(int pid) {
  LOGI("start tracing %d (tracer %d)", pid, getpid());

  int status = 0;

  struct kernel_version version = parse_kversion();

  /* INFO: EXITKILL keeps a tracer death from leaving a traced zygote behind,
            and TRACESECCOMP lets wait_for_trace skip seccomp events. */
  long seize_options = 0;
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) seize_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP;

  if (ptrace(PTRACE_SEIZE, pid, 0, seize_options) == -1) {
    PLOGE("seize");

    return false;
  }

  WAIT_OR_DIE;

  kill(pid, SIGCONT);
  ptrace(PTRACE_SYSCALL, pid, 0, 0);

  int syscall_stop_status;
  wait_for_ptrace_syscall_stop(pid, &syscall_stop_status);

  uintptr_t libc_init_got_slot = 0, libc_init_resolved = 0;
  if (!wait_linker_ready(pid, &libc_init_resolved, &libc_init_got_slot)) {
    LOGE("Failed to wait for linker ready for injection");

    ptrace(PTRACE_DETACH, pid, 0, SIGCONT);

    return false;
  }

  LOGD("Resolved __libc_init at %p (GOT slot %p)", (void *)libc_init_resolved, (void *)libc_init_got_slot);

  /* INFO: `status` intentionally still holds the stop observed right after the
            seize: the waits above only synchronized the syscall-stop and the
            linker, and left it untouched. SEIZE stops with SIGSTOP, either as
            PTRACE_EVENT_STOP or as a plain SIGSTOP (event 0) when the monitor
            already stopped the target for hand-off, as with hyos_spawner. */
  int stop_event = (int)((unsigned int)status >> 16);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP &&
      (stop_event == PTRACE_EVENT_STOP || stop_event == 0)) {
    char *lib_path = ZYGISK_MODULE_DIR "/lib64/libzygisk.so";
    if (!inject_on_main(pid, lib_path, libc_init_resolved, libc_init_got_slot)) {
      LOGE("failed to inject");

      return false;
    }

    LOGD("inject done, continue process");
    if (kill(pid, SIGCONT)) {
      PLOGE("kill");

      return false;
    }

    CONT_OR_DIE
    WAIT_OR_DIE

    if (STOPPED_WITH(status, SIGTRAP, PTRACE_EVENT_STOP)) {
      CONT_OR_DIE
      WAIT_OR_DIE
    }

    if (STOPPED_WITH(status, SIGCONT, 0)) {
      LOGD("received SIGCONT");

      /* INFO: Due to kernel bugs, fixed in 5.16+, ptrace_message (msg of
             PTRACE_GETEVENTMSG) may not represent the current state of
             the process. Because we set some options, which alters the
             ptrace_message, we need to call PTRACE_SYSCALL to reset the
             ptrace_message to 0, the default/normal state.
        */
      ptrace(PTRACE_SYSCALL, pid, 0, 0);

      WAIT_OR_DIE

      ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
    } else {
      char status_str[64];
      parse_status(status, status_str, sizeof(status_str));

      LOGE("Expected SIGTRAP or a direct SIGCONT, found: %s", status_str);

      ptrace(PTRACE_DETACH, pid, 0, 0);

      return false;
    }
  } else {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("Expected SIGSTOP (event: EVENT_STOP), found: %s", status_str);

    ptrace(PTRACE_DETACH, pid, 0, 0);

    return false;
  }

  return true;
}
