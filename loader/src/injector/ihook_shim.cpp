/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * VexZygisk - C bridge to the YukiZygisk inline hook engine.
 *
 * The engine itself is vendored verbatim under src/external/ihook/ and carries
 * its own SPDX headers (Apache-2.0, (c) Anatdx). This file is ours.
 *
 * Why it is here: the Zygisk Next contract's inlineHook entry has to be a
 * relocating inline hook, and this fork served it with Dobby - a second
 * third-party engine, for one entry, next to the LSPlt the pltHook entry already
 * needs. The reference for the contract ships its own engine instead, so this
 * fork uses that one now and the extra dependency is gone.
 */

#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "logging.h"

#include "inline_hook.hpp"
#include "zn_ihook.h"

/* INFO: The one part of the engine that is not in the headers.
 *
 *         The engine patches the instruction stream through this call, and the
 *         reference implements it in its kernel driver: install() sends the
 *         expected and the replacement bytes to zygiskd, which hands them to a
 *         kernel module that pokes the text through text_poke() - a private,
 *         copy-on-write patch that never touches the file behind the mapping.
 *
 *         This fork has no such driver (KernelSU and APatch give us nothing of
 *         the sort), so the same contract is kept in userspace: the write goes
 *         through /proc/self/mem, which the kernel resolves with FOLL_FORCE and
 *         which likewise breaks the shared clean mapping into a private copy
 *         instead of writing through to the file. The expected bytes are
 *         compared first, exactly as the kernel side does, because the engine's
 *         whole safety argument rests on "the bytes are what I left" being
 *         checked by whoever writes.
 *
 *         Returns the same three answers the engine knows: 0 rejected, 1
 *         applied, 2 indeterminate.
 *
 *         Note for whoever debugs this on a device: the instruction-cache
 *         synchronization is NOT done here. The engine does it itself, around
 *         this call, through synchronize_instruction_view(). */
extern "C" uint8_t yz_patch_text_checked(uintptr_t addr, const void *expected,
                                        const void *replacement, unsigned int len) {
  if (addr == 0 || expected == nullptr || replacement == nullptr) return 0;

  const size_t size = len;
  if (size == 0 || size > 64 || addr > UINTPTR_MAX - size) return 0;

  const int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
  if (fd == -1) {
    /* INFO: Nothing has been written and nothing has been changed, so the
              honest answer is "rejected" and not "indeterminate". It matters:
              the engine's answer to an indeterminate patch is to take the
              process down, because it can no longer reason about its own
              state. A denied /proc/self/mem would then kill every process that
              tried to place a hook, instead of failing the hook. */
    LOGE("inline hook: cannot open /proc/self/mem for the patch at %p", reinterpret_cast<void *>(addr));

    return 0;
  }

  /* INFO: The bytes at the target are read through the descriptor and not
            through the mapping: the address is a module's word for where a
            function is, and one that is unmapped or unreadable would turn a
            direct memcmp into the SIGSEGV this protocol exists to answer with
            "rejected". A pread on /proc/self/mem fails cleanly instead. */
  uint8_t current[64];
  ssize_t got = pread(fd, current, size, static_cast<off_t>(addr));
  if (got != static_cast<ssize_t>(size)) {
    close(fd);

    LOGE("inline hook: the target at %p cannot be read", reinterpret_cast<void *>(addr));

    return 0;
  }

  if (memcmp(current, expected, size) != 0) {
    close(fd);

    return 0;
  }

  const auto *bytes = static_cast<const uint8_t *>(replacement);
  size_t written = 0;

  while (written < size) {
    const ssize_t step = pwrite(fd, bytes + written, size - written,
                               static_cast<off_t>(addr + written));
    if (step <= 0) {
      close(fd);

      LOGE("inline hook: the patch at %p stopped after %zu of %zu byte(s)",
           reinterpret_cast<void *>(addr), written, size);

      /* INFO: Partly written is the state the engine calls indeterminate, and
                it must not be told "nothing happened": the bytes already went
                in, and its own recovery would restore from a copy that is no
                longer there. */
      return written == 0 ? 0 : 2;
    }

    written += static_cast<size_t>(step);
  }

  /* INFO: Verified through the descriptor as well, for the same reason the
            comparison above was: the state of the mapping is the module's to
            change, and the answer has to come from a read that cannot fault.
            A read that fails here is the indeterminate case - the write
            reported success and the check could not see the result. */
  got = pread(fd, current, size, static_cast<off_t>(addr));

  close(fd);

  if (got != static_cast<ssize_t>(size)) return 2;

  return memcmp(current, replacement, size) == 0 ? 1 : 2;
}

namespace {

/* INFO: One placed hook: the address it was placed on, and the engine's own
         state for it. The engine returns the address the original can be called
         through, which the caller keeps; the state has to outlive the call, so
         it is owned here and freed on unhook. */
struct Record {
  void *target;
  yuki::ihook::Hook hook;
};

Record **records = nullptr;
size_t records_count = 0;
size_t records_capacity = 0;

pthread_mutex_t records_lock = PTHREAD_MUTEX_INITIALIZER;

/* INFO: What the reference refuses to hook: two addresses inside one patch
         window are one hook, because the first rewrite already moved the bytes
         the second would have measured. The window is the length of the patch
         the engine plants. */
#if defined(__aarch64__)
constexpr size_t kPatchWindow = 8;
#else
constexpr size_t kPatchWindow = 10;
#endif

bool window_is_free(uintptr_t address) {
  for (size_t i = 0; i < records_count; i++) {
    const auto existing = reinterpret_cast<uintptr_t>(records[i]->target);

    if (yuki::ihook::hook_ranges_overlap(address, kPatchWindow, existing, kPatchWindow)) {
      LOGE("inline hook: %p is inside the window of the hook at %p",
           reinterpret_cast<void *>(address), records[i]->target);

      return false;
    }
  }

  return true;
}

Record *find_record(void *target) {
  for (size_t i = 0; i < records_count; i++) {
    if (records[i]->target == target) return records[i];
  }

  return nullptr;
}

/* INFO: The slot is taken before the hook is placed, so two threads racing for
         the same address cannot both get past the window check. */
Record *reserve_record(void *target) {
  if (records_count == records_capacity) {
    const size_t capacity = records_capacity == 0 ? 16 : records_capacity * 2;

    Record **grown = static_cast<Record **>(realloc(records, capacity * sizeof(Record *)));
    if (grown == nullptr) {
      LOGE("inline hook: cannot grow the hook table for %p", target);

      return nullptr;
    }

    records = grown;
    records_capacity = capacity;
  }

  Record *record = new Record();
  record->target = target;

  records[records_count++] = record;

  return record;
}

void release_record(Record *record) {
  for (size_t i = 0; i < records_count; i++) {
    if (records[i] != record) continue;

    records[i] = records[records_count - 1];
    records_count--;

    break;
  }

  delete record;
}

}  // namespace

bool zn_ihook_install(void *target, void *replacement, void **original) {
  if (target == nullptr || replacement == nullptr) return false;

  /* INFO: The engine rewrites the instruction stream while other threads may
            still be executing it, so the reference refuses a process that has
            more than one thread, and so does this one - the refusal is part of
            what a module sees. */
  if (!yuki::ihook::single_threaded_process()) {
    LOGE("inline hook: refusing %p, this process has more than one thread", target);

    return false;
  }

  pthread_mutex_lock(&records_lock);

  if (!window_is_free(reinterpret_cast<uintptr_t>(target))) {
    pthread_mutex_unlock(&records_lock);

    return false;
  }

  Record *record = reserve_record(target);
  if (record == nullptr) {
    pthread_mutex_unlock(&records_lock);

    return false;
  }

#if defined(__aarch64__)
  yuki::ihook::a64::Error reason = yuki::ihook::a64::Error::None;
  void *orig = yuki::ihook::install(target, replacement, &record->hook, true, false, &reason);
#else
  void *orig = yuki::ihook::install(target, replacement, &record->hook, true);
#endif

  if (orig == nullptr) {
#if defined(__aarch64__)
    LOGE("inline hook: the engine refused %p (%s)", target,
         yuki::ihook::a64::error_name(reason));
#else
    LOGE("inline hook: the engine refused %p", target);
#endif
    release_record(record);
    pthread_mutex_unlock(&records_lock);

    return false;
  }

  if (original != nullptr) *original = orig;

  pthread_mutex_unlock(&records_lock);

  LOGI("inline hook: placed on %p, original at %p", target, orig);

  return true;
}

bool zn_ihook_uninstall(void *target) {
  if (target == nullptr) return false;

  if (!yuki::ihook::single_threaded_process()) {
    LOGE("inline hook: refusing to unhook %p, this process has more than one thread", target);

    return false;
  }

  pthread_mutex_lock(&records_lock);

  Record *record = find_record(target);
  if (record == nullptr) {
    pthread_mutex_unlock(&records_lock);

    LOGE("inline hook: no hook of ours on %p", target);

    return false;
  }

  const bool removed = yuki::ihook::uninstall(&record->hook);
  if (removed) release_record(record);

  pthread_mutex_unlock(&records_lock);

  if (!removed) LOGE("inline hook: the engine could not remove the hook on %p", target);

  return removed;
}
