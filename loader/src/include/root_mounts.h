#ifndef ROOT_MOUNTS_H
#define ROOT_MOUNTS_H

/* INFO: What counts as a root trace in a mount table, shared by the loader
          (injector/unmount.c, which reverts them in the hidden process) and the
          daemon (utils.c, which builds the clean namespace). Both walk the same
          /proc/<pid>/mountinfo and must remove the same set; a name added on one
          side alone would leave them disagreeing and a process half hidden. The
          walk itself stays per-binary, since only the loader needs the mount id. */

#include <stdbool.h>
#include <string.h>

#define MOUNT_SOURCE_LOOP "/dev/block/loop"
#define ROOT_MODULES_DIR "/data/adb/modules"
#define ROOT_MODULES_ROOT "/adb/modules"

/* INFO: True when `path` equals `prefix` or sits directly underneath it (the
          next byte is '/'). A bare prefix test would also match a sibling such
          as /data/adb/modules_extra, which must never be reverted. It lives
          here rather than in either walker because both decide from it which
          mounts a process loses: a set that differs by one path leaves the
          process half hidden, which is the disagreement this header exists to
          prevent. */
static inline bool mount_path_at_or_under(const char *path, const char *prefix) {
  size_t len = strlen(prefix);

  if (strncmp(path, prefix, len) != 0) return false;

  char next = path[len];

  return next == '\0' || next == '/';
}

/* INFO: True when a mount is the KernelSU module store: the modules live on a
         loop device, and that device name shows up as the source of every mount
         under the module directory. APatch mounts them as a plain overlay, so
         only the KernelSU flavour looks for it. The loader and the daemon walk
         their own tables - one of them needs the mount id, the other does not -
         but this is the rule they have to agree on, so it lives here instead of
         in two walkers that could drift apart on it. */
static inline bool mount_is_module_loop_source(const char *target, const char *source) {
#ifdef ROOT_IMPL_APATCH
  (void) target;
  (void) source;

  return false;
#else
  return strcmp(target, ROOT_MODULES_DIR) == 0 &&
         strncmp(source, MOUNT_SOURCE_LOOP, strlen(MOUNT_SOURCE_LOOP)) == 0;
#endif
}

/* INFO: The overlay source each root solution reports: KernelSU mounts as
         "KSU" and APatch, being KernelPatch based, as "APatch" or "kpatch".
         The flavour is fixed at build time, so only the matching names are
         compiled in. */
#ifdef ROOT_IMPL_APATCH
  static const char *const kRootSources[] = { "APatch", "kpatch" };
  #define ROOT_SOURCE_COUNT 2
#else
  static const char *const kRootSources[] = { "KSU" };
  #define ROOT_SOURCE_COUNT 1
#endif

/* INFO: The whole decision, in one place: whether this mount is one the
         process loses. The loader asks it while reverting, the daemon while
         building the clean namespace, and the two answers have to be the same
         set - a mount dropped by one walker and kept by the other is a process
         that is half hidden. It is written once here for that reason; both
         walkers used to spell the four conditions out themselves, in two
         different orders, which is exactly the drift this header exists to
         prevent.

         `loop_source` is the module store's loop device, which each walker
         looks up before it starts deciding (KernelSU mounts the modules from
         it, and its name shows up as the source of every mount under the module
         directory). It is NULL when there is no such mount, which is the APatch
         case - hence the NULL check rather than a strcmp against it. */
static inline bool mount_carries_root_trace(const char *root, const char *target,
                                            const char *source, const char *loop_source) {
  if (mount_path_at_or_under(root, ROOT_MODULES_ROOT)) return true;
  if (mount_path_at_or_under(target, ROOT_MODULES_DIR)) return true;

  for (size_t i = 0; i < ROOT_SOURCE_COUNT; i++) {
    if (strcmp(source, kRootSources[i]) == 0) return true;
  }

  return loop_source != NULL && strcmp(source, loop_source) == 0;
}

#endif /* ROOT_MOUNTS_H */
