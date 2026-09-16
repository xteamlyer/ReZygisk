#ifndef ROOT_MOUNTS_H
#define ROOT_MOUNTS_H

/* INFO: What counts as a root trace in a mount table, shared by the loader
         (injector/unmount.c, which reverts the traces in the hidden process)
         and the daemon (utils.c, which builds the clean namespace).

         Both walk the same /proc/<pid>/mountinfo and both have to remove the
         same set, so the names they match on are one definition: a source
         added on one side alone would leave the two disagreeing about what
         root even looks like, and a process could come away half hidden.

         The walk itself stays in each binary — the two parse into different
         shapes, because only the loader needs the mount id to unmount nested
         mounts in the right order. */

#define MOUNT_SOURCE_LOOP "/dev/block/loop"
#define ROOT_MODULES_DIR "/data/adb/modules"
#define ROOT_MODULES_ROOT "/adb/modules"

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

#endif /* ROOT_MOUNTS_H */
