#ifndef ROOT_MOUNTS_H
#define ROOT_MOUNTS_H

/* INFO: What counts as a root trace in a mount table, shared by the loader
          (injector/unmount.c, which reverts them in the hidden process) and the
          daemon (utils.c, which builds the clean namespace). Both walk the same
          /proc/<pid>/mountinfo and must remove the same set; a name added on one
          side alone would leave them disagreeing and a process half hidden. The
          walk itself stays per-binary, since only the loader needs the mount id. */

#define MOUNT_SOURCE_LOOP "/dev/block/loop"
#define ROOT_MODULES_DIR "/data/adb/modules"
#define ROOT_MODULES_ROOT "/adb/modules"

/* INFO: Where a mount *lands*. Covered whole rather than down to the modules
         directory: a root solution keeps more than its modules under /data/adb
         - the directories its stages run from among them - and a mount point
         anywhere under it is the solution's to have made. A bare prefix test
         would swallow a sibling such as /data/adbx, which is why the two are
         compared as whole path components. */
#define ROOT_ADB_DIR "/data/adb"

/* INFO: The filesystem type, kept only so an overlay can be told from
         everything else. A bind mount reports the filesystem it was taken
         from, so this field says nothing about how it was made - but an
         overlay always says "overlay", which is exactly the case the
         source-path test below has to stay away from. */
#define MOUNT_TYPE_OVERLAY "overlay"

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
