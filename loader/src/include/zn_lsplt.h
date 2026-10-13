#ifndef ZN_LSPLT_H
#define ZN_LSPLT_H

/* INFO: The C bridge to LSPlt (injector/zn_lsplt_shim.cpp), the hooking engine
         the LSPosed ecosystem builds its modules against.

         Both the Zygisk Next pltHook entry and the HyperOS runtime's own hooks
         in the spawner go through it, so the two entry points live here rather
         than next to either caller. The shim itself stays C++ because LSPlt is:
         it allocates through the standard library, and the exception barrier on
         the far side is what keeps a throw out of the injector's C frames.

         All of them return 0 on success and -1 on failure - an inverted `bool`
         at the boundary so no caller has to know what LSPlt speaks. */

#include <sys/types.h>

int zn_lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *hook, void **backup);
int zn_lsplt_commit_hook(void);

/* INFO: The same commit, against the map snapshot LSPlt already took in this
         process instead of a fresh /proc/self/maps scan.

         The snapshot is populated by the first commit that runs, which is the
         spawner's: it installs the runtime's own hooks before any application is
         forked, and every application inherits the snapshot with the rest of the
         memory. An application therefore has one to commit against and does not
         have to read the maps again - which is the whole reason the reference
         picks this form for the forked side. It answers -1 when no snapshot
         exists yet, exactly as a fresh scan would fail. */
int zn_lsplt_commit_hook_cached(void);

#endif /* ZN_LSPLT_H */
