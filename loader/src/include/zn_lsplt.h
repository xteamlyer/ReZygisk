#ifndef ZN_LSPLT_H
#define ZN_LSPLT_H

/* INFO: The C bridge to LSPlt (injector/zn_lsplt_shim.cpp), the hooking engine
         the LSPosed ecosystem builds its modules against.

         Both the Zygisk Next pltHook entry and the HyperOS runtime's own hooks
         in the spawner go through it, so the two entry points live here rather
         than next to either caller. The shim itself stays C++ because LSPlt is:
         it allocates through the standard library, and the exception barrier on
         the far side is what keeps a throw out of the injector's C frames.

         Both return 0 on success and -1 on failure - an inverted `bool` at the
         boundary so neither caller has to know what LSPlt speaks. */

#include <sys/types.h>

int zn_lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *hook, void **backup);
int zn_lsplt_commit_hook(void);

#endif /* ZN_LSPLT_H */
