/* INFO: The Zygisk Next pltHook is served by LSPlt - the hooking engine the
         LSPosed ecosystem builds its modules against, and the one the modules
         serviced here were compiled against. The injector itself is C, so the
         C++ island is confined to this bridge and the static library behind
         it. */
#include <lsplt.hpp>

/* INFO: LSPlt allocates through the standard library, so the C boundary also
         carries an exception barrier: a throw crossing back into the C
         frames of the injector would have no handler to reach. */
extern "C" int zn_lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *hook, void **backup) {
  try {
    return lsplt::RegisterHook(dev, inode, symbol, hook, backup) ? 0 : -1;
  } catch (...) {
    return -1;
  }
}

extern "C" int zn_lsplt_commit_hook(void) {
  try {
    return lsplt::CommitHook() ? 0 : -1;
  } catch (...) {
    return -1;
  }
}

extern "C" int zn_lsplt_commit_hook_cached(void) {
  try {
    return lsplt::CommitHookCached() ? 0 : -1;
  } catch (...) {
    return -1;
  }
}
