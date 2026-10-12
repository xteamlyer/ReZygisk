#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <dobby.h>
#include <sys/types.h>

#include "elf_util.h"
#include "logging.h"
#include "misc.h"
#include "zn_lsplt.h"

#include "zn_api.h"
#include "zn_hyos.h"
#include "zn_loader.h"

/* INFO: LSPlt identifies libraries by file identity (device + inode) while the ZN
          API hands us a base address, so the owning mapping is looked up in the
          process maps.

          The scan is redone per call, which is what the reference does and what
          keeps the answer honest: a cached identity goes stale the moment a
          library is unloaded and another one is mapped where it was, and a
          pltHook then lands on the wrong file. Nothing here is shared between
          threads either, so no lock is needed. */
static bool get_lib_location_by_base(uintptr_t base_addr, dev_t *dev, ino_t *inode) {
  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) {
    LOGE("Failed to scan maps for the library at %p", (void *)base_addr);

    return false;
  }

  /* INFO: The module may pass the load base, the load bias or any address
            inside the library, so the owning mapping is found first and its
            file identity is then resolved to the mapping at offset zero,
            which is what LSPlt keys on. */
  bool found = false;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];

    if (entry->inode == 0 || entry->path == NULL) continue;

    uintptr_t load_base = entry->start - entry->offset;
    bool inside = (base_addr >= entry->start && base_addr < entry->end) ||
                  base_addr == entry->start || base_addr == load_base;
    if (!inside) continue;

    for (size_t j = 0; j < maps->length; j++) {
      struct map_entry *head = &maps->maps[j];

      if (head->dev == entry->dev && head->inode == entry->inode && head->offset == 0) {
        *dev = head->dev;
        *inode = head->inode;
        found = true;

        break;
      }
    }

    if (!found) {
      *dev = entry->dev;
      *inode = entry->inode;
      found = true;
    }

    break;
  }

  free_maps(maps);

  if (!found) {
    LOGE("No library mapped at %p", (void *)base_addr);

    return false;
  }

  return true;
}

static int zn_plt_hook(void *base_addr, const char *symbol, void *hook_handler, void **original) {
  if (base_addr == NULL || symbol == NULL || hook_handler == NULL) return ZN_FAILED;

  dev_t dev = 0;
  ino_t inode = 0;
  if (!get_lib_location_by_base((uintptr_t)base_addr, &dev, &inode)) return ZN_FAILED;

  /* INFO: LSPlt implements the ZN unhook contract natively: registering the
             backup of a previous call back as the handler restores the GOT
             entries and cleans up. */
  void *backup = NULL;
  if (zn_lsplt_register_hook(dev, inode, symbol, hook_handler, &backup) != 0) {
    LOGE("Failed registering the PLT hook for %s", symbol);

    return ZN_FAILED;
  }

  if (zn_lsplt_commit_hook() != 0) {
    LOGE("Failed committing the PLT hook for %s", symbol);

    return ZN_FAILED;
  }

  /* INFO: A NULL backup means LSPlt never replaced an entry for this symbol.
           The previous code still reported success and handed the module a
           NULL original, which a module that trusts the return value would
           then call. Fail instead, before *original is touched. */
  if (backup == NULL) {
    LOGE("No PLT entry was replaced for %s", symbol);

    return ZN_FAILED;
  }

  if (original != NULL) *original = backup;

  return ZN_SUCCESS;
}

/* INFO: The Zygisk Next contract allows a single inline hook per address, so
         the hooked addresses are remembered: a second request for one of them
         is rejected instead of piling a second trampoline on top. The table
         itself is unbounded, exactly as NyaZygisk's is - a module that hooks
         many addresses is not refused at an arbitrary cap; it only fails when
         memory does. */
static pthread_mutex_t zn_hooked_lock = PTHREAD_MUTEX_INITIALIZER;
static uintptr_t *zn_hooked = NULL;
static size_t zn_hooked_count = 0;
static size_t zn_hooked_capacity = 0;

static bool zn_is_hooked(uintptr_t address) {
  for (size_t i = 0; i < zn_hooked_count; i++)
    if (zn_hooked[i] == address) return true;

  return false;
}

static void zn_forget_hooked(uintptr_t address) {
  for (size_t i = 0; i < zn_hooked_count; i++) {
    if (zn_hooked[i] != address) continue;

    zn_hooked[i] = zn_hooked[zn_hooked_count - 1];
    zn_hooked_count--;

    return;
  }
}

/* INFO: The slot is claimed before hooking so two threads racing for the same
         address cannot both get past the check. */
static int zn_claim_address(uintptr_t address) {
  pthread_mutex_lock(&zn_hooked_lock);

  if (zn_is_hooked(address)) {
    pthread_mutex_unlock(&zn_hooked_lock);

    LOGW("The address %p already carries an inline hook, rejecting the new one", (void *)address);

    return ZN_FAILED;
  }

  if (zn_hooked_count == zn_hooked_capacity) {
    size_t capacity = zn_hooked_capacity == 0 ? 16 : zn_hooked_capacity * 2;

    uintptr_t *grown = (uintptr_t *)realloc(zn_hooked, capacity * sizeof(uintptr_t));

    if (grown == NULL) {
      pthread_mutex_unlock(&zn_hooked_lock);

      LOGE("Failed growing the inline hook table for %p", (void *)address);

      return ZN_FAILED;
    }

    zn_hooked = grown;
    zn_hooked_capacity = capacity;
  }

  zn_hooked[zn_hooked_count++] = address;

  pthread_mutex_unlock(&zn_hooked_lock);

  return ZN_SUCCESS;
}

static int zn_inline_hook(void *target, void *addr, void **original) {
  if (target == NULL || addr == NULL) return ZN_FAILED;

  if (zn_claim_address((uintptr_t)target) != ZN_SUCCESS) return ZN_FAILED;

  dobby_dummy_func_t backup = NULL;
  if (DobbyHook(target, (dobby_dummy_func_t)(uintptr_t)addr, &backup) != RS_SUCCESS) {
    LOGE("Failed placing the inline hook on %p", target);

    pthread_mutex_lock(&zn_hooked_lock);
    zn_forget_hooked((uintptr_t)target);
    pthread_mutex_unlock(&zn_hooked_lock);

    return ZN_FAILED;
  }

  if (original != NULL) *original = (void *)backup;

  return ZN_SUCCESS;
}

static int zn_inline_unhook(void *target) {
  if (target == NULL) return ZN_FAILED;

  if (DobbyDestroy(target) != 0) {
    LOGE("Failed removing the inline hook on %p", target);

    return ZN_FAILED;
  }

  pthread_mutex_lock(&zn_hooked_lock);
  zn_forget_hooked((uintptr_t)target);
  pthread_mutex_unlock(&zn_hooked_lock);

  return ZN_SUCCESS;
}

/* INFO: st_value is a link-time vaddr; the runtime address is the mapped ELF
         header (img->base) shifted by the difference to the first PT_LOAD's
         vaddr (img->bias), the same conversion getSymbAddress performs. */
static void *symbol_to_address(ElfImg *img, ElfW(Sym) *sym) {
  if (sym->st_value == 0) return NULL;

  return (void *)((uintptr_t)img->base + sym->st_value - img->bias);
}

/* INFO: Lookup order mirrors Zygisk Next: the parsed symbol tables are walked
           first - the file .symtab, then .dynsym, then the .gnu_debugdata
           mini-debug symbols - and an exact lookup that finds nothing there
           falls back to the hash tables of the dynamic symbol section. A prefix
           request is only ever served from those tables, which is why .dynsym
           has to be among them. */
static void *zn_symbol_lookup(struct ZnSymbolResolver *resolver, const char *name, bool prefix, size_t *size) {
  if (resolver == NULL || name == NULL) return NULL;

  ElfImg *img = (ElfImg *)resolver;

  size_t name_len = strlen(name);
  if (name_len == 0) return NULL;

  if (ElfImg_load_symbols(img)) {
    for (size_t i = 0; i < img->symtabs_count_; i++) {
      ElfW(Sym) *sym = img->symtabs_[i];

      const char *sym_name = getSymbName(img, sym);
      if (sym_name == NULL) continue;

      if (prefix ? (strncmp(sym_name, name, name_len) != 0) : (strcmp(sym_name, name) != 0)) continue;

      /* INFO: A match whose value converts to no address is not a hit the
                module can use, so it does not end the search - and *size is
                left alone rather than describing a symbol nobody can call. */
      void *addr = symbol_to_address(img, sym);
      if (addr == NULL) continue;

      if (size != NULL) *size = sym->st_size;

      return addr;
    }
  }

  /* INFO: Last resort for an exact lookup: the hash tables of the dynamic
             symbol section, resolved against the image base. */
  if (!prefix) {
    void *dynamic = (void *)getSymbAddress(img, name);
    if (dynamic != NULL) return dynamic;
  }

  return NULL;
}

static void zn_for_each_symbols(struct ZnSymbolResolver *resolver, bool (*callback)(const char *name, void *addr, size_t size, void *data), void *data) {
  if (resolver == NULL || callback == NULL) return;

  ElfImg *img = (ElfImg *)resolver;
  if (!ElfImg_load_symbols(img)) return;

  /* INFO: The seen-set is keyed on the symbol name, which is what identifies a
            symbol across tables. Now that the walk covers .symtab, .dynsym and
            the mini-debug table, one function is routinely described by all
            three; reporting it twice hands the module a second entry for an
            address it was already asked to hook, which its own duplicate check
            then refuses - so the repeat reads as a failure instead of as the
            same symbol. The name stays valid for the walk: it points into the
            mapped image or the decompressed mini-debug buffer. */
  char **seen = NULL;
  size_t seen_count = 0;
  size_t seen_capacity = 0;

  for (size_t i = 0; i < img->symtabs_count_; i++) {
    ElfW(Sym) *sym = img->symtabs_[i];

    const char *name = getSymbName(img, sym);
    if (name == NULL || name[0] == '\0') continue;

    void *addr = symbol_to_address(img, sym);
    if (addr == NULL) continue;

    bool duplicate = false;
    for (size_t j = 0; j < seen_count; j++) {
      if (strcmp(seen[j], name) == 0) {
        duplicate = true;

        break;
      }
    }

    if (duplicate) continue;

    if (seen_count == seen_capacity) {
      size_t capacity = seen_capacity == 0 ? 64 : seen_capacity * 2;

      char **grown = (char **)realloc(seen, capacity * sizeof(char *));
      if (grown == NULL) {
        LOGE("Failed growing the duplicate filter, reporting %s anyway", name);
      } else {
        seen = grown;
        seen_capacity = capacity;
      }
    }

    if (seen_count < seen_capacity) seen[seen_count++] = (char *)name;

    if (!callback(name, addr, sym->st_size, data)) break;
  }

  free(seen);
}

/* INFO: The contract lets a resolver be requested by bare file name ("libc.so"
         instead of "/apex/.../libc.so"). The ELF reader opens the file itself,
         so a name without a directory is resolved against the libraries
         actually mapped in this process first. */
static char *get_lib_path_by_name(const char *name) {
  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) return NULL;

  char *lib_path = NULL;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];
    if (entry->path == NULL || entry->offset != 0) continue;

    /* INFO: [heap], [stack] and the anon mappings are not files. Handing one
              back as a path would only produce an open() that fails. */
    if (entry->path[0] == '[') continue;

    const char *base = strrchr(entry->path, '/');
    base = base == NULL ? entry->path : base + 1;

    if (strcmp(base, name) != 0) continue;

    lib_path = strdup(entry->path);

    break;
  }

  free_maps(maps);

  return lib_path;
}

static struct ZnSymbolResolver *zn_new_symbol_resolver(const char *path, void *base_addr) {
  if (path == NULL) return NULL;

  /* INFO: The path is tried as given first, exactly as the reference does. A
            bare soname is only resolved against the loaded mappings when it
            does not open - a caller that passes a real path that happens to
            resolve should get that file, not whatever the maps hold under the
            same name. */
  struct ZnSymbolResolver *resolver = (struct ZnSymbolResolver *)ElfImg_create(path, base_addr);
  if (resolver != NULL) return resolver;

  if (strchr(path, '/') != NULL) return NULL;

  char *resolved = get_lib_path_by_name(path);
  if (resolved == NULL) return NULL;

  resolver = (struct ZnSymbolResolver *)ElfImg_create(resolved, base_addr);

  free(resolved);

  return resolver;
}

static void zn_free_symbol_resolver(struct ZnSymbolResolver *resolver) {
  if (resolver == NULL) return;

  ElfImg_destroy((ElfImg *)resolver);
}

static void *zn_get_base_address(struct ZnSymbolResolver *resolver) {
  if (resolver == NULL) return NULL;

  return ((ElfImg *)resolver)->base;
}

/* INFO: The self handle is the loader's module entry, which carries the
         companion control socket when the module declared one. */
static int zn_connect_companion(void *handle) {
  int fd = zn_companion_connect(handle);
  if (fd < 0) LOGE("The module has no reachable companion process");

  return fd;
}

/* INFO: The table every Zygisk Next module is served.

         There is one table and not one per version. The versions this fork
         accepts are the ones the contract can be served with as it stands - the
         gate in zn_loader.c says which ones and why - so an older table would be
         a table for a module that is refused before it can call anything, and a
         stub table pretending a version nothing ever reaches is a way of
         answering a question nobody asks. Every entry here is real: a module
         that got this far can call any of them. */
static const struct ZygiskNextAPI zn_api = {
  .pltHook = zn_plt_hook,
  .inlineHook = zn_inline_hook,
  .inlineUnhook = zn_inline_unhook,

  .newSymbolResolver = zn_new_symbol_resolver,
  .freeSymbolResolver = zn_free_symbol_resolver,
  .getBaseAddress = zn_get_base_address,
  .symbolLookup = zn_symbol_lookup,
  .forEachSymbols = zn_for_each_symbols,

  .connectCompanion = zn_connect_companion,

  /* INFO: The HyperOS runtime, answered from the process and not from the
            version: a module loaded into the spawner finds it, a module loaded
            anywhere else is told there is none. */
  .getRuntime = zn_hyos_runtime
};

const struct ZygiskNextAPI *zn_get_api(void) {
  return &zn_api;
}
