/* INFO: Host-side tests for what hiding.c treats as a trace in a maps listing.

         Replacing a mapping only ever happens on a device, but deciding which
         mappings to replace is pure text handling, and it is the part that
         breaks quietly: too wide and ashmem or the ART images become private
         copies, too narrow and every module library stays named. The .c is
         included so the static predicate is reachable. */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>

#include "check.h"

#include "../../loader/src/injector/hiding.c"

/* INFO: hide_module_maps() reaches the maps through this, which lives in the
         loader's common code and is never exercised here. The stub keeps the
         predicate linkable without pulling the rest of the loader in. */
bool scan_maps_safe(const char *pid, maps_visitor visit, void *userdata) {
  (void) pid;
  (void) visit;
  (void) userdata;

  return false;
}

#define DATA_DEV  ((dev_t) 0x0a03)
#define OTHER_DEV ((dev_t) 0x0b04)

static bool hides(const char *path, bool is_private, dev_t map_dev) {
  struct map_entry map = {
    .start = 0x70000000,
    .end = 0x70001000,
    .perms = PROT_READ | PROT_EXEC,
    .is_private = is_private,
    .offset = 0,
    .dev = map_dev,
    .inode = 1,
    .path = (char *) path
  };

  return map_is_a_trace(&map, DATA_DEV);
}

static void check_module_libraries(void) {
  printf("-- what a hidden process has to stop naming\n");

  CHECK(hides("/data/adb/modules/any_module/lib/libexample.so", true, DATA_DEV),
        "a module library is not hidden");
  CHECK(hides("/data/adb/modules/any_module/lib/libexample.so (deleted)", true, DATA_DEV),
        "a deleted module library is not hidden");

  /* INFO: The injector's own mapping is the one hiding.c calls out as having
            to be replaced - the target's linker loaded it, and an entry left
            naming it is what the replacement exists to remove. It is covered
            here because it is the easiest one to lose: it lives inside the
            directory that the module-directory check excludes, so the two rules
            have to agree and only their order makes them. */
  CHECK(hides(ZYGISK_LOADER_LIB, true, DATA_DEV), "the injector itself is not hidden");
  CHECK(hides(ZYGISK_LOADER_LIB " (deleted)", true, DATA_DEV),
        "an injector whose file is gone is not hidden");

  /* INFO: The device decides a path but not the memfd, which is where a
            Zygisk Next library has to be loaded from - there is no /data
            device number that could ever describe it. */
  CHECK(hides(ZYGISK_ZN_MEMFD, true, OTHER_DEV), "the Zygisk Next memfd is not hidden");
  CHECK(hides(ZYGISK_ZN_MEMFD " (deleted)", true, OTHER_DEV),
        "a deleted Zygisk Next memfd is not hidden");
}

static void check_everything_else(void) {
  printf("-- what it must leave alone\n");

  CHECK(!hides(NULL, true, DATA_DEV), "an anonymous map is hidden");
  CHECK(!hides("/system/lib64/libc.so", true, DATA_DEV), "a system library is hidden");
  CHECK(!hides("/memfd:/boot-image-methods.art", true, DATA_DEV), "the ART image is hidden");
  CHECK(!hides(ZYGISK_ZN_MEMFD, false, DATA_DEV), "a shared Zygisk Next memfd is hidden");

  /* INFO: The memfd's name is the whole of what identifies it - it is on no
            filesystem, so nothing else about the mapping can - and a name that
            merely begins with it belongs to somebody else. A prefix compare
            answers this one wrong, which is why the rule is the whole name. */
  CHECK(!hides(ZYGISK_ZN_MEMFD "-2", true, OTHER_DEV),
        "a memfd whose name only starts with ours is hidden");
  CHECK(!hides(ZYGISK_ZN_MEMFD "x", true, OTHER_DEV),
        "a memfd named with ours as a prefix is hidden");

  CHECK(!hides("/data/local/tmp/loader.so", true, DATA_DEV),
        "a library mapped from /data/local/tmp is hidden");
  CHECK(!hides("/data/adb/modules/any_module/lib/libexample.so", false, DATA_DEV),
        "a shared map is hidden");

  /* INFO: Inside our own module directory, and not the injector: everything
            the module ships lives there, and replacing all of it would take the
            module's own libraries apart along with the loader. */
  CHECK(!hides(ZYGISK_MODULE_DIR "/lib/libexample.so", true, DATA_DEV),
        "a library from our own module directory is hidden");

  CHECK(!hides("/data/adb/modules/any_module/lib/libexample.so", true, OTHER_DEV),
        "a matching path on another device is hidden");
}

int main(void) {
  check_module_libraries();
  check_everything_else();

  if (g_failures == 0) {
    printf("all hiding checks passed\n");

    return 0;
  }

  printf("%d hiding check(s) failed\n", g_failures);

  return 1;
}
