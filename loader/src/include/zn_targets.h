#ifndef ZN_TARGETS_H
#define ZN_TARGETS_H

/* INFO: The zygote-class target names of zn_modules.txt, resolved by the
         daemon when it builds the per-process set. It lives in the loader's
         include tree because that is where the two halves of the protocol meet,
         not because the loader matches these names: the daemon is the only
         source of the module plan. */

#include <string.h>

static inline bool zn_target_is_zygote_class(const char *target) {
  return strcmp(target, "zygote") == 0 ||
         strcmp(target, "zygote64") == 0 ||
         strcmp(target, "zygote32") == 0 ||
         strcmp(target, "hyos_spawner") == 0;
}

/* INFO: The processes a zygote-class target names. The three spellings are the
         classic ones, and artd is where Android 15 moved the application
         runtime host: a target that means "the process applications come from"
         has to reach it there, or the module is never loaded into the process
         every application of this boot is forked from. The first three are
         matched by substring on purpose - the platform spells them with
         suffixes (zygote64, app_process64) that vary by build - while artd is
         matched exactly, because it is short enough that a substring would
         start naming other processes. */
static inline bool zn_process_is_zygote_class(const char *process_name) {
  return strstr(process_name, "zygote") != NULL ||
         strstr(process_name, "app_process") != NULL ||
         strstr(process_name, "hyos_spawner") != NULL ||
         strcmp(process_name, "artd") == 0;
}

#endif /* ZN_TARGETS_H */
