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

static inline bool zn_process_is_zygote_class(const char *process_name) {
  return strstr(process_name, "zygote") != NULL ||
         strstr(process_name, "app_process") != NULL ||
         strstr(process_name, "hyos_spawner") != NULL;
}

#endif /* ZN_TARGETS_H */
