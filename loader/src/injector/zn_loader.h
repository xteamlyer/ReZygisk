#ifndef ZN_LOADER_H
#define ZN_LOADER_H

#include <stddef.h>

/* INFO: Scans the modules for a zn_modules.txt and loads the Zygisk Next
         libraries whose target matches the current process. Meant for the
         zygote itself, where the process name can be read off /proc/self/exe. */
void zn_load_all_modules(void);

/* INFO: Same scan, but for a forked child that is about to specialize:
         process_name is the nice_name the zygote was given, and only the
         modules targeting it are loaded. Libraries already inherited from the
         zygote are skipped. */
void zn_load_modules_for_process(const char *process_name);

/* INFO: Opens a fresh connection to the companion of the module behind
         `handle`, which is the self handle it received in onModuleLoaded.
         Returns the socket, or -1 when there is no reachable companion. */
int zn_companion_connect(void *handle);

/* INFO: How many Zygisk Next libraries this process holds. Zero means its maps
         carry none of ours, so there is nothing there to stop naming - and a
         count inherited from the zygote is inherited along with the libraries
         it was raised for. */
size_t zn_loaded_library_count(void);

#endif /* ZN_LOADER_H */
