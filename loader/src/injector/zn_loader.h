#ifndef ZN_LOADER_H
#define ZN_LOADER_H

#include <stddef.h>
#include <stdint.h>

/* INFO: Asks the daemon for the Zygisk Next libraries targeting this process
         and loads them. Meant for the zygote itself, where the process name
         can be read off /proc/self/exe.

         The daemon is the only source of the module plan. There is no fallback
         that reads /data/adb/modules directly: the HyperOS spawner and the apps
         it forks sit outside the zygote's domain and cannot read that tree
         anyway, so such a fallback could only ever have worked for targets the
         daemon already serves - and a loader that reads the tree on its own can
         disagree with the daemon about what is installed.

         `connect_retry` is the number of extra daemon connection attempts
         after the first, spaced `connect_delay_us` apart. Ordinary targets
         pass the default 0.1s spacing; the HyperOS spawner passes five
         attempts a second apart, because it can exec in the same breath as
         the daemon's own fork and its module plan is the only one its apps will
         ever see - they inherit it and nothing asks again. NyaZygisk, whose
         loader carries the same one-shot contract, waits out the same window;
         the wait only ever costs anything while the daemon is unreachable. */
void zn_load_all_modules(uint8_t connect_retry, uint32_t connect_delay_us);

/* INFO: Same scan, but for a forked child that is about to specialize:
         process_name is the nice_name the zygote was given, and only the
         modules targeting it are loaded. Libraries already inherited from the
         zygote are skipped. The daemon is long up by the time a process
         specializes, so one connection attempt is enough. */
void zn_load_modules_for_process(const char *process_name);

/* INFO: Opens a fresh connection to the companion of the module behind
         `handle`, which is the self handle it received in onModuleLoaded.
         Returns the socket, or -1 when there is no reachable companion. */
int zn_companion_connect(void *handle);

#endif /* ZN_LOADER_H */
