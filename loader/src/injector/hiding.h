#ifndef HIDING_H
#define HIDING_H

#include <stdbool.h>

/* INFO: The one trace the mount revert cannot reach, per process and only
         final once the modules have run: a library still mapped into a
         hidden process names its own file in /proc/self/maps - the
         injector itself, every module library the loader abandons rather
         than unloads, and every Zygisk Next library the system linker
         holds.

         The other half of this is the mount line bionic parses into one
         static buffer, which the zygote hands down to every application it
         forks. That one lives in unmount.c next to the revert which leaves
         the tree clean: see refresh_mount_line() there. */

bool hide_module_maps(void);

/* INFO: Whether hide_module_maps() has already run in this process.
         The specialize path hides once, after the modules have run, and the
         teardown hides again as its last step. The second call has nothing
         left to act on in the processes the first one reached - the entries it
         worked on are anonymous now - and finding that out costs a fork and a
         walk of the whole table, which is the most expensive thing either call
         does. The teardown asks this first; a process where the specialize path
         did not run still gets its one pass. */
bool module_maps_hidden(void);

#endif /* HIDING_H */
