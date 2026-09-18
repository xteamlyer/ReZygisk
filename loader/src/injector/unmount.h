#ifndef UNMOUNT_H
#define UNMOUNT_H

#include <stdbool.h>
#include <stdint.h>

/* INFO: Revert-only is how denylisted processes are hidden by default: the
           process gets a private copy of the mount tree and the root traces are
           stripped from that copy, in place. Unlike a namespace switch this
           leaves everyone else's mounts alone, so metamodule overlays stay
           visible, and each app ends up with a namespace object of its own. A
           metamodule's mounts are indistinguishable from a root trace, which is
           why this is only ever applied to the processes being hidden. */

/* True unless a disable-revert marker opts the device out. */
bool revert_mode_enabled(void);

/* Strips the root traces from the mount namespace this process is in, returning
   true when nothing is left to hide. Run it right after a denylisted process
   unshared its own copy of the mount tree. False means the caller should hide
   the process with a namespace switch instead. */
bool revert_root_traces_here(void);

#endif /* UNMOUNT_H */
