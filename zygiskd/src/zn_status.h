#ifndef ZN_STATUS_H
#define ZN_STATUS_H

#include <stddef.h>

/* INFO: What the last plans came to, written where the module card can show it.

         An empty plan looks the same from the loader whichever of several things
         went wrong - no module held a list, no row named this process, the
         library would not open - and the daemon is the only side that knows
         which. A release build compiles every log line out entirely, so the
         answer is written to a file instead, and the monitor reads it back onto
         the card, which is where a user looks.

         Only requests from a process that hosts the runtime are recorded: one
         the zygote-class names resolve to - which is a question about the
         process's own name, not about the spelling a manifest wrote - or the
         process that reported a runtime image. An application asking for its own
         plan is the common case and says nothing about whether the path works.

         `example_target` is the first row that did not name this process, kept
         only to be shown when nothing did: it is what a reader compares against
         the name the process reported, and that comparison is the whole
         diagnosis. */

void zn_status_record(const char *process_name, size_t dirs_walked,
                      size_t lists_valid, size_t rows_examined,
                      size_t rows_matched, const char *example_target);

#endif /* ZN_STATUS_H */
