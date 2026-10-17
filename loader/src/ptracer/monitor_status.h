#ifndef MONITOR_STATUS_H
#define MONITOR_STATUS_H

#include <stdbool.h>

#include "monitor.h"

/* INFO: The module card, in its own file.

         Two things are written for a reader and neither is part of tracing: the
         description the manager draws the module card from, and the state.json a
         frontend reads. Both exist because a release build compiles every log
         line out - the card is the only place this monitor still says anything
         once it ships.

         The monitor fills in a struct monitor_status_view and calls these; no
         part of the drawing holds state of its own beyond the buffers it
         assembles the text in. */

/* INFO: Captures the pristine description this run is going to be written in
         front of, once, before the first write. False when module.prop cannot
         be read at all, which is a broken installation rather than a card that
         will not refresh. */
bool monitor_status_prepare(void);

/* INFO: Writes the card, and state.json with it.

         `message` replaces the generated status line and skips the state file:
         the callers that pass one carry a transient note about what just
         happened, not a status. */
bool monitor_status_update(const struct monitor_status_view *view, const char *message);

#endif /* MONITOR_STATUS_H */
