#ifndef ZN_COMPANION_PROTOCOL_H
#define ZN_COMPANION_PROTOCOL_H

/* INFO: The wire contract of the Zygisk Next companion socket, shared by the
         loader side that serves it (injector/zn_loader.c) and the daemon side
         that hosts it as `zygiskd zn-companion` (zygiskd/src/zn_companion.c).

         Both halves used to carry their own copy, right down to the comments,
         and nothing checked that the two agreed: a command byte edited on one
         side alone still compiles and only shows up as a companion that never
         connects. One definition makes that impossible. */

#include <stdint.h>

#include <sys/socket.h>

/* INFO: Command byte the module sends when it calls connectCompanion. */
#define ZN_COMPANION_CMD_CONNECT ((uint8_t)1)

/* INFO: The byte the companion writes on a connection the moment it takes it
         over, and the loader reads before it returns that socket to the module.
         Without it the two race: the module can reach its end of the socket
         before the companion has accepted it, and the loader hands out a socket
         it has no evidence the companion holds. Both companion halves send it
         from this one definition, so a locally forked companion and the
         daemon-hosted one stay indistinguishable to the module. */
#define ZN_COMPANION_ACK ((uint8_t)1)

/* INFO: How long the loader waits for that byte. It only covers a companion
         that is already running, so the wait is short - but it must be bounded:
         a companion left over from an older build never acknowledges, and
         blocking on it would turn a version skew into a hung connectCompanion
         instead of a socket that still works. */
#include "socket_protocol.h"

#define ZN_COMPANION_ACK_TIMEOUT_MS 1000

/* INFO: The control-message buffer the descriptor handshake needs is in
         socket_protocol.h, which this header includes: it is part of the
         framing, and the framing is now shared with the daemon. It used to be
         written out here as a second copy, because the only shared header
         available at the time also declared the loader's read_string. */

#endif /* ZN_COMPANION_PROTOCOL_H */
