#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

/* INFO: The framing - the loops, the descriptor exchange, the length-prefixed
         string - is shared with the daemon through socket_protocol.h, because
         the two ends of the protocol have to agree byte for byte and one copy
         of it is the only way to keep them agreeing.

         What is left here is this side's read_string, which is deliberately not
         shared: it allocates, while the daemon's fills a caller's buffer. */
#include "socket_protocol.h"

char *read_string(int fd);

#define write_func_def(type)              \
  ssize_t write_## type(int fd, type val)

#define read_func_def(type)               \
  ssize_t read_## type(int fd, type *val)

write_func_def(uint8_t);
read_func_def(uint8_t);

write_func_def(uint32_t);
read_func_def(uint32_t);

write_func_def(size_t);
read_func_def(size_t);

#endif /* SOCKET_UTILS_H */
