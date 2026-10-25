#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>

#include "logging.h"

#include "socket_utils.h"

char *read_string(int fd) {
  /* INFO: The length is a fixed uint32_t on the wire - see write_string in
            socket_protocol.h for why it is not this side's size_t. */
  uint32_t str_len = 0;
  ssize_t read_bytes = read_loop(fd, &str_len, sizeof(str_len));
  if (read_bytes != (ssize_t)sizeof(str_len)) {
    LOGE("Failed to read string length: Not all bytes were read (%zd != %zu).\n", read_bytes, sizeof(str_len));

    return NULL;
  }

  /* INFO: A length is only sane up to a path's worth of bytes; anything
            beyond it is a desynchronised stream, and trusting it would let
            the allocation grow without bound. */
  if (str_len > (1u << 20)) {
    LOGE("Failed to read string: Length %u is out of bounds.\n", str_len);

    return NULL;
  }

  char *buf = malloc((size_t)str_len + 1);
  if (buf == NULL) {
    PLOGE("allocate memory for string");

    return NULL;
  }

  read_bytes = read_loop(fd, buf, str_len);
  if (read_bytes != (ssize_t)str_len) {
    LOGE("Failed to read string: Promised bytes doesn't exist (%zd != %u).\n", read_bytes, str_len);

    free(buf);

    return NULL;
  }

  buf[str_len] = '\0';

  return buf;
}

#define write_func(type)                       \
  ssize_t write_## type(int fd, type val) {    \
    return write_loop(fd, &val, sizeof(type)); \
  }

#define read_func(type)                      \
  ssize_t read_## type(int fd, type *val) {  \
    return read_loop(fd, val, sizeof(type)); \
  }

write_func(uint8_t)
read_func(uint8_t)

write_func(uint32_t)
read_func(uint32_t)

/* INFO: The count fields ride the wire as uint32_t for the same reason the
         string lengths do: a size_t would make the protocol's shape depend on
         the ABI of whichever side compiled it. Every value that crosses here
         is a count of modules or an index into them, so the narrowing bound
         is not a limit any install will meet. */
ssize_t write_size_t(int fd, size_t val) {
  if (val > UINT32_MAX) {
    LOGE("Value %zu does not fit the protocol's 32-bit count field.\n", val);

    return -1;
  }

  uint32_t wire = (uint32_t)val;

  return write_loop(fd, &wire, sizeof(wire));
}

ssize_t read_size_t(int fd, size_t *val) {
  uint32_t wire = 0;
  ssize_t read_bytes = read_loop(fd, &wire, sizeof(wire));

  if (read_bytes == (ssize_t)sizeof(wire) && val != NULL) *val = wire;

  return read_bytes;
}
