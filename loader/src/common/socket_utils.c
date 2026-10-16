#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>

#include "logging.h"

#include "socket_utils.h"

char *read_string(int fd) {
  size_t str_len = 0;
  ssize_t read_bytes = read_loop(fd, &str_len, sizeof(size_t));
  if (read_bytes != (ssize_t)sizeof(size_t)) {
    LOGE("Failed to read string length: Not all bytes were read (%zd != %zu).\n", read_bytes, sizeof(size_t));

    return NULL;
  }

  /* INFO: A length is only sane up to a path's worth of bytes; anything
            beyond it is a desynchronised stream, and trusting it would let
            the allocation grow without bound. */
  if (str_len > (size_t)(1u << 20)) {
    LOGE("Failed to read string: Length %zu is out of bounds.\n", str_len);

    return NULL;
  }

  char *buf = malloc(str_len + 1);
  if (buf == NULL) {
    PLOGE("allocate memory for string");

    return NULL;
  }

  read_bytes = read_loop(fd, buf, str_len);
  if (read_bytes != (ssize_t)str_len) {
    LOGE("Failed to read string: Promised bytes doesn't exist (%zd != %zu).\n", read_bytes, str_len);

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

write_func(size_t)
read_func(size_t)
