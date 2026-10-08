#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

/* INFO: The kernel may copy a struct cmsghdr into the control buffer, so the
         buffer has to be aligned as one instead of being a plain byte array.

         The ZN companion protocol header carries an identical union and does
         not include this one: the daemon compiles its own read_string with a
         different signature - buffer and length instead of an allocation - so
         pulling these declarations into that header would be a conflicting
         declaration for its translation unit. The two unions are deliberately
         separate, not a duplication that was missed. */
union zygisk_cmsg_buffer {
  struct cmsghdr header;
  char control[CMSG_SPACE(sizeof(int))];
};

ssize_t write_loop(int fd, const void *buf, size_t count);

ssize_t read_loop(int fd, void *buf, size_t len);

ssize_t write_fd(int fd, int sendfd);

int read_fd(int fd);

ssize_t write_string(int fd, const char *str);

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
