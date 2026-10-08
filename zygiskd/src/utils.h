#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android/log.h>

#include "constants.h"
#include "root_impl/common.h"

/* INFO: Duplicated rather than pulled from the loader's shared header: reusing
         it would couple every file that includes utils.h to the loader's
         include tree, including the host tests, which build the daemon
         sources on their own. */
#define APP_ID(uid) ((uid) % 100000)

/* INFO: The identity a cached verdict is invalidated on. A staged library, the
         APatch policy file and a module directory each spelled this comparison
         out in their own file, so a change to what counts as the same file
         could reach one caller and miss the others. It sits beside APP_ID for
         the same reason that one is duplicated rather than pulled from the
         loader's header: utils.h is the only header the daemon's own sources
         share, and depending on the loader's would drag the host tests along. */
static inline bool stat_identity_same(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev &&
         a->st_ino == b->st_ino &&
         a->st_size == b->st_size &&
         a->st_mtime == b->st_mtime;
}

#ifndef LOG_TAG
  #define LOG_TAG "zygiskd"
#endif

/* INFO: Release builds are completely silent: every log level, and the
         logd/printf writes each one costs, compiles away under NDEBUG.
         Debug packages keep the full output for troubleshooting. */
#ifdef NDEBUG
  #define LOGD(...) do { } while (0)
  #define LOGI(...) do { } while (0)
  #define LOGW(...) do { } while (0)
  #define LOGE(...) do { } while (0)
#else
  #define LOGD(...)                                              \
    do {                                                         \
      __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__); \
      printf(__VA_ARGS__);                                       \
    } while (0)

  #define LOGI(...)                                              \
    do {                                                         \
      __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
      printf(__VA_ARGS__);                                       \
    } while (0)

  #define LOGW(...)                                              \
    do {                                                         \
      __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__); \
      printf(__VA_ARGS__);                                       \
    } while (0)

  #define LOGE(...)                                              \
    do {                                                         \
      __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
      printf(__VA_ARGS__);                                       \
    } while (0)
#endif

/* INFO: Fixed-argument on purpose. A variadic PLOGE("read") would pass an
         empty __VA_ARGS__, which -Wpedantic rejects as ISO C99 requires at
         least one argument for "...". */
#define PLOGE(msg) LOGE("%s: %s", (msg), strerror(errno))

/* INFO: Not wrapped in do { } while (0) on purpose: the on_fail argument is
         instantiated with break, continue or goto, whose meaning would be
         swallowed by the loop instead of reaching the enclosing statement. */
#define ASSURE_SIZE_WRITE(area_name, subarea_name, sent_size, expected_size, return_type)                        \
  if (sent_size != (ssize_t)(expected_size)) {                                                                   \
    LOGE("Failed to sent " subarea_name " in " area_name ": Expected %zu, got %zd\n", expected_size, sent_size); \
                                                                                                                 \
    return_type;                                                                                                 \
  }

#define ASSURE_SIZE_READ(area_name, subarea_name, sent_size, expected_size, return_type)                         \
  if (sent_size != (ssize_t)(expected_size)) {                                                                   \
    LOGE("Failed to read " subarea_name " in " area_name ": Expected %zu, got %zd\n", expected_size, sent_size); \
                                                                                                                 \
    return_type;                                                                                                 \
  }

#define write_func_def(type)              \
  ssize_t write_## type(int fd, type val)

#define read_func_def(type)               \
  ssize_t read_## type(int fd, type *val)

bool switch_mount_namespace(pid_t pid);

void set_socket_create_context(const char *restrict context);

void unix_datagram_sendto(const char *restrict path, const void *restrict buf, size_t len);

int chcon(const char *path, const char *restrict context);

int unix_listener_from_path(const char *path);

ssize_t write_fd(int fd, int sendfd);
int read_fd(int fd);

/* INFO: *shared reports ownership: true means the fd is a daemon-cached,
         sealed copy that later requests reuse (never close it); false means
         a per-call copy the caller closes right after the handover. */
int create_library_fd(const char *restrict path, bool *shared);

ssize_t write_loop(int fd, const void *restrict buf, size_t count);
ssize_t read_loop(int fd, void *restrict buf, size_t count);

write_func_def(size_t);
read_func_def(size_t);

write_func_def(uint32_t);
read_func_def(uint32_t);

write_func_def(uint8_t);
read_func_def(uint8_t);

ssize_t write_string(int fd, const char *restrict str);

ssize_t read_string(int fd, char *restrict buf, size_t buf_size);

bool check_unix_socket(int fd, bool block);

void stringify_root_impl_name(struct root_impl impl, char *restrict output);

int save_mns_fd(int pid);

#endif /* UTILS_H */
