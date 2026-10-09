#ifndef MISC_H
#define MISC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

/* INFO: Every uid is userId * 100000 + appId, and it is the appId that root
         implementations key off. A later user - Private Space included - shifts
         the uid by whole 100000s, so the raw value has to be reduced first. */
#define APP_ID(uid) ((uid) % 100000)

#define IS_ISOLATED_SERVICE(uid)      \
  (APP_ID(uid) >= 90000)

/* INFO: The kernel appends " (deleted)" to the link target of an executable
         whose file was replaced while it was running - an OTA is the usual
         cause - and the suffix is part of the target, so a plain comparison
         against the expected path would miss it. Every /proc/<pid>/exe reader in
         this tree has to drop it first, and the suffix, the memcmp and the
         arithmetic behind it were written out once per reader. Returns the
         length to terminate the path at. The test is strict so that a path
         consisting of the suffix alone cannot come back empty; a real link
         target is absolute and never reaches that case. */
static inline size_t strip_deleted_suffix(const char *path, size_t len) {
  static const char kDeletedSuffix[] = " (deleted)";
  size_t suffix_len = sizeof(kDeletedSuffix) - 1;

  if (len > suffix_len && memcmp(path + len - suffix_len, kDeletedSuffix, suffix_len) == 0) {
    return len - suffix_len;
  }

  return len;
}

/* INFO: Reads the target of /proc/<pid>/exe into `buf` with the " (deleted)"
         suffix dropped and a terminator written, and returns its length, or -1
         when the link could not be read.

         This whole sequence - the path, the readlink, the clamp at the end of
         the buffer, the suffix strip, the terminating write - was written out
         once per reader, and they drifted: one of them never stripped the
         suffix at all, so a binary replaced under it stopped matching its own
         path. Only what a failure means stays with the caller, because that is
         the one part that genuinely differs: a sweep of /proc stays silent,
         since most entries there are kernel threads and zombies, while a reader
         that was handed one specific pid reports it. */
static inline ssize_t read_exe_path(int pid, char *buf, size_t size) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/exe", pid);

  ssize_t len = readlink(path, buf, size);
  if (len <= 0) return -1;

  if ((size_t)len >= size) len = (ssize_t)size - 1;

  len = (ssize_t)strip_deleted_suffix(buf, (size_t)len);
  buf[len] = '\0';

  return len;
}

struct kernel_version {
  uint8_t major;
  unsigned int minor;
  unsigned int patch;
};

struct map_entry {
  uintptr_t start;
  uintptr_t end;
  int perms;
  bool is_private;
  uintptr_t offset;
  dev_t dev;
  ino_t inode;
  char *path;
};

struct maps_info {
  struct map_entry *maps;
  size_t length;
};

/* INFO: One entry of a maps listing, handed to a visitor while the line it was
         read from is still alive - path points into that line, so a visitor
         that keeps the entry has to copy the path itself. Returning false
         stops the walk early, which is not a failure. */
typedef bool (*maps_visitor)(const struct map_entry *map, void *userdata);

int parse_int(const char *str);

struct kernel_version parse_kversion(void);

struct maps_info *parse_maps_safe(const char *pid);

struct maps_info *parse_maps(const char *pid);

void free_maps(struct maps_info *maps);

/* INFO: parse_maps_safe without the table: the entries are handed to the
         visitor as they are read, so looking for a few of them costs nothing
         for the thousands that are not. Returns false when the maps could not
         be read at all. */
bool scan_maps_safe(const char *pid, maps_visitor visit, void *userdata);

#endif /* MISC_H */
