#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <ctype.h>
#include <fcntl.h>

#include <unistd.h>

#include "logging.h"
#include "socket_utils.h"

#include "misc.h"

int parse_int(const char *str) {
  int val = 0;

  char *c = (char *)str;
  while (*c) {
    if (*c > '9' || *c < '0')
      return -1;

    val = val * 10 + *c - '0';
    c++;
  }

  return val;
}

struct kernel_version parse_kversion(void) {
  struct utsname uts;
  if (uname(&uts) == -1) {
    PLOGE("uname");

    return (struct kernel_version) { 0 };
  }

  struct kernel_version version;
  if (sscanf(uts.release, "%hhu.%u.%u", &version.major, &version.minor, &version.patch) != 3) {
    LOGE("Failed to parse kernel version");

    return (struct kernel_version) { 0 };
  }

  return version;
}

/* INFO: One line of a maps stream into an entry. The path points into the
         line, which stays the caller's to keep alive - the entry is only
         valid for as long as that buffer is. */
static bool parse_maps_line(char *line, struct map_entry *entry) {
  /* INFO: strcspn leaves the content intact when the last maps line has no
            trailing newline, which strlen - 1 would corrupt. */
  line[strcspn(line, "\n")] = '\0';

  uintptr_t start, end, offset;
  unsigned int dev_major, dev_minor;
  ino_t inode;
  char perms[5] = { 0 };
  int path_off;

  if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n",
             &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, &path_off) != 7) {
    return false;
  }

  int perms_bit = 0;
  if (perms[0] == 'r') perms_bit |= PROT_READ;
  if (perms[1] == 'w') perms_bit |= PROT_WRITE;
  if (perms[2] == 'x') perms_bit |= PROT_EXEC;

  while (isspace((unsigned char)line[path_off]))
    path_off++;

  *entry = (struct map_entry) {
    .start = start,
    .end = end,
    .perms = perms_bit,
    .is_private = (perms[3] == 'p'),
    .offset = offset,
    .dev = makedev(dev_major, dev_minor),
    .inode = inode,
    .path = line + path_off
  };

  return true;
}

/* INFO: getline instead of a fixed buffer: maps lines with long paths used to
           be split mid-line, fail the sscanf and silently drop their mapping. */
static bool walk_maps_stream(FILE *fp, maps_visitor visit, void *userdata) {
  char *line = NULL;
  size_t line_capacity = 0;

  while (getline(&line, &line_capacity, fp) != -1) {
    struct map_entry entry;

    if (!parse_maps_line(line, &entry)) continue;

    if (!visit(&entry, userdata)) break;
  }

  /* INFO: A stream that ends early leaves a partial listing behind, which is
            worse than none at all: the caller would take it for the whole
            map. */
  bool complete = !ferror(fp);
  if (!complete) PLOGE("read a maps stream");

  free(line);

  return complete;
}

/* INFO: Collects every entry into a fresh table, which is what the callers
         that want all of it - the ELF reader and the hook scanner - need. */
struct collect_state {
  struct maps_info *info;
  size_t capacity;
  bool failed;
};

static bool collect_map(const struct map_entry *map, void *userdata) {
  struct collect_state *state = userdata;

  if (state->info->length >= state->capacity) {
    size_t capacity = state->capacity * 2;

    struct map_entry *grown = realloc(state->info->maps, capacity * sizeof(struct map_entry));
    if (grown == NULL) {
      PLOGE("reallocate (extend: %zu -> %zu) memory for maps", state->capacity, capacity);

      state->failed = true;

      return false;
    }

    state->info->maps = grown;
    state->capacity = capacity;
  }

  char *path = strdup(map->path);
  if (path == NULL) {
    PLOGE("allocate memory for map path");

    state->failed = true;

    return false;
  }

  state->info->maps[state->info->length] = *map;
  state->info->maps[state->info->length].path = path;
  state->info->length++;

  return true;
}

/* INFO: Parses the lines of an already-open maps stream into a fresh
         maps_info. Returns NULL on failure. */
static struct maps_info *parse_maps_stream(FILE *fp) {
  struct maps_info *info = calloc(1, sizeof(struct maps_info));
  if (info == NULL) {
    PLOGE("allocate memory");

    return NULL;
  }

  info->maps = malloc(2 * sizeof(struct map_entry));
  if (info->maps == NULL) {
    PLOGE("allocate memory for maps");

    free(info);

    return NULL;
  }

  struct collect_state state = { .info = info, .capacity = 2 };

  bool walked = walk_maps_stream(fp, collect_map, &state);
  if (!walked || state.failed) {
    free_maps(info);

    return NULL;
  }

  if (info->length == 0) {
    LOGE("Failed to find any maps");

    free_maps(info);

    return NULL;
  }

  /* INFO: Resize to the actual size */
  struct map_entry *tmp_maps = realloc(info->maps, info->length * sizeof(struct map_entry));
  if (tmp_maps == NULL)
    PLOGE("reallocate (reduce: %zu -> %zu) memory for maps", state.capacity, info->length);
  else info->maps = tmp_maps;

  return info;
}

/* INFO: The maps of a process, read through a child that opens them, so that
         the access time the read leaves behind lands on that child's file and
         not on the one the application can stat. */
typedef bool (*maps_stream_fn)(FILE *fp, void *userdata);

/* INFO: Opening /proc/.../maps leads to its access time being updated. This
           function bypasses this by reading the maps from a forked process,
           which is the same memory topology anyway. See more information in
           parse_maps().
*/
static bool with_maps_stream(const char *pid, maps_stream_fn callback, void *userdata) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
    LOGE("Failed to create socket pair");

    return false;
  }

  int ppid = clone(NULL, NULL, SIGCHLD, NULL);
  if (ppid == -1) {
    LOGE("Failed to clone process");

    close(sockets[0]);
    close(sockets[1]);

    return false;
  }

  if (ppid == 0) {
    close(sockets[0]);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);

    int maps_file = open(path, O_RDONLY | O_CLOEXEC);
    if (maps_file < 0) {
      LOGE("Failed to open %s", path);

      uint8_t can_kill_myself = 0;
      if (TEMP_FAILURE_RETRY(write(sockets[1], &can_kill_myself, sizeof(can_kill_myself))) < 0) {
        LOGE("Failed to write to socket");
      }

      goto scan_children_fail;
    }

    if (write_fd(sockets[1], maps_file) < 0) {
      LOGE("Failed to write file descriptor to socket");

      goto post_open_scan_children_fail;
    }

    /* INFO: Wait for the parent process to finish reading */
    uint8_t can_kill_myself = 1;
    if (TEMP_FAILURE_RETRY(read(sockets[1], &can_kill_myself, sizeof(can_kill_myself))) < 0) {
      LOGE("Failed to read from socket");

      goto post_open_scan_children_fail;
    }

    close(maps_file);
    close(sockets[1]);

    _exit(EXIT_SUCCESS);

    post_open_scan_children_fail:
      close(maps_file);
    scan_children_fail:
      close(sockets[1]);

      _exit(EXIT_FAILURE);
  }

  close(sockets[1]);

  int fd = read_fd(sockets[0]);
  if (fd < 0) {
    LOGE("Failed to read file descriptor from socket");

    close(sockets[0]);

    /* INFO: The child is blocked on the can-kill byte; closing the socket
             makes its read fail and it exits, so reap it here or it stays a
             zombie under the long-lived monitor. */
    waitpid(ppid, NULL, 0);

    return false;
  }

  FILE *fp = fdopen(fd, "r");
  if (fp == NULL) {
    LOGE("Failed to open file descriptor as FILE");

    close(fd);
    close(sockets[0]);

    /* INFO: Same as above: the child never gets its can-kill byte on this
             path, so the closed socket lets it exit and this reaps it. */
    waitpid(ppid, NULL, 0);

    return false;
  }

  bool ok = callback(fp, userdata);

  /* INFO: Notify the children process that we are done */
  uint8_t can_kill_itself = 1;
  if (TEMP_FAILURE_RETRY(write(sockets[0], &can_kill_itself, sizeof(can_kill_itself))) < 0) {
    LOGE("Failed to write to socket");
  }

  fclose(fp);
  close(sockets[0]);

  /* INFO: This waitpid ensures that we only resume code execution once the child dies,
            or the child process will become zombie as shown in /proc/<child_pid>/status */
  waitpid(ppid, NULL, 0);

  return ok;
}

static bool collect_maps(FILE *fp, void *userdata) {
  struct maps_info **out = userdata;

  *out = parse_maps_stream(fp);

  return *out != NULL;
}

struct maps_info *parse_maps_safe(const char *pid) {
  struct maps_info *info = NULL;

  if (!with_maps_stream(pid, collect_maps, &info)) return NULL;

  return info;
}

struct scan_state {
  maps_visitor visit;
  void *userdata;
};

static bool walk_maps(FILE *fp, void *userdata) {
  struct scan_state *state = userdata;

  return walk_maps_stream(fp, state->visit, state->userdata);
}

bool scan_maps_safe(const char *pid, maps_visitor visit, void *userdata) {
  struct scan_state state = { .visit = visit, .userdata = userdata };

  return with_maps_stream(pid, walk_maps, &state);
}

/* INFO: Accessing /proc/.../maps will update its access time. This is detectable
           by using stat() to check when the application takes control of the
           execution of the process. However, if we do this before the fork(),
           it will update the access time of the maps file of the parent process,
           not child, making it undetectable.
*/
struct maps_info *parse_maps(const char *pid) {
  /* INFO: The character limit for a 32-bit PID is 10 */
  char path[(sizeof("/proc//maps") - 1) + 10 + 1];
  snprintf(path, sizeof(path), "/proc/%s/maps", pid);

  FILE *fp = fopen(path, "r");
  if (fp == NULL) {
    PLOGE("Failed to open %s", path);

    return NULL;
  }

  struct maps_info *info = parse_maps_stream(fp);

  fclose(fp);

  return info;
}

void free_maps(struct maps_info *maps) {
  for (size_t i = 0; i < maps->length; i++) {
    free(maps->maps[i].path);
  }

  free(maps->maps);
  free(maps);
}
