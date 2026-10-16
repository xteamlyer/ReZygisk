/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * What the last Zygisk Next plans came to, written where the module card can
 * show it.
 *
 * This lives apart from the plan itself because it is a different question: the
 * plan answers which modules a process gets, and this answers why a user is
 * looking at a module that did not load. The daemon is the only side that knows
 * - a manifest line that names nothing looks the same from the loader whichever
 * of the several things went wrong - and a release build compiles every log line
 * out entirely, so the answer goes to a file the monitor reads onto the card,
 * which is where somebody actually looks.
 */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "zygisk_paths.h"

#include "zn_status.h"

/* INFO: What the last plans came to, for the module card.

         An empty plan looks the same from the loader whichever of several
         things went wrong - no module held a list, no row named this process,
         the library would not open - and the daemon is the only side that knows
         which. A release build compiles every log line out entirely, so the
         answer is written to a file instead, and the monitor puts it on the
         card, which is where a user looks.

         Only requests from a process that hosts the runtime are kept: one the
         zygote-class names resolve to - which is a question about the process's
         own name, not about the spelling a manifest wrote - or the process that
         reported a runtime image. An application asking for its own plan is the
         common case and says nothing about whether the Zygisk Next path
         works. */
#define ZN_STATUS_SLOTS 3
#define ZN_STATUS_NAME_MAX 64
#define ZN_STATUS_LINE_MAX 220

struct zn_status_entry {
  char name[ZN_STATUS_NAME_MAX];
  char line[ZN_STATUS_LINE_MAX];
};

static struct zn_status_entry zn_status[ZN_STATUS_SLOTS];
static size_t zn_status_len = 0;

/* INFO: No snprintf on this path, deliberately: the daemon is built with
         -Wformat-truncation among the warnings it treats as errors, and a
         bounded append is both what is wanted here and what cannot trip it. */
static void zn_status_append(char *buf, size_t cap, size_t *off, const char *text) {
  while (*text != '\0' && *off + 1 < cap) buf[(*off)++] = *text++;

  buf[*off] = '\0';
}

static void zn_status_append_size(char *buf, size_t cap, size_t *off, size_t value) {
  char digits[24];
  size_t at = sizeof(digits);

  if (value == 0) {
    at--;

    digits[at] = '0';
  }

  while (value != 0 && at > 0) {
    at--;

    digits[at] = (char)('0' + (int)(value % 10));
    value /= 10;
  }

  for (size_t i = at; i < sizeof(digits) && *off + 1 < cap; i++) buf[(*off)++] = digits[i];

  buf[*off] = '\0';
}

static void write_zn_status(void) {
  int fd = open(ZYGISK_ZN_STATUS_TMP, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd == -1) return;

  for (size_t i = 0; i < zn_status_len; i++) {
    const size_t len = strlen(zn_status[i].line);

    if (write_loop(fd, zn_status[i].line, len) != (ssize_t)len ||
        write_loop(fd, "\n", 1) != 1) {
      close(fd);
      unlink(ZYGISK_ZN_STATUS_TMP);

      return;
    }
  }

  close(fd);

  if (rename(ZYGISK_ZN_STATUS_TMP, ZYGISK_ZN_STATUS) == -1) unlink(ZYGISK_ZN_STATUS_TMP);
}

/* INFO: One line per process, replaced rather than appended when the same
         process asks twice, so the card shows this boot's last answer and not
         its first. */
void zn_status_record(const char *process_name, size_t dirs_walked, size_t lists_valid,
                             size_t rows_examined, size_t rows_matched, const char *example_target) {
  size_t slot = zn_status_len;

  for (size_t i = 0; i < zn_status_len; i++) {
    if (strcmp(zn_status[i].name, process_name) == 0) {
      slot = i;

      break;
    }
  }

  if (slot == zn_status_len) {
    if (zn_status_len == ZN_STATUS_SLOTS) {
      /* INFO: The oldest line is the one given up, so a noisy process cannot
                push everything else out with one request. */
      memmove(&zn_status[0], &zn_status[1], (ZN_STATUS_SLOTS - 1) * sizeof(struct zn_status_entry));
      slot = ZN_STATUS_SLOTS - 1;
    } else {
      zn_status_len++;
    }
  }

  struct zn_status_entry *entry = &zn_status[slot];

  size_t name_len = strlen(process_name);
  if (name_len >= sizeof(entry->name)) name_len = sizeof(entry->name) - 1;

  memcpy(entry->name, process_name, name_len);
  entry->name[name_len] = '\0';

  size_t off = 0;
  entry->line[0] = '\0';

  zn_status_append(entry->line, sizeof(entry->line), &off, entry->name);
  zn_status_append(entry->line, sizeof(entry->line), &off, ": ");
  zn_status_append_size(entry->line, sizeof(entry->line), &off, rows_matched);
  zn_status_append(entry->line, sizeof(entry->line), &off, "/");
  zn_status_append_size(entry->line, sizeof(entry->line), &off, rows_examined);
  zn_status_append(entry->line, sizeof(entry->line), &off, " row(s) named it (");
  zn_status_append_size(entry->line, sizeof(entry->line), &off, lists_valid);
  zn_status_append(entry->line, sizeof(entry->line), &off, " list(s), ");
  zn_status_append_size(entry->line, sizeof(entry->line), &off, dirs_walked);
  zn_status_append(entry->line, sizeof(entry->line), &off, " dir(s))");

  if (rows_matched == 0 && example_target != NULL) {
    zn_status_append(entry->line, sizeof(entry->line), &off, " e.g. ");
    zn_status_append(entry->line, sizeof(entry->line), &off, example_target);
  }

  write_zn_status();
}
