/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * The module card: what this monitor's state reads as on the manager's screen.
 *
 * The monitor's own file is about tracing - which process to seize, when to
 * hand it to a tracer, when a stop is justified. This is about the sentence a
 * user reads afterwards: the run line, the module list, the Zygisk Next
 * diagnosis, and the two files it goes into (module.prop's description and
 * state.json), which are the only places a release build still says anything.
 *
 * They share nothing but the state they describe, and keeping both in one file
 * meant every change to either one was a change to a file already long enough
 * that neither was easy to follow.
 *
 * Everything here is drawn once per update from the struct monitor_status_view
 * the monitor fills in where it hands the state over. Nothing caches a copy of
 * that state: a second copy of "is the daemon running" is exactly the kind of
 * answer that ends up disagreeing with the process it describes, which is the
 * bug this card has already had once.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "utils.h"
#include "zygisk_paths.h"
#include "zn_spawner.h"

#include "monitor.h"
#include "monitor_status.h"

static char pre_section[1024];
static char post_section[1024];
static char module_text[2048];

/* INFO: What a whole rewritten module.prop can hold: both sections, the module
         list, and the status line with room for its brackets and the separator
         that follows it. One size serves the text assembled for a write and the
         read-back that decides whether that write has to happen at all. */
#define PROP_TEXT_MAX (sizeof(pre_section) + sizeof(post_section) + sizeof(module_text) + 1024)

/* INFO: A module that ships both a Zygisk library and a zn_modules.txt lands in
         both the plain and the Zygisk Next lists, so check for a Next twin
         before listing the plain copy. */
static bool has_zn_twin(const struct monitor_status_view *view, const char *name) {
  if (view->zn_len == 0) return false;

  for (uint32_t j = 0; j < view->modules_len; j++) {
    const struct daemon_module *twin = &view->modules[j];

    if (twin->is_zn && twin->name != NULL && strcmp(twin->name, name) == 0) return true;
  }

  return false;
}

/* INFO: Appends to a bounded buffer and keeps the offset inside it. snprintf
         reports the length it would have written rather than the length it did,
         so a truncated append advances the offset past the end of the buffer -
         and the next call would then be handed a negative size as a size_t,
         along with a pointer past the array, and write into whatever follows it
         in memory. Every append goes through here for that reason. */
static void append_bounded(char *buf, size_t cap, size_t *off, const char *text) {
  if (*off >= cap) return;

  int written = snprintf(buf + *off, cap - *off, "%s", text);
  if (written > 0) *off += (size_t)written;

  if (*off >= cap) *off = cap - 1;
}

/* INFO: The same append for a caller that only holds the buffer, taking the
         offset from the string itself. Both forms exist because a loop wants to
         carry the offset and a single statement does not, and writing either
         one out by hand is where the strncat calls below went wrong: with the
         string already filling the buffer, `cap - strlen(buf) - 1` underflows
         into a size_t so large that strncat stops bounding anything. */
static void str_append_bounded(char *buf, size_t cap, const char *text) {
  size_t off = strlen(buf);

  append_bounded(buf, cap, &off, text);
}

/* INFO: Folds the detected Zygisk modules into the module description so the
         manager shows them right on the module card, Mountify-style. */
static void build_module_text(const struct monitor_status_view *view) {
  module_text[0] = '\0';

  if (view->modules == NULL || view->modules_len == 0) return;

  size_t off = 0;
  append_bounded(module_text, sizeof(module_text), &off, "Modules: ");

  bool first = true;

  for (uint32_t i = 0; i < view->modules_len && off < sizeof(module_text) - 1; i++) {
    const struct daemon_module *module = &view->modules[i];
    if (module->name == NULL) continue;

    if (!module->is_zn && has_zn_twin(view, module->name)) continue;

    if (!first) append_bounded(module_text, sizeof(module_text), &off, ", ");
    first = false;

    append_bounded(module_text, sizeof(module_text), &off, module->name);

    if (module->is_zn) append_bounded(module_text, sizeof(module_text), &off, " (Next)");
  }

  append_bounded(module_text, sizeof(module_text), &off, " \u00b7 ");
}

/* INFO: JSON string writer used by the state file below; quotes, backslashes
         and control characters would otherwise produce invalid JSON. Writes
         at most cap - 1 bytes plus the terminator. */
static void json_escape_into(char *dst, size_t cap, const char *src) {
  size_t off = 0;

  for (const unsigned char *cursor = (const unsigned char *)src; *cursor != '\0' && off + 1 < cap; cursor++) {
    unsigned char c = *cursor;
    const char *escape = NULL;
    /* INFO: \uXXXX plus the terminator; a three byte buffer truncated
              every control character to a broken escape. */
    char short_escape[8] = { 0 };

    switch (c) {
      case '"': escape = "\\\""; break;
      case '\\': escape = "\\\\"; break;
      case '\n': escape = "\\n"; break;
      case '\r': escape = "\\r"; break;
      case '\t': escape = "\\t"; break;
      default: {
        if (c < 0x20) {
          snprintf(short_escape, sizeof(short_escape), "\\u%04x", (unsigned)c);
          escape = short_escape;
        }

        break;
      }
    }

    if (escape != NULL) {
      size_t escape_len = strlen(escape);
      if (off + escape_len >= cap) break;

      memcpy(dst + off, escape, escape_len);
      off += escape_len;

      continue;
    }

    dst[off++] = (char)c;
  }

  dst[off] = '\0';
}

/* INFO: Whether a process is one of the executables the spawner hides behind.

         Only the name is asked here, not the image behind it: this runs over
         every process in /proc and the image check reads the maps. */
static bool program_has_art_host_name(const char *program) {
  const char *base = strrchr(program, '/');
  base = base == NULL ? program : base + 1;

  return strcmp(base, "app_process64") == 0 || strcmp(base, "artd") == 0;
}

/* INFO: A number, appended where a caller already holds the offset. It exists
         because the bounded append above takes text, and formatting a number
         into a temporary to hand it that text is how the buffers on this card
         were made too small before. */
static void append_bounded_number(char *buf, size_t cap, size_t *off, unsigned long value) {
  char digits[16];
  size_t at = sizeof(digits);
  unsigned long magnitude = value;

  if (magnitude == 0) {
    at--;

    digits[at] = '0';
  }

  while (magnitude != 0 && at > 0) {
    at--;

    digits[at] = (char)('0' + (int)(magnitude % 10));
    magnitude /= 10;
  }

  while (at < sizeof(digits) && *off + 1 < cap) buf[(*off)++] = digits[at++];

  buf[*off] = '\0';
}

/* INFO: The exec path of a pid, or false when it cannot be read.

         The monitor reads the same path behind program_matches, which reports
         the failure; the sweep below meets kernel threads, zombies and entries
         that are not readable at all, and none of that is worth a line, which is
         the only difference between the two. */
static bool probe_program_path(int pid, char *buf, size_t size) {
  return read_exe_path(pid, buf, size) > 0;
}

/* INFO: Why the spawner was never recognised, as far as this side can tell.

         The monitor learns about a target from init: it seizes init, sees the
         forks, and attaches each child to catch the exec that follows. That is
         one level deep, and a child that turns out not to be a target is let
         go - so whatever it forks afterwards is invisible.

         "The spawner was never seen" therefore has two very different causes
         needing different fixes. The process may not be running under a name
         this monitor knows, or it may be running but out of reach. One pass
         over /proc tells them apart, and it only runs while the answer is still
         no.

         The question asked of each candidate is the one the exec path asks -
         monitor_program_is_spawner, name and image together - because anything weaker
         would answer a different question. The name is tried first since it is
         free; the image check reads that process's maps, so it is done for the
         ART hosts only, and only for the first few of them: a booted system has
         one app_process64 per running application.

         The process count is reported as well, and that is not decoration: a
         card written during the first moments of a boot is a card written
         before most of the system exists, and the reader has to be able to tell
         "there is no spawner" from "there was not much of anything yet". */
#define SPAWNER_PROBE_IMAGE_CHECKS 8

static void append_spawner_probe(char *out, size_t cap) {
  DIR *proc = opendir("/proc");
  if (proc == NULL) {
    str_append_bounded(out, cap, " (proc unreadable)");

    return;
  }

  pid_t spawner_pid = 0;
  pid_t spawner_parent = 0;
  size_t host_named = 0;
  size_t scanned = 0;
  size_t image_checks = 0;
  bool by_image = false;

  struct dirent *entry;
  while ((entry = readdir(proc)) != NULL) {
    if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

    char *endptr = NULL;
    const long pid_value = strtol(entry->d_name, &endptr, 10);
    if (endptr == entry->d_name || *endptr != '\0' || pid_value <= 1) continue;

    char program[PATH_MAX];
    if (!probe_program_path((int)pid_value, program, sizeof(program))) continue;

    scanned++;

    if (zn_spawner_map_is_spawner(program)) {
      spawner_pid = (pid_t)pid_value;
      spawner_parent = monitor_parent_of((int)pid_value);

      break;
    }

    if (!program_has_art_host_name(program)) continue;

    host_named++;

    if (image_checks >= SPAWNER_PROBE_IMAGE_CHECKS) continue;

    image_checks++;

    if (!monitor_program_is_spawner((pid_t)pid_value, program)) continue;

    spawner_pid = (pid_t)pid_value;
    spawner_parent = monitor_parent_of((int)pid_value);
    by_image = true;

    break;
  }

  closedir(proc);

  str_append_bounded(out, cap, " (");

  if (spawner_pid == 0) {
    str_append_bounded(out, cap, "no process carries the spawner image, ");

    size_t off = strlen(out);
    append_bounded_number(out, cap, &off, (unsigned long)host_named);
    str_append_bounded(out, cap, " app_process64/artd of ");
    off = strlen(out);
    append_bounded_number(out, cap, &off, (unsigned long)scanned);
    str_append_bounded(out, cap, " process(es)");

    return;
  }

  size_t off = strlen(out);
  str_append_bounded(out, cap, "spawner is pid ");
  off = strlen(out);
  append_bounded_number(out, cap, &off, (unsigned long)spawner_pid);
  if (by_image) str_append_bounded(out, cap, " (by image)");
  str_append_bounded(out, cap, ", parent ");
  off = strlen(out);
  append_bounded_number(out, cap, &off, (unsigned long)spawner_parent);
  str_append_bounded(out, cap, spawner_parent == 1 ? " (init - its exec was missed)"
                                                  : " (not init - out of the traced tree)");
}

/* INFO: The Zygisk Next half of the status line.

         Three different faults all look like "my Zygisk Next module does not
         load": the spawner was never recognised, the daemon was never asked,
         or a plan came back with nothing that named the process. Only the
         first is visible from here; the other two are what the daemon writes
         down, read back for the same line. A release build keeps no log of
         any of it, and the card is where somebody actually looks. */
static void append_zn_status_text(const struct monitor_status_view *view, char *out, size_t cap) {
  if (view->spawner_seen) {
    str_append_bounded(out, cap, ", ZN: spawner seen");
  } else {
    str_append_bounded(out, cap, ", ZN: spawner unseen");
    append_spawner_probe(out, cap);
  }

  int fd = 0;

  do {
    fd = open(ZYGISK_ZN_STATUS, O_RDONLY | O_CLOEXEC);
  } while (fd == -1 && errno == EINTR);

  if (fd == -1) {
    str_append_bounded(out, cap, " (no plan asked)");

    return;
  }

  char contents[768] = { 0 };
  ssize_t got = 0;

  do {
    got = read(fd, contents, sizeof(contents) - 1);
  } while (got == -1 && errno == EINTR);

  close(fd);

  /* INFO: An empty file and no file say the same thing: nobody has asked,
            which is itself the answer when the spawner was never injected. */
  if (got <= 0) {
    str_append_bounded(out, cap, " (no plan asked)");

    return;
  }

  contents[(size_t)got] = '\0';

  str_append_bounded(out, cap, " (");

  bool first = true;
  char *line = contents;

  for (char *cursor = contents; ; cursor++) {
    if (*cursor != '\n' && *cursor != '\0') continue;

    const char saved = *cursor;
    *cursor = '\0';

    if (line[0] != '\0') {
      if (!first) str_append_bounded(out, cap, " | ");

      str_append_bounded(out, cap, line);
      first = false;
    }

    *cursor = saved;

    if (saved == '\0') break;

    line = cursor + 1;
  }

  str_append_bounded(out, cap, ")");
}

/* INFO: Appends the live status to `out`, every append bounded to its
         capacity: the daemon error text arrives over a socket and can be
         longer than the line is allowed to hold. */
static void append_status_text(const struct monitor_status_view *view, char *out, size_t cap) {
  #define STATUS_APPEND(text) str_append_bounded(out, cap, (text))

  /* INFO: Read from the module's point of view rather than the monitor's. An
            injection is a one-shot inside the zygote, and a monitor that stops
            afterwards does not undo it - every application forked since already
            carries it, and the modules keep working. The monitor's own state
            therefore chooses the wording but never decides whether the module
            counts as working: only "the injection never landed" is a failure.
            Reporting the raw state as one is what made a working session read
            as broken on the manager's card. */
  const bool injected = view->zygote_injected;

  switch (view->state) {
    case TRACING: {
      STATUS_APPEND("✅");

      break;
    }
    case STOPPING: {
      /* INFO: A transition rather than a verdict: the stop is in flight, and
                the next update reports where it landed. */
      STATUS_APPEND(injected ? "⏸" : "⏳");

      break;
    }
    case STOPPED: {
      STATUS_APPEND(injected ? "⏸" : "⛔");

      break;
    }
    case EXITING: {
      STATUS_APPEND(injected ? "⏸" : "❌");

      break;
    }
  }

  if (view->supported) {
    STATUS_APPEND(", VexZygisk ");
    STATUS_APPEND(MONITOR_ABI);
    STATUS_APPEND("-bit: ");

    if (view->state == TRACING) {
      if (injected && view->daemon_running) STATUS_APPEND("✅");
      else STATUS_APPEND("⚠️");
    } else if (injected) {
      /* INFO: Both halves of the state, because either one alone has been
                read as the whole story. The loader is in the zygote and every
                process forked since carries it, but a monitor that is not
                tracing injects nothing new: a zygote or spawner that restarts
                from here on gets nothing, and the boot ends with no injection
                at all. A bare "✅ injected" next to the pause emoji is what
                had people reporting a stopped monitor with a green line beside
                it. The way back is named here because it is the one thing
                neither the emoji nor the reason says. */
      STATUS_APPEND("⚠️ injected, but not tracing - a restarted zygote is not injected again (resume from the module action)");
    } else {
      STATUS_APPEND("❌");
    }

    if (!view->daemon_running) {
      if (view->daemon_error) {
        STATUS_APPEND("(VexZygiskd: ");
        STATUS_APPEND(view->daemon_error);
        STATUS_APPEND(")");
      } else {
        STATUS_APPEND("(VexZygiskd: not running)");
      }
    }
  }

  append_zn_status_text(view, out, cap);

  /* INFO: Why the monitor is not tracing, once that is known. The state alone
            says what happened but not why, and the reason is what tells a stop
            that was asked for apart from one that went wrong. */
  if (view->state != TRACING && view->stop_reason != NULL) {
    STATUS_APPEND(" — ");
    STATUS_APPEND(view->stop_reason);
  }

  #undef STATUS_APPEND
}

/* INFO: Mirrors the status into the JSON a frontend reads. Written only once a
         root solution has been identified — without one the file would
         describe a run that never named itself — and an existing file is
         removed in that case rather than left describing a previous run. */
static bool write_state_json(const struct monitor_status_view *view) {
  if (view->root_impl == NULL) {
    if (remove(ZYGISK_STATE_JSON) == -1) {
      PLOGE("failed to remove state.json");
    }

    return true;
  }

  FILE *json = fopen(ZYGISK_STATE_JSON, "w");
  if (json == NULL) {
    PLOGE("failed to open state.json");

    return false;
  }

  char root_impl_json[256];
  json_escape_into(root_impl_json, sizeof(root_impl_json), view->root_impl);

  fprintf(json, "{\n");
  fprintf(json, "  \"root\": \"%s\",\n", root_impl_json);

  fprintf(json, "  \"monitor\": {\n");
  fprintf(json, "    \"state\": %d", view->state);

  if (view->stop_reason) {
    char reason_json[256];
    json_escape_into(reason_json, sizeof(reason_json), view->stop_reason);

    fprintf(json, ",\n    \"reason\": \"%s\"\n", reason_json);
  } else fprintf(json, "\n");

  if (view->supported) fprintf(json, "  },\n");
  else fprintf(json, "  }\n");

  if (view->supported) {
    char reason_json[256];
    if (view->daemon_error) json_escape_into(reason_json, sizeof(reason_json), view->daemon_error);

    fprintf(json, "  \"rezygiskd\": {\n");
    fprintf(json, "    \"%s\": {\n", MONITOR_ABI);
    fprintf(json, "      \"state\": %d,\n", view->daemon_running);
    if (view->daemon_error) fprintf(json, "      \"reason\": \"%s\",\n", reason_json);
    fprintf(json, "      \"modules\": [");

    if (view->modules) for (uint32_t i = 0; i < view->modules_len; i++) {
      const struct daemon_module *module = &view->modules[i];

      if (i > 0) fprintf(json, ", ");

      char module_json[256];
      json_escape_into(module_json, sizeof(module_json), module->name ? module->name : "");

      fprintf(json, "{\"id\": \"%s\", \"next\": %s, \"companion\": %s",
              module_json,
              module->is_zn ? "true" : "false",
              module->companion ? "true" : "false");

      if (module->targets) {
        fprintf(json, ", \"targets\": [");
        for (uint32_t t = 0; t < module->targets_len; t++) {
          if (t > 0) fprintf(json, ", ");

          char target_json[256];
          json_escape_into(target_json, sizeof(target_json), module->targets[t] ? module->targets[t] : "");

          fprintf(json, "\"%s\"", target_json);
        }
        fprintf(json, "]");
      }

      fprintf(json, "}");
    }

    fprintf(json, "]\n");
    fprintf(json, "    }\n");
    fprintf(json, "  },\n");

    fprintf(json, "  \"zygote\": {\n");
    fprintf(json, "    \"%s\": %d\n", MONITOR_ABI, view->zygote_injected);
    fprintf(json, "  }\n");
  }

  fprintf(json, "}\n");

  fclose(json);

  return true;
}

/* INFO: Whether the property file already holds exactly this text, read without
         touching it: the answer is what keeps an unchanged card from being
         rewritten. */
static bool prop_holds(const char *text) {
  FILE *prop = fopen(ZYGISK_MODULE_PROP, "r");
  if (prop == NULL) return false;

  char current[PROP_TEXT_MAX];
  const size_t got = fread(current, 1, sizeof(current) - 1, prop);

  /* INFO: A file longer than the buffer cannot be the text being compared, and
            a full read alone would not say so. */
  const bool longer = fgetc(prop) != EOF;

  fclose(prop);

  current[got] = '\0';

  return !longer && got == strlen(text) && memcmp(current, text, got) == 0;
}

bool monitor_status_update(const struct monitor_status_view *view, const char *message) {
  build_module_text(view);

  char status_text[512] = "Monitor: ";
  if (message == NULL) append_status_text(view, status_text, sizeof(status_text));

  /* INFO: The write replaces the file whole, so the comparison is against the
            whole of it: the lines in front of the description, the generated
            run, and whatever that description carried when this monitor
            started. */
  char wanted[PROP_TEXT_MAX];
  const int written = snprintf(wanted, sizeof(wanted), "%s[%s] %s%s",
                               pre_section, message ? message : status_text,
                               module_text, post_section);

  if (written < 0 || (size_t)written >= sizeof(wanted)) {
    LOGE("status line does not fit the property buffer");

    return false;
  }

  /* INFO: Written only when the file does not already say this. Opening it for
            writing truncates it first, and the manager reads it to draw the
            card: a write for a line that did not change is a reader that can
            catch the card half-written, and the refresh timer fires thirty of
            them per boot on behalf of a card that has not moved since the last
            one. A file reset behind our back - the boot stages restore the
            pristine copy - is a difference here, which is the other half of
            what comparing buys. */
  if (prop_holds(wanted)) return true;

  FILE *prop = fopen(ZYGISK_MODULE_PROP, "w");
  if (prop == NULL) {
    PLOGE("failed to open prop");

    return false;
  }

  fputs(wanted, prop);

  if (fclose(prop) != 0) {
    PLOGE("failed to close prop");

    return false;
  }

  /* INFO: A caller-supplied message is a transient note and not a status, so it
            leaves the state file describing what the last real update found. */
  if (message != NULL) return true;

  if (!write_state_json(view)) return false;

  LOGI("status updated: %s", status_text);

  return true;
}

/* INFO: A description a previous monitor wrote carries its status run in
         front of the pristine text, and the capture below takes the whole tail
         verbatim - so without this, every later write prints that old run
         again under the new one. That is not cosmetic: a card whose last write
         happened while the monitor was stopped kept saying "stopped" for the
         rest of the boot, next to a fresh run that said it was running, and a
         reader had no way to tell which of the two described the process in
         front of them. It is also the only way a stale run ever outlives the
         session that wrote it, since the boot-stage reset only restores the
         file between boots.

         One run is "[<status>] <Modules: ... · >", and nothing else is ever
         written in front of the description, so the cut is anchored at the
         start. The loop is for a file that already accumulated runs: each pass
         removes the frontmost one. */
static void strip_written_status(char *tail) {
  for (int pass = 0; pass < 8; pass++) {
    if (tail[0] != '[') return;

    char *closing = strchr(tail, ']');
    if (closing == NULL) return;

    char *rest = closing + 1;
    if (*rest == ' ') rest++;

    /* INFO: The module list follows the status inside the same run and is
              regenerated on every write as well; left in place it would be
              printed once per accumulated run. */
    if (strncmp(rest, "Modules: ", sizeof("Modules: ") - 1) == 0) {
      char *separator = strstr(rest, " \u00b7 ");
      if (separator == NULL) return;

      rest = separator + sizeof(" \u00b7 ") - 1;
    }

    memmove(tail, rest, strlen(rest) + 1);
  }
}

bool monitor_status_prepare(void) {
  FILE *orig_prop = fopen(ZYGISK_MODULE_PROP, "r");
  if (orig_prop == NULL) {
    PLOGE("failed to open orig prop");

    return false;
  }

  bool after_description = false;

  char line[1024];
  while (fgets(line, sizeof(line), orig_prop) != NULL) {
    /* INFO: The appends go through the same bounded helper as the status line,
              so a module.prop with lines longer than expected cannot walk
              either section past its end. */
    if (strncmp(line, "description=", strlen("description=")) == 0) {
      const size_t tag_len = strlen("description=");

      str_append_bounded(pre_section, sizeof(pre_section), "description=");

      /* INFO: Stripped in place, on the reader's own buffer: what survives is
                the pristine text the file carried before any monitor wrote to
                it, and that is the only part a write has to preserve. */
      strip_written_status(line + tag_len);
      str_append_bounded(post_section, sizeof(post_section), line + tag_len);

      after_description = true;

      continue;
    }

    if (after_description) str_append_bounded(post_section, sizeof(post_section), line);
    else str_append_bounded(pre_section, sizeof(pre_section), line);
  }

  fclose(orig_prop);

  return true;
}
