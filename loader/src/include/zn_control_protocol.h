#ifndef ZN_CONTROL_PROTOCOL_H
#define ZN_CONTROL_PROTOCOL_H

/* INFO: The wire contract of the HyperOS runtime's control session: the loader
         writes reports on it (loader/src/common/daemon.c) and the daemon reads
         them (zygiskd/src/zygiskd.c).

         It lives in one header for the reason zn_companion_protocol.h does: two
         copies of a record agree right up until somebody edits one of them, and
         from the outside a session that is out of step looks like a module that
         was never told anything. The action byte that introduces a record is NOT
         here - it belongs to the enum that both halves already declare and
         check-protocol already compares.

         The two headers it is reached through are the loader's daemon.h and the
         daemon's own source, so nothing that includes the daemon's utils.h
         (including the host tests, which compile the daemon's root-implementation
         files without the loader's include tree) is coupled to this file. */

#include <stddef.h>
#include <stdint.h>

/* INFO: How long a module id may be, which is how long a module directory name
         may be: that is where a `zn_modules.txt` is read from and what the
         module is named by afterwards. Both halves bound a report with it, and a
         report longer than the reader's buffer is one the reader answers by
         ending the session. */
#define ZN_CONTROL_MODULE_ID_MAX (256 + 1)

/* INFO: A report's own header.

         Two 32-bit fields and not a uint32 + a size_t: the latter carries
         padding, so a writer that sends the struct and a reader that reads the
         fields one by one would disagree about how far apart they are - on the
         one ABI where it matters, silently. At 8 bytes with the fields at 0 and
         4 this is the same record on every ABI this fork ships, and a module id
         of up to 256 bytes fits a uint32 many times over. */
struct zn_control_report_header {
  uint32_t pid;
  uint32_t module_id_len;
};

/* INFO: Checked rather than assumed, for the reason vexcore.h checks its own
         structure: a compiler that laid this one out differently from the other
         side would not fail to build - it would read the wrong fields and
         report a module that was never loaded. Both spellings are here because
         the loader is built as C18 and the daemon as C99, where -Wpedantic
         applies and `_Static_assert` is only spelled that way from C11 on. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct zn_control_report_header) == 2 * sizeof(uint32_t),
               "a report header is two 32-bit fields with no padding");
_Static_assert(offsetof(struct zn_control_report_header, pid) == 0,
               "the reporting pid is the first field of a report header");
_Static_assert(offsetof(struct zn_control_report_header, module_id_len) == sizeof(uint32_t),
               "the module id length follows the pid");
#else
typedef char zn_control_report_header_must_be_two_uint32[(sizeof(struct zn_control_report_header) == 2 * sizeof(uint32_t)) ? 1 : -1];
typedef char zn_control_report_pid_must_come_first[(offsetof(struct zn_control_report_header, pid) == 0) ? 1 : -1];
typedef char zn_control_report_len_must_follow_the_pid[(offsetof(struct zn_control_report_header, module_id_len) == sizeof(uint32_t)) ? 1 : -1];
#endif

/* INFO: The bytes one report occupies, its action byte excluded. */
static inline size_t zn_control_report_size(size_t module_id_len) {
  return sizeof(struct zn_control_report_header) + module_id_len;
}

#endif /* ZN_CONTROL_PROTOCOL_H */
