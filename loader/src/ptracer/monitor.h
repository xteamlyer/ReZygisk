#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>

/* INFO: The ABI this monitor injects, in the spelling the card and the tracer
         command line use. There is one monitor binary and it is the 64-bit one;
         the 32-bit counterpart was retired along with its command values below. */
#define MONITOR_ABI "64"

/* INFO: One module as the daemon reported it. A record rather than the five
         arrays this used to be: the name, whether it is a Zygisk Next module,
         whether it wants a companion and the targets it asked for only mean
         anything next to each other, and keeping them apart cost five
         allocations that had to succeed together and five indices that had to
         agree. */
struct daemon_module {
  char *name;
  bool is_zn;
  bool companion;
  char **targets;
  uint32_t targets_len;
};

/* INFO: Where the monitor is in its own life. The card words each one
         differently, and the wording is what a user reads when the module is
         not doing what they expected. */
enum ptracer_tracing_state {
  TRACING,
  STOPPING,
  STOPPED,
  EXITING
};

/* INFO: The monitor's state, as the card draws it.

         Filled in at the one place the monitor hands its state over. The card
         is a view and nothing else: every field here is read from the monitor's
         own variables at that moment, so there is no second copy of "is the
         daemon running" that could disagree with the process it describes. */
struct monitor_status_view {
  enum ptracer_tracing_state state;

  /* INFO: Why tracing stopped, or NULL while it has not. */
  const char *stop_reason;

  /* INFO: What the daemon said it was built for, and its last error. */
  const char *root_impl;
  const char *daemon_error;

  /* INFO: Every module the daemon reported, and how many of them are Zygisk
             Next modules - the listing asks the second question of the whole
             list, and the usual machine answers it without looking. */
  const struct daemon_module *modules;
  uint32_t modules_len;
  uint32_t zn_len;

  bool supported;
  bool zygote_injected;
  bool daemon_running;

  /* INFO: Whether this monitor has ever recognised the HyperOS spawner. */
  bool spawner_seen;
};

void init_monitor();

/* INFO: `exit_kill` says whether a tracer death may take the target with it
         (PTRACE_O_EXITKILL): yes for a zygote the monitor restarts anyway,
         never for the HyperOS spawner, which every application comes from. */
bool trace_zygote(int pid, bool exit_kill);

/* INFO: The two questions the card's spawner scan asks of the monitor.

         The scan exists to say why a spawner was never recognised, and it has
         to ask the same question the exec path asks - name and image together -
         or it answers something else. Both live here because the monitor is the
         side that already knows how to read them. */
bool monitor_program_is_spawner(pid_t pid, const char *program);
pid_t monitor_parent_of(int pid);

enum rezygiskd_command {
  START = 1,
  STOP = 2,
  EXIT = 3,

  /* INFO: Sent from the daemon. The gaps are the retired 32-bit
           counterparts: these are wire values shared with the daemon, so
           they keep their numbers instead of being renumbered. */
  ZYGOTE64_INJECTED = 4,
  DAEMON64_SET_INFO = 6,
  DAEMON64_SET_ERROR_INFO = 8,

  /* INFO: One module record of the list a DAEMON64_SET_INFO announced. It is
           its own datagram and not a field of the announcement, because a
           datagram is the only unit this socket delivers whole: each record
           is self-describing from its first byte, and a lost or stray
           datagram can never be parsed as the middle of another. */
  DAEMON64_MODULE_ENTRY = 9
};

int send_control_command(enum rezygiskd_command cmd);

#endif /* MONITOR_H */
