#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>

void init_monitor();

bool trace_zygote(int pid, bool is_tango);

enum rezygiskd_command {
  START = 1,
  STOP = 2,
  EXIT = 3,

  /* INFO: Sent from the daemon. The gaps are the retired 32-bit
           counterparts: these are wire values shared with the daemon, so
           they keep their numbers instead of being renumbered. */
  ZYGOTE64_INJECTED = 4,
  DAEMON64_SET_INFO = 6,
  DAEMON64_SET_ERROR_INFO = 8
};

int send_control_command(enum rezygiskd_command cmd);

#endif /* MONITOR_H */
