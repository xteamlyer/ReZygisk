#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "daemon.h"
#include "socket_utils.h"
#include "utils.h"
#include "zn_spawner.h"

#include "monitor.h"
#include "monitor_status.h"

/* INFO: The executables that host Android's application runtime, and so the
         processes this monitor exists to inject.

         app_process64 is the classic one. Android 15 moved the ART host into
         the ART APEX, where the same role is carried by
         /apex/com.android.art/bin/artd - which is also a process the Zygisk
         Next modules of this generation ask for by name, "name=artd" being one
         of the two targets LSPosed declares on HyperOS. Knowing only the first
         spelling meant such a device was never injected at all, and no module
         of that generation ever loaded. An exec of anything else is left to
         whichever monitor owns it.

         The two are kept apart from the crash-loop counter below, which is
         about a zygote that keeps coming back rather than about every exec
         this monitor serves. */
#define APP_PROCESS_NAME "/system/bin/app_process64"
#define ART_DAEMON_NAME "/apex/com.android.art/bin/artd"

/* INFO: Whether this executable is a host of the application runtime. */
static bool is_runtime_host(const char *program) {
  return strcmp(program, APP_PROCESS_NAME) == 0 || strcmp(program, ART_DAEMON_NAME) == 0;
}
#define CMD_ZYGOTE_INJECTED ZYGOTE64_INJECTED
#define CMD_DAEMON_SET_INFO DAEMON64_SET_INFO
#define CMD_DAEMON_SET_ERROR_INFO DAEMON64_SET_ERROR_INFO

/* INFO: HyperOS's app spawner, the third process (besides the two zygotes)
         that forks application processes. Both ABI monitors match it, each
         injecting its own bitness into its own bitness spawner.

         What identifies it - the file name, and the image behind it - lives in
         zn_spawner.h and is asked for by monitor_program_is_spawner() below. */
static bool update_status(const char *message);

static const char *monitor_stop_reason = NULL;

struct environment_information {
  char *root_impl;
  struct daemon_module *modules;
  uint32_t modules_len;
  /* INFO: How many of those are Zygisk Next modules. The listing asks whether
             a plain module has a Next twin, and that question is decided by a
             scan of the whole list - but when not one module is a Next module
             the answer is no without looking, which is the usual machine. */
  uint32_t zn_len;
};

static struct environment_information environment_information;

/* INFO: Releases every module of the environment. Safe on a zeroed or partially
         filled state: the array is kept calloc'ed, so a slot that was never
         filled reads as an empty record. */
static void free_environment_information(void) {
  if (environment_information.modules != NULL) {
    for (uint32_t i = 0; i < environment_information.modules_len; i++) {
      struct daemon_module *module = &environment_information.modules[i];

      free(module->name);

      if (module->targets != NULL) {
        for (uint32_t t = 0; t < module->targets_len; t++) free(module->targets[t]);

        free(module->targets);
      }
    }
  }

  free(environment_information.modules);
  environment_information.modules = NULL;
}

static enum ptracer_tracing_state tracing_state = TRACING;

/* INFO: The crash-loop guard's memory: how many zygote restarts have been seen
         back to back, and when the one before the current call was. Only
         should_stop_inject() below reads them; the injection report resets the
         count, because a zygote that ran far enough to report back was
         injected, and the restarts counted before it were therefore not a
         loop. Declared up here rather than beside that guard because the
         report is handled above it. */
static struct timespec last_zygote = {
  .tv_sec = 0,
  .tv_nsec = 0
};

static int count_zygote = 0;

struct rezygiskd_status {
  bool supported;
  bool zygote_injected;
  bool daemon_running;

  /* INFO: Whether this monitor has ever recognised the HyperOS spawner.
            Latched, because the question the card answers is "did it ever
            happen", and because nothing downstream of the Zygisk Next path
            can happen until it does. */
  bool spawner_seen;

  pid_t daemon_pid;
  char *daemon_error_info;
};

static struct rezygiskd_status status = {
  .supported = false,
  .zygote_injected = false,
  .daemon_running = false,
  .spawner_seen = false,
  .daemon_pid = -1,
  .daemon_error_info = NULL
};

static int monitor_epoll_fd;
static bool monitor_events_running = true;

/* INFO: The descriptor the card's refresh timer fires on, or -1 while there is
         no timer to fire. */
static int status_refresh_fd = -1;
typedef void (*monitor_event_callback_t)(void);

bool monitor_events_init() {
  /* INFO: Close-on-exec, like every other descriptor this process opens. The
            events are set up before the daemon and the tracer are forked, and
            without the flag the poll fd would be inherited by both of them. */
  monitor_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (monitor_epoll_fd == -1) {
    PLOGE("epoll_create1");

    return false;
  }

  return true;
}

bool monitor_events_register_event(monitor_event_callback_t event_cb, int fd, uint32_t events) {
  struct epoll_event ev = {
    .data.ptr = (void *)event_cb,
    .events = events
  };

  if (epoll_ctl(monitor_epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    PLOGE("epoll_ctl");

    return false;
  }

  return true;
}

void monitor_events_stop() {
  monitor_events_running = false;
}

/* INFO: How often the card is written again while the Zygisk Next path has not
         started working.

         Every other write is an event - a command, an injection - and the
         fastest of those lands in the first moments of a boot, when most of the
         system has not started yet. A reader then sees "no spawner" and cannot
         tell a system that has none from one that had not started it. One slow
         tick while the answer is still no makes the card describe a booted
         system instead, and it stops the moment there is nothing left to wait
         for. */
#define STATUS_REFRESH_SECONDS 60

/* INFO: And how many times it is worth doing.

         The timer exists so that somebody reading the card after a boot sees a
         system that has finished starting rather than one that had barely
         begun, and because the two halves of that card arrive at different
         times: the monitor knows at once whether it has recognised the spawner,
         while the daemon's half - which plan was built for which process - only
         exists once a loader has asked it, which is later. The card is written
         on events, and the last event of a boot can land between the two.

         So it ticks a fixed number of times and then stops. It used to stop
         early, as soon as the spawner had been recognised, which is exactly the
         wrong moment: that is the event that writes a card whose daemon half is
         still empty, and stopping there left it empty for the rest of the
         session.

         Half an hour rather than ten minutes, because the spawner this waits
         for does not come up on a schedule: on the device this was written for
         it is there when applications are being started and not before, so a
         card read twenty minutes into a boot had reported its absence for the
         rest of the session. Past the bound the monitor goes back to writing
         the card on events alone, which is what it did before: a device whose
         spawner is genuinely absent would otherwise rewrite its module property
         file every minute for as long as it is running, on behalf of a question
         nobody is asking any more. */
#define STATUS_REFRESH_TICKS 30

static size_t status_refresh_ticks = 0;

static void status_refresh_callback() {
  uint64_t expirations = 0;

  /* INFO: Read to disarm it. A timerfd nobody reads stays readable, and the
            loop this is called from would spin on it. */
  while (read(status_refresh_fd, &expirations, sizeof(expirations)) == -1 && errno == EINTR) {
  }

  (void)update_status(NULL);

  status_refresh_ticks++;

  if (status_refresh_ticks < STATUS_REFRESH_TICKS) return;

  const struct itimerspec stop = { 0 };

  if (timerfd_settime(status_refresh_fd, 0, &stop, NULL) == -1) PLOGE("timerfd_settime");
}

static bool status_refresh_init() {
  status_refresh_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (status_refresh_fd == -1) {
    PLOGE("timerfd_create");

    return false;
  }

  const struct itimerspec every = {
    .it_interval = {
      .tv_sec = STATUS_REFRESH_SECONDS
    },
    .it_value = {
      .tv_sec = STATUS_REFRESH_SECONDS
    }
  };

  if (timerfd_settime(status_refresh_fd, 0, &every, NULL) == -1) {
    PLOGE("timerfd_settime");

    return false;
  }

  return monitor_events_register_event(status_refresh_callback, status_refresh_fd, EPOLLIN);
}

void monitor_events_loop() {
  struct epoll_event events[3];
  while (monitor_events_running) {
    int nfds = epoll_wait(monitor_epoll_fd, events, 3, -1);
    if (nfds == -1 && errno != EINTR) {
      PLOGE("epoll_wait");

      monitor_events_running = false;

      break;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].events & (EPOLLERR | EPOLLHUP)) {
        LOGE("Failed event (mask %u)", events[i].events);

        monitor_events_running = false;

        break;
      }

      ((monitor_event_callback_t)events[i].data.ptr)();

      if (!monitor_events_running) break;
    }
  }

  if (monitor_epoll_fd >= 0) close(monitor_epoll_fd);
  monitor_epoll_fd = -1;
}

static int monitor_sock_fd;

/* INFO: The monitor's own socket address, which the listener and a one-shot
         control sender both have to build. Only the path not fitting can fail,
         and each caller turns that into its own error, so the length it returns
         is all that has to travel back: the socklen to hand bind(2)/sendto(2),
         or -1. */
static int controller_addr(struct sockaddr_un *addr) {
  memset(addr, 0, sizeof(*addr));

  addr->sun_family = AF_UNIX;

  int path_len = snprintf(addr->sun_path, sizeof(addr->sun_path), "%s", ZYGISK_CONTROLLER_SOCKET);
  if (path_len < 0 || (size_t)path_len >= sizeof(addr->sun_path)) return -1;

  return (int)(sizeof(sa_family_t) + (size_t)path_len);
}

bool rezygiskd_listener_init() {
  monitor_sock_fd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (monitor_sock_fd == -1) {
    PLOGE("socket create");

    return false;
  }

  struct sockaddr_un addr = { 0 };

  int socklen = controller_addr(&addr);
  if (socklen == -1) {
    LOGE("The monitor socket path does not fit into sockaddr_un");

    close(monitor_sock_fd);
    monitor_sock_fd = -1;

    return false;
  }

  if (bind(monitor_sock_fd, (struct sockaddr *)&addr, (socklen_t)socklen) == -1) {
    PLOGE("bind socket");

    /* INFO: Closed here as on the path above that also gives up, so the fd does
              not outlive the function that decided it is useless. */
    close(monitor_sock_fd);
    monitor_sock_fd = -1;

    return false;
  }

  return true;
}

/* INFO: Upper bound for one length-prefixed string the daemon sends. Every one
         of them is a name or a message — a module id, a target, the root
         solution, an error text — so this ceiling is generous by orders of
         magnitude while still keeping a corrupted length from being trusted. */
#define MONITOR_STRING_MAX (64u * 1024u)

/* INFO: Reads one length-prefixed string off the daemon socket, or NULL.

          The length is validated before use: a uint32_t of 0xffffffff wraps to
          zero in `length + 1`, so the allocation would hand back a minimal block
          that read_loop then fills with four gigabytes of datagram. On NULL the
          caller abandons the datagram - the stream is already out of step with
          the daemon, so dispatching on what follows would act on garbage. */
static char *read_socket_string(const char *what) {
  uint32_t length = 0;

  if (read_uint32_t(monitor_sock_fd, &length) != sizeof(length)) {
    LOGE("read VexZygiskd%s %s len", MONITOR_ABI, what);

    return NULL;
  }

  if (length > MONITOR_STRING_MAX) {
    LOGE("VexZygiskd%s %s length %u is out of range", MONITOR_ABI, what, length);

    return NULL;
  }

  char *value = malloc((size_t)length + 1);
  if (value == NULL) {
    PLOGE("malloc VexZygiskd%s %s", MONITOR_ABI, what);

    return NULL;
  }

  if (read_loop(monitor_sock_fd, value, length) != (ssize_t)length) {
    LOGE("read VexZygiskd%s %s", MONITOR_ABI, what);

    free(value);

    return NULL;
  }

  value[length] = '\0';

  return value;
}

/* INFO: The module list the daemon sends, one entry at a time: the name, a
         type byte, and for a Zygisk Next module a companion flag and the
         targets it was registered for.

         Every slot is allocated before anything is read into it, so the cleanup
         path can walk the full lists - which is what the label at the end is
         for, and why the failure paths jump to it rather than unwinding by
         hand. A read that fails partway leaves the lists empty rather than half
         filled: the status line says so instead of naming modules that were
         never delivered. */
static void read_daemon_modules(void) {
  /* INFO: Read into a local first: the old list is freed through the length it
            was allocated with, so the stored length must not be overwritten
            before that. */
  uint32_t modules_len;
  if (read_uint32_t(monitor_sock_fd, &modules_len) != sizeof(modules_len)) {
    LOGE("read VexZygiskd%s modules len", MONITOR_ABI);

    free(environment_information.root_impl);
    environment_information.root_impl = NULL;

    return;
  }

  free_environment_information();

  environment_information.modules_len = modules_len;
  environment_information.zn_len = 0;
  environment_information.modules = calloc(modules_len, sizeof(struct daemon_module));

  if (environment_information.modules == NULL) {
    PLOGE("malloc VexZygiskd%s module list", MONITOR_ABI);

    free(environment_information.root_impl);
    environment_information.root_impl = NULL;

    free_environment_information();

    return;
  }

  for (size_t i = 0; i < environment_information.modules_len; i++) {
    struct daemon_module *module = &environment_information.modules[i];

    module->name = read_socket_string("module name");
    if (module->name == NULL) goto set_info_modules_cleanup;

    uint8_t module_type;
    if (read_uint8_t(monitor_sock_fd, &module_type) != sizeof(module_type)) {
      LOGE("read VexZygiskd%s module type", MONITOR_ABI);

      goto set_info_modules_cleanup;
    }

    module->is_zn = module_type == 1;
    if (module->is_zn) environment_information.zn_len++;

    if (module->is_zn) {
      uint8_t companion;
      if (read_uint8_t(monitor_sock_fd, &companion) != sizeof(companion)) {
        LOGE("read VexZygiskd%s module companion", MONITOR_ABI);

        goto set_info_modules_cleanup;
      }
      module->companion = companion == 1;

      if (read_uint32_t(monitor_sock_fd, &module->targets_len) != sizeof(module->targets_len)) {
        LOGE("read VexZygiskd%s module targets len", MONITOR_ABI);

        goto set_info_modules_cleanup;
      }

      if (module->targets_len > 0) {
        module->targets = calloc(module->targets_len, sizeof(char *));
        if (module->targets == NULL) {
          PLOGE("malloc VexZygiskd%s module targets", MONITOR_ABI);

          goto set_info_modules_cleanup;
        }

        for (uint32_t t = 0; t < module->targets_len; t++) {
          module->targets[t] = read_socket_string("module target");
          if (module->targets[t] == NULL) goto set_info_modules_cleanup;
        }
      }
    }

    LOGD("VexZygiskd%s module %zu: %s (%s)", MONITOR_ABI, i, module->name, module->is_zn ? "next" : "zygisk");
  }

  update_status(NULL);

  return;

  /* INFO: Reached from any failed read above. The array was calloc'ed, so
            free_environment_information walks the full list. */
  set_info_modules_cleanup:
    free(environment_information.root_impl);
    environment_information.root_impl = NULL;

    free_environment_information();

    update_status(NULL);

    return;
}


/* INFO: One command from the daemon, dispatched. The caller owns the socket
         and the read loop around it; everything below is about what the
         command means.

         Reads that fail are answered with an early return rather than by
         unwinding the caller: the stream is already out of step with the
         daemon, so acting on what follows would act on garbage. */
static void dispatch_daemon_command(uint8_t cmd) {
  switch (cmd) {
    case START: {
      if (tracing_state == STOPPING) {
        LOGI("Continue tracing init");

        tracing_state = TRACING;
        monitor_stop_reason = NULL;
      } else if (tracing_state == STOPPED) {
        LOGI("Start tracing init");

        /* INFO: Checked here the way claim_init_tracer() checks it. A seize
                  that failed would leave this monitor believing it was tracing
                  init, and every later decision - the fork handling, the
                  status line the manager reads - made on that belief. Staying
                  where it is the honest answer, and the status reports it. */
        if (ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK) == -1) {
          PLOGE("seize init");
        } else {
          tracing_state = TRACING;
          monitor_stop_reason = NULL;
        }
      }

      update_status(NULL);

      break;
    }
    case STOP: {
      if (tracing_state == TRACING) {
        LOGI("Stop tracing requested");

        tracing_state = STOPPING;
        monitor_stop_reason = "stopped with `ctl stop`";

        ptrace(PTRACE_INTERRUPT, 1, 0, 0);
        update_status(NULL);
      }

      break;
    }
    case EXIT: {
      LOGI("Prepare for exit ...");

      tracing_state = EXITING;

      /* INFO: The only thing in this repository that sends this is the module's
                own installer, which stops the monitor so that its rewrite of
                module.prop cannot race the status line, and which does not
                start one again in that session - the manager's own flow is
                "install, then reboot". Nothing is injected from that moment to
                the next boot, so the line the card keeps until then is the last
                thing a user sees, and "user requested" read as "the module is
                broken" for as long as it took to work out that the injection
                had simply stopped at the install. */
      monitor_stop_reason = "an update was installed - reboot to start it";

      update_status(NULL);
      monitor_events_stop();

      break;
    }
    case CMD_ZYGOTE_INJECTED: {
      LOGI("Received Zygote%s injected command", MONITOR_ABI);

      status.zygote_injected = true;

      /* INFO: A zygote that ran far enough to report back was injected, so
                the restarts counted before it were not a crash loop. Only a
                zygote that dies between its exec and this report keeps
                counting, which is what the guard is for.

                WebView's zygote is why this reset exists: it runs as the same
                binary and restarts on its own schedule, and it reports back
                exactly like the main one - so a device that merely used
                WebView often enough was read as a crash loop and had its
                injection shut off on it. */
      count_zygote = 0;

      update_status(NULL);

      break;
    }
    case CMD_DAEMON_SET_INFO: {
      LOGD("Received VexZygiskd%s info", MONITOR_ABI);

      /* INFO: Read into a local first: a failed read then leaves the previous
                value in place instead of dropping it. */
      char *root_impl = read_socket_string("root impl");
      if (root_impl == NULL) break;

      free(environment_information.root_impl);
      environment_information.root_impl = root_impl;

      LOGD("VexZygiskd%s root impl: %s", MONITOR_ABI, environment_information.root_impl);

      read_daemon_modules();

      break;
    }
    case CMD_DAEMON_SET_ERROR_INFO: {
      LOGD("Received VexZygiskd%s error info", MONITOR_ABI);

      /* INFO: Same ordering as the info case above: the old text survives a
                failed read. */
      char *error_info = read_socket_string("error info");
      if (error_info == NULL) break;

      free(status.daemon_error_info);
      status.daemon_error_info = error_info;

      LOGD("VexZygiskd%s error info: %s", MONITOR_ABI, status.daemon_error_info);

      update_status(NULL);

      break;
    }
  }
}

void rezygiskd_listener_callback() {
  while (1) {
    uint8_t cmd = 0;
    ssize_t nread = TEMP_FAILURE_RETRY(read(monitor_sock_fd, &cmd, sizeof(cmd)));
    if (nread == -1) {
      if (errno == EINTR || errno == EWOULDBLOCK) break;

      /* INFO: Any other error is permanent for this socket - continuing
                would spin the monitor at 100% CPU on the same failure. The
                next datagram the daemon sends re-arms the edge event. */
      PLOGE("read socket");

      break;
    }

    /* INFO: A zero-length datagram carries no command; skip it and keep
              draining instead of dispatching on stale state. */
    if (nread == 0) continue;

    dispatch_daemon_command(cmd);
  }
}

void rezygiskd_listener_stop() {
  if (monitor_sock_fd >= 0) close(monitor_sock_fd);
  monitor_sock_fd = -1;
}

#define MAX_RETRY_COUNT 5

/* INFO: Left behind by the module's post-fs-data.sh when it finds this monitor
         already running, which only happens when the boot stages have just been
         replayed around a session that stayed up.

         That mark is the one thing that tells a soft reboot apart from a crash
         on this side: both are a zygote that went away and came back. Counting
         a soft reboot towards the crash-loop stop is what shuts injection off
         on the third one in a row, and a single reboot costs more than one
         count - the classic zygote binary is also what the WebView zygote runs
         as, and the reboot restarts both.

         Only the classic binary counts. The ART daemon execs on its own
         schedule for its own reasons, and counting those would shut injection
         off the first time it did so a few times in a row. */
static bool counts_as_zygote_restart(const char *program) {
  return strcmp(program, APP_PROCESS_NAME) == 0;
}

#define SOFT_REBOOT_MARKER ZYGISK_TMP_PATH "/soft-reboot"

static bool should_stop_inject() {
  struct timespec now = {};
  clock_gettime(CLOCK_MONOTONIC, &now);

  /* INFO: Consumed as it is read, so one replayed stage restarts the count
            once. Done before the count is touched: this exec belongs to the
            reboot, and must not also be read as the first restart of a new
            crash loop. */
  if (unlink(SOFT_REBOOT_MARKER) == 0) {
    LOGI("The boot stages were replayed around this session, restarting the zygote count");

    count_zygote = 0;
    last_zygote = now;

    return false;
  }

  if (now.tv_sec - last_zygote.tv_sec < 30)
    count_zygote++;
  else
    count_zygote = 0;

  last_zygote = now;

  return count_zygote >= MAX_RETRY_COUNT;
}

/* INFO: How long a freshly forked daemon is given to bind its socket before the
         socket's absence is read as "unreachable". Only exists so the zygote
         and the spawner, which exec within milliseconds of each other on a
         normal boot, cannot have the daemon that was just forked for them
         mistaken for a stale one and killed. */
#define DAEMON_SETTLE_SECONDS 5

/* INFO: How long the spawner waits for a daemon this monitor could not fork,
         before it is injected without one. The loader on the other side of that
         injection waits seconds for the same daemon, so a spawner injected here
         is not a spawner lost - which is the whole point: the alternative was to
         skip it, and a skipped spawner means no HyperOS runtime and no Zygisk
         Next module in that boot. */
#define SPAWNER_DAEMON_ATTEMPTS 4
#define SPAWNER_DAEMON_RETRY_US 250000

/* INFO: When the current daemon was forked, on the monotonic clock. */
static struct timespec daemon_forked_at = {};

/* INFO: A daemon is reachable through its socket, not through its pid: one that
         is still alive but whose socket file has been removed cannot be
         connected to at all, and answering "already running" for it disables
         every module while the process sits there looking healthy.

         That is not hypothetical. A soft reboot replays the boot stages, and
         the module's post-fs-data.sh clears the directory holding these sockets
         while a monitor and daemon from the previous session are still running.
         The pid alone left that session permanently unreachable.

         Only an outright missing file counts as "gone". Any other failure -
         EACCES if the policy denies the check itself, ELOOP, a transient
         ENOMEM - is answered as present on purpose, because reading it as
         missing would kill a daemon that may be perfectly reachable, once per
         process start, and the replacement would hit the same wall. */
static bool daemon_socket_present() {
  if (access(ZYGISK_CP_SOCKET, F_OK) == 0) return true;

  return errno != ENOENT;
}

static bool ensure_daemon_created() {
  pid_t stale_pid = -1;

  if (status.daemon_pid != -1) {
    struct timespec now = {};
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (now.tv_sec - daemon_forked_at.tv_sec < DAEMON_SETTLE_SECONDS || daemon_socket_present()) {
      LOGD("VexZygiskd%s already running", MONITOR_ABI);

      return status.daemon_running;
    }

    LOGW("VexZygiskd%s is alive but %s is gone, replacing it", MONITOR_ABI, ZYGISK_CP_SOCKET);

    /* INFO: Recorded rather than killed on the spot. Killing here and forking
              afterwards would let a failed fork leave nothing behind at all,
              turning a transient failure - ENOMEM on a loaded device - into the
              permanent "not running" answer below. The old daemon keeps its
              socket until the replacement has taken the path over. */
    stale_pid = status.daemon_pid;

    status.daemon_pid = -1;
    status.daemon_running = false;
  }

  pid_t pid = fork();
  if (pid < 0) {
    PLOGE("create VexZygiskd%s", MONITOR_ABI);

    /* INFO: Put the daemon that was about to be replaced back as the current
              one. It cannot be connected to, but neither can nothing, and the
              next attempt is still free to replace it. */
    if (stale_pid != -1) {
      status.daemon_pid = stale_pid;
      status.daemon_running = true;
    }

    return false;
  }

  if (pid == 0) {
    char daemon_name[] = "./bin/zygiskd" MONITOR_ABI;

    execl(daemon_name, daemon_name, NULL);

    PLOGE("exec VexZygiskd%s failed", MONITOR_ABI);

    exit(1);
  }

  if (stale_pid != -1) {
    /* INFO: The stale daemon is killed rather than abandoned: it holds a socket
              nobody can reach any more, and leaving it behind would leak one
              daemon per replacement. Its own exit is then reaped by the generic
              child handling, which no longer matches it against the pid below,
              and answers it as what it is - a process that already exited. */
    kill(stale_pid, SIGKILL);
  }

  /* INFO: A daemon that has just come up answers whatever the last one said on
            its way out. The text is deliberately not cleared where it is set -
            the first failure explains the most - so it is cleared here, at the
            point it stops being true, instead of being reported for the rest of
            the session. */
  if (status.daemon_error_info) {
    free(status.daemon_error_info);
    status.daemon_error_info = NULL;
  }

  status.supported = true;
  status.daemon_pid = pid;
  status.daemon_running = true;

  clock_gettime(CLOCK_MONOTONIC, &daemon_forked_at);

  return true;
}

static int sigchld_signal_fd;
static struct signalfd_siginfo sigchld_fdsi;
static int sigchld_status;

static pid_t *sigchld_process;
static size_t sigchld_process_count = 0;
static size_t sigchld_process_capacity = 0;
/* INFO: Every slot below this one is known to be taken, so the search for a
         free slot starts here instead of at the beginning. The array is walked
         once per fork and holds every process under trace, so starting over
         each time made a burst cost a scan of everything recorded so far. */
static size_t sigchld_process_free = 0;

/* INFO: Who holds init right now, or 0 when nobody does. Read out of
         /proc/1/status instead of inferred, because it answers the only
         question a failed seizure leaves open. */
static pid_t init_tracer_pid() {
  FILE *status = fopen("/proc/1/status", "re");
  if (status == NULL) return 0;

  char line[256];
  pid_t tracer = 0;

  while (fgets(line, sizeof(line), status) != NULL) {
    if (sscanf(line, "TracerPid: %d", &tracer) == 1) break;
  }

  fclose(status);

  return tracer;
}

/* INFO: Whether the process tracing init is one of ours. A second monitor
         losing the race is a normal outcome of a soft reboot - the boot stages
         replay and two of them can look at the same untraced init within
         milliseconds - and it is worth saying nothing about. A seizure held by
         anything else is the conflict the status line below exists to report.
         The two are only told apart by looking at who is holding it. */
static bool init_traced_by_monitor() {
  pid_t tracer = init_tracer_pid();
  if (tracer <= 0) return false;

  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/comm", tracer);

  FILE *comm = fopen(path, "re");
  if (comm == NULL) return false;

  char name[64] = { 0 };
  /* INFO: The comm is capped at fifteen characters, which both monitor names
            fit exactly; the prefix leaves the ABI out of it. */
  bool matched = fgets(name, sizeof(name), comm) != NULL &&
                 strncmp(name, "zygisk-ptrace", sizeof("zygisk-ptrace") - 1) == 0;

  fclose(comm);

  return matched;
}

static bool claim_init_tracer() {
  if (ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK) == -1) {
    /* INFO: In cases where, for example, 2 VexZygisks were executed, the second
               process won't be able to seize init due to limitations of ptrace.
               In this case, we should just exit the second process to avoid
               conflicts. */
    if (errno == EPERM) {
      if (init_traced_by_monitor()) {
        /* INFO: Another monitor of ours holds init. Nothing is wrong, this
                  process simply has nothing to do, and reporting it as a
                  conflict would put a failure into the manager's status for a
                  session that is working. */
        LOGD("A VexZygisk monitor is already tracing init, leaving it to that one");
      } else {
        LOGW("Another process is already tracing init");

        update_status("❌ Multiple Zygisks functioning");
      }
    } else {
      PLOGE("failed to seize init");
    }

    return false;
  }

  return true;
}

bool sigchld_listener_init() {
  sigchld_process = NULL;
  sigchld_process_count = 0;
  sigchld_process_capacity = 0;

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    PLOGE("set sigprocmask");

    return false;
  }

  sigchld_signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sigchld_signal_fd == -1) {
    PLOGE("create signalfd");

    return false;
  }

  return true;
}

/* INFO: Whether the process that just exec'd is the spawner.

         Two answers, and which one is asked depends on what the executable is:

           - its file name, when that is the spawner's. Matching the name rather
             than one fixed path is deliberate: HyperOS has shipped the binary
             from more than one directory across releases, so whichever one the
             running build uses has to be followed.
           - the image mapped at offset zero, when the executable is
             app_process64 - the name a zygote and (on the builds this exists
             for) the spawner both read back as. A zygote has no such mapping; a
             spawner whose runtime image is mapped into an app_process binary
             does. It is the same question the injector asks from inside the
             process, answered here from outside through the target's own maps,
             which is all this side has.

         Getting this wrong is not cosmetic, and it is why the name alone is not
         enough: a spawner taken for a zygote has its execs counted as zygote
         restarts, which stops injection for the rest of the boot, and a second
         exec tells the daemon to drop every Zygisk Next companion - the loader
         on the other side of that injection is where the applications already
         forked from the spawner are talking to.

         The maps are read once per ambiguous exec, not per application: only an
         exec of app_process64 reaches the scan, and an application is forked,
         not exec'd. */
bool monitor_program_is_spawner(pid_t pid, const char *program) {
  if (zn_spawner_map_is_spawner(program)) return true;

  /* INFO: Only a runtime host is ambiguous: anything else that is not the
            spawner by name is not the spawner. */
  if (!is_runtime_host(program)) return false;

  char pid_str[32];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);

  struct maps_info *maps = parse_maps(pid_str);
  if (maps == NULL) return false;

  bool found = false;

  for (size_t i = 0; i < maps->length; i++) {
    const struct map_entry *map = &maps->maps[i];

    /* INFO: The same four conditions the injector's own scan applies to a
              mapping before it will call it the runtime: at the start of the
              image, backed by a file, and readable - a PROT_NONE mapping is in
              the listing too. What it cannot do from here is read the header
              behind it, so the name is the whole answer at this distance. */
    if (map->offset != 0 || map->dev == 0 || map->inode == 0 || map->path == NULL) continue;
    if ((map->perms & PROT_READ) == 0) continue;
    if (!zn_spawner_map_is_spawner(map->path)) continue;

    found = true;

    break;
  }

  free_maps(maps);

  return found;
}

/* INFO: Which executable this monitor owns and how the tracer has to be told
         about it. False for anything left to another monitor. The tracer and
         the spawner flag describe the fork path's hand-off only, so a caller
         that just needs the ownership answer - the respawn below - passes NULL
         for both instead of keeping a second copy of the table. */
static bool match_target(pid_t pid, const char *program, const char **tracer, bool *is_spawner) {
  bool matched_spawner = monitor_program_is_spawner(pid, program);
  if (!is_runtime_host(program) && !matched_spawner) return false;

  if (tracer != NULL) *tracer = "./bin/zygisk-ptrace" MONITOR_ABI;
  if (is_spawner != NULL) *is_spawner = matched_spawner;

  return true;
}

/* INFO: The hand-off leaves the target stopped and untraced. Detaching with
         SIGSTOP is what lets a fresh tracer seize a process that is already
         past its exec. */
static void launch_tracer(pid_t pid, const char *tracer, bool is_spawner) {
  LOGD("Detaching %d", pid);
  ptrace(PTRACE_DETACH, pid, 0, SIGSTOP);

  int p = fork_dont_care();

  if (p == 0) {
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    /* INFO: Only a later zygote exec restarts the companions: the first one
              has none yet, and the spawner is not a zygote restart at all -
              telling the daemon otherwise makes it drop every companion and
              leaves the apps it already forked talking to nothing. */
    bool restart = count_zygote > 1 && !is_spawner;

    LOGI("exec tracer command: %s trace %s%s", tracer, pid_str, restart ? " --restart" : "");

    const char *tracer_name = position_after(tracer, '/');

    char *exec_argv[6];
    int exec_argc = 0;
    exec_argv[exec_argc++] = (char *)tracer_name;
    exec_argv[exec_argc++] = "trace";
    exec_argv[exec_argc++] = pid_str;
    if (restart) exec_argv[exec_argc++] = "--restart";
    exec_argv[exec_argc] = NULL;

    execv(tracer, exec_argv);

    PLOGE("exec");

    kill(pid, SIGKILL);

    /* INFO: _exit, not exit: this fork shares the monitor's stdio
              buffers and atexit handlers. */
    _exit(1);
  } else if (p == -1) {
    PLOGE("fork");

    kill(pid, SIGKILL);
  }
}

/* INFO: get_program() is written for a single, known target: it reports a
         readlink failure as an error. A /proc sweep is the opposite case -
         most entries are kernel threads, zombies or otherwise unreadable, and
         none of that is worth a line - so the bulk scan uses this silent
         variant instead. The (deleted) suffix is stripped by the shared
         helper, so a program the kernel annotated still matches its path. */
static bool program_matches(int pid, char *buf, size_t size) {
  return read_exe_path(pid, buf, size) > 0;
}

/* INFO: The parent of a pid, or 0 when it cannot be determined. Field four of
         /proc/<pid>/stat is the ppid, but the second field is the command name
         in parentheses and may itself contain spaces and parentheses, so the
         fields are counted from the last ')' rather than from the start of the
         line. */
pid_t monitor_parent_of(int pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/stat", pid);

  /* INFO: open/read rather than stdio on purpose. This is called once for
            every entry under /proc by the scan that looks for a target which a
            normal boot does not have, so it is called to read one bounded line
            a few hundred times and find nothing. fopen, fgets and fclose
            allocate and release a FILE and its buffer on each of those calls;
            the line wanted here is at the front of the file either way, and a
            short read still leaves the closing paren in place or returns 0. */
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd == -1) return 0;

  char line[512];
  ssize_t got = TEMP_FAILURE_RETRY(read(fd, line, sizeof(line) - 1));

  close(fd);

  if (got <= 0) return 0;

  line[got] = '\0';

  char *rparen = strrchr(line, ')');
  if (rparen == NULL) return 0;

  int ppid = 0;

  /* INFO: After the ')' come the state, then the ppid. */
  if (sscanf(rparen + 1, " %*c %d", &ppid) != 1) return 0;

  return (pid_t)ppid;
}

/* INFO: A TRACEFORK monitor sees only the forks made after init was seized, so
         anything already running when this monitor starts is invisible to that
         path. That is the whole of a late-load session - KernelSU loaded from
         an LKM once the boot stages have passed - and also the case for a
         monitor that had to be restarted.

         Taking those processes over in place does not work. Every injection
         entry point waits on a step of the target's own start-up that a process
         which finished starting minutes ago never takes again: the tracer on
         the linker resolving app_process's __libc_init slot, the injected GOT
         break on the call through that slot. A tracer handed such a process
         ends up stepping a live target instead of injecting it, and every
         Zygisk module stays dead.

         The one event that does work is the fresh fork+exec the fork path
         already handles, so a target that predates this monitor is respawned
         rather than taken over. init owns both the zygote and the HyperOS
         spawner as services and forks them itself, so killing one makes init
         start a fresh process that this monitor catches exactly the way it
         catches them on a normal boot. The zygote is the framework's parent, so
         its restart also replays the boot stages and re-forks system_server -
         the one-time bootstrap a late-load user otherwise triggers by hand with
         the root manager's "soft restart", and what makes a framework that is
         already up agree to be injected at all.

         On a normal boot this finds nothing, because the monitor starts well
         before init ever execs either target; the scan only ever matches in a
         late-load session or after a monitor restart.

         A target is identified by three things together - its executable, its
         parent being init, and being the lowest-pid match - because none of
         them is enough on its own. See the scan below. */
static void respawn_stale_targets(void) {
  DIR *proc = opendir("/proc");
  if (proc == NULL) {
    PLOGE("opendir /proc");

    return;
  }

  /* INFO: The whole directory is read before anything is killed, and each
           target is then killed at most once - the lowest pid that matched.

           Two reasons it cannot be a kill-as-you-go scan. The executable alone
           does not identify a target: every app process is a fork of the
           zygote and reads back as app_process64, and there is more than one
           init service using that executable (the secondary zygote uses the
           32-bit one, but a WebView zygote does not). readdir returns entries
           in directory order, so whichever one happens to come first would be
           the one killed - possibly a user app, while the real zygote is left
           alone and injection silently never happens. Restricting to init's
           children removes the app processes, and taking the lowest pid picks
           the zygote over any later, on-demand service. The zygote is init's
           first Java process and so carries the lowest pid of any of them.

           Killing one target also cannot disturb the other: init can bring a
           fresh one up while this scan is still reading /proc, and killing that
           one too would turn the respawn into a loop. */
  pid_t stale_zygote = 0;
  pid_t stale_spawner = 0;

  struct dirent *entry;
  while ((entry = readdir(proc)) != NULL) {
    if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

    char *endptr = NULL;
    long pid_value = strtol(entry->d_name, &endptr, 10);
    if (endptr == entry->d_name || *endptr != '\0' || pid_value <= 1) continue;

    /* INFO: The parent is asked first, because it is the cheap question and the
              one that excludes the most: the zygote and the spawner are init's
              own services, so both are direct children of pid 1 - which no
              application ever is - and the answer costs one read of
              /proc/<pid>/stat.

              Deciding by executable first is what made this scan expensive on
              the device it exists for: every application runs app_process64,
              so every one of them was handed to match_target(), which reads
              that process's whole map table to rule out a HyperOS spawner
              image. A late load runs this with a hundred applications up; the
              maps of all of them were read to answer a question the parent id
              had already answered. */
    if (monitor_parent_of((int)pid_value) != 1) continue;

    char program[PATH_MAX];
    if (!program_matches((int)pid_value, program, sizeof(program))) continue;

    bool is_spawner = false;
    if (!match_target((pid_t)pid_value, program, NULL, &is_spawner)) continue;

    pid_t *stale = is_spawner ? &stale_spawner : &stale_zygote;
    if (*stale == 0 || (pid_t)pid_value < *stale) *stale = (pid_t)pid_value;
  }

  closedir(proc);

  pid_t targets[2] = { stale_zygote, stale_spawner };

  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
    if (targets[i] == 0) continue;

    LOGI("pid %d predates this monitor; killing it so init hands us a fresh one to inject", targets[i]);

    kill(targets[i], SIGKILL);
  }
}

/* INFO: A child this monitor traces rather than one it spawned: the init it
         seized. Two things matter here - the forks init makes, which is how the
         monitor learns about the processes worth injecting, and the stop signals
         it receives, which have to be passed through with the signal intact, or
         suppressed when they are the job-control ones the zygote has no handler
         for.

         Every return in here means this child is done with, which is what the
         loop this was lifted out of did with a continue. */
static void handle_init_event(int pid, long sigchld_status) {
  if (STOPPED_WITH(sigchld_status, SIGTRAP, PTRACE_EVENT_FORK)) {
    /* INFO: Initialised and checked: the call fills this in only on
              success, and the line below would otherwise print whatever
              the stack held. It is a debug line, so nothing acts on the
              value - but a pid out of nowhere costs a search. */
    long child_pid = 0;
    if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid) == -1)
      PLOGE("read the pid of the process %d forked", pid);

    LOGV("Forked %ld", child_pid);
  } else if (STOPPED_WITH(sigchld_status, SIGTRAP, PTRACE_EVENT_STOP) && tracing_state == STOPPING) {
    if (ptrace(PTRACE_DETACH, 1, 0, 0) == -1) PLOGE("failed to detach init");

    tracing_state = STOPPED;

    LOGI("Stopped tracing init");

    return;
  }

  if (WIFSTOPPED(sigchld_status)) {
    if (WPTEVENT(sigchld_status) == 0) {
      if (WSTOPSIG(sigchld_status) != SIGSTOP && WSTOPSIG(sigchld_status) != SIGTSTP && WSTOPSIG(sigchld_status) != SIGTTIN && WSTOPSIG(sigchld_status) != SIGTTOU) {
        LOGW("Injecting signal sent to init: %s %d", sigabbrev_np(WSTOPSIG(sigchld_status)), WSTOPSIG(sigchld_status));

        ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(sigchld_status));

        return;
      } else {
        LOGW("Suppressing stop signal sent to init: %s %d", sigabbrev_np(WSTOPSIG(sigchld_status)), WSTOPSIG(sigchld_status));
      }
    }

    ptrace(PTRACE_CONT, pid, 0, 0);
  }

  return;
}

/* INFO: The daemon this monitor forked, reporting its own exit.

         False means the pass should be abandoned. That is the one case where
         something went wrong on this side rather than on the child's: the text
         explaining the exit could not be kept, and walking the rest of the list
         would go on reporting an exit nothing recorded. */
static bool handle_daemon_exit(int pid, long sigchld_status) {
  char status_str[64];
  parse_status(sigchld_status, status_str, sizeof(status_str));

  LOGW("daemon%s pid %d exited: %s", MONITOR_ABI, pid, status_str);
  status.daemon_running = false;

  /* INFO: Resetting the pid lets ensure_daemon_created fork a fresh
            daemon at the next zygote start instead of reporting "already
            running" forever; without it a single daemon crash disabled
            injection until reboot. */
  status.daemon_pid = -1;

  if (!status.daemon_error_info) {
    status.daemon_error_info = strdup(status_str);
    if (!status.daemon_error_info) {
      LOGE("malloc daemon%s error info failed", MONITOR_ABI);

      return false;
    }
  }

  return true;
}


/* INFO: Whether this pid is one of the children the monitor has taken over.
         The table only ever holds live processes, so a pid found here has a
         slot to give back when its stop arrives. */
static bool child_is_tracked(pid_t pid) {
  for (size_t i = 0; i < sigchld_process_count; i++) {
    if (sigchld_process[i] == pid) return true;
  }

  return false;
}

/* INFO: Takes over a child the monitor has not seen before, so that the exec
         that follows is handled here rather than by whichever monitor owns the
         process next.

         The slot comes from the water mark when there is one, which is the
         common case - a launch is a burst of forks followed by a burst of
         exits - and the table grows in powers of two when there is not.
         Growing by a single element made every process of every launch pay for
         a realloc and a copy of the whole array, where the water mark keeps the
         array at the high-water mark of one burst rather than of the session.

         A child that cannot be recorded is detached and let run: it is stopped
         and under this monitor's control, and the slot it would have gone into
         is exactly what just failed to allocate - so nothing later in the loop
         would pick it up, and continuing without it leaves it stopped for good.
         Detaching loses track of one process, which the failed allocation has
         already cost, but the process survives and the fork it was making
         completes. */
static void track_child(pid_t pid) {
  size_t slot = sigchld_process_count;

  for (size_t i = sigchld_process_free; i < sigchld_process_count; i++) {
    if (sigchld_process[i] != 0) continue;

    slot = i;

    break;
  }

  if (slot == sigchld_process_count) {
    if (sigchld_process_count == sigchld_process_capacity) {
      size_t capacity = sigchld_process_capacity == 0 ? 64 : sigchld_process_capacity * 2;

      pid_t *grown = (pid_t *)realloc(sigchld_process, sizeof(pid_t) * capacity);
      if (grown == NULL) {
        PLOGE("realloc sigchld_process");

        ptrace(PTRACE_DETACH, pid, 0, 0);

        return;
      }

      sigchld_process = grown;
      sigchld_process_capacity = capacity;
    }

    sigchld_process[sigchld_process_count] = pid;
    sigchld_process_count++;
    sigchld_process_free = sigchld_process_count;
  } else {
    sigchld_process[slot] = pid;
    sigchld_process_free = slot + 1;
  }

  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC);
  ptrace(PTRACE_CONT, pid, 0, 0);
}

/* INFO: The exec of a tracked child: read what the process became, decide
         whether this monitor is the one that owns it, and hand it to a tracer
         when it is.

         True means the process has been handed over and was deliberately left
         stopped for its tracer, so the caller must not detach it again. Every
         false means the opposite - this was not the monitor's process to take,
         or the hand-off could not be prepared - and that the process has to be
         let run. */
static bool hand_over_on_exec(pid_t pid) {
  char program[PATH_MAX];
  if (get_program(pid, program, sizeof(program)) == -1) {
    LOGW("failed to get program %d", pid);

    return false;
  }

  LOGV("%d program %s", pid, program);

  if (tracing_state != TRACING) {
    LOGD("Stopped injecting %d because status is not set to tracing", pid);

    return false;
  }

  const char *tracer = NULL;
  bool is_spawner = false;

  if (!match_target(pid, program, &tracer, &is_spawner)) return false;

  if (is_spawner) status.spawner_seen = true;

  /* INFO: The crash-loop counter is about the zygote restarting. The spawner
           has its own lifecycle and execs on its own schedule, so counting
           those execs the same way would trip the crash-loop stop after a burst
           of app launches. */
  if (counts_as_zygote_restart(program) && should_stop_inject()) {
    LOGW("Zygote" MONITOR_ABI " restart too many times, stop injecting");

    tracing_state = STOPPING;
    monitor_stop_reason = "Zygote crashed";
    ptrace(PTRACE_INTERRUPT, 1, 0, 0);

    return false;
  }

  /* INFO: Both targets need the daemon, and the spawner can exec before the
           zygote ever does, so creating it cannot be left to the zygote
           injection. A spawner with no daemon is injected anyway rather than
           skipped: this monitor's job is the zygote, and stopping here would
           take a healthy zygote down with it, while a skipped spawner loses the
           whole boot's runtime. */
  bool daemon_ready = ensure_daemon_created();

  /* INFO: The one way that answers false is a fork that failed - the device was
           out of memory at the instant the spawner exec'd. It is retried for the
           spawner and not for the zygote because nothing comes after the
           spawner: the runtime this injection sets up is what every app of this
           boot registers against, and the next chance to install it is the next
           boot. */
  for (int attempt = 0; !daemon_ready && is_spawner && attempt < SPAWNER_DAEMON_ATTEMPTS; attempt++) {
    usleep(SPAWNER_DAEMON_RETRY_US);

    daemon_ready = ensure_daemon_created();
  }

  if (!daemon_ready) {
    if (!is_spawner) {
      LOGW("VexZygiskd%s not running, stop injecting", MONITOR_ABI);

      tracing_state = STOPPING;
      monitor_stop_reason = "VexZygiskd not running";
      ptrace(PTRACE_INTERRUPT, 1, 0, 0);

      return false;
    }

    /* INFO: The spawner goes in anyway. Skipping it - which is what this used
             to do - loses the whole boot's runtime rather than the one thing the
             skip was protecting: the loader waits for the daemon on its side,
             and the spawner is the target whose window is measured in seconds
             exactly because its daemon may have been forked in the same breath
             as its own exec. The cost of being wrong is that wait; the cost of
             the skip was a boot with no HyperOS runtime and no Zygisk Next
             module in it. */
    LOGW("VexZygiskd%s not running, injecting hyos_spawner %d anyway for its loader to wait out", MONITOR_ABI, pid);
  }

  LOGD("Stopping %d (program: %s, tracer: %s)", pid, program, tracer);

  /* INFO: The stop is taken here, before the tracer exists, and its status is
           a local: it describes this hand-off and not the child that was just
           reaped. Writing it over the loop's own variable is what made a later
           pass read this stop as the one it was handling. */
  kill(pid, SIGSTOP);
  ptrace(PTRACE_CONT, pid, 0, 0);

  int wstatus = 0;
  if (waitpid(pid, &wstatus, __WALL) == -1) {
    PLOGE("waitpid");

    return false;
  }

  if (!STOPPED_WITH(wstatus, SIGSTOP, 0)) {
    LOGE("Failed to stop process %d", pid);

    return false;
  }

  launch_tracer(pid, tracer, is_spawner);

  return true;
}

/* INFO: The stop of a child the monitor already owns.

         The slot goes back and a process that is still stopped is let run, and
         both happen on every path - including the ones that only log a
         problem. The single exception is a process the tracer has taken:
         launch_tracer leaves it stopped for the tracer on purpose, and
         detaching it here would take it back. */
static void handle_tracked_stop(pid_t pid, int wstatus) {
  bool handed_over = false;

  if (STOPPED_WITH(wstatus, SIGTRAP, PTRACE_EVENT_EXEC)) {
    handed_over = hand_over_on_exec(pid);
  } else {
    char status_str[64];
    parse_status(wstatus, status_str, sizeof(status_str));

    LOGW("process %d received unknown sigchld_status %s", pid, status_str);
  }

  for (size_t i = 0; i < sigchld_process_count; i++) {
    if (sigchld_process[i] != pid) continue;

    sigchld_process[i] = 0;
    if (i < sigchld_process_free) sigchld_process_free = i;

    break;
  }

  if (!handed_over && WIFSTOPPED(wstatus)) {
    LOGV("detach process %d", pid);

    ptrace(PTRACE_DETACH, pid, 0, 0);
  }
}

void sigchld_listener_callback() {
  while (1) {
    ssize_t s = read(sigchld_signal_fd, &sigchld_fdsi, sizeof(sigchld_fdsi));
    if (s == -1) {
      if (errno == EAGAIN) break;

      PLOGE("read signalfd");

      continue;
    }

    if (s != sizeof(sigchld_fdsi)) {
      LOGE("read %zu != %zu", s, sizeof(sigchld_fdsi));

      continue;
    }

    if (sigchld_fdsi.ssi_signo != SIGCHLD) {
      LOGE("No sigchld received");

      continue;
    }

    int pid;
    while ((pid = waitpid(-1, &sigchld_status, __WALL | WNOHANG)) != 0) {
      if (pid == -1) {
        /* INFO: EINTR is retried by the loop; ECHILD simply means every child
                  is reaped. Any other error is logged once and drained here,
                  otherwise pid -1 would flow into the handling below forever. */
        if (errno == EINTR) continue;

        if (errno != ECHILD) PLOGE("waitpid");

        break;
      }

      if (pid == 1) {
        handle_init_event(pid, sigchld_status);

        continue;
      }

      if (status.supported && pid == status.daemon_pid) {
        if (!handle_daemon_exit(pid, sigchld_status)) return;

        continue;
      }

      if (child_is_tracked(pid)) {
        handle_tracked_stop(pid, sigchld_status);

        continue;
      }

      /* INFO: A process that has already exited is not "newly attached": there
                is nothing left to set ptrace options on, and a slot taken here
                is never handed back. This is the path a replaced daemon takes -
                the daemon branch above no longer matches it, because the pid it
                was recorded under already names the replacement. Letting it
                fall through would leak that slot and, once the kernel hands the
                pid to somebody else, make an unrelated process look like one
                that is already under trace. */
      if (WIFEXITED(sigchld_status) || WIFSIGNALED(sigchld_status)) continue;

      LOGV("New process %d attached", pid);

      track_child(pid);
    }
  }
}

void sigchld_listener_stop() {
  if (sigchld_signal_fd >= 0) close(sigchld_signal_fd);
  sigchld_signal_fd = -1;

  if (sigchld_process != NULL) free(sigchld_process);
  sigchld_process = NULL;
  sigchld_process_count = 0;
  sigchld_process_capacity = 0;
  sigchld_process_free = 0;
  sigchld_process_free = 0;
}

/* INFO: The card is written by monitor_status.c; this is the one place the
         monitor's state is handed to it.

         The state is read here rather than kept as a copy over there, for the
         reason described at the top of that file. */
static bool update_status(const char *message) {
  const struct monitor_status_view view = {
    .state = tracing_state,
    .stop_reason = monitor_stop_reason,
    .root_impl = environment_information.root_impl,
    .daemon_error = status.daemon_error_info,
    .modules = environment_information.modules,
    .modules_len = environment_information.modules_len,
    .zn_len = environment_information.zn_len,
    .supported = status.supported,
    .zygote_injected = status.zygote_injected,
    .daemon_running = status.daemon_running,
    .spawner_seen = status.spawner_seen
  };

  return monitor_status_update(&view, message);
}

void init_monitor() {
  LOGI("VexZygisk %s", ZKSU_VERSION);

  if (!monitor_status_prepare()) exit(1);

  if (!claim_init_tracer()) exit(1);

  /* INFO: Targets that predate this monitor are not forks of init and so
            never reach the TRACEFORK path; a late-load session is made
            entirely of them, so they are respawned here. Ordered after the
            seize on purpose: the fresh fork init makes in response is what
            the fork path below then catches. */
  respawn_stale_targets();

  if (!monitor_events_init()) exit(1);

  if (!rezygiskd_listener_init()) {
    LOGE("failed to create socket");

    close(monitor_epoll_fd);

    exit(1);
  }

  if (!monitor_events_register_event(rezygiskd_listener_callback, monitor_sock_fd, EPOLLIN | EPOLLET)) {
    rezygiskd_listener_stop();
    close(monitor_epoll_fd);

    exit(1);
  }

  if (!sigchld_listener_init()) {
    LOGE("failed to create signalfd");

    rezygiskd_listener_stop();
    close(monitor_epoll_fd);

    exit(1);
  }

  if (!monitor_events_register_event(sigchld_listener_callback, sigchld_signal_fd, EPOLLIN | EPOLLET)) {
    sigchld_listener_stop();
    rezygiskd_listener_stop();
    close(monitor_epoll_fd);

    exit(1);
  }

  /* INFO: Not fatal on its own: without it the card is only written on events,
            which is what it did before the timer existed. */
  if (!status_refresh_init()) LOGE("failed to start the status refresh timer");

  monitor_events_loop();

  /* INFO: Once it stops the loop, we cannot access the epoll data, so we
             either manually call the stops or save to a structure. */
  rezygiskd_listener_stop();
  sigchld_listener_stop();

  if (status.daemon_error_info) free(status.daemon_error_info);

  if (environment_information.root_impl) free(environment_information.root_impl);
  free_environment_information();

  LOGI("Terminating VexZygisk monitor");
}

int send_control_command(enum rezygiskd_command cmd) {
  int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1) return -1;

  struct sockaddr_un addr = { 0 };

  int socklen = controller_addr(&addr);
  if (socklen == -1) {
    close(sockfd);

    return -1;
  }

  uint8_t cmd_op = cmd;
  ssize_t nsend = sendto(sockfd, (void *)&cmd_op, sizeof(cmd_op), 0, (struct sockaddr *)&addr, (socklen_t)socklen);

  close(sockfd);

  return nsend != sizeof(cmd_op) ? -1 : 0;
}
