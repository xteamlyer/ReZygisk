#!/system/bin/sh

# INFO: VexZygisk late-load stage script. Installed to /data/adb/late-load.d/,
#         which KernelSU runs through init_event::run_stage("late-load") right
#         after `ksud late-load` has injected the kernel module into an already
#         running system (late_load.rs).
#
#         Why this exists: on a normal boot KernelSU is up before post-fs-data,
#         so the module's own post-fs-data.sh starts the monitor there. In a
#         late-load session KernelSU does not exist while that stage runs, so
#         post-fs-data.sh is never executed: nothing starts the monitor, the
#         daemon is never forked, and every Zygisk module stays dead — while the
#         manager still lists registered modules as installed. The stage does
#         not exist under a normal boot (KernelSU reports it as absent and
#         run_stage finds nothing to run), so this file is a no-op off the
#         late-load path.
#
#         A soft reboot keeps the late-loaded KernelSU alive but replays the
#         boot stages, so this is also the entry that brings the monitor back
#         after one. It has to be safe to run repeatedly.

set -e

# INFO: The stage is run as a plain shell script with an inherited working
#         directory, and nothing here may assume it is the module root: the
#         monitor resolves its daemon as "./bin/zygiskd64", a path relative
#         to the current directory, so the module directory has to be entered
#         explicitly before the monitor is started. A wrong cwd makes that exec
#         fail, which the monitor reports as "daemon not running" and reacts to
#         by stopping injection.
MODDIR=/data/adb/modules/rezygisk

if [ ! -d "$MODDIR" ]; then
  echo "VexZygisk: $MODDIR is missing, module tree not mounted yet" >&2
  exit 1
fi

cd "$MODDIR"

if [ ! -x "$MODDIR/bin/zygisk-ptrace64" ]; then
  echo "VexZygisk: no monitor binary in $MODDIR/bin, nothing to start" >&2
  exit 1
fi

# INFO: A monitor surviving from the current session must not be duplicated:
#         the late-load stage replays on every soft reboot, and two monitors
#         would race on the same zygote, each spawning its own daemon.
#
#         The check is on the binary's own name rather than a pidfile, which
#         the monitor does not keep and which every soft reboot would leave
#         stale anyway.
if pidof "zygisk-ptrace64" >/dev/null 2>&1; then
  echo "VexZygisk: monitor already running, leaving it alone"
  exit 0
fi

# INFO: Unlike post-fs-data.sh this does not wipe TMP_PATH. That directory
#         holds the live sockets of the running session, and this stage can run
#         while a session from an earlier soft reboot is still up. Only make
#         sure it exists and carries the label the loader needs.
TMP_PATH=/data/adb/rezygisk
if [ ! -d "$TMP_PATH" ]; then
  mkdir -p "$TMP_PATH"
  chmod 555 "$TMP_PATH"
  chcon u:object_r:system_file:s0 "$TMP_PATH"
fi
export TMP_PATH

# INFO: The monitor binds its controller socket by path, and the kernel refuses
#         a bind on a path that is still occupied, so the endpoint a monitor
#         that died left behind has to go before a new one can come up. Only the
#         monitor's own endpoint is removed: cp64.sock belongs to the daemon,
#         and a daemon from an earlier session may still be serving it. The
#         pidof check above already returned when a monitor is alive, so this
#         can never pull the endpoint out from under a running one.
rm -f "$TMP_PATH/init_monitor"

"$MODDIR/bin/zygisk-ptrace64" monitor &

exit 0
