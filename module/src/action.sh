#!/system/bin/sh

# INFO: The module's action button - the manager shows it as "execute" - and
#         the only way back from the two states this module can be found in
#         while it is simply not running:
#
#           - installing or updating the module from the manager stops the
#             monitor on purpose (customize.sh, so that its rewrite of
#             module.prop cannot race the installer) and starts nothing in its
#             place. Nothing is injected from then until the next boot, and the
#             card a reader is left looking at is the one written as the
#             monitor exited;
#           - `zygisk-ptrace64 ctl stop` leaves a monitor alive and idle, which
#             on that same card looks exactly like a module that never loaded.
#
#         One tap covers both. A monitor that is already there is told to start
#         again, which does nothing while it is tracing and resumes it while it
#         is stopped; one that is gone is started here.
#
#         This is only ever run by hand from the manager, never from a stage
#         directory, so unlike post-fs-data.sh and late-load.sh it has no
#         placeholders to fill in and is copied into the archive as it is.

set -e

MODDIR=${0%/*}

if [ ! -x "$MODDIR/bin/zygisk-ptrace64" ]; then
  echo "VexZygisk: no monitor binary in $MODDIR/bin, reinstall the module" >&2

  exit 1
fi

if pidof "zygisk-ptrace64" >/dev/null 2>&1; then
  echo "VexZygisk: a monitor is already running, asking it to trace"

  "$MODDIR/bin/zygisk-ptrace64" ctl start

  exit 0
fi

# INFO: The monitor resolves its daemon as "./bin/zygiskd64", a path relative to
#         its working directory, so the directory has to be set before it is
#         started. A wrong working directory makes that exec fail, which the
#         monitor reports as the daemon not running.
cd "$MODDIR"

echo "VexZygisk: starting the monitor"

"$MODDIR/bin/zygisk-ptrace64" monitor &

exit 0
