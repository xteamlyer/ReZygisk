#!/system/bin/sh

set -e

# INFO: Stop the running session before taking the directory out from under it,
#         in the same order the installer uses. The monitor holds the controller
#         socket and the daemon it forked holds cp64.sock, so a process whose
#         sockets have been removed cannot be told anything - it would keep
#         tracing init and injecting into every target for as long as the device
#         stays up, with the library it means to inject already gone. The daemon
#         is named explicitly because killing the monitor does not take its
#         child with it.
tracer=${MODDIR:-/data/adb/modules/rezygisk}/bin/zygisk-ptrace64
if [ -x "$tracer" ]; then
  "$tracer" ctl exit >/dev/null 2>&1 || true
fi
killall -9 zygisk-ptrace64 >/dev/null 2>&1 || true
killall -9 zygiskd64 >/dev/null 2>&1 || true

export TMP_PATH=/data/adb/rezygisk
rm -rf "$TMP_PATH"

rm -f /data/adb/post-fs-data.d/rezygisk.sh
rm -f /data/adb/post-mount.d/rezygisk.sh
rm -f /data/adb/late-load.d/late-load.sh

# INFO: Only removes if dir is empty. `set -e` is in force above, so the
#         expected "Directory not empty" has to be swallowed here - otherwise
#         the first non-empty shared directory aborts the script before the
#         lines after it, and before its own exit 0.
rmdir /data/adb/post-fs-data.d 2>/dev/null || true
rmdir /data/adb/post-mount.d 2>/dev/null || true
rmdir /data/adb/late-load.d 2>/dev/null || true

exit 0
