#!/system/bin/sh

set -e

# INFO: A monitor surviving from the current session owns this entire directory:
#         it holds the controller socket, and the daemon it forked holds
#         cp64.sock. A soft reboot replays the boot stages but leaves both
#         processes running, so clearing TMP_PATH out from under them does not
#         clean up after a dead session - it leaves a *live* daemon that nothing
#         can reach, because the loader connects to the socket path and not to
#         the process. Every module then stays dead until a real reboot.
#
#         That is why this only ever broke on the second soft reboot: the first
#         one runs while no monitor exists yet, so the wipe below is harmless,
#         and from the second one onwards the monitor from the previous session
#         is still there and has its sockets pulled out from under it.
#
#         So a live session is left completely alone, exactly as late-load.sh
#         already leaves it alone. On a cold boot nothing survives, pidof finds
#         nothing, and the wipe still does its job of clearing the previous
#         session's sockets before a fresh monitor binds them.
if pidof "zygisk-ptrace64" >/dev/null 2>&1; then
  echo "VexZygisk: monitor already running, leaving this session alone"
  exit 0
fi

MODDIR=${0%/*}

cd "$MODDIR"

create_sys_perm() {
  mkdir -p $1
  chmod 555 $1
  chcon u:object_r:system_file:s0 $1
}

export TMP_PATH=/data/adb/rezygisk
rm -rf "$TMP_PATH"

create_sys_perm $TMP_PATH

# INFO: rezygisk.sh in post-fs-data.d resets module.prop from its pristine
#         .bak copy. This explicit call looks redundant with the global
#         script, but it is the only run with a guaranteed ordering: the
#         root solution's own post-fs-data.d stage may execute before the
#         module is mounted (KernelSU 2.x does), where the module directory
#         is not reachable yet. Running it again from here — which always
#         happens after the module tree is mounted — is what makes the reset
#         actually stick on every root. post-mount.d/rezygisk.sh (KernelSU
#         flavour only) covers the same gap from the other side.
#
#         Guarded on purpose: a missing copy — or one that fails on its own,
#         its cp having nothing to copy — only costs the stale status text in
#         module.prop for one boot. Letting that reach `set -e` would abort
#         before the monitor is started and take the whole injection down with
#         it, silently.
if [ -f /data/adb/post-fs-data.d/rezygisk.sh ]; then
  sh /data/adb/post-fs-data.d/rezygisk.sh || true
fi

if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
  "$MODDIR/bin/zygisk-ptrace64" monitor &
fi

exit 0
