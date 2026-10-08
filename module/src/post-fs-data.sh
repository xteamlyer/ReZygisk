#!/system/bin/sh

set -e

MODDIR=${0%/*}

cd "$MODDIR"

create_sys_perm() {
  mkdir -p "$1"
  chmod 555 "$1"
  chcon u:object_r:system_file:s0 "$1"
}

export TMP_PATH=/data/adb/rezygisk

# INFO: The boot stages replay on a soft reboot while the session from before
#         it can still be up. When that happens the monitor is alive, and so is
#         the daemon it started with the sockets it carved out of TMP_PATH:
#         wiping that directory would unlink the endpoint every client connects
#         to and leave the running daemon unreachable, and starting a second
#         monitor would put two of them on the same zygote, racing each other.
#         Looking for the monitor first avoids both. This is the same check
#         late-load.sh makes, and for the same reason.
#
#         On a normal boot nothing carries that name yet, so both branches
#         below take the path they always took. A pidof that is missing or
#         fails is read as "not running" on purpose: starting the monitor is
#         the safe side of this decision either way.
if pidof "zygisk-ptrace64" >/dev/null 2>&1; then
  MONITOR_RUNNING=1
else
  MONITOR_RUNNING=0
fi

if [ "$MONITOR_RUNNING" -eq 0 ]; then
  rm -rf "$TMP_PATH"

  # INFO: Guarded because a kernel whose policy does not carry the label would
  #         make chcon return non-zero, and `set -e` would then abort this
  #         script before the monitor is started - the whole injection would go
  #         down over the label of a directory. The rezygisk.sh call below is
  #         guarded for the same reason.
  create_sys_perm "$TMP_PATH" || true
fi

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

if [ "$MONITOR_RUNNING" -eq 0 ] && [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
  "$MODDIR/bin/zygisk-ptrace64" monitor &
fi

exit 0
