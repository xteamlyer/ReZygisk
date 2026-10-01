#!/system/bin/sh

set -e

MODDIR=${0%/*}

cd "$MODDIR"

create_sys_perm() {
  mkdir -p $1
  chmod 555 $1
  chcon u:object_r:system_file:s0 $1
}

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
#
#         Deliberately above the session check below: the reset has nothing to
#         do with the sockets, and skipping it on a soft reboot would leave the
#         stale status text it exists to clear in place for another boot.
if [ -f /data/adb/post-fs-data.d/rezygisk.sh ]; then
  sh /data/adb/post-fs-data.d/rezygisk.sh || true
fi

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
#         Only the two steps a live session would be harmed by are skipped — the
#         wipe and starting a second monitor. On a cold boot nothing survives,
#         pidof finds nothing, and both still run, exactly as late-load.sh
#         already leaves a live session alone on its side.
#
#         Getting here also means the boot stages have just been replayed around
#         a session that stayed up, which is a soft reboot and not a crash. The
#         monitor cannot tell the two apart by itself - a replayed stage and a
#         zygote that died look identical from where it stands - so the mark
#         below is left for it, and it restarts its zygote count on finding it.
#         Without that, a user rebooting three times in a row is counted as a
#         crash loop and injection is shut off.
if pidof "zygisk-ptrace64" >/dev/null 2>&1; then
  echo "VexZygisk: monitor already running, leaving its session alone"

  : > /data/adb/rezygisk/soft-reboot || true

  exit 0
fi

export TMP_PATH=/data/adb/rezygisk
rm -rf "$TMP_PATH"

create_sys_perm $TMP_PATH

if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
  "$MODDIR/bin/zygisk-ptrace64" monitor &
fi

exit 0
