#!/system/bin/sh

set -e

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
elif [ -f "$MODDIR/bin/zygisk-ptrace32" ]; then
  "$MODDIR/bin/zygisk-ptrace32" monitor &
fi

exit 0
