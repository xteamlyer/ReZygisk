#!/system/bin/sh

set -e

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
