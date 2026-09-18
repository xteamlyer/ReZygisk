#!/system/bin/sh

set -e

export TMP_PATH=/data/adb/rezygisk
rm -rf "$TMP_PATH"

rm -f /data/adb/post-fs-data.d/rezygisk.sh

# INFO: APatch has no late-load stage and this flavour never installs one, but
#         a switch from the KernelSU flavour would otherwise leave its copy
#         behind to start a monitor on a root solution that no longer drives
#         it. Same reasoning as the post-mount.d cleanup on install.
rm -f /data/adb/late-load.d/late-load.sh

# INFO: Only removes if dir is empty
rmdir /data/adb/post-fs-data.d
rmdir /data/adb/late-load.d

exit 0
