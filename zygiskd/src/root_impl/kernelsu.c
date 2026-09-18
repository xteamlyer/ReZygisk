#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include "../utils.h"
#include "common.h"

#include "kernelsu.h"

/* INFO: 0xDEADBEEF and 0xCAFEBABE exceed INT_MAX, so the constants are written
           as signed ints to keep the syscall arguments well defined. */
#define KSU_INSTALL_MAGIC1 (int)0xDEADBEEF
#define KSU_INSTALL_MAGIC2 (int)0xCAFEBABE

struct ksu_uid_granted_root_cmd {
  uint32_t uid;
  uint8_t granted;
};

struct ksu_uid_should_umount_cmd {
  uint32_t uid;
  uint8_t should_umount;
};

struct ksu_get_manager_uid_cmd {
  uint32_t uid;
};

struct ksu_set_feature_cmd {
  uint32_t feature_id;
  uint64_t value;
};

#define KSU_IOCTL_UID_GRANTED_ROOT _IOC(_IOC_READ|_IOC_WRITE, 'K', 8, 0)
#define KSU_IOCTL_UID_SHOULD_UMOUNT _IOC(_IOC_READ|_IOC_WRITE, 'K', 9, 0)
#define KSU_IOCTL_GET_MANAGER_UID _IOC(_IOC_READ, 'K', 10, 0)
#define KSU_IOCTL_SET_FEATURE _IOC(_IOC_WRITE, 'K', 14, 0)

static int ksu_fd = -1;

/* KSU_INVALID_APPID. Means "no manager crowned yet" as much as "no manager". */
#define KSU_MANAGER_APPID_UNKNOWN (-1)

/* Never cached. The kernel owns this value and moves it in both directions (set
   when the manager is crowned, cleared when it is uninstalled), so a stored copy
   can only go stale - and going stale means naming a uid that is no longer the
   manager while the real one falls through to the denylist branch. One cheap
   ioctl, already made once per request, so caching saves nothing. */
static int ksu_read_manager_appid(void) {
  if (ksu_fd == -1) return KSU_MANAGER_APPID_UNKNOWN;

  struct ksu_get_manager_uid_cmd cmd = { 0 };
  if (ioctl(ksu_fd, KSU_IOCTL_GET_MANAGER_UID, &cmd) == -1) return KSU_MANAGER_APPID_UNKNOWN;

  return (int)cmd.uid;
}

void ksu_get_existence(struct root_impl_state *state) {
  /* INFO: KernelSU v2+ exposes its interface through this magic syscall,
             while older versions relied on prctl. Only the ioctl based
             interface is supported, so anything older is reported missing. */
  syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, (void *)&ksu_fd);
  if (ksu_fd == -1) {
    state->state = Inexistent;

    return;
  }

  if (access("/data/adb/ksud", F_OK) == -1) {
    LOGW("KernelSU (ioctl) detected, but ksud not found.");

    close(ksu_fd);
    ksu_fd = -1;

    state->state = Inexistent;

    return;
  }

  struct ksu_set_feature_cmd cmd = {
    .feature_id = 1, /* INFO: kernel_umount */
    .value = 0
  };

  /* INFO: Tell KernelSU to not umount, and let us handle it */
  if (ioctl(ksu_fd, KSU_IOCTL_SET_FEATURE, &cmd) == -1) {
    LOGW("Failed to ioctl KSU_IOCTL_SET_FEATURE: %s\n", strerror(errno));

    /* INFO: Not a fatal error, just log and continue */
  }

  /* INFO: The one check the feature call above cannot give us: a kernel may
             answer command 14 and refuse command 10, and that mismatch now shows
             up here instead of as a manager that is never recognised. Not
             stored - just logged, so the state at boot is visible on-device. */
  int manager_appid = ksu_read_manager_appid();
  if (manager_appid == KSU_MANAGER_APPID_UNKNOWN) {
    LOGW("KernelSU reports no manager appid yet; manager queries will answer \"unknown\" until one is crowned.");
  } else {
    LOGI("KernelSU manager appid: %d", manager_appid);
  }

  state->state = Supported;
}

void ksu_uid_query_root(uid_t uid, bool *granted_root, bool *should_umount) {
  *granted_root = false;
  *should_umount = false;

  struct ksu_uid_granted_root_cmd granted_cmd = {
    .uid = uid,
    .granted = 0
  };

  if (ioctl(ksu_fd, KSU_IOCTL_UID_GRANTED_ROOT, &granted_cmd) == -1) {
    LOGE("Failed to ioctl KSU_IOCTL_UID_GRANTED_ROOT: %s\n", strerror(errno));

    return;
  }

  *granted_root = granted_cmd.granted;

  struct ksu_uid_should_umount_cmd umount_cmd = {
    .uid = uid,
    .should_umount = 0
  };

  if (ioctl(ksu_fd, KSU_IOCTL_UID_SHOULD_UMOUNT, &umount_cmd) == -1) {
    LOGE("Failed to ioctl KSU_IOCTL_UID_SHOULD_UMOUNT: %s\n", strerror(errno));

    return;
  }

  *should_umount = umount_cmd.should_umount;
}

enum ksu_manager_query ksu_uid_is_manager(uid_t uid) {
  int appid = ksu_read_manager_appid();

  if (appid == KSU_MANAGER_APPID_UNKNOWN) {
    /* INFO: The kernel reports no manager, or the query failed. Saying "no"
               here would send the manager down the denylist path, where the
               revert then umounts the module tree out of its own namespace and
               every WebUI it opens renders blank. "Unknown" keeps it out of both
               branches; the cost is a possibly missing ZYGISK_ENABLED. */
    return KSU_MANAGER_QUERY_UNKNOWN;
  }

  /* INFO: For Private Space, UID will be 10xxxxx, being xxxxx the original UID. To check if
             the UID is the manager UID in Private Space, we "normalize" it with the modulo operator. */
  if ((int)(uid % 100000) == appid) return KSU_MANAGER_QUERY_YES;

  return KSU_MANAGER_QUERY_NO;
}

void ksu_cleanup(void) {
  if (ksu_fd != -1) {
    close(ksu_fd);
    ksu_fd = -1;
  }
}
