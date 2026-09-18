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

/* INFO: -1 is as much "not known yet" as it is "no manager": it is the
           kernel's own KSU_INVALID_APPID, which it reports both before a
           manager has been crowned and after one has been uninstalled.
           Anything that cannot be answered is reported as this. */
#define KSU_MANAGER_APPID_UNKNOWN (-1)

/* INFO: The appid is asked for on every call, with no caching. The kernel owns
           this value and moves it in both directions - it is set when
           track_throne() crowns the manager and cleared back to
           KSU_INVALID_APPID when the manager turns out to be gone - so any
           remembered copy can only ever be staler than the kernel's, and the
           stale direction that matters is the dangerous one: a cached appid
           that is no longer the manager would name the wrong uid as manager
           while the real one fell through to the denylist branch.

           Nothing is saved by caching anyway. This is a single ioctl, and it is
           the same call the code already made on every request before. Reading
           it fresh is also what makes the answer deterministic across boots:
           the crowning is asynchronous, so a query that lands before
           search_manager() has run sees -1 and says "unknown", and the next
           one sees the real appid. */
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

  /* INFO: Probe the manager query once at startup. This is the one check the
             feature call above cannot give us - a kernel may answer command 14
             and refuse command 10 - and without it that mismatch would only
             surface later, as a manager that never gets recognised. The result
             is not stored; it is logged so the state at boot is visible on a
             device where the manager then behaves oddly. Either outcome is
             fine here, including -1, which is expected whenever the manager has
             not been crowned yet. */
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
    /* INFO: The kernel reports no manager, or the query failed. Both mean the
               daemon cannot tell who the manager is, and the answer that
               matters is "unknown" rather than "no": the loader turns a plain
               "no" into a denylist classification, and a manager classified
               as denylisted gets /data/adb/modules reverted out of its own
               namespace, which breaks every WebUI it then tries to load.
               Returning "unknown" makes the caller keep the manager flag off
               but also keeps it out of the denylist path, so the worst case
               is a missing ZYGISK_ENABLED instead of a broken mount
               namespace. */
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
