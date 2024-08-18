#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "../constants.h"
#include "../utils.h"

#include "apatch.h"

enum RootImplState apatch_get_existence(void) {
  struct stat s;
  if (stat("/data/adb/apd", &s) != 0) {
    LOGE("APATCH | Failed to stat /data/adb/apd: %s\n", strerror(errno));

    return Inexistent;
  }

  char apatch_version[32];
  char *const argv[] = { "apd", "-V", NULL };

  LOGI("APATCH | Checking for apd existence\n");
  if (!exec_command(apatch_version, sizeof(apatch_version), "/data/adb/apd", argv)) {
    LOGE("APATCH | Failed to execute apd binary: %s\n", strerror(errno));
    errno = 0;

    return Inexistent;
  }

  int version = atoi(apatch_version + strlen("apd "));
  LOGI("APATCH | apd version: %d\n", version);
  if (version == 0) return Abnormal;

  if (version >= MIN_APATCH_VERSION && version <= 999999) return Supported;
  if (version >= 1 && version <= MIN_APATCH_VERSION - 1) return TooOld;

  return Inexistent;
}

struct package_config {
  uid_t uid;
  bool root_granted;
  bool umount_needed;
};

struct packages_config {
  struct package_config *configs;
  size_t size;
};

bool _apatch_get_package_config(struct packages_config *config) {
  FILE *fp = fopen("/data/adb/ap/package_config", "r");
  if (fp == NULL) {
    LOGE("APATCH | Failed to open package_config: %s\n", strerror(errno));

    return false;
  }

  char line[256];
  /* INFO: Skip the CSV header */
  fgets(line, sizeof(line), fp);

  while (fgets(line, sizeof(line), fp) != NULL) {
    config->configs = realloc(config, (config->size + 1) * sizeof(struct package_config));
    if (config->configs == NULL) {
      LOGE("APATCH | Failed to realloc package config: %s\n", strerror(errno));

      fclose(fp);

      return false;
    }

    strtok(line, ",");

    char *exclude_str = strtok(NULL, ",");
    if (exclude_str == NULL) continue;

    char *allow_str = strtok(NULL, ",");
    if (allow_str == NULL) continue;

    char *uid_str = strtok(NULL, ",");
    if (uid_str == NULL) continue;    

    config->configs[config->size].uid = atoi(uid_str);
    config->configs[config->size].root_granted = strcmp(allow_str, "1") == 0;
    config->configs[config->size].umount_needed = strcmp(exclude_str, "1") == 0;

    config->size++;
  }

  fclose(fp);

  return true;
}

bool apatch_uid_granted_root(uid_t uid) {
  struct packages_config *config = NULL;
  if (!_apatch_get_package_config(config)) {
    free(config);

    return false;
  }

  for (size_t i = 0; i < config->size; i++) {
    if (config->configs[i].uid == uid) {
      free(config);

      return config->configs[i].root_granted;
    }
  }

  free(config);

  return false;
}

bool apatch_uid_should_umount(uid_t uid) {
  struct packages_config *config = NULL;
  if (!_apatch_get_package_config(config)) {
    free(config);

    return false;
  }

  for (size_t i = 0; i < config->size; i++) {
    if (config->configs[i].uid == uid) {
      free(config);

      return config->configs[i].umount_needed;
    }
  }

  free(config);

  return false;
}

bool apatch_uid_is_manager(uid_t uid) {
  struct stat s;
  if (stat("/data/user_de/0/me.bmax.apatch", &s) == -1) return false;

  return s.st_uid == uid;
}
