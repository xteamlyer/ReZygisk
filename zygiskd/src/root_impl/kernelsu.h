#ifndef KERNELSU_H
#define KERNELSU_H

#include "common.h"

/* INFO: Three answers, not two. "Unknown" is what the daemon says when it
           cannot read the manager appid at all - either the kernel reports no
           manager, or the query failed. Collapsing that into "no" is what let
           a manager be classified as a denylisted app. */
enum ksu_manager_query {
  KSU_MANAGER_QUERY_NO = 0,
  KSU_MANAGER_QUERY_YES = 1,
  KSU_MANAGER_QUERY_UNKNOWN = 2
};

void ksu_get_existence(struct root_impl_state *state);

void ksu_uid_query_root(uid_t uid, bool *granted_root, bool *should_umount);

enum ksu_manager_query ksu_uid_is_manager(uid_t uid);

void ksu_cleanup(void);

#endif
