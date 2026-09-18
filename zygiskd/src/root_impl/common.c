#include "common.h"

#include "../utils.h"

/* INFO: One backend is compiled in per build; the macros keep the dispatch
         code below identical for both. The daemon is built for a specific
         root solution, so a missing interface only means it is running
         somewhere it cannot serve; keep serving requests that do not need
         root instead of failing to start.

         The manager query is not routed through a macro: the two backends
         answer in their own enums, so uid_is_manager() spells the mapping
         out and the compiler checks that every case is handled. */
#ifdef ROOT_IMPL_APATCH
  #include "apatch.h"
  #define ROOT_GET_EXISTENCE ap_get_existence
  #define ROOT_UID_QUERY_ROOT ap_uid_query_root
#else
  #include "kernelsu.h"
  #define ROOT_GET_EXISTENCE ksu_get_existence
  #define ROOT_UID_QUERY_ROOT ksu_uid_query_root
#endif

static struct root_impl impl;
static bool impl_supported = false;

void root_impls_setup(void) {
  struct root_impl_state state;
  ROOT_GET_EXISTENCE(&state);

  if (state.state != Supported) {
    LOGW("No supported root implementation found.");

    return;
  }

  impl.impl = ROOT_IMPL_KIND;
  impl_supported = true;

  LOGI("%s root implementation found.", ROOT_IMPL_NAME);
}

void get_impl(struct root_impl *uimpl) {
  *uimpl = impl;
}

void uid_query_root(uid_t uid, bool *granted_root, bool *should_umount) {
  *granted_root = false;
  *should_umount = false;

  if (!impl_supported) return;

  ROOT_UID_QUERY_ROOT(uid, granted_root, should_umount);
}

enum uid_manager_state uid_is_manager(uid_t uid) {
  /* INFO: An unsupported backend has not denied anything, it simply never
             looked, so "unknown" is the honest answer and keeps the caller
             from reading a denylist verdict into it. */
  if (!impl_supported) return UID_MANAGER_UNKNOWN;

#ifdef ROOT_IMPL_APATCH
  return ap_uid_is_manager(uid);
#else
  /* INFO: KernelSU answers in its own three states, and they do not line up
             numerically with the shared ones: UNKNOWN is 2 there and 1 here.
             The mapping is written out instead of relying on the values. */
  switch (ksu_uid_is_manager(uid)) {
    case KSU_MANAGER_QUERY_YES: return UID_MANAGER_YES;
    case KSU_MANAGER_QUERY_NO: return UID_MANAGER_NO;
    case KSU_MANAGER_QUERY_UNKNOWN: break;
  }

  return UID_MANAGER_UNKNOWN;
#endif
}

void root_impl_cleanup(void) {
  if (!impl_supported) return;

#ifndef ROOT_IMPL_APATCH
  /* INFO: APatch holds nothing on this side; its apd daemon is external. */
  ksu_cleanup();
#endif
}
