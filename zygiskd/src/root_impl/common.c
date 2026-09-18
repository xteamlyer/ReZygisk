#include "common.h"

#include "../utils.h"

/* INFO: One backend is compiled in per build; the macros keep the dispatch
         below identical for both. A missing interface only means this daemon is
         running somewhere it cannot serve, so keep serving requests that do not
         need root instead of failing to start. The manager query is not routed
         through a macro: the backends answer in their own enums, so
         uid_is_manager() spells the mapping out and the compiler checks it. */
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
  /* INFO: An unsupported backend has not denied anything, it never looked, so
             "unknown" is the honest answer. */
  if (!impl_supported) return UID_MANAGER_UNKNOWN;

#ifdef ROOT_IMPL_APATCH
  return ap_uid_is_manager(uid);
#else
  /* INFO: Mapped explicitly, not by value: KernelSU's UNKNOWN is 2 where the
             shared one is 1. */
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
