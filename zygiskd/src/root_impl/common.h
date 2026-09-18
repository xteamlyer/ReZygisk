#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#include <sys/types.h>

#include "../constants.h"

/* INFO: The backend the daemon was built for. Only the matching member is
         compiled in, so the switches and the name table cannot carry the
         other root solution at all. */
#ifdef ROOT_IMPL_APATCH
enum root_impls {
  RootAPatch
};
#else
enum root_impls {
  RootKernelSU
};
#endif

struct root_impl_state {
  enum RootImplState state;
};

struct root_impl {
  enum root_impls impl;
};

/* INFO: The display name and the kind live next to the enum so the length
         can be derived from the one string that is actually compiled in —
         a fixed sizeof("KernelSU") would silently overflow once a root
         with a longer name shows up. */
#ifdef ROOT_IMPL_APATCH
  #define ROOT_IMPL_KIND RootAPatch
  #define ROOT_IMPL_NAME "APatch"
#else
  #define ROOT_IMPL_KIND RootKernelSU
  #define ROOT_IMPL_NAME "KernelSU"
#endif

#define LONGEST_ROOT_IMPL_NAME sizeof(ROOT_IMPL_NAME)

/* INFO: Whether a uid belongs to the root manager is a question with three
           answers, not two: yes, no, and "cannot tell". The third one exists
           because both backends can be asked before they are able to answer -
           KernelSU before the kernel has crowned a manager, APatch before its
           scan has settled. Reporting "no" in that moment is not a safe
           default: the loader reads "no" as "ordinary app", and an ordinary
           app that should_umount gets the root mounts reverted out of its own
           namespace. A manager treated that way loses sight of the module
           tree and every WebUI under it turns into a blank page. "Cannot
           tell" keeps such a process out of both branches. */
enum uid_manager_state {
  UID_MANAGER_NO = 0,
  UID_MANAGER_YES = 1,
  UID_MANAGER_UNKNOWN = 2
};

void root_impls_setup(void);

void get_impl(struct root_impl *uimpl);

void uid_query_root(uid_t uid, bool *granted_root, bool *should_umount);

enum uid_manager_state uid_is_manager(uid_t uid);

void root_impl_cleanup(void);

#endif /* COMMON_H */
