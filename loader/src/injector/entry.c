#include <stdbool.h>

#include "daemon.h"
#include "logging.h"
#include "misc.h"

#include "hook.h"
#include "ptrace_clear.h"
#include "zn_hyos.h"
#include "zn_loader.h"
#include "zn_spawner.h"

__attribute__((visibility("default")))
void entry(void *handle, void *addr, size_t size) {
  LOGD("VexZygisk library injected, version %s", ZKSU_VERSION);

  /* INFO: Kept for the teardown. This is the only moment the handle exists on
            this side of the ptrace boundary - it came back from the dlopen in a
            register, and nothing here could ask the linker for it again by
            value. */
  injector_handle = handle;

  start_addr = addr;
  block_size = size;

  /* INFO: Which branch this process takes is decided by what is mapped in it.
           On HyperOS 4 the process hosting the Rust runtime is an app_process
           binary with the spawner image mapped into it, so its /proc/self/exe
           names the wrong file, and the other branch installs the JNI hooks
           into the spawner - the crash that left every application unable to
           start. zn_hyos.h answers the question, and finding the image is also
           what opens the window the modules register in.

           The executable's own name is asked as well, and only for the branch
           that must not be taken: a process that is the spawner by name but
           whose image could not be inspected is still not a zygote, and handing
           it to hook_functions() is the one mistake here that costs a boot.
           That second answer cannot arm the runtime - the hooks need the image
           identity the scan produces - so it only ever keeps a process out of
           the wrong branch.

           The two branches install different hooks, and only the runtime branch
           is followed by anything else: the applications the spawner forks are
           not injected again, so whatever is set up here is what they start
           with. The JNI and PLT hooks belong to the zygote. */
  const bool is_runtime = zn_hyos_initialize(zn_open_runtime_session, zn_report_runtime_module);

  bool named_as_spawner = false;
  char exe[PATH_MAX] = { 0 };

  if (!is_runtime) {
    const ssize_t exe_len = read_exe_path((int)getpid(), exe, sizeof(exe));

    named_as_spawner = exe_len > 0 && zn_spawner_path_is_image(exe, (size_t)exe_len);
  }

  /* INFO: The spawner, either way it was recognised. What the process *is*
           decides two more things below - how long its plan is waited for, and
           whether the daemon is told about a zygote - and both are about being
           the spawner and not about the runtime having been armed. */
  const bool is_spawner = is_runtime || named_as_spawner;

  if (is_runtime) {
    LOGD("Running inside hyos_spawner, arming the HyperOS runtime");
  } else if (named_as_spawner) {
    LOGW("The executable is the HyperOS spawner (\"%s\") but its image was not found, taking no branch", exe);
  } else {
    LOGD("start plt hooking");

    hook_functions();
  }

  /* INFO: Both targets are waited for, for different lengths. The spawner's
           daemon may have been forked for this very process moments ago, a
           single connection attempt would lose that race and leave it with no
           runtime modules at all, and nothing after this point ever asks again:
           every app the spawner forks inherits what was loaded here. The zygote
           loses less - its apps ask again for themselves - but it loses the
           modules that name the zygote, and nothing else loads those either.
           zn_loader.h has both windows and why they differ. */
  zn_load_all_modules(is_spawner ? ZN_PLAN_ATTEMPTS_SPAWNER : ZN_PLAN_ATTEMPTS_TREE,
                      is_spawner ? REZYGISKD_RETRY_DELAY_SPAWNER_US : REZYGISKD_RETRY_DELAY_US);

  /* INFO: The runtime's hooks go in after its modules, because the modules are
           what register: what is armed here is a fork hook and a setcontext
           hook whose whole purpose is to reach callbacks nobody has registered
           yet, and the contract's own answer to a runtime with no module is to
           install nothing. The window that was open while the modules loaded is
           closed by this call either way - a module that registers after it has
           missed the boot it was loaded for. */
  if (is_runtime && !zn_hyos_install_hooks()) {
    LOGW("HyperOS runtime: not armed, no module will be told about a specialization");
  }

  struct kernel_version version = parse_kversion();
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) {
    LOGD("Supported kernel version %d.%d.%d, sending seccomp event", version.major, version.minor, version.patch);

    perform_ptrace_message_clear();
  }

  /* INFO: The daemon's zygote bookkeeping is about the zygote: the spawner
           has no specialize to track and no companions of its own. */
  if (is_spawner) return;

  if (!rezygiskd_zygote_injected()) {
    LOGE("VexZygiskd is not running");

    return;
  }

  LOGD("Zygisk library execution done, addr: %p, size: %zu", addr, size);
}
