#include <stdbool.h>

#include "daemon.h"
#include "logging.h"
#include "misc.h"

#include "hook.h"
#include "ptrace_clear.h"
#include "zn_api.h"
#include "zn_loader.h"

__attribute__((visibility("default")))
void entry(void *addr, size_t size) {
  LOGD("VexZygisk library injected, version %s", ZKSU_VERSION);

  /* INFO: HyperOS runs applications on its own Rust runtime instead of a
           zygote, and there is no ART specialize path there to hook — hooking
           the JNI is what crashed the spawner and left every app unable to
           start (the second-screen loop). That runtime only carries the module
           table: the modules load, register through getRuntime(), and are
           notified from the SELinux hooks the runtime installs. The JNI and
           PLT hooks belong to the zygote. */
  bool is_spawner = zn_is_hyos_spawner();

  if (is_spawner) {
    /* INFO: Pins the runtime to this process before any module can register,
             so every app forked from here can tell itself apart from the
             spawner by pid. */
    zn_init_hyos_runtime();

    LOGD("Running inside hyos_spawner, initializing the HyperOS runtime");
  } else {
    LOGD("start plt hooking");

    hook_functions();
  }

  /* INFO: The spawner is waited for: the daemon may have been forked for this
           very process moments ago, a single connection attempt would lose
           that race and leave it with no runtime modules at all, and nothing
           after this point ever asks again - every app the spawner forks
           inherits what was loaded here. Its plan is also beyond the reach of
           the direct-scan fallback, which needs the zygote's permissions on
           /data/adb, so the retry window is the one safety there is: five
           attempts a second apart, the window NyaZygisk's loader waits out
           for the same one-shot contract. Every other target is reached long
           after the daemon is up and keeps the short spacing. */
  zn_load_all_modules(is_spawner ? 5 : 1,
                      is_spawner ? REZYGISKD_RETRY_DELAY_SPAWNER_US : REZYGISKD_RETRY_DELAY_US);

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
