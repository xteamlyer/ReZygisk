#ifndef ZN_IHOOK_H
#define ZN_IHOOK_H

/* INFO: The C bridge to the inline hook engine the Zygisk Next inlineHook entry
         is served by (injector/ihook_shim.cpp, over src/external/ihook/).

         The engine is YukiZygisk's, taken whole: the same relocating arm64
         patcher, the same instruction-cache synchronization, the same lifecycle
         states. It is C++ and this injector is C, so the boundary is a pair of
         calls and the engine keeps its own hooks; a hook is named by the
         address it was placed on, which is also what the contract keys on.

         Both answer false when the engine refuses - a process with more than one
         thread, an address that is already inside another hook's window, an
         address the relocator cannot rewrite. The refusal is not silent: the
         shim logs why, and the reasons are the engine's own. */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* INFO: Places the hook and hands back the address the original can be called
         through, which the engine returns and this hands on as `*original`
         (untouched when the caller passed NULL). */
bool zn_ihook_install(void *target, void *replacement, void **original);

/* INFO: Removes the hook placed on `target` and reclaims its trampoline. The
         engine restores the bytes rather than discarding the page, which is the
         one of its two modes the contract's unhook corresponds to. */
bool zn_ihook_uninstall(void *target);

#ifdef __cplusplus
}
#endif

#endif /* ZN_IHOOK_H */
