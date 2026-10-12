#ifndef ZYGISK_H
#define ZYGISK_H

#include <stddef.h>

extern void *start_addr;
extern size_t block_size;

/* INFO: The handle the target's linker returned for this library. The ptracer
         gets it from the dlopen that loads us and hands it to entry(), and the
         teardown closes it - closing the handle is what takes the library, and
         its entry in the linker's module list, out of the process. */
extern void *injector_handle;

void hook_functions(void);

#endif /* ZYGISK_H */
