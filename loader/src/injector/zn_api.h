#ifndef ZN_API_H
#define ZN_API_H

#include "zygisk_next_api.h"

/* INFO: The oldest Zygisk Next module contract this fork serves.

         The table below is one object whose every entry is real, and that only
         works while what is served it is the contract as it stands. An older
         module is not refused for being old: it describes a table whose fields
         have moved since, and handing it one whose entries it would read at the
         wrong offsets is worse than telling it no. Zygisk Next's own versions 3
         and 4 are the two the reference implementation accepts, and the two
         this one serves. */
#define ZN_MODULE_API_MIN 3

/* INFO: The table handed to every Zygisk Next module this loader loads. */
const struct ZygiskNextAPI *zn_get_api(void);

#endif /* ZN_API_H */
