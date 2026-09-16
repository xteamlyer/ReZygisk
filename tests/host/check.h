#ifndef CHECK_H
#define CHECK_H

/* INFO: The assertion primitive the three host tests share. The counter is
         per test binary on purpose: each of them is a standalone main() that
         prints and returns its own total, so a shared definition would need a
         translation unit of its own to link against.

         __FILE__ and __LINE__ are expanded where CHECK is used, so the
         reported location is the failing assertion rather than this header. */

#include <stdio.h>

static int g_failures = 0;

#define CHECK(condition, ...)                     \
  do {                                            \
    if (!(condition)) {                           \
      g_failures++;                               \
      printf("FAIL %s:%d: ", __FILE__, __LINE__); \
      printf(__VA_ARGS__);                        \
      printf("\n");                               \
    }                                             \
  } while (0)

#endif /* CHECK_H */
