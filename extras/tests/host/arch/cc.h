/* lwIP architecture glue for the host tests. */
#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdio.h>
#include <stdlib.h>

#define LWIP_PLATFORM_DIAG(x)                                                  \
  do {                                                                         \
    printf x;                                                                  \
  } while (0)

#define LWIP_PLATFORM_ASSERT(x)                                                \
  do {                                                                         \
    fprintf(stderr, "lwIP assertion \"%s\" failed at %s:%d\n", x, __FILE__,    \
            __LINE__);                                                         \
    abort();                                                                   \
  } while (0)

#define LWIP_RAND() ((u32_t)rand())

#endif
