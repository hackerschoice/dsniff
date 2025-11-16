
#include "config.h"
#ifndef MAX
# define MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef MIN
# define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif


// MacOS missing defines below:
#ifndef NS_GET16
#define NS_GET16(s, cp) do { \
        const unsigned char *t_cp = (const unsigned char *)(cp); \
        (s) = ((uint16_t)t_cp[0] << 8) \
            | ((uint16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
} while (0)
#endif
#ifndef GETSHORT
# define GETSHORT                       NS_GET16
#endif

#ifndef NS_GET32
#define NS_GET32(l, cp) do { \
        const unsigned char *t_cp = (const unsigned char *)(cp); \
        (l) = ((uint32_t)t_cp[0] << 24) \
            | ((uint32_t)t_cp[1] << 16) \
            | ((uint32_t)t_cp[2] << 8) \
            | ((uint32_t)t_cp[3]) \
            ; \
        (cp) += NS_INT32SZ; \
} while (0)
#endif
#ifndef GETLONG
# define GETLONG                       NS_GET32
#endif