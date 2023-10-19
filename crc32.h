

#ifndef __DS_CRC32_H__
#define __DS_CRC32_H__ 1

#define CRC32_INITIAL         (0xffffffffUL)
#define CRC32_INITIAL_STATE   (~CRC32_INITIAL)

#include <stdint.h>
#include <stddef.h>

uint32_t crc32_update(const void *buf, size_t len, uint32_t crc);
uint32_t crc32(const void *buf, size_t len);

#endif /* __DS_CRC32_H__ */
