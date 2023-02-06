#ifndef __FNV1A_HASHES_H_
#define __FNV1A_HASHES_H_
#include <stdint.h>

uint64_t fnv1a_hash64(const char* str);

uint32_t fnv1a_hash32(const char* str);

#endif
