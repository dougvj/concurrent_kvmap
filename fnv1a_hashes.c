#include <fnv1a_hashes.h>

uint64_t fnv1a_hash64(const char* str) {
  static const uint64_t BASIS = 14695981039346656037ull;
  static const uint64_t FNV_PRIME = 1099511628211ull;
  uint64_t hash = BASIS;
  for (const char* c = str; *c != '\0'; c++) {
    hash = hash ^ *c;
    hash = hash * FNV_PRIME;
  }
  return hash;
}

uint32_t fnv1a_hash32(const char* str) {
  static const uint64_t BASIS = 2166136261ul;
  static const uint64_t FNV_PRIME = 16777619ull;
  uint32_t hash = BASIS;
  for (const char* c = str; *c != '\0'; c++) {
    hash = hash ^ *c;
    hash = hash * FNV_PRIME;
  }
  return hash;
}

// TODO provide mem block implementations
