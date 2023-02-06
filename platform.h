#ifndef _PHMAP_PLATFORM_H_
#define _PHMAP_PLATFORM_H_
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define maybe_unused __attribute__((unused))

static void *platform_region_alloc(size_t size);
static void *platform_region_expand(void *region, size_t old_size,
                                    size_t new_size, bool allow_move);
static void platform_region_unalloc(void *region, size_t size);

typedef struct platform_rwlock platform_rwlock;

static maybe_unused void platform_rwlock_init(platform_rwlock *rwlock);
static maybe_unused void platform_rwlock_destroy(platform_rwlock *rwlock);
static maybe_unused void platform_rwlock_rdlock(platform_rwlock *rwlock);
static maybe_unused void platform_rwlock_rdunlock(platform_rwlock *rwlock);
static maybe_unused void platform_rwlock_wrlock(platform_rwlock *rwlock);
static maybe_unused void platform_rwlock_wrunlock(platform_rwlock *rwlock);

#ifdef __unix__

#include <pthread.h>

struct platform_rwlock {
  pthread_rwlock_t lock;
};

static void platform_rwlock_init(platform_rwlock *rwlock) {
  pthread_rwlock_init(&(rwlock->lock), NULL);
}

static void platform_rwlock_destroy(platform_rwlock *rwlock) {
  pthread_rwlock_destroy(&(rwlock->lock));
}

static void platform_rwlock_rdlock(platform_rwlock *rwlock) {
  pthread_rwlock_rdlock(&(rwlock->lock));
}

static void platform_rwlock_rdunlock(platform_rwlock *rwlock) {
  pthread_rwlock_unlock(&(rwlock->lock));
}

static void platform_rwlock_wrlock(platform_rwlock *rwlock) {
  pthread_rwlock_rdlock(&(rwlock->lock));
}

static void platform_rwlock_wrunlock(platform_rwlock *rwlock) {
  pthread_rwlock_rdlock(&(rwlock->lock));
}

#ifdef __linux__

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

static maybe_unused void *platform_region_alloc(size_t size) {
  void *region = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (region == MAP_FAILED) {
    perror("mmap");
    return NULL;
  }
  return region;
}

static maybe_unused void *platform_region_expand(void *region, size_t old_size,
                                                 size_t new_size,
                                                 bool allow_move) {
  void *new_region =
      mremap(region, old_size, new_size, MREMAP_MAYMOVE ? allow_move : 0);
  fprintf(stderr, "%lx->%lx: %zu, %zu\n", (intptr_t)region,
          (intptr_t)new_region, old_size, new_size);
  if (new_region == MAP_FAILED) {
    perror("mremap");
    return NULL;
  }
  return new_region;
}

static maybe_unused void platform_region_unalloc(void *region, size_t size) {
  munmap(region, size);
}

#else
static void *platform_region_alloc(size_t size) { return calloc(size, 1); }

static void *platform_region_expand(void *region, size_t old_size,
                                    size_t new_size, bool allow_move) {
  if (allow_move) {
    return realloc(region, new_size);
  }
  return NULL;
}
#endif

#else
#error "unsupported platform"
#endif

#endif
