#define _GNU_SOURCE
#include <assert.h>
#include <kv_map.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

static const unsigned NUM_ENTRIES = 4096;
static const unsigned NUM_REMOVE_TESTS = NUM_ENTRIES - 100;
static const unsigned MAX_LEN = 128;
#define NUM_THREADS 32

static int __thread thread_id;
static struct drand48_data __thread thread_seed;
static unsigned int seed;
static atomic_int cur_thread_num = 0;


long int better_rand() {
  long int result;
  lrand48_r(&thread_seed, &result);
  return result;
}

void gen_random_ascii(char *gen, int max_len) {
  int rand_len = better_rand() % (max_len - 1);
  if (rand_len < 15) {
    rand_len = 15;
  }
  int i = 0;
  for (; i < rand_len; i++) {
    gen[i] = better_rand() % 26 + 65;
  }
  gen[i] = '\0';
}

bool iterate(const char *key, const char *val, void *data) {
  int *count = data;
  *count = *count + 1;
  return true;
}

bool iterate_with_abort(const char *key, const char *val, void *data) {
  int *count = data;
  *count = *count + 1;
  if (*count == 10)
    return false;
  return true;
}


void test_kv(kv_map *kv, bool single, int rounds) {
  fprintf(stderr, "generating random entries\n");
  // dynamically allocated list of strings
  char(*entries)[MAX_LEN];
  entries = malloc(sizeof(char[MAX_LEN]) * NUM_ENTRIES);
  assert(entries != NULL);
  char fname[256];
  sprintf(fname, "%u.txt", thread_id);
  FILE *f = fopen(fname, "w");
  for (int i = 0; i < NUM_ENTRIES; i++) {
    gen_random_ascii(entries[i], MAX_LEN);
    fprintf(f, "%s\n", entries[i]);
  }
  fclose(f);
  for (int off = 0; off < rounds; off++) {
    fprintf(stderr, "inserting entries into map\n");
    // Deterministically associate keys and values
    for (int i = 0; i < NUM_ENTRIES; i++) {
      assert(kv_map_set(kv, entries[i], entries[(i + off) % NUM_ENTRIES]) ==
             KV_MAP_ERROR_NONE);
    }
    //
    if (single) {
      fprintf(stderr, "%"KV_MAP_SIZE_PRI", %i\n", kv_map_count(kv), NUM_ENTRIES);
      assert(kv_map_count(kv) == NUM_ENTRIES);
    }
    fprintf(stderr, "Checking entry retrieval consistency\n");
    for (int i = 0; i < NUM_ENTRIES; i++) {
      const char *str = kv_map_get(kv, entries[i]);
      if (!str) {
        fprintf(stderr, "failed retrieve: %s\n", entries[i]);
      }
      assert(str);
      assert(strcmp(str, entries[(i + off) % NUM_ENTRIES]) == 0);
    }
    fprintf(stderr, "Randomly removing subset of entries\n");
    for (int i = 0; i < NUM_REMOVE_TESTS; i++) {
      int j;
      do {
        j = better_rand() % NUM_ENTRIES;
      } while (kv_map_get(kv, entries[j]) == NULL);
      kv_map_unset(kv, entries[j]);
      assert(kv_map_get(kv, entries[j]) == NULL);
    }
    int missing_count = 0;
    // TODO check missing based on iteration with our set of keys
    fprintf(stderr, "Checking entry consistency with num removed\n");
    for (int i = 0; i < NUM_ENTRIES; i++) {
      const char *entry = kv_map_get(kv, entries[i]);
      if (entry) {
        assert(strcmp(entry, entries[(i + off) % NUM_ENTRIES]) == 0);
      } else {
        missing_count++;
      }
    }
    assert(missing_count == NUM_REMOVE_TESTS);
    fprintf(stderr, "Checking specific key insert/remove\n");
    if (single) {
      kv_map_set(kv, "foo", "bar");
      assert(strcmp("bar", kv_map_get(kv, "foo")) == 0);
      kv_map_set(kv, "foo", "baz");
      assert(strcmp("baz", kv_map_get(kv, "foo")) == 0);
      assert(kv_map_unset(kv, "foo") == true);
      assert(kv_map_unset(kv, "foo") == false);
    }
    int count = 0;
    fprintf(stderr, "Checking iteration is consistent\n");
    kv_map_iterate(kv, (kv_map_iterate_callback)iterate, &count);
    if (single) {
      fprintf(stderr, "%"KV_MAP_SIZE_PRI", %i, %i\n", kv_map_count(kv), count,
                   NUM_ENTRIES - NUM_REMOVE_TESTS);
      assert(count == NUM_ENTRIES - NUM_REMOVE_TESTS);
      assert(kv_map_count(kv) == NUM_ENTRIES - NUM_REMOVE_TESTS);
    }
    count = 0;
    kv_map_iterate(kv, (kv_map_iterate_callback)iterate_with_abort, &count);
    assert(count == 10);
    fprintf(stderr, "Checking all removal makes sense\n");
    if (single) {
      kv_map_empty(kv);
      assert(kv_map_count(kv) == 0);
    } else {
      for (int i = 0; i < NUM_ENTRIES; i++) {
        kv_map_unset(kv, entries[i]);
      }
    }
    missing_count = 0;
    for (int i = 0; i < NUM_ENTRIES; i++) {
      const char *entry = kv_map_get(kv, entries[i]);
      if (entry) {
        assert(strcmp(entry, entries[(i + off) % NUM_ENTRIES]) == 0);
      } else {
        missing_count++;
      }
    }
    assert(missing_count == NUM_ENTRIES);
  }
  free(entries);
}

#include <unistd.h>

int main(int argc, char **argv) {
  thread_id = cur_thread_num++;
  struct timespec s;
  clock_gettime(CLOCK_MONOTONIC_RAW, &s);
  // seed = s.tv_nsec;
  seed = 193725964;
  srand48_r(seed, &thread_seed);
  fprintf(stderr, "using seed %u\n", seed);
  fprintf(stderr, "testing creation\n");
  kv_map *kv = kv_map_str_create(0);
  assert(kv != NULL);
  fprintf(stderr, "running thorough test\n");
  test_kv(kv, true, 1);
  kv_map_free(kv);
  fprintf(stderr, "checking generic map creation\n");
  kv = kv_map_create((kv_map_create_params){
      .size = 100,
  });
  // Check that the map failed due to non Po2 size
  assert(kv == NULL);
  // We need sensible defaults (IE, resizable, etc)
  kv = kv_map_create((kv_map_create_params){});
  assert(kv);
  kv_map_free(kv);
  kv = kv_map_str_create(0);
  kv_map_set(kv, "foo", "bar");
  char *str_rep;
  size_t str_size;
  FILE *f = open_memstream(&str_rep, &str_size);
  kv_map_print(kv, f);
  fclose(f);
  fprintf(stderr, "str_rep: %s", str_rep);
  assert(strcmp(str_rep, "{\n\t\"foo\": \"bar\"\n}\n") == 0);
  free(str_rep);
  kv_map_free(kv);
  return 0;
}
