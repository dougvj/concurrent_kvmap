#define _GNU_SOURCE
#include <assert.h>
#include <ckv_map.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int __thread thread_id;
static struct drand48_data __thread thread_seed;
static unsigned int seed;
static atomic_int cur_thread_num = 0;

#define test_println(fmt, ...)                                                 \
  fprintf(stderr, "test_thread %i: " fmt "\n", thread_id, ##__VA_ARGS__)

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

// ============================================================================
// Unit Tests
// ============================================================================

static void test_create_destroy(void) {
  test_println("test_create_destroy");
  ckv_map *kv = ckv_map_str_create(0);
  assert(kv != NULL);
  ckv_map_free(kv);
  test_println("  PASSED");
}

static void test_create_requires_callbacks(void) {
  test_println("test_create_requires_callbacks");
  // Size must be power of 2
  ckv_map *kv = ckv_map_create((ckv_map_create_params){.size = 100});
  assert(kv == NULL);
  // Require hash_func and key_cmp_func
  kv = ckv_map_create((ckv_map_create_params){.size = 0});
  assert(kv == NULL);
  test_println("  PASSED");
}

static void test_basic_set_get(void) {
  test_println("test_basic_set_get");
  ckv_map *kv = ckv_map_str_create(0);

  assert(ckv_map_set(kv, "key1", "value1") == CKV_MAP_ERROR_NONE);
  char *val = ckv_map_get(kv, "key1");
  assert(val != NULL);
  assert(strcmp(val, "value1") == 0);
  ckv_map_val_unref(kv, val);

  ckv_map_free(kv);
  test_println("  PASSED");
}

static void test_set_overwrite(void) {
  test_println("test_set_overwrite");
  ckv_map *kv = ckv_map_str_create(0);

  ckv_map_set(kv, "key", "first");
  ckv_map_set(kv, "key", "second");

  char *val = ckv_map_get(kv, "key");
  assert(val != NULL);
  assert(strcmp(val, "second") == 0);
  ckv_map_val_unref(kv, val);

  assert(ckv_map_count(kv) == 1);

  ckv_map_free(kv);
  test_println("  PASSED");
}

static void test_unset(void) {
  test_println("test_unset");
  ckv_map *kv = ckv_map_str_create(0);

  ckv_map_set(kv, "key", "value");
  assert(ckv_map_count(kv) == 1);

  assert(ckv_map_unset(kv, "key") == true);
  assert(ckv_map_count(kv) == 0);
  assert(ckv_map_get(kv, "key") == NULL);

  // Unset non-existent key returns false
  assert(ckv_map_unset(kv, "key") == false);

  ckv_map_free(kv);
  test_println("  PASSED");
}

static bool count_iterate_cb(const char *key, const char *val, void *data) {
  (void)key;
  (void)val;
  int *count = data;
  *count = *count + 1;
  return true;
}

static void test_iterate(void) {
  test_println("test_iterate");
  ckv_map *kv = ckv_map_str_create(0);

  ckv_map_set(kv, "a", "1");
  ckv_map_set(kv, "b", "2");
  ckv_map_set(kv, "c", "3");

  int count = 0;
  ckv_map_iterate(kv, (ckv_map_iterate_callback)count_iterate_cb, &count);
  assert(count == 3);

  ckv_map_free(kv);
  test_println("  PASSED");
}

static bool abort_iterate_cb(const char *key, const char *val, void *data) {
  (void)key;
  (void)val;
  int *count = data;
  *count = *count + 1;
  return (*count < 2);  // Abort after 2 items
}

static void test_iterate_abort(void) {
  test_println("test_iterate_abort");
  ckv_map *kv = ckv_map_str_create(0);

  ckv_map_set(kv, "a", "1");
  ckv_map_set(kv, "b", "2");
  ckv_map_set(kv, "c", "3");

  int count = 0;
  bool completed = ckv_map_iterate(kv, (ckv_map_iterate_callback)abort_iterate_cb, &count);
  assert(!completed);
  assert(count == 2);

  ckv_map_free(kv);
  test_println("  PASSED");
}

static void test_empty(void) {
  test_println("test_empty");
  ckv_map *kv = ckv_map_str_create(0);

  ckv_map_set(kv, "a", "1");
  ckv_map_set(kv, "b", "2");
  assert(ckv_map_count(kv) == 2);

  ckv_map_empty(kv);
  assert(ckv_map_count(kv) == 0);
  assert(ckv_map_get(kv, "a") == NULL);

  ckv_map_free(kv);
  test_println("  PASSED");
}

static void test_print(void) {
  test_println("test_print");
  ckv_map *kv = ckv_map_str_create(0);

  ckv_map_set(kv, "foo", "bar");

  char *str_rep;
  size_t str_size;
  FILE *f = open_memstream(&str_rep, &str_size);
  ckv_map_print(kv, f);
  fclose(f);

  assert(strcmp(str_rep, "{\n\t\"foo\": \"bar\"\n}\n") == 0);
  free(str_rep);

  ckv_map_free(kv);
  test_println("  PASSED");
}

// ============================================================================
// Concurrency Unit Tests - Testing for race conditions
// ============================================================================

// Test for use-after-free in iterate while unset happens concurrently
typedef struct {
  ckv_map *kv;
  atomic_bool stop;
  atomic_int iterations;
} iterate_unset_test_ctx;

static bool slow_iterate_cb(const char *key, const char *val, void *data) {
  iterate_unset_test_ctx *ctx = data;
  (void)key;
  // Access the value to trigger use-after-free if memory was freed
  if (val) {
    volatile char c = val[0];
    (void)c;
  }
  atomic_fetch_add(&ctx->iterations, 1);
  // Small delay to increase chance of race
  usleep(100);
  return !atomic_load(&ctx->stop);
}

static void *iterate_thread(void *arg) {
  iterate_unset_test_ctx *ctx = arg;
  while (!atomic_load(&ctx->stop)) {
    ckv_map_iterate(ctx->kv, (ckv_map_iterate_callback)slow_iterate_cb, ctx);
  }
  return NULL;
}

static void *unset_thread(void *arg) {
  iterate_unset_test_ctx *ctx = arg;
  const char *keys[] = {"key0", "key1", "key2", "key3", "key4"};
  int num_keys = sizeof(keys) / sizeof(keys[0]);

  while (!atomic_load(&ctx->stop)) {
    // Add keys
    for (int i = 0; i < num_keys; i++) {
      ckv_map_set(ctx->kv, (void*)keys[i], "value");
    }
    // Remove keys - this should trigger key_remove_cb
    for (int i = 0; i < num_keys; i++) {
      ckv_map_unset(ctx->kv, (void*)keys[i]);
    }
  }
  return NULL;
}

static void test_iterate_unset_race(void) {
  test_println("test_iterate_unset_race (testing for use-after-free)");

  ckv_map *kv = ckv_map_str_create(0);

  // Pre-populate with some keys
  for (int i = 0; i < 10; i++) {
    char key[32], val[32];
    snprintf(key, sizeof(key), "init%d", i);
    snprintf(val, sizeof(val), "val%d", i);
    ckv_map_set(kv, key, val);
  }

  iterate_unset_test_ctx ctx = {
    .kv = kv,
    .stop = false,
    .iterations = 0,
  };

  pthread_t iter_tid, unset_tid;
  pthread_create(&iter_tid, NULL, iterate_thread, &ctx);
  pthread_create(&unset_tid, NULL, unset_thread, &ctx);

  // Run for a short time to try to trigger the race
  usleep(500000);  // 500ms

  atomic_store(&ctx.stop, true);

  pthread_join(iter_tid, NULL);
  pthread_join(unset_tid, NULL);

  test_println("  Completed %d iterations without crash", atomic_load(&ctx.iterations));

  ckv_map_free(kv);
  test_println("  PASSED (no crash - but race may still exist)");
}

// ============================================================================
// Stress/Integration Tests
// ============================================================================

static const unsigned NUM_ENTRIES = 4096;
static const unsigned NUM_REMOVE_TESTS = NUM_ENTRIES - 100;
static const unsigned MAX_LEN = 128;
#define NUM_THREADS 32

static ckv_map *_dump_kv = NULL;
static pthread_t threads[NUM_THREADS];

static bool stress_iterate(const char *key, const char *val, void *data) {
  (void)key;
  (void)val;
  int *count = data;
  *count = *count + 1;
  return true;
}

static bool stress_iterate_with_abort(const char *key, const char *val, void *data) {
  (void)key;
  (void)val;
  int *count = data;
  *count = *count + 1;
  if (*count == 10)
    return false;
  return true;
}

void dumptable(int signum) {
  signal(signum, SIG_DFL);
  fprintf(stderr, "Abort failed, dumping table");
  if (_dump_kv) {
    for (int i = 0; i < NUM_THREADS; i++) {
      if (!pthread_equal(pthread_self(), threads[i])) {
        pthread_cancel(threads[i]);
      }
    }
    fprintf(stderr, "Dumping table\n");
    FILE *f = fopen("kv_dump.csv", "w");
    ckv_map_debug_dump_table(_dump_kv, f);
    fprintf(stderr, "Done dumping table\n");
    fclose(f);
  }
  abort();
}

void stress_test_kv(ckv_map *kv, bool single, int rounds) {
  test_println("generating random entries");
  char(*entries)[MAX_LEN];
  entries = malloc(sizeof(char[MAX_LEN]) * NUM_ENTRIES);
  assert(entries != NULL);
  char fname[256];
  sprintf(fname, "%u.txt", thread_id);
  FILE *f = fopen(fname, "w");
  for (unsigned i = 0; i < NUM_ENTRIES; i++) {
    gen_random_ascii(entries[i], MAX_LEN);
    fprintf(f, "%s\n", entries[i]);
  }
  fclose(f);
  for (int off = 0; off < rounds; off++) {
    test_println("inserting entries into map");
    for (unsigned i = 0; i < NUM_ENTRIES; i++) {
      assert(ckv_map_set(kv, entries[i], entries[(i + off) % NUM_ENTRIES]) ==
             CKV_MAP_ERROR_NONE);
    }
    if (single) {
      test_println("%i, %u", ckv_map_count(kv), NUM_ENTRIES);
      assert((unsigned)ckv_map_count(kv) == NUM_ENTRIES);
    }
    test_println("Checking entry retrieval consistency");
    for (unsigned i = 0; i < NUM_ENTRIES; i++) {
      char *str = ckv_map_get(kv, entries[i]);
      if (!str) {
        test_println("failed retrieve: %s", entries[i]);
      }
      assert(str);
      assert(strcmp(str, entries[(i + off) % NUM_ENTRIES]) == 0);
      ckv_map_val_unref(kv, str);
    }
    test_println("Randomly removing subset of entries");
    for (unsigned i = 0; i < NUM_REMOVE_TESTS; i++) {
      unsigned j;
      do {
        j = better_rand() % NUM_ENTRIES;
        char *val = ckv_map_get(kv, entries[j]);
        if (val) {
          ckv_map_val_unref(kv, val);
          break;
        }
      } while (1);
      ckv_map_unset(kv, entries[j]);
      assert(ckv_map_get(kv, entries[j]) == NULL);
    }
    unsigned missing_count = 0;
    test_println("Checking entry consistency with num removed");
    for (unsigned i = 0; i < NUM_ENTRIES; i++) {
      char *entry = ckv_map_get(kv, entries[i]);
      if (entry) {
        assert(strcmp(entry, entries[(i + off) % NUM_ENTRIES]) == 0);
      } else {
        missing_count++;
      }
      ckv_map_val_unref(kv, entry);
    }
    assert(missing_count == NUM_REMOVE_TESTS);
    test_println("Checking specific key insert/remove");
    if (single) {
      ckv_map_set(kv, "foo", "bar");
      CKV_MAP_GET_AUTOUNREF(kv, "foo", val,
                              { assert(strcmp(val, "bar") == 0); });
      ckv_map_set(kv, "foo", "baz");
      CKV_MAP_GET_AUTOUNREF(kv, "foo", val,
                              { assert(strcmp("baz", val) == 0); });
      assert(ckv_map_unset(kv, "foo") == true);
      assert(ckv_map_unset(kv, "foo") == false);
    }
    int count = 0;
    test_println("Checking iteration is consistent");
    ckv_map_iterate(kv, (ckv_map_iterate_callback)stress_iterate, &count);
    if (single) {
      test_println("%i, %i, %u", ckv_map_count(kv), count,
                   NUM_ENTRIES - NUM_REMOVE_TESTS);
      assert((unsigned)count == NUM_ENTRIES - NUM_REMOVE_TESTS);
      assert((unsigned)ckv_map_count(kv) == NUM_ENTRIES - NUM_REMOVE_TESTS);
    }
    count = 0;
    ckv_map_iterate(kv, (ckv_map_iterate_callback)stress_iterate_with_abort, &count);
    assert(count == 10);
    test_println("Checking all removal makes sense");
    if (single) {
      ckv_map_empty(kv);
      assert(ckv_map_count(kv) == 0);
    } else {
      for (unsigned i = 0; i < NUM_ENTRIES; i++) {
        ckv_map_unset(kv, entries[i]);
      }
    }
    missing_count = 0;
    for (unsigned i = 0; i < NUM_ENTRIES; i++) {
      CKV_MAP_GET_AUTOUNREF(kv, entries[i], entry, {
        if (entry) {
          assert(strcmp(entry, entries[(i + off) % NUM_ENTRIES]) == 0);
        } else {
          missing_count++;
        }
      });
    }
    assert(missing_count == NUM_ENTRIES);
  }
  free(entries);
}

typedef struct {
  ckv_map *kv;
  int rounds;
} kv_test_thread_args;

void *test_ckv_thread_start(void *args) {
  kv_test_thread_args *a = (kv_test_thread_args *)args;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  thread_id = cur_thread_num++;
  char *thread_name;
  if (asprintf(&thread_name, "thread %i", thread_id) > 0)
    pthread_setname_np(pthread_self(), thread_name);
  srand48_r(seed + thread_id * 12345678, &thread_seed);
  stress_test_kv(a->kv, false, a->rounds);
  free(thread_name);
  return NULL;
}

typedef struct {
  ckv_map *kv;
  const char *key;
} kv_test_thread_continuous_args;

void *test_ckv_continuous_read_thread(void *args) {
  kv_test_thread_continuous_args *a = (kv_test_thread_continuous_args *)args;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  pthread_setname_np(pthread_self(), "kv_continuous_read_thread");
  const char *last_val = NULL;
  for (;;) {
    const char *val = ckv_map_get(a->kv, (void *)a->key);
    if (val) {
      for (uint64_t i = 0; i < UINT64_MAX; i++) {
        if (strcmp(val, "foo") != 0 && strcmp(val, "bar") != 0) {
          test_println("bad value after %" PRIu64 " iteration(s): '%s'", i,
                       val);
          assert(false);
        }
      }
    } else {
      if (last_val) {
        test_println("key disappeared after being set");
        assert(false);
      }
    }
  }
  return NULL;
}

void *test_ckv_continuous_modify_thread(void *args) {
  kv_test_thread_continuous_args *a = (kv_test_thread_continuous_args *)args;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  pthread_setname_np(pthread_self(), "kv_continuous_modify_thread");
  for (;;) {
    ckv_map_set(a->kv, (void *)a->key, "foo");
    ckv_map_set(a->kv, (void *)a->key, "bar");
  }
  return NULL;
}

static void run_stress_tests(void) {
  test_println("=== STRESS TESTS ===");

  ckv_map *kv = ckv_map_str_create(0);
  assert(kv != NULL);

  test_println("running single threaded stress test");
  stress_test_kv(kv, true, 1);

  test_println("running multi threaded stress test");
  ckv_map_empty(kv);
  _dump_kv = kv;

  kv_test_thread_args test_thread_args = {
      .kv = kv,
      .rounds = 10,
  };
  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_create(&(threads[i]), NULL, test_ckv_thread_start,
                   &test_thread_args);
  }
  kv_test_thread_continuous_args test_thread_continuous_args = {
      .kv = kv,
      .key = "dontcare!",
  };
  pthread_t continuous_read_thread, continuous_modify_thread;
  pthread_create(&continuous_read_thread, NULL, test_ckv_continuous_read_thread,
                 &test_thread_continuous_args);
  pthread_create(&continuous_modify_thread, NULL,
                 test_ckv_continuous_modify_thread,
                 &test_thread_continuous_args);
  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  pthread_cancel(continuous_read_thread);
  pthread_cancel(continuous_modify_thread);
  pthread_join(continuous_read_thread, NULL);
  pthread_join(continuous_modify_thread, NULL);
  ckv_map_free(kv);

  test_println("=== STRESS TESTS PASSED ===");
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
  thread_id = cur_thread_num++;
  struct timespec s;
  clock_gettime(CLOCK_MONOTONIC_RAW, &s);
  seed = 193725964;
  srand48_r(seed, &thread_seed);
  test_println("using seed %u", seed);

  bool run_stress = false;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--stress") == 0) {
      run_stress = true;
    }
  }

  // Unit tests - always run
  test_println("=== UNIT TESTS ===");
  test_create_destroy();
  test_create_requires_callbacks();
  test_basic_set_get();
  test_set_overwrite();
  test_unset();
  test_iterate();
  test_iterate_abort();
  test_empty();
  test_print();

  // Concurrency unit tests
  test_println("=== CONCURRENCY UNIT TESTS ===");
  test_iterate_unset_race();

  test_println("=== UNIT TESTS PASSED ===");

  // Stress tests - only with --stress flag
  if (run_stress) {
    run_stress_tests();
  } else {
    test_println("Skipping stress tests (use --stress to run)");
  }

  return 0;
}
