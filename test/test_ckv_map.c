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

static const unsigned NUM_ENTRIES = 4096;
static const unsigned NUM_REMOVE_TESTS = NUM_ENTRIES - 100;
static const unsigned MAX_LEN = 128;
#define NUM_THREADS 32

static int __thread thread_id;
static struct drand48_data __thread thread_seed;
static unsigned int seed;
static atomic_int cur_thread_num = 0;

#define test_println(fmt, ...)                                                 \
  printf("test_thread %i: " fmt "\n", thread_id, ##__VA_ARGS__)

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

static ckv_map *_dump_kv = NULL;
static pthread_t threads[NUM_THREADS];

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

void test_kv(ckv_map *kv, bool single, int rounds) {
  test_println("generating random entries");
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
    test_println("inserting entries into map");
    // Deterministically associate keys and values
    for (int i = 0; i < NUM_ENTRIES; i++) {
      assert(ckv_map_set(kv, entries[i], entries[(i + off) % NUM_ENTRIES]) ==
             CKV_MAP_ERROR_NONE);
    }
    //
    if (single) {
      test_println("%i, %i", ckv_map_count(kv), NUM_ENTRIES);
      assert(ckv_map_count(kv) == NUM_ENTRIES);
    }
    test_println("Checking entry retrieval consistency");
    for (int i = 0; i < NUM_ENTRIES; i++) {
      char *str = ckv_map_get(kv, entries[i]);
      if (!str) {
        test_println("failed retrieve: %s", entries[i]);
      }
      assert(str);
      assert(strcmp(str, entries[(i + off) % NUM_ENTRIES]) == 0);
      ckv_map_val_unref(kv, str);
    }
    test_println("Randomly removing subset of entries");
    for (int i = 0; i < NUM_REMOVE_TESTS; i++) {
      int j;
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
    int missing_count = 0;
    // TODO check missing based on iteration with our set of keys
    test_println("Checking entry consistency with num removed");
    for (int i = 0; i < NUM_ENTRIES; i++) {
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
    ckv_map_iterate(kv, (ckv_map_iterate_callback)iterate, &count);
    if (single) {
      test_println("%i, %i, %i", ckv_map_count(kv), count,
                   NUM_ENTRIES - NUM_REMOVE_TESTS);
      assert(count == NUM_ENTRIES - NUM_REMOVE_TESTS);
      assert(ckv_map_count(kv) == NUM_ENTRIES - NUM_REMOVE_TESTS);
    }
    count = 0;
    ckv_map_iterate(kv, (ckv_map_iterate_callback)iterate_with_abort, &count);
    assert(count == 10);
    test_println("Checking all removal makes sense");
    if (single) {
      ckv_map_empty(kv);
      assert(ckv_map_count(kv) == 0);
    } else {
      for (int i = 0; i < NUM_ENTRIES; i++) {
        ckv_map_unset(kv, entries[i]);
      }
    }
    missing_count = 0;
    for (int i = 0; i < NUM_ENTRIES; i++) {
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

#include <unistd.h>

typedef struct {
  ckv_map *kv;
  int rounds;
} kv_test_thread_args;

void *test_ckv_thread_start(void *args) {
  kv_test_thread_args *a = (kv_test_thread_args *)args;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  thread_id = cur_thread_num++;
  char *thread_name;
  asprintf(&thread_name, "thread %i", thread_id);
  pthread_setname_np(pthread_self(), thread_name);
  srand48_r(seed + thread_id * 12345678, &thread_seed);
  test_kv(a->kv, false, a->rounds);
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

int main(int argc, char **argv) {
  thread_id = cur_thread_num++;
  struct timespec s;
  clock_gettime(CLOCK_MONOTONIC_RAW, &s);
  // seed = s.tv_nsec;
  seed = 193725964;
  srand48_r(seed, &thread_seed);
  test_println("using seed %u\n", seed);
  test_println("testing creation\n");
  ckv_map *kv = ckv_map_str_create(0);
  assert(kv != NULL);
  test_println("running single threaded test");
  test_kv(kv, true, 1);
  test_println("running multi threaded test with no overlapping keys/vals");
  ckv_map_empty(kv);
  _dump_kv = kv;
  //  signal(SIGABRT, dumptable);
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
  test_println("checking generic map creation\n");
  kv = ckv_map_create((ckv_map_create_params){
      .size = 100,
  });
  assert(kv == NULL);
  // Require hash_func and key_cmp_func
  kv = ckv_map_create((ckv_map_create_params){.size = 0});
  assert(kv == NULL);
  kv = ckv_map_str_create(0);
  ckv_map_set(kv, "foo", "bar");
  char *str_rep;
  size_t str_size;
  FILE *f = open_memstream(&str_rep, &str_size);
  ckv_map_print(kv, f);
  fclose(f);
  assert(strcmp(str_rep, "{\n\t\"foo\": \"bar\"\n}\n") == 0);
  free(str_rep);
  ckv_map_free(kv);
  return 0;
}
