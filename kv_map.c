#include <fnv1a_hashes.h>
#include <inttypes.h>
#include <kv_map.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KV_MAP_START_SIZE_DEFAULT 32

#ifdef KV_MAP_DEBUG
#define KV_MAP_DEBUG_PRINT(...)                                                \
  do {                                                                         \
    fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);                            \
    fprintf(stderr, __VA_ARGS__);                                              \
    fprintf(stderr, "\n");                                                     \
  } while (0)
#else
#define KV_MAP_DEBUG_PRINT(...)                                                \
  while (0) {                                                                  \
  }
#endif

static char *KV_REMOVED_MARKER = "REMOVED";

typedef struct {
  char *key;
  char *val;
} _kv_pair;

struct kv_map {
  kv_map_size_t count;
  kv_map_size_t
      mask; /* The bits that are mapped to the table, representing table
          size - 1. IE, if table size is 32, that's 0x20 and mask is 0x1F */
  _kv_pair *table;
  kv_map_create_params p;
};

const char *kv_map_error_messages_table[] = {
    [KV_MAP_ERROR_NONE] = "No error",
    [KV_MAP_ERROR_OUT_OF_MEMORY] = "Out of memory",
    [KV_MAP_ERROR_KEY_INSERT_HOOK_FAILED] = "Key insert hook failed",
    [KV_MAP_ERROR_VAL_INSERT_HOOK_FAILED] = "Value insert hook failed",
    [KV_MAP_ERROR_FULL] = "Map is full",
};

const char *kv_map_error_messages(enum kv_map_error err) {
  return kv_map_error_messages_table[err];
}

#define RETURN_CASE_STRING(x)                                                  \
  case x:                                                                      \
    return #x

const char *kv_map_error_name(enum kv_map_error err) {
  switch (err) {
    RETURN_CASE_STRING(KV_MAP_ERROR_NONE);
    RETURN_CASE_STRING(KV_MAP_ERROR_OUT_OF_MEMORY);
    RETURN_CASE_STRING(KV_MAP_ERROR_KEY_INSERT_HOOK_FAILED);
    RETURN_CASE_STRING(KV_MAP_ERROR_VAL_INSERT_HOOK_FAILED);
    RETURN_CASE_STRING(KV_MAP_ERROR_FULL);
  default:
    return "Unknown error";
  }
}

kv_map *kv_map_create(kv_map_create_params create_params) {
  int bitcount = 0;
  kv_map_size_t size = create_params.size;
  if (size == 0) {
    size = KV_MAP_START_SIZE_DEFAULT;
  }
  for (int i = 0; i < sizeof(int) * 8; i++) {
    if ((size >> i & 1) == 1) {
      bitcount++;
    }
  }
  if (bitcount != 1) {
    KV_MAP_DEBUG_PRINT("Size must be a power of 2");
    return NULL;
  }
  kv_map *kv = malloc(sizeof(kv_map));
  kv->p = create_params;
  if (kv) {
    kv->table = malloc(sizeof(_kv_pair) * size);
    if (kv->table == NULL) {
      free(kv);
      return NULL;
    }
    kv->count = 0;
    kv->mask = size - 1;

    for (int i = 0; i < size; i++) {
      kv->table[i] = (_kv_pair){NULL, NULL};
    }
  }
  return kv;
}

static void _wrap_free(void *ptr, void *user_data) { free(ptr); }

static int _wrap_strcmp(void *a, void *b) { return strcmp(a, b); }

static kv_map_hash_t _wrap_fnv1a32(void *ptr) { return fnv1a_hash32(ptr); }

static kv_map_hash_t _wrap_fnv1a64(void *ptr) { return fnv1a_hash64(ptr); }

static void *_wrap_strdup(void *ptr, void *user_data) { return strdup(ptr); }

static void _str_print_cb(void *key, FILE *stream) {
  fprintf(stream, "%s", (char *)key);
}

kv_map *kv_map_str_create(kv_map_size_t initial_size) {
  kv_map_create_params p = {
      .size = initial_size,
      .hash_func = sizeof(kv_map_hash_t) == 8 ? _wrap_fnv1a64 : _wrap_fnv1a32,
      .key_insert_cb = _wrap_strdup,
      .val_insert_cb = _wrap_strdup,
      .key_remove_cb = _wrap_free,
      .val_remove_cb = _wrap_free,
      .key_cmp_func = _wrap_strcmp,
      .key_print_func = _str_print_cb,
      .val_print_func = _str_print_cb,
  };
  return kv_map_create(p);
}

static kv_map_size_t _kv_map_search_index_for_insert(kv_map *kv, void *key) {
  kv_map_size_t index = kv->p.hash_func(key) & kv->mask;
  _kv_pair candidate;
  for (;;) {
    candidate = kv->table[index];
    if (candidate.key == NULL || kv->p.key_cmp_func(candidate.key, key) == 0) {
      return index;
    }
    index = (index + 1) & kv->mask;
  }
}

static kv_map_size_t _kv_map_search_index_for_lookup(kv_map *kv, void *key) {
  kv_map_size_t start_index = _kv_map_search_index_for_insert(kv, key);
  _kv_pair candidate;
  kv_map_size_t index = start_index;
  int count = 0;
  for (;;) {
    candidate = kv->table[index];
    if ((candidate.key == NULL && candidate.val != KV_REMOVED_MARKER)) {
      if (count) {
        KV_MAP_DEBUG_PRINT("Max probed: %u", count);
      }
      return index;
    } else if (candidate.key != NULL &&
               kv->p.key_cmp_func(candidate.key, key) == 0) {
      if (index != start_index) {
        KV_MAP_DEBUG_PRINT("Moving %" KV_MAP_SIZE_PRI " to %" KV_MAP_SIZE_PRI,
                           index, start_index);
        // Move the entry closer to hash index
        kv->table[start_index] = kv->table[index];
        kv->table[index].key = NULL;
        if (kv->table[(index + 1) & kv->mask].val != NULL) {
          kv->table[index].val = KV_REMOVED_MARKER;
        } else {
          KV_MAP_DEBUG_PRINT("Move was at a termination point");
          kv->table[index].val = NULL;
        }
        return start_index;
      } else {
        return index;
      }
    }
    index = (index + 1) & kv->mask;
    count++;
    // We have looped around, so just return free index
    if (index == start_index) {
      return index;
    }
  };
  return index;
}

void *kv_map_get(kv_map *kv, void *key) {
  _kv_pair candidate = kv->table[_kv_map_search_index_for_lookup(kv, key)];
  return candidate.val;
}

static void _kv_map_reindex(kv_map *kv) {
  for (kv_map_size_t i = 0; i <= kv->mask; i++) {
    _kv_pair kv_pair = kv->table[i];
    if (kv_pair.key != NULL) {
      kv_map_size_t index = _kv_map_search_index_for_insert(kv, kv_pair.key);
      if (index == i) {
        continue;
      } else {
        kv->table[index] = kv->table[i];
        kv->table[i].key = NULL;
        if (kv->table[(i + 1) & kv->mask].val != NULL) {
          kv->table[i].val = KV_REMOVED_MARKER;
        } else {
          kv->table[i].val = NULL;
        }
      }
    }
  }
  // Lookup all kv pairs to move into removed entries
  for (kv_map_size_t i = 0; i <= kv->mask; i++) {
    _kv_pair kv_pair = kv->table[i];
    if (kv_pair.key != NULL) {
      _kv_map_search_index_for_lookup(kv, kv_pair.key);
    }
  }
  // Remove all removed entires
  for (kv_map_size_t i = 0; i <= kv->mask; i++) {
    _kv_pair kv_pair = kv->table[i];
    if (kv_pair.val == KV_REMOVED_MARKER) {
      kv_pair.val = NULL;
    }
  }
}

static bool _kv_map_inplace_expand(kv_map *kv) {
  int size = kv->mask + 1;
  _kv_pair *new_table = realloc(kv->table, sizeof(_kv_pair) * (size)*2);
  if (!new_table) {
    return false;
  }
  kv->table = new_table;
  for (int i = size; i < size * 2; i++) {
    kv->table[i] = (_kv_pair){NULL, NULL};
  }
  kv->mask = (kv->mask << 1) | 1;
  _kv_map_reindex(kv);
  return true;
}

enum kv_map_error kv_map_set(kv_map *kv, void *key, void *val) {
  if (!(kv->p.flags & KV_MAP_FLAG_RESIZE_DISABLED) &&
      kv->count == (kv->mask / 2)) {
    if (!_kv_map_inplace_expand(kv)) {
      KV_MAP_DEBUG_PRINT("Failed to expand kv map");
      return KV_MAP_ERROR_OUT_OF_MEMORY;
    }
  } else if (kv->count == kv->mask) {
    KV_MAP_DEBUG_PRINT("kv map is full");
    return KV_MAP_ERROR_FULL;
  }
  kv_map_hash_t index = _kv_map_search_index_for_insert(kv, key);
  // KV_MAP_DEBUG_PRINT("%"KV_MAP_SIZE_PRI"\n", index);
  _kv_pair candidate = kv->table[index];
  char *_key = (char *)key;
  char *_val = (char *)val;
  // If the key is empty, add a new key
  if (candidate.key == NULL) {
    if (kv->p.key_insert_cb) {
      _key = kv->p.key_insert_cb(key, kv->p.cb_user_data);
      if (!_key) {
        return KV_MAP_ERROR_KEY_INSERT_HOOK_FAILED;
      }
    } else {
      _key = key;
    }
  } else {
    // Othwerise retain the key and free the old value
    _key = candidate.key;
    if (kv->p.val_remove_cb) {
      kv->p.val_remove_cb(candidate.val, kv->p.cb_user_data);
    }
    kv->count--;
  }
  if (kv->p.val_insert_cb) {
    _val = kv->p.val_insert_cb(val, kv->p.cb_user_data);
    if (!_val) {
      if (kv->p.key_remove_cb) {
        kv->p.key_remove_cb(_key, kv->p.cb_user_data);
      }
      return KV_MAP_ERROR_VAL_INSERT_HOOK_FAILED;
    }
  }
  candidate.key = _key;
  candidate.val = _val;
  kv->table[index] = candidate;
  kv->count++;
  return KV_MAP_ERROR_NONE;
}

bool kv_map_unset(kv_map *kv, void *key) {
  kv_map_size_t index = _kv_map_search_index_for_lookup(kv, key);
  _kv_pair candidate = kv->table[index];
  if (candidate.key) {
    if (kv->p.key_remove_cb) {
      kv->p.key_remove_cb(candidate.key, kv->p.cb_user_data);
    }
    if (kv->p.val_remove_cb) {
      kv->p.val_remove_cb(candidate.val, kv->p.cb_user_data);
    }
    candidate.key = NULL;
    candidate.val =
        KV_REMOVED_MARKER; // Marks 'was present' to keep probing intact
    kv->table[index] = candidate;
    kv->count--;
    return true;
  }
  return false;
}

kv_map_size_t kv_map_count(kv_map *kv) { return kv->count; }

bool kv_map_iterate(kv_map *kv, kv_map_iterate_callback callback, void *data) {
  for (int i = 0; i <= kv->mask; i++) {
    _kv_pair kv_pair = kv->table[i];
    if (kv_pair.key) {
      if (!callback(kv_pair.key, kv_pair.val, data)) {
        return false;
      }
    }
  }
  return true;
}

void kv_map_print(kv_map *kv, FILE *fp) {
  fprintf(fp, "{\n");
  bool comma = false;
  for (kv_map_size_t i = 0; i <= kv->mask; i++) {
    if (kv->table[i].key) {
      if (comma) {
        fprintf(fp, ",\n");
      }
      fprintf(fp, "\t\"%s\": \"%s\"", kv->table[i].key, kv->table[i].val);
      comma = true;
    }
  }
  fprintf(fp, "\n}\n");
}

void kv_map_empty(kv_map *kv) {
  for (kv_map_size_t i = 0; i <= kv->mask; i++) {
    if (kv->table[i].key) {
      if (kv->p.key_remove_cb) {
        kv->p.key_remove_cb(kv->table[i].key, kv->p.cb_user_data);
      }
      if (kv->p.val_remove_cb) {
        kv->p.val_remove_cb(kv->table[i].val, kv->p.cb_user_data);
      }
      kv->table[i].key = NULL;
      kv->table[i].val = NULL;
    }
  }
  kv->count = 0;
}

void kv_map_free(kv_map *kv) {
  kv_map_empty(kv);
  free(kv->table);
  free(kv);
}
