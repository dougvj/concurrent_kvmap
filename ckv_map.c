#define _GNU_SOURCE
#include "fnv1a_hashes.h"
#include "platform.h"
#include <assert.h>
#include <inttypes.h>
#include "ckv_map.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <refcnt.h>

static void *CKV_REMOVED_MARKER = "REMOVED";
static void *CKV_MOVING_MARKER = "MOVING";

#define CKV_MIN_SIZE 4096

#ifdef ENABLE_DEBUG
#define CKV_MAP_DEBUG(s, ...)                                                   \
  fprintf(stderr, "%s:%u: " s "\n", __FILE__, __LINE__, ##__VA_ARGS__);
#else
#define CKV_MAP_DEBUG(...)                                                      \
  while (0)                                                                    \
    ;
#endif

#if __SIZEOF_POINTER__ == 8
typedef __uint128_t _ckv_int_ptr_entry;
#elif __SIZEOF_POINTER__ == 4
typedef __uint64_t _ckv_int_ptr_entry;
#else
#error "Incompatible machine"
#endif
typedef ckv_map_size _ckv_index;
#define CKV_INDEX_FMT PRIuFAST32
typedef atomic_uint_fast32_t _ckv_atomic_index;

typedef struct {
  union {
    struct {
      void *key;
      void *val;
    };
    _Atomic _ckv_int_ptr_entry intval;
  };
} _ckv_entry;

typedef struct {
  _ckv_entry entry;
  _ckv_entry prev;
  _ckv_index start_index;
  _ckv_index index;
  _ckv_index mask;
} _ckv_search_result;

// Retired item node for deferred freeing
typedef struct _ckv_retired_item {
  struct _ckv_retired_item *next;
  void *ptr;
  bool is_key;  // true = use key_remove_cb, false = use val_remove_cb
} _ckv_retired_item;

struct ckv_map {
  _ckv_atomic_index count;
  _ckv_index
      mask; /* The bits that are mapped to the table, representing table
          size - 1. IE, if table size is 32, that's 0x20 and mask is 0x1F */
  _ckv_int_ptr_entry *_Atomic table;
  _Atomic bool is_resizing;
  atomic_int table_refs;
  _Atomic(_ckv_retired_item *) retired_head;  // Lock-free stack of retired items
  ckv_map_insert_callback key_insert_cb;
  ckv_map_remove_callback key_remove_cb;
  ckv_map_insert_callback val_insert_cb;
  ckv_map_remove_callback val_remove_cb;
  ckv_map_ref_callback key_ref_cb;
  ckv_map_ref_callback val_ref_cb;
  ckv_map_unref_callback key_unref_cb;
  ckv_map_unref_callback val_unref_cb;
  void *callback_user_data;
  ckv_map_hash_function hash_func;
  ckv_map_key_cmp_func key_cmp_func;
  ckv_map_print_func key_print_func;
  ckv_map_print_func val_print_func;
  enum ckv_map_flags flags;
};

// Push an item to the retired list (lock-free Treiber stack)
static void _ckv_retire_item(ckv_map *kv, void *ptr, bool is_key) {
  if (!ptr) return;
  _ckv_retired_item *item = malloc(sizeof(_ckv_retired_item));
  if (!item) return;  // Best effort - leak on OOM
  item->ptr = ptr;
  item->is_key = is_key;
  _ckv_retired_item *old_head;
  do {
    old_head = atomic_load(&kv->retired_head);
    item->next = old_head;
  } while (!atomic_compare_exchange_weak(&kv->retired_head, &old_head, item));
}

// Drain and free all retired items (call when no threads are accessing)
static void _ckv_drain_retired(ckv_map *kv) {
  // Atomically take the entire list
  _ckv_retired_item *head = atomic_exchange(&kv->retired_head, NULL);
  while (head) {
    _ckv_retired_item *next = head->next;
    if (head->is_key) {
      if (kv->key_remove_cb) {
        kv->key_remove_cb(head->ptr, kv->callback_user_data);
      }
    } else {
      if (kv->val_remove_cb) {
        kv->val_remove_cb(head->ptr, kv->callback_user_data);
      }
    }
    free(head);
    head = next;
  }
}

static _ckv_int_ptr_entry *_ckv_acquire_table_ref(ckv_map *kv) {
  _ckv_int_ptr_entry *table;
  for (;;) {
    atomic_fetch_add(&(kv->table_refs), 1);
    table = kv->table;
    if (table == NULL) {
      atomic_fetch_sub(&(kv->table_refs), 1);
      while (kv->table == NULL) {
      }
      continue;
    } else {
      break;
    }
  }
  return table;
}

static void _ckv_release_table_ref(ckv_map *kv) {
  atomic_fetch_sub(&(kv->table_refs), 1);
}

// Pull kv entry from table
static _ckv_entry get_ckv_entry(ckv_map *kv, _ckv_index index) {
  _ckv_int_ptr_entry *table = _ckv_acquire_table_ref(kv);
  _ckv_entry ret = (_ckv_entry){.intval = table[index]};
  _ckv_release_table_ref(kv);
  return ret;
}

static bool _ckv_val_empty(void *val) {
  return val == NULL || val == CKV_REMOVED_MARKER;
}

// Commit kv entry, if another thread already committed it then this returns
// false and the callee needs to retry
static bool put_ckv_entry_atomic(ckv_map *kv, _ckv_index index, _ckv_entry old_val,
                                _ckv_entry new_val) {
  _ckv_int_ptr_entry *table = _ckv_acquire_table_ref(kv);
  assert(new_val.key != NULL || _ckv_val_empty(new_val.val));
  bool success = __sync_bool_compare_and_swap(&(table[index]), old_val.intval,
                                              new_val.intval);
  _ckv_release_table_ref(kv);
  return success;
}

static const char *const CKV_MAP_ERROR_STRINGS[] = {
    [CKV_MAP_ERROR_NONE] = "No error",
    [CKV_MAP_ERROR_KEY_INSERT_HOOK_FAILED] = "Key insert hook failed",
    [CKV_MAP_ERROR_VAL_INSERT_HOOK_FAILED] = "Value insert hook failed",
    [CKV_MAP_ERROR_OUT_OF_MEMORY] = "Out of memory",
    [CKV_MAP_ERROR_FULL] = "Map is full",
    [CKV_MAP_ERROR_INTERRUPTED] = "Read modify write interrupted",
};

const char *ckv_map_error_message(enum ckv_map_error error) {
  return CKV_MAP_ERROR_STRINGS[error];
}

static const char *const CKV_MAP_ERROR_NAMES[] = {
    [CKV_MAP_ERROR_NONE] = "CKV_MAP_ERROR_NONE",
    [CKV_MAP_ERROR_OUT_OF_MEMORY] = "CKV_MAP_ERROR_OUT_OF_MEMORY",
    [CKV_MAP_ERROR_KEY_INSERT_HOOK_FAILED] =
        "CKV_MAP_ERROR_KEY_INSERT_HOOK_FAILED",
    [CKV_MAP_ERROR_VAL_INSERT_HOOK_FAILED] =
        "CKV_MAP_ERROR_VAL_INSERT_HOOK_FAILED",
    [CKV_MAP_ERROR_FULL] = "CKV_MAP_ERROR_FULL",
    [CKV_MAP_ERROR_INTERRUPTED] = "CKV_MAP_ERROR_INTERRUPTED",
};

const char *ckv_map_error_name(enum ckv_map_error error) {
  return CKV_MAP_ERROR_NAMES[error];
}

ckv_map *ckv_map_create(ckv_map_create_params create_params) {
  // Require hash and comparison functions
  if (!create_params.hash_func || !create_params.key_cmp_func) {
    CKV_MAP_DEBUG("hash_func and key_cmp_func are required");
    return NULL;
  }
  uint_fast32_t size = create_params.size;
  if (!size) {
    size = 32;
  } else {
    int bitcount = 0;
    for (size_t i = 0; i < sizeof(ckv_map_size) * 8; i++) {
      if ((size >> i & 1) == 1) {
        bitcount++;
      }
    }
    if (bitcount != 1) {
      return NULL;
    }
  }
  if (size < CKV_MIN_SIZE) {
    size = CKV_MIN_SIZE;
  }
  ckv_map *kv = malloc(sizeof(ckv_map));
  if (kv) {
    kv->table = platform_region_alloc(size * sizeof(_ckv_int_ptr_entry));
    if (kv->table == NULL) {
      free(kv);
      return NULL;
    }
    kv->table_refs = 0;
    kv->count = 0;
    kv->mask = size - 1;
    kv->is_resizing = false;
    kv->retired_head = NULL;
    kv->key_insert_cb = create_params.key_insert_cb;
    kv->key_remove_cb = create_params.key_remove_cb;
    kv->val_insert_cb = create_params.val_insert_cb;
    kv->val_remove_cb = create_params.val_remove_cb;
    kv->key_ref_cb = create_params.key_ref_cb;
    kv->val_ref_cb = create_params.val_ref_cb;
    kv->key_unref_cb = create_params.key_unref_cb;
    kv->val_unref_cb = create_params.val_unref_cb;
    kv->callback_user_data = create_params.callback_user_data;
    kv->hash_func = create_params.hash_func;
    kv->key_cmp_func = create_params.key_cmp_func;
    kv->key_print_func = create_params.key_print_func;
    kv->val_print_func = create_params.val_print_func;
    kv->flags = create_params.flags;
    // NULL may not be 0, but it's basically impossible
    assert(NULL == 0);
#ifdef CKV_MAP_LOCKS_ENABLED
    platform_rwlock_init(&(kv->rwlock));
#endif
  }
  return kv;
}

static void *_refcnt_strdup_wrap(void *str, void *user_data) {
  (void)user_data;
  return refcnt_strdup(str);
}

static void _refcnt_unref_wrap(void *ptr, void *user_data) {
  (void)user_data;
  refcnt_unref(ptr);
}

static void *_refcnt_ref_wrap(void *ptr, void *user_data) {
  (void)user_data;
  return refcnt_ref(ptr);
}


static void _fputs(void *s, FILE *stream) { fputs(s, stream); }

static int _strcmp(void *a, void *b) { return strcmp(a, b); }

ckv_map *ckv_map_str_create(uint_fast32_t size) {
  return ckv_map_create((ckv_map_create_params){
      .size = size,
      .key_insert_cb = _refcnt_strdup_wrap,
      .val_insert_cb = _refcnt_strdup_wrap,
      .key_remove_cb = _refcnt_unref_wrap,
      .val_remove_cb = _refcnt_unref_wrap,
      .key_ref_cb = _refcnt_ref_wrap,
      .val_ref_cb = _refcnt_ref_wrap,
      .key_unref_cb = _refcnt_unref_wrap,
      .val_unref_cb = _refcnt_unref_wrap,
      .hash_func =
          ((sizeof(uint_fast32_t) == 4) ? (ckv_map_hash_function)fnv1a_hash32
                                        : (ckv_map_hash_function)fnv1a_hash64),
      .key_cmp_func = _strcmp,
      .val_print_func = _fputs,
      .key_print_func = _fputs,
      //      .flags = CKV_MAP_RESIZE_DISABLED,
  });
}

void ckv_map_debug_dump_table(ckv_map *kv, FILE *f) {
  fprintf(f, "idx,hash,key,val\n");
  for (_ckv_index i = 0; i <= kv->mask; i++) {
    _ckv_entry entry = get_ckv_entry(kv, i);
    _ckv_index hash = 0;
    if (_ckv_val_empty(entry.val)) {
      entry.key = NULL;
    } else {
      hash = kv->hash_func(entry.key) & kv->mask;
    }
    if (entry.val != NULL) {
      fprintf(f, "%" CKV_INDEX_FMT ",%" PRIuFAST32 ",%s,%s\n", i, hash,
              (char *)entry.key, (char *)entry.val);
    }
  }
}

// Performs a move of an entry from one location to another. The move maintains
// thready safety by marking the source entry as "moving" and then completes
// the move to the destination, unmarking the source destination as "moving" to
// "removed"
static bool _ckv_map_move_entry(ckv_map *kv, uint_fast32_t old_location,
                               _ckv_entry old_location_val,
                               uint_fast32_t new_location,
                               _ckv_entry new_location_val, bool null_entry) {
  _ckv_entry old_location_val_moving_marker = old_location_val;
  old_location_val_moving_marker.val = CKV_MOVING_MARKER;
  _ckv_entry old_location_val_removed_marker = old_location_val;
  old_location_val_removed_marker.val = null_entry ? NULL : CKV_REMOVED_MARKER;
  old_location_val_removed_marker.key = NULL;
  if (put_ckv_entry_atomic(kv, old_location, old_location_val,
                          old_location_val_moving_marker)) {
    if (put_ckv_entry_atomic(kv, new_location, new_location_val,
                            old_location_val)) {
      if (!put_ckv_entry_atomic(kv, old_location, old_location_val_moving_marker,
                               old_location_val_removed_marker)) {
        goto should_never;
      }
      return true;
    } else if (!put_ckv_entry_atomic(kv, old_location,
                                    old_location_val_moving_marker,
                                    old_location_val)) {
      goto should_never;
    }
  }
  // Move aborted
  return false;
should_never:
  CKV_MAP_DEBUG("This should never occur!!!");
  assert(false);
  return false;
}

static void *CKV_UNINIT = "UNINIT";

#define UNREF_KEY(kv, key)                                                 \
  do {                                                                     \
    if (kv->key_unref_cb && key) {                                                \
      kv->key_unref_cb(key, kv->callback_user_data);                       \
    }                                                                      \
  } while (0)

#define REF_KEY(kv, key)                                                   \
  do {                                                                     \
    if (kv->key_ref_cb && key) {                                                  \
      key = kv->key_ref_cb(key, kv->callback_user_data);                         \
    }                                                                      \
  } while (0)

// Performs the search for the entry with the given key. The search starts with
// the hash of the key and then probes until an empty entry is found. An entry
// may be found at a different point due to a table resize, so the search is
// repeated with a smaller table mask until either the key is found or an empty
// entry is encountered. If the key entry is not found, the first empty or
// removed entry is returned at the correct table size
//
// The search returns the index of the entry, the entry value, the original
// index (start of probe) and the value of the previous entry to detect an edge
// of cluster removal (see how this is used in ckv_map_set and ckv_map_unset)
static _ckv_search_result _ckv_map_search_index(ckv_map *kv, void *key) {
  // Define the mask for the table and the hash
  _ckv_index mask = kv->mask;
  _ckv_index orig_mask = kv->mask;
  _ckv_index hash = kv->hash_func(key);
  _ckv_index optimal_index = 0;
  _ckv_entry optimal_entry = {};
  _ckv_index original_start_index = hash & mask;
  _ckv_entry prev = {};
  _ckv_entry optimal_prev = {};
probe:
  for (;;) {
    _ckv_index start_index = hash & mask;
    _ckv_index index = start_index;
    _ckv_entry entry = {.val = CKV_UNINIT};
#ifdef ENABLE_DEBUG
    int count = 0;
#endif
    for (;;) {
      prev = entry;
      entry = get_ckv_entry(kv, index);
      // If we found a NULL, then that means that we are done searching and
      // didn't find our entry
      void* entry_key = entry.key;
      REF_KEY(kv, entry_key);
      if (entry.val == NULL) {
#ifdef ENABLE_DEBUG
        /*if (count > 20) {
          CKV_MAP_DEBUG("perf: max probed: %u", count);
        }*/
#endif
        // If we haven't found our optimal entry and this is the first sweep,
        // set the optimal entry to this
        if (optimal_entry.val == NULL && mask == orig_mask) {
          optimal_entry = entry;
          optimal_prev = prev;
          optimal_index = index;
        }
        // We didn't find a entry. Should we search with a samller mask?
        for (;;) {
          // If we reach the minimum mask size, return the optimal entry
          if (mask == (CKV_MIN_SIZE - 1)) {
            return (_ckv_search_result){.prev = optimal_prev,
                                       .entry = optimal_entry,
                                       .index = optimal_index,
                                       .start_index = original_start_index,
                                       .mask = mask};
          }
          mask >>= 1;
          // If our start index is not the same with the new mask then we
          // probe, otherwise we try the next mask
          // if (start_index != (hash & mask)) {
          goto probe;
          //}
        }
      } else if (_ckv_val_empty(entry.val)) {
        if (optimal_entry.val == NULL && mask == orig_mask) {
          // Set the optimal entry
          optimal_index = index;
          optimal_entry = entry;
          optimal_prev = prev;
        }
      } else if (entry_key && kv->key_cmp_func(entry_key, key) == 0) {
        // We found our entry. Move to optimal entry if we have one
        if (optimal_index != index && optimal_entry.val != NULL) {
          long jump_size = labs((long)index - (long)optimal_index);
          if (jump_size > 10) {
            CKV_MAP_DEBUG("moving %" CKV_INDEX_FMT " spaces %" CKV_INDEX_FMT
                         " to %" CKV_INDEX_FMT,
                         jump_size, index, optimal_index);
          }
          // Move the entry closer to hash index
          bool null_entry = get_ckv_entry(kv, (index + 1) & mask).val == NULL;
          if (_ckv_map_move_entry(kv, index, entry, optimal_index, optimal_entry,
                                 null_entry)) {
            UNREF_KEY(kv, entry_key);
            return (_ckv_search_result){.prev = optimal_prev,
                                       // TODO deal with resizable, perhaps
                                       // platform.h and platform.c and remap?
                                       .index = optimal_index,
                                       .entry = entry,
                                       .start_index = original_start_index,
                                       .mask = mask};
          }
          CKV_MAP_DEBUG("move failure");
        }
        UNREF_KEY(kv, entry_key);
        return (_ckv_search_result){.prev = prev,
                                   .index = index,
                                   .entry = entry,
                                   .start_index = original_start_index,
                                   .mask = mask};
      }
      // Probe next index
      UNREF_KEY(kv, entry_key);
      index = (index + 1) & mask;
#ifdef ENABLE_DEBUG
      count++;
      assert(count != kv->mask && "Linear probe should never be infinite");
#endif
    };
  };
}

void *ckv_map_get(ckv_map *kv, void *key) {
  _ckv_entry entry;
  for (int count = 0;; count++) {
    _ckv_search_result res = _ckv_map_search_index(kv, key);
    entry = res.entry;
    if (entry.val != CKV_MOVING_MARKER) {

      if(_ckv_val_empty(entry.val)) {
        return NULL;
      } else {
        if (kv->val_ref_cb) {
          return kv->val_ref_cb(entry.val, kv->callback_user_data);
        }
        return entry.val;
      };
    } else {
      CKV_MAP_DEBUG("Encountered Moving");
      if (count > 100) {
        CKV_MAP_DEBUG("KV_MOVING took too long")
        assert(false);
      }
    }
  }
}

void ckv_map_val_unref(ckv_map *kv, void *val) {
  if (kv->val_unref_cb && val) {
    kv->val_unref_cb(val, kv->callback_user_data);
  }
}

void ckv_map_key_unref(ckv_map *kv, void *key) {
  if (kv->key_unref_cb && key) {
    kv->key_unref_cb(key, kv->callback_user_data);
  }
}

static void maybe_unused _ckv_map_reindex(ckv_map *kv) {
  for (_ckv_index i = 0; i <= kv->mask; i++) {
    _ckv_entry kv_entry;
    kv_entry = get_ckv_entry(kv, i);
    if (kv_entry.key != NULL) {
      for (;;) {
        _ckv_search_result res = _ckv_map_search_index(kv, kv_entry.key);
        if (res.index == i) {
          break;
        } else {
          if (_ckv_map_move_entry(kv, i, kv_entry, res.index, res.entry,
                                 false)) {
            break;
          }
        }
      }
    }
  }
  // Lookup all kv entrys to move into removed entries
  for (_ckv_index i = 0; i <= kv->mask; i++) {
    _ckv_entry kv_entry = get_ckv_entry(kv, i);
    if (kv_entry.key != NULL) {
      _ckv_map_search_index(kv, kv_entry.key);
    }
  }
}

#include <unistd.h>

static bool _ckv_map_inplace_expand(ckv_map *kv) {
  bool expected = false;
  if (atomic_compare_exchange_strong(&(kv->is_resizing), &expected, true)) {
    _ckv_index old_len = (kv->mask + 1);
    _ckv_index new_len = old_len * 2;
    _ckv_index old_size = old_len * sizeof(_ckv_entry);
    _ckv_index new_size = new_len * sizeof(_ckv_entry);
    // First try to do this atomically. This is possible on platofrms (such as
    // linux with mremap) that allow expanding atomically without changin
    // pointers. As I understand it, Linux halts the process while it is doing
    // the remap so we are safe to keep any other threads running while doing
    // this.
    //
    // It would be possible to have a remap and move with a _DONTUNMAP flag, but
    // linux doesn't allow resizing in this case. Maybe that will change in the
    // future.

    // First we have to do a full acquire and release
    _ckv_int_ptr_entry *table = _ckv_acquire_table_ref(kv);
    // Do the remap disallowing relocation
    _ckv_int_ptr_entry *new_table = platform_region_expand(table, old_size, new_size, false);
    if (new_table) {
      assert(new_table == table);
      CKV_MAP_DEBUG("Atomic expand succeeded");
      kv->mask = (kv->mask << 1) | 1;
      _ckv_release_table_ref(kv);
      kv->is_resizing = false;
      return true;
    }
    // This makes sure that only one thread owns the pointer making sure that
    // the reference is NULLd atomically
    kv->table = NULL;
    // Wait for any threads using the table ptr
    while (atomic_load(&(kv->table_refs)) > 1)
      ;
    CKV_MAP_DEBUG("Doing non-atomic expand");
    new_table =
        platform_region_expand(table, old_size, new_size, true);
    if (!new_table) {
      CKV_MAP_DEBUG("could not expand, alloc failure");
      return false;
    }
    for (_ckv_index i = old_len; i < new_len; i++) {
      new_table[i] = 0;
    }
    kv->mask = (kv->mask << 1) | 1;
    kv->table = new_table;
    //_ckv_map_reindex(kv);
    kv->is_resizing = false;
    _ckv_release_table_ref(kv);
  } else {
    CKV_MAP_DEBUG("expand already happening elsewhere");
  }
  return true;
}

enum ckv_map_error ckv_map_set(ckv_map *kv, void *key, void *val) {
  void *cb_key = NULL;
  void *cb_val = NULL;
  for (;;) {
    if (!(kv->flags & CKV_MAP_FLAG_RESIZE_DISABLED) &&
        kv->count >= (kv->mask / 8)) {
      if (!_ckv_map_inplace_expand(kv)) {
        return CKV_MAP_ERROR_OUT_OF_MEMORY;
      }
    } else if (kv->count == kv->mask / 2) {
      CKV_MAP_DEBUG("no more space in table");
      return CKV_MAP_ERROR_FULL;
    }
    _ckv_search_result res = _ckv_map_search_index(kv, key);
    _ckv_entry replacement = res.entry;
    if (kv->val_insert_cb) {
      if (!cb_val) {
        cb_val = kv->val_insert_cb(val, kv->callback_user_data);
        if (!cb_val) {
          CKV_MAP_DEBUG("val insert cb returned null");
          return CKV_MAP_ERROR_VAL_INSERT_HOOK_FAILED;
        }
      }
      replacement.val = cb_val;
    } else {
      replacement.val = val;
    }
    if (_ckv_val_empty(res.entry.val)) {
      if (kv->key_insert_cb) {
        if (!cb_key) {
          cb_key = kv->key_insert_cb(key, kv->callback_user_data);
          if (!cb_key) {
            CKV_MAP_DEBUG("key insert cb returned null");
            if (kv->val_remove_cb && cb_val) {
              kv->val_remove_cb(cb_val, kv->callback_user_data);
            }
            return CKV_MAP_ERROR_KEY_INSERT_HOOK_FAILED;
          }
        }
        replacement.key = cb_key;
      } else {
        replacement.key = key;
      }
    }
    assert(replacement.key);
    assert(replacement.val);
    if (res.index == 0) {
      CKV_MAP_DEBUG("null slot: %" CKV_INDEX_FMT " %s %lx",
                   kv->hash_func(key) & kv->mask, (char *)key, kv->mask);
    }
    // Atomic swap here and on failure, restart
    if (put_ckv_entry_atomic(kv, res.index, res.entry, replacement)) {
      if (!_ckv_val_empty(res.entry.val)) {
        // Retire old value for deferred freeing (other threads may still reference it)
        _ckv_retire_item(kv, res.entry.val, false);
        if (cb_key) {
          // We allocated a new key but the key already existed, retire the duplicate
          CKV_MAP_DEBUG("read modify write after original read, retiring key");
          _ckv_retire_item(kv, cb_key, true);
        }
        //CKV_MAP_DEBUG("read modify write: %s", (char *)key);
      } else {
        // If our current entry is empty and the previous entry is valid, check
        // that it has not changed. If it has changed, check that the new value
        // is not a null.
        //
        // THis solves a problem where simultaneous removal and write on the
        // end of a cluster can place a key entry after a NULL value, ending
        // probing prematurely
        if (res.entry.val == NULL && res.start_index != res.index) {
          if (!put_ckv_entry_atomic(kv, res.index - 1, res.prev, res.prev)) {
            CKV_MAP_DEBUG(
                "Previous entry changed while comitting %s: %" CKV_INDEX_FMT
                ", %" CKV_INDEX_FMT,
                (char *)key, res.index, res.start_index);
            _ckv_entry cur_prev = get_ckv_entry(kv, res.index - 1);
            if (_ckv_val_empty(cur_prev.val)) {
              CKV_MAP_DEBUG("Moving to previous entry");
              if (!_ckv_map_move_entry(kv, res.index, replacement, res.index - 1,
                                      cur_prev, true)) {
                CKV_MAP_DEBUG(
                    "Could not move entry, probably ok, either another thread "
                    "wrote to the empty slot, or another thread modified "
                    "this entry. This should be safe, but needs more testing");
              }
            } else {
              CKV_MAP_DEBUG("Previous entry is not empty: %s",
                           (char *)cur_prev.val);
            }
          }
        }
        atomic_fetch_add(&(kv->count), 1);
      }
      return CKV_MAP_ERROR_NONE;
    }
  }
}

bool ckv_map_unset(ckv_map *kv, void *key) {
  for (;;) {
    _ckv_search_result res = _ckv_map_search_index(kv, key);
    _ckv_entry to_remove = res.entry;
    if (_ckv_val_empty(to_remove.val)) {
      // CKV_MAP_DEBUG("key %s not found", (char*)key);
      return false;
    } else {
      _ckv_entry next = get_ckv_entry(kv, (res.index + 1) & kv->mask);
      to_remove.key = NULL;
      if (next.val != NULL) {
        to_remove.val =
            CKV_REMOVED_MARKER; // Marks 'was present' to keep probing intact
      } else {
        // We're at the end of a cluster
        to_remove.val = NULL;
      }
      if (put_ckv_entry_atomic(kv, res.index, res.entry, to_remove)) {
        // CKV_MAP_DEBUG("%lx: %s\n", (intptr_t)res.entry.val,
        // (char*)res.entry.val);
        // Add to retired list for deferred freeing. We can't free immediately
        // because other threads may still hold references (from iteration/search).
        // Items will be freed when ckv_map_empty or ckv_map_free is called.
        _ckv_retire_item(kv, res.entry.key, true);
        _ckv_retire_item(kv, res.entry.val, false);
        atomic_fetch_sub(&(kv->count), 1);
        // If we wrote an empty entry, make sure the next entry is still empty
        if (to_remove.val == NULL) {
          if (!put_ckv_entry_atomic(kv, (res.index + 1) & kv->mask, next,
                                   next)) {
            CKV_MAP_DEBUG("next entry changed while removing %s: %" CKV_INDEX_FMT
                         ", %" CKV_INDEX_FMT ", ",
                         (char *)key, res.index, (res.index + 1) & kv->mask);
            next = get_ckv_entry(kv, (res.index + 1) & kv->mask);
            // If our next entry isn't empty, we can no longer be certain that
            // our NULL removal is justified
            if (next.val != NULL) {
              _ckv_entry reset_entry = to_remove;
              reset_entry.val = CKV_REMOVED_MARKER;
              if (!put_ckv_entry_atomic(kv, res.index, to_remove, reset_entry)) {
                CKV_MAP_DEBUG("failed to reset entry: %" CKV_INDEX_FMT,
                             res.index);
              }
            }
          }
        }
        return true;
      }
    }
  }
}

int ckv_map_count(ckv_map *kv) { return kv->count; }

bool ckv_map_iterate(ckv_map *kv, ckv_map_iterate_callback callback, void *data) {
  for (_ckv_index i = 0; i <= kv->mask; i++) {
    _ckv_entry kv_entry = get_ckv_entry(kv, i);
    if (!_ckv_val_empty(kv_entry.val)) {
      bool status = true;
      void* val = kv_entry.val;
      void* key = kv_entry.key;
      if (kv->val_ref_cb) {
        val = kv->val_ref_cb(kv_entry.val, kv->callback_user_data);
      }
      if (kv->key_ref_cb) {
        key = kv->key_ref_cb(kv_entry.key, kv->callback_user_data);
      }
      status = callback(key, val, data);
      if (kv->val_unref_cb) {
        kv->val_unref_cb(val, kv->callback_user_data);
      }
      if (kv->key_unref_cb) {
        kv->key_unref_cb(key, kv->callback_user_data);
      }
      if (!status) {
        return false;
      }
    }
  }
  return true;;
}

void ckv_map_print(ckv_map *kv, FILE *fp) {
  fputs("{\n", fp);
  bool comma = false;
  for (_ckv_index i = 0; i <= kv->mask; i++) {
    _ckv_entry entry = get_ckv_entry(kv, i);
    if (entry.key) {
      if (comma) {
        fputs(",\n", fp);
      }
      fputs("\t\"", fp);
      if (kv->key_print_func) {
        kv->key_print_func(entry.key, fp);
      } else {
        fprintf(fp, "<ptr:%p>", entry.key);
      }
      fputs("\": \"", fp);
      if (kv->val_print_func) {
        kv->val_print_func(entry.val, fp);
      } else {
        fprintf(fp, "<ptr:%p>", entry.val);
      }
      fputs("\"", fp);
      comma = true;
    }
  }
  fputs("\n}\n", fp);
}

void ckv_map_empty(ckv_map *kv) {
  // First, drain retired items from unset operations
  _ckv_drain_retired(kv);

  // Then clear the table
  for (_ckv_index i = 0; i <= kv->mask; i++) {
    _ckv_entry p;
    do {
      p = get_ckv_entry(kv, i);
    } while (!put_ckv_entry_atomic(kv, i, p, (_ckv_entry){}));
    if (!_ckv_val_empty(p.val)) {
      if (p.key && kv->key_remove_cb) {
        kv->key_remove_cb(p.key, kv->callback_user_data);
      }
      if (p.val && kv->val_remove_cb && p.val != CKV_REMOVED_MARKER) {
        kv->val_remove_cb(p.val, kv->callback_user_data);
      }
      atomic_fetch_sub(&(kv->count), 1);
    }
  }
}

void ckv_map_free(ckv_map *kv) {
  ckv_map_empty(kv);
  platform_region_unalloc(kv->table, kv->mask + 1);
  free(kv);
}
