#define _GNU_SOURCE
#include "fnv1a_hashes.h"
#include "platform.h"
#include <assert.h>
#include <inttypes.h>
#include <concur_kv_map.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <refcnt.h>

static void *KV_REMOVED_MARKER = "REMOVED";
static void *KV_MOVING_MARKER = "MOVING";

#define KV_MIN_SIZE 4096

#ifdef ENABLE_DEBUG
#define KV_MAP_DEBUG(s, ...)                                                   \
  fprintf(stderr, "%s:%u: " s "\n", __FILE__, __LINE__, ##__VA_ARGS__);
#else
#define KV_MAP_DEBUG(...)                                                      \
  while (0)                                                                    \
    ;
#endif

#if __SIZEOF_POINTER__ == 8
typedef __uint128_t _kv_int_ptr_entry;
#elif __SIZEOF_POINTER__ == 4
typedef __uint64_t _kv_int_ptr_entry;
#else
#error "Incompatible machine"
#endif
typedef kv_map_size _kv_index;
#define KV_INDEX_FMT PRIuFAST32
typedef atomic_uint_fast32_t _kv_atomic_index;

typedef struct {
  union {
    struct {
      void *key;
      void *val;
    };
    _Atomic _kv_int_ptr_entry intval;
  };
} _kv_entry;

typedef struct {
  _kv_entry entry;
  _kv_entry prev;
  _kv_index start_index;
  _kv_index index;
  _kv_index mask;
} _kv_search_result;

struct kv_map {
  _kv_atomic_index count;
  _kv_index
      mask; /* The bits that are mapped to the table, representing table
          size - 1. IE, if table size is 32, that's 0x20 and mask is 0x1F */
  _kv_int_ptr_entry *_Atomic table;
  _Atomic bool is_resizing;
  atomic_int table_refs;
  kv_map_insert_callback key_insert_cb;
  kv_map_remove_callback key_remove_cb;
  kv_map_insert_callback val_insert_cb;
  kv_map_remove_callback val_remove_cb;
  kv_map_ref_callback key_ref_cb;
  kv_map_ref_callback val_ref_cb;
  kv_map_unref_callback key_unref_cb;
  kv_map_unref_callback val_unref_cb;
  void *callback_user_data;
  kv_map_hash_function hash_func;
  kv_map_key_cmp_func key_cmp_func;
  kv_map_print_func key_print_func;
  kv_map_print_func val_print_func;
  enum kv_map_flags flags;
};

static _kv_int_ptr_entry *_kv_acquire_table_ref(kv_map *kv) {
  _kv_int_ptr_entry *table;
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

static void _kv_release_table_ref(kv_map *kv) {
  atomic_fetch_sub(&(kv->table_refs), 1);
}

// Pull kv entry from table
static _kv_entry get_kv_entry(kv_map *kv, int index) {
  _kv_int_ptr_entry *table = _kv_acquire_table_ref(kv);
  _kv_entry ret = (_kv_entry){.intval = table[index]};
  _kv_release_table_ref(kv);
  return ret;
}

static bool _kv_val_empty(void *val) {
  return val == NULL || val == KV_REMOVED_MARKER;
}

// Commit kv entry, if another thread already committed it then this returns
// false and the callee needs to retry
static bool put_kv_entry_atomic(kv_map *kv, int index, _kv_entry old_val,
                                _kv_entry new_val) {
  _kv_int_ptr_entry *table = _kv_acquire_table_ref(kv);
  assert(new_val.key != NULL || _kv_val_empty(new_val.val));
  bool success = __sync_bool_compare_and_swap(&(table[index]), old_val.intval,
                                              new_val.intval);
  _kv_release_table_ref(kv);
  return success;
}

static const char *const KV_MAP_ERROR_STRINGS[] = {
    [KV_MAP_ERROR_NONE] = "No error",
    [KV_MAP_ERROR_KEY_INSERT_HOOK_FAILED] = "Key insert hook failed",
    [KV_MAP_ERROR_VAL_INSERT_HOOK_FAILED] = "Value insert hook failed",
    [KV_MAP_ERROR_OUT_OF_MEMORY] = "Out of memory",
    [KV_MAP_ERROR_FULL] = "Map is full",
    [KV_MAP_ERROR_INTERRUPTED] = "Read modify write interrupted",
};

const char *kv_map_error_message(enum kv_map_error error) {
  return KV_MAP_ERROR_STRINGS[error];
}

static const char *const KV_MAP_ERROR_NAMES[] = {
    [KV_MAP_ERROR_NONE] = "KV_MAP_ERROR_NONE",
    [KV_MAP_ERROR_OUT_OF_MEMORY] = "KV_MAP_ERROR_OUT_OF_MEMORY",
    [KV_MAP_ERROR_KEY_INSERT_HOOK_FAILED] =
        "KV_MAP_ERROR_KEY_INSERT_HOOK_FAILED",
    [KV_MAP_ERROR_VAL_INSERT_HOOK_FAILED] =
        "KV_MAP_ERROR_VAL_INSERT_HOOK_FAILED",
    [KV_MAP_ERROR_FULL] = "KV_MAP_ERROR_FULL",
    [KV_MAP_ERROR_INTERRUPTED] = "KV_MAP_ERROR_INTERRUPTED",
};

const char *kv_map_error_name(enum kv_map_error error) {
  return KV_MAP_ERROR_NAMES[error];
}

kv_map *kv_map_create(kv_map_create_params create_params) {
  uint_fast32_t size = create_params.size;
  if (!size) {
    size = 32;
  } else {
    int bitcount = 0;
    for (int i = 0; i < sizeof(int) * 8; i++) {
      if ((size >> i & 1) == 1) {
        bitcount++;
      }
    }
    if (bitcount != 1) {
      return NULL;
    }
  }
  kv_map *kv = malloc(sizeof(kv_map));
  if (kv) {
    kv->table = platform_region_alloc(size * sizeof(_kv_int_ptr_entry));
    if (kv->table == NULL) {
      free(kv);
      return NULL;
    }
    kv->table_refs = 0;
    kv->count = 0;
    kv->mask = size - 1;
    kv->is_resizing = false;
    kv->key_insert_cb = create_params.key_insert_cb;
    kv->key_remove_cb = create_params.key_remove_cb;
    kv->val_insert_cb = create_params.val_insert_cb;
    kv->val_remove_cb = create_params.val_remove_cb;
    kv->callback_user_data = create_params.callback_user_data;
    kv->hash_func = create_params.hash_func;
    kv->key_cmp_func = create_params.key_cmp_func;
    kv->key_print_func = create_params.key_print_func;
    kv->val_print_func = create_params.val_print_func;
    kv->flags = create_params.flags;
    // NULL may not be 0, but it's basically impossible
    assert(NULL == 0);
#ifdef KV_MAP_LOCKS_ENABLED
    platform_rwlock_init(&(kv->rwlock));
#endif
  }
  return kv;
}

static void *_refcnt_strdup_wrap(void *str, void *_) { return refcnt_strdup(str); }

static void _refcnt_unref_wrap(void *ptr, void *_) { refcnt_unref(ptr); }

static void* _refcnt_ref_wrap(void *ptr, void *_) { refcnt_ref(ptr); return ptr; }


static void _fputs(void *s, FILE *stream) { fputs(s, stream); }

static int _strcmp(void *a, void *b) { return strcmp(a, b); }

kv_map *kv_map_str_create(uint_fast32_t size) {
  return kv_map_create((kv_map_create_params){
      .size = KV_MIN_SIZE,
      .key_insert_cb = _refcnt_strdup_wrap,
      .val_insert_cb = _refcnt_strdup_wrap,
      .key_remove_cb = _refcnt_unref_wrap,
      .val_remove_cb = _refcnt_unref_wrap,
      .key_ref_cb = _refcnt_ref_wrap,
      .val_ref_cb = _refcnt_ref_wrap,
      .key_unref_cb = _refcnt_unref_wrap,
      .val_unref_cb = _refcnt_unref_wrap,
      .hash_func =
          ((sizeof(uint_fast32_t) == 4) ? (kv_map_hash_function)fnv1a_hash32
                                        : (kv_map_hash_function)fnv1a_hash64),
      .key_cmp_func = _strcmp,
      .val_print_func = _fputs,
      .key_print_func = _fputs,
      //      .flags = KV_MAP_RESIZE_DISABLED,
  });
}

void kv_map_debug_dump_table(kv_map *kv, FILE *f) {
  fprintf(f, "idx,hash,key,val\n");
  for (_kv_index i = 0; i <= kv->mask; i++) {
    _kv_entry entry = get_kv_entry(kv, i);
    _kv_index hash = 0;
    if (_kv_val_empty(entry.val)) {
      entry.key = NULL;
    } else {
      hash = kv->hash_func(entry.key) & kv->mask;
    }
    if (entry.val != NULL) {
      fprintf(f, "%" KV_INDEX_FMT ",%" PRIuFAST32 ",%s,%s\n", i, hash,
              (char *)entry.key, (char *)entry.val);
    }
  }
}

// Performs a move of an entry from one location to another. The move maintains
// thready safety by marking the source entry as "moving" and then completes
// the move to the destination, unmarking the source destination as "moving" to
// "removed"
static bool _kv_map_move_entry(kv_map *kv, uint_fast32_t old_location,
                               _kv_entry old_location_val,
                               uint_fast32_t new_location,
                               _kv_entry new_location_val, bool null_entry) {
  _kv_entry old_location_val_moving_marker = old_location_val;
  old_location_val_moving_marker.val = KV_MOVING_MARKER;
  _kv_entry old_location_val_removed_marker = old_location_val;
  old_location_val_removed_marker.val = null_entry ? NULL : KV_REMOVED_MARKER;
  if (put_kv_entry_atomic(kv, old_location, old_location_val,
                          old_location_val_moving_marker)) {
    if (put_kv_entry_atomic(kv, new_location, new_location_val,
                            old_location_val)) {
      if (!put_kv_entry_atomic(kv, old_location, old_location_val_moving_marker,
                               old_location_val_removed_marker)) {
        goto should_never;
      }
      return true;
    } else if (!put_kv_entry_atomic(kv, old_location,
                                    old_location_val_moving_marker,
                                    old_location_val)) {
      goto should_never;
    }
  }
  // Move aborted
  return false;
should_never:
  KV_MAP_DEBUG("This should never occur!!!");
  assert(false);
  return false;
}

static void *KV_UNINIT = "UNINIT";

// Performs the search for the entry with the given key. The search starts with
// the hash of the key and then probes until an empty entry is found. An entry
// may be found at a different point due to a table resize, so the search is
// repeated with a smaller table mask until either the key is found or an empty
// entry is encountered. If the key entry is not found, the first empty or
// removed entry is returned at the correct table size
//
// The search returns the index of the entry, the entry value, the original
// index (start of probe) and the value of the previous entry to detect an edge
// of cluster removal (see how this is used in kv_map_set and kv_map_unset)
static _kv_search_result _kv_map_search_index(kv_map *kv, void *key) {
  // Define the mask for the table and the hash
  _kv_index mask = kv->mask;
  _kv_index orig_mask = kv->mask;
  _kv_index hash = kv->hash_func(key);
  _kv_index optimal_index = 0;
  _kv_entry optimal_entry = {};
  _kv_index original_start_index = hash & mask;
  _kv_entry prev = {};
  _kv_entry optimal_prev = {};
probe:
  for (;;) {
    _kv_index start_index = hash & mask;
    _kv_index index = start_index;
    _kv_entry entry = {.val = KV_UNINIT};
#ifdef ENABLE_DEBUG
    int count = 0;
#endif
    for (;;) {
      prev = entry;
      entry = get_kv_entry(kv, index);
      // If we found a NULL, then that means that we are done searching and
      // didn't find our entry
      if (entry.val == NULL) {
#ifdef ENABLE_DEBUG
        /*if (count > 20) {
          KV_MAP_DEBUG("perf: max probed: %u", count);
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
          if (mask == (KV_MIN_SIZE - 1)) {
            return (_kv_search_result){.prev = optimal_prev,
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
      } else if (_kv_val_empty(entry.val)) {
        if (optimal_entry.val == NULL && mask == orig_mask) {
          // Set the optimal entry
          optimal_index = index;
          optimal_entry = entry;
          optimal_prev = prev;
        }
      } else if (kv->key_cmp_func(entry.key, key) == 0) {
        // We found our entry. Move to optimal entry if we have one
        if (optimal_index != index && optimal_entry.val != NULL) {
          long jump_size = labs((long)index - (long)optimal_index);
          if (jump_size > 10) {
            KV_MAP_DEBUG("moving %" KV_INDEX_FMT " spaces %" KV_INDEX_FMT
                         " to %" KV_INDEX_FMT,
                         jump_size, index, optimal_index);
          }
          // Move the entry closer to hash index
          bool null_entry = get_kv_entry(kv, (index + 1) & mask).val == NULL;
          if (_kv_map_move_entry(kv, index, entry, optimal_index, optimal_entry,
                                 null_entry)) {
            return (_kv_search_result){.prev = optimal_prev,
                                       // TODO deal with resizable, perhaps
                                       // platform.h and platform.c and remap?
                                       .index = optimal_index,
                                       .entry = entry,
                                       .start_index = original_start_index,
                                       .mask = mask};
          }
          KV_MAP_DEBUG("move failure");
        }
        return (_kv_search_result){.prev = prev,
                                   .index = index,
                                   .entry = entry,
                                   .start_index = original_start_index,
                                   .mask = mask};
      }
      // Probe next index
      index = (index + 1) & mask;
#ifdef ENABLE_DEBUG
      count++;
      assert(count != kv->mask && "Linear probe should never be infinite");
#endif
    };
  };
}

void *kv_map_get(kv_map *kv, void *key) {
  _kv_entry entry;
  for (int count = 0;; count++) {
    _kv_search_result res = _kv_map_search_index(kv, key);
    entry = res.entry;
    if (entry.val != KV_MOVING_MARKER) {

      if(_kv_val_empty(entry.val)) {
        return NULL;
      } else {
        if (kv->val_ref_cb) {
          return kv->val_ref_cb(entry.val, kv->callback_user_data);
        }
        return entry.val;
      };
    } else {
      KV_MAP_DEBUG("Encountered Moving");
      if (count > 100) {
        KV_MAP_DEBUG("KV_MOVING took too long")
        assert(false);
      }
    }
  }
}

static void maybe_unused _kv_map_reindex(kv_map *kv) {
  for (_kv_index i = 0; i <= kv->mask; i++) {
    _kv_entry kv_entry;
    kv_entry = get_kv_entry(kv, i);
    if (kv_entry.key != NULL) {
      for (;;) {
        _kv_search_result res = _kv_map_search_index(kv, kv_entry.key);
        if (res.index == i) {
          break;
        } else {
          if (_kv_map_move_entry(kv, i, kv_entry, res.index, res.entry,
                                 false)) {
            break;
          }
        }
      }
    }
  }
  // Lookup all kv entrys to move into removed entries
  for (_kv_index i = 0; i <= kv->mask; i++) {
    _kv_entry kv_entry = get_kv_entry(kv, i);
    if (kv_entry.key != NULL) {
      _kv_map_search_index(kv, kv_entry.key);
    }
  }
}

#include <unistd.h>

static bool _kv_map_inplace_expand(kv_map *kv) {
  if (__sync_bool_compare_and_swap(&(kv->is_resizing), false, true)) {
    _kv_index old_len = (kv->mask + 1);
    _kv_index new_len = old_len * 2;
    _kv_index old_size = old_len * sizeof(_kv_entry);
    _kv_index new_size = new_len * sizeof(_kv_entry);
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
    _kv_int_ptr_entry *table = _kv_acquire_table_ref(kv);
    // Do the remap disallowing relocation
    _kv_int_ptr_entry *new_table = platform_region_expand(table, old_size, new_size, false);
    if (new_table) {
      assert(new_table == table);
      KV_MAP_DEBUG("Atomic expand succeeded");
      kv->mask = (kv->mask << 1) | 1;
      _kv_release_table_ref(kv);
      kv->is_resizing = false;
      return true;
    }
    // This makes sure that only one thread owns the pointer making sure that
    // the reference is NULLd atomically
    kv->table = NULL;
    // Wait for any threads using the table ptr
    while (atomic_load(&(kv->table_refs)) > 1)
      ;
    KV_MAP_DEBUG("Doing non-atomic expand");
    new_table =
        platform_region_expand(table, old_size, new_size, true);
    if (!new_table) {
      KV_MAP_DEBUG("could not expand, alloc failure");
      return false;
    }
    for (_kv_index i = old_len; i < new_len; i++) {
      new_table[i] = 0;
    }
    kv->mask = (kv->mask << 1) | 1;
    kv->table = new_table;
    //_kv_map_reindex(kv);
    kv->is_resizing = false;
    _kv_release_table_ref(kv);
  } else {
    KV_MAP_DEBUG("expand already happening elsewhere");
  }
  return true;
}

enum kv_map_error kv_map_set(kv_map *kv, void *key, void *val) {
  void *cb_key = NULL;
  void *cb_val = NULL;
  for (;;) {
    if (!(kv->flags & KV_MAP_FLAG_RESIZE_DISABLED) &&
        kv->count >= (kv->mask / 8)) {
      if (!_kv_map_inplace_expand(kv)) {
        return KV_MAP_ERROR_OUT_OF_MEMORY;
      }
    } else if (kv->count == kv->mask / 2) {
      KV_MAP_DEBUG("no more space in table");
      return KV_MAP_ERROR_FULL;
    }
    _kv_search_result res = _kv_map_search_index(kv, key);
    _kv_entry replacement = res.entry;
    if (kv->val_insert_cb) {
      if (!cb_val) {
        cb_val = kv->val_insert_cb(val, kv->callback_user_data);
        if (!cb_val) {
          KV_MAP_DEBUG("val insert cb returned null");
          return KV_MAP_ERROR_VAL_INSERT_HOOK_FAILED;
        }
      }
      replacement.val = cb_val;
    } else {
      replacement.val = val;
    }
    if (_kv_val_empty(res.entry.val)) {
      if (kv->key_insert_cb) {
        if (!cb_key) {
          cb_key = kv->key_insert_cb(key, kv->callback_user_data);
          if (!cb_key) {
            KV_MAP_DEBUG("key insert cb returned null");
            if (kv->val_remove_cb && cb_val) {
              kv->val_remove_cb(cb_val, kv->callback_user_data);
            }
            return KV_MAP_ERROR_KEY_INSERT_HOOK_FAILED;
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
      KV_MAP_DEBUG("null slot: %" KV_INDEX_FMT " %s %lx",
                   kv->hash_func(key) & kv->mask, (char *)key, kv->mask);
    }
    // Atomic swap here and on failure, restart
    if (put_kv_entry_atomic(kv, res.index, res.entry, replacement)) {
      if (!_kv_val_empty(res.entry.val)) {
        if (kv->val_remove_cb) {
          kv->val_remove_cb(res.entry.val, kv->callback_user_data);
        }
        if (cb_key && kv->key_remove_cb) {
          KV_MAP_DEBUG("read modify write after original read, freeing key");
          kv->key_remove_cb(cb_key, kv->callback_user_data);
        }
        KV_MAP_DEBUG("read modify write: %s", (char *)key);
      } else {
        // If our current entry is empty and the previous entry is valid, check
        // that it has not changed. If it has changed, check that the new value
        // is not a null.
        //
        // THis solves a problem where simultaneous removal and write on the
        // end of a cluster can place a key entry after a NULL value, ending
        // probing prematurely
        if (res.entry.val == NULL && res.start_index != res.index) {
          if (!put_kv_entry_atomic(kv, res.index - 1, res.prev, res.prev)) {
            KV_MAP_DEBUG(
                "Previous entry changed while comitting %s: %" KV_INDEX_FMT
                ", %" KV_INDEX_FMT,
                (char *)key, res.index, res.start_index);
            _kv_entry cur_prev = get_kv_entry(kv, res.index - 1);
            if (_kv_val_empty(cur_prev.val)) {
              KV_MAP_DEBUG("Moving to previous entry");
              if (!_kv_map_move_entry(kv, res.index, replacement, res.index - 1,
                                      cur_prev, true)) {
                KV_MAP_DEBUG(
                    "Could not move entry, probably ok, either another thread "
                    "wrote to the empty slot, or another thread modified "
                    "this entry. This should be safe, but needs more testing");
              }
            } else {
              KV_MAP_DEBUG("Previous entry is not empty: %s",
                           (char *)cur_prev.val);
            }
          }
        }
        atomic_fetch_add(&(kv->count), 1);
      }
      return KV_MAP_ERROR_NONE;
    }
  }
}

bool kv_map_unset(kv_map *kv, void *key) {
  for (;;) {
    _kv_search_result res = _kv_map_search_index(kv, key);
    _kv_entry to_remove = res.entry;
    if (_kv_val_empty(to_remove.val)) {
      // KV_MAP_DEBUG("key %s not found", (char*)key);
      return false;
    } else {
      _kv_entry next = get_kv_entry(kv, (res.index + 1) & kv->mask);
      if (next.val != NULL) {
        to_remove.val =
            KV_REMOVED_MARKER; // Marks 'was present' to keep probing intact
      } else {
        // We're at the end of a cluster
        to_remove.val = NULL;
      }
      if (put_kv_entry_atomic(kv, res.index, res.entry, to_remove)) {
        // KV_MAP_DEBUG("%lx: %s\n", (intptr_t)res.entry.val,
        // (char*)res.entry.val);
        if (kv->key_remove_cb)
          kv->key_remove_cb(res.entry.key, kv->callback_user_data);
        if (kv->val_remove_cb)
          kv->val_remove_cb(res.entry.val, kv->callback_user_data);
        atomic_fetch_sub(&(kv->count), 1);
        // If we wrote an empty entry, make sure the next entry is still empty
        if (to_remove.val == NULL) {
          if (!put_kv_entry_atomic(kv, (res.index + 1) & kv->mask, next,
                                   next)) {
            KV_MAP_DEBUG("next entry changed while removing %s: %" KV_INDEX_FMT
                         ", %" KV_INDEX_FMT ", ",
                         (char *)key, res.index, (res.index + 1) & kv->mask);
            next = get_kv_entry(kv, (res.index + 1) & kv->mask);
            // If our next entry isn't empty, we can no longer be certain that
            // our NULL removal is justified
            if (next.val != NULL) {
              _kv_entry reset_entry = to_remove;
              reset_entry.val = KV_REMOVED_MARKER;
              if (!put_kv_entry_atomic(kv, res.index, to_remove, reset_entry)) {
                KV_MAP_DEBUG("failed to reset entry: %" KV_INDEX_FMT,
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

int kv_map_count(kv_map *kv) { return kv->count; }

bool kv_map_iterate(kv_map *kv, kv_map_iterate_callback callback, void *data) {
  for (_kv_index i = 0; i <= kv->mask; i++) {
    _kv_entry kv_entry = get_kv_entry(kv, i);
    if (!_kv_val_empty(kv_entry.val)) {
      if (!callback(kv_entry.key, kv_entry.val, data)) {
        return false;
      }
    }
  }
  return true;
}

void kv_map_print(kv_map *kv, FILE *fp) {
  fputs("{\n", fp);
  for (_kv_index i = 0; i <= kv->mask; i++) {
    _kv_entry entry = get_kv_entry(kv, i);
    if (entry.key) {
      fputs("\t", fp);
      kv->key_print_func(entry.key, fp);
      fputs(": ", fp);
      kv->val_print_func(entry.val, fp);
      fputs("\n", fp);
    }
  }
  fputs("}\n", fp);
}

void kv_map_empty(kv_map *kv) {
  for (_kv_index i = 0; i <= kv->mask; i++) {
    _kv_entry p;
    do {
      p = get_kv_entry(kv, i);
    } while (!put_kv_entry_atomic(kv, i, p, (_kv_entry){}));
    if (!_kv_val_empty(p.val)) {
      if (p.key && kv->key_remove_cb) {
        kv->key_remove_cb(p.key, kv->callback_user_data);
      }
      if (p.val && kv->val_remove_cb && p.val != KV_REMOVED_MARKER) {
        kv->val_remove_cb(p.val, kv->callback_user_data);
      }
      atomic_fetch_sub(&(kv->count), 1);
    }
  }
}

void kv_map_free(kv_map *kv) {
  kv_map_empty(kv);
  platform_region_unalloc(kv->table, kv->mask + 1);
  free(kv);
}
