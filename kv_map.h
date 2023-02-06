#ifndef _KV_MAP_H__
#define _KV_MAP_H__
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/**
 * A key-value map.
 */
typedef struct kv_map kv_map;

enum kv_map_flags {
  KV_MAP_FLAGS_NONE,
  KV_MAP_FLAG_RESIZE_DISABLED = 0x1,
};

enum kv_map_error {
  KV_MAP_ERROR_NONE,
  KV_MAP_ERROR_OUT_OF_MEMORY,
  KV_MAP_ERROR_KEY_INSERT_HOOK_FAILED,
  KV_MAP_ERROR_VAL_INSERT_HOOK_FAILED,
  KV_MAP_ERROR_FULL,
};

/**
 * Typedef for the initial  of the key value map
 *
 * This should be a 32-bit int on 32-bit platforms and a 64-bit int on
 * 64-bit platforms.
 */
typedef uint_fast32_t kv_map_size_t;

typedef uint_fast32_t kv_map_hash_t;

#define KV_MAP_SIZE_PRI PRIuFAST32
#define KV_MAP_HASH_PRI PRIuFAST32

/**
 * Retrieves a human-readable error message for the given error code.
 * @param error The error code.
 * @return A human-readable error message.
 *
 */
const char *kv_map_error_message(enum kv_map_error error);

/**
 * Returns a string value of the enumeration identifier
 * @param error The error code.
 * @return A string value of the enumeration identifier.
 */
const char *kv_map_error_name(enum kv_map_error error);

/**
 * Function pointer type for an insertion hook
 * @param item Pointer to the item to be inserted
 * @param user_data User data passed into the hook as specified in the
 * creation parameters
 * @return Pointer to the item that will be tracked in the map
 * @examples If you're inserting a string into a map, you may wan to
 * duplicate the string to ensure the string is valid through the lifetime
 * of the map. The insert hook would then be a wrapper arounds stdrup. If
 * you're inserting a reference counted object into the map, you could
 * provide a wrapper around the reference counting
 */
typedef void *(*kv_map_insert_callback)(void *item, void *user_data);

/**
 * Function pointer type for a removal hook
 * @param item Pointer to the item to be remove
 * @param user_data User data pointer as provided by the creation parameters
 * @examples If you passed a wrapper around strdup for the string, then you
 * would have to pass a wrapper around free here.
 */
typedef void (*kv_map_remove_callback)(void *item, void *user_data);

/**
 * Function pointer type for a hash function which takes the key value
 */
typedef kv_map_hash_t (*kv_map_hash_function)(void *key);

/**
 * Function pointer type for comparing two key values. Follows the same
 * semantics as strcmp, where 0 is equality.
 */
typedef int (*kv_map_key_cmp_func)(void *key_a, void *key_b);

/**
 * Function pointer type for printing a key or value.
 * @param stream THe file stream to print to
 * @param void* item The item to print
 */
typedef void (*kv_map_print_func)(void *item, FILE *stream);

/**
 * A set of creation parameters for the kv map.
 */
typedef struct {
  /// The initial  of the map. The size must be a power of two
  kv_map_size_t size;
  /**
   * Creation flags controlling behavior. Right now the only creation flag that
   * can be specified is whether re on the map is enabled
   */
  enum kv_map_flags flags;
  /// The insert hook call. When NULL, the insertion hook is disabled
  kv_map_insert_callback key_insert_cb;
  /// The remove hook callback for the key. When NULL, the remove hook is
  /// disabled
  kv_map_remove_callback key_remove_cb;
  /// THe insert hook callback for the value. When NULL, the insertion hook is
  /// disabled
  kv_map_insert_callback val_insert_cb;
  /// The remove hook callback for the value. When NULL, the iremoval hook is
  /// disabled
  kv_map_remove_callback val_remove_cb;
  /// User data passed into remove/insert hooks
  void *cb_user_data;
  /// The hash function for the key value
  kv_map_hash_function hash_func;
  /// The compare function for the key values
  kv_map_key_cmp_func key_cmp_func;
  /// The function for printing the key
  kv_map_print_func key_print_func;
  /// The function for printing the value
  kv_map_print_func val_print_func;
} kv_map_create_params;

/**
 * Creates a new key value map with the specified parameters
 *
 * @return A new handle to a key value map. `NULL` on allocation failure or
 * invalid parameter (such as non-power of two initial )
 */
kv_map *kv_map_create(kv_map_create_params create_params);

/**
 * Creates a new key value mapping strings to strings
 *
 * This function is the equivalent of calling `kv_map_create2`
 * with the following parameters set in kv_map_create_params:
 *
 * - key_insert_kb = strdup (wrapper around strdup)
 * - key_remove_cb = free (wrapper around free)
 * - val_insert_kb = strdup (wrapper around strdup)
 * - val_remove_kb = free (wrapper around free)
 * - hash_func = fvn1_64 or fvnc1_32 dpeending on fast_int64
 *
 * @return A new handle to a key value map. `NULL` on allocation failure
 */
kv_map *kv_map_str_create(kv_map_size_t initial_size);

/**
 * Dumps a table in to a file for debugging purposes
 *
 * TODO only works with string key/vals right now
 */
void kv_map_debug_dump_table(kv_map *kv, FILE *f);

/**
 * Returns the value associated with the given key.
 *
 * @param kv The key value map object handle
 * @param key The key to lookup
 * @return The value associated with the key, or NULL of no value exists
 */
void *kv_map_get(kv_map *kv, void *key);

/**
 * Sets a value associated with the given key. If a value is already set for
 * the key, the value is overwritten.
 *
 * @param kv The key vale map object handle
 * @param key The key to associate the value with
 * @param val The value to store
 * @return The error code. KV_MAP_ERROR_NONE on success
 */
enum kv_map_error kv_map_set(kv_map *kv, void *key, void *val);

/**
 * Clears a value associated with the given key
 *
 * @param kv The key vale map object handle
 * @param key The key whose associated value is removed
 * @return True on sucess, false if the key is not found
 */
bool kv_map_unset(kv_map *kv, void *key);

/**
 * Returns the number of items in the map
 *
 * @param kv The key value map object handle
 * @return The number of items in the map
 */
kv_map_size_t kv_map_count(kv_map *kv);

/**
 * A callback called for every key in the map using `kv_map_iterate`
 *
 * @param key The key
 * @param val The value
 * @param data The data parameter passed in `kv_map_iterate`
 * @return The callback must return true to continue iteration or false if the
 *  iteration should be aborted
 */
typedef bool (*kv_map_iterate_callback)(void *key, void *val, void *data);

/**
 * Iterate through all key value pairs in the map
 *
 * @param kv THe key value map object handle
 * @param callback The function callback which is issued for every key value
 *  pair
 * @param data A user specified data parameter which is passed into the
 *  `callback` function for every key value pair
 * @return true if the iteration completed, false if it was aborted by a
 *  callback function call
 */
bool kv_map_iterate(kv_map *kv, kv_map_iterate_callback callback, void *data);

/**
 * Prints the kv map in something that looks kinda like JSON (depending on what
 * value of `kv_map_print_func` is set to).
 *
 * May be actually JSON compatible but no rigorous attempt is made
 */
void kv_map_print(kv_map *kv, FILE *fp);

/**
 * Empties the kv map without freeing underlying backing memory for the table.
 * Useful for reusing kv object without a free/malloc turnaround.
 *
 * Note that remove hooks are still called for keys and values which may still
 * free resources
 */
void kv_map_empty(kv_map *kv);

/**
 * Frees the key value map object and deallocates all resources
 */
void kv_map_free(kv_map *kv);

#endif
