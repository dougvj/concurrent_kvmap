# Generic Hash Map in C

## Simple string key/val map

```c
#include <kv_map.h>

...

kv_map* map = kv_map_create_str(0); // 0 means default size
assert(map != NULL);

assert(kv_map_set(map, "foo", "bar") == KV_MAP_ERROR_NONE)
assert(kv_map_get(map, "foo") == "bar")

void iterate(void* _key, void* _val, void* _stream) {
  const char* key = _key;
  const char* val = _val;
  FILE* stream;
  fprintf(stream, "key: %s, val: %s\n", key, val);
}

kv_map_iterate(map, iterate, stderr); // pass stderr to user data which is the stream

kv_map_unset(map, "foo");
assert(kv_map_get(map, "foo") == NULL);

```

## Complicated custom key/val map

```c
#include <kv_map.h>

...

struct custom_key_t;

kv_map_hash_t custom_key_hash(struct custom_key_hash* key);

struct custom_val_t;

custom_val_t* val_dup(struct custom_val_t* val);

custom_key_t* key_dup(struct custom_key_t* key);

kv_map* map = kv_map_create((kv_map_create_params) {
  .size = 256, // Can be omitted, 0 defaults to 32
  .key_insert_cb = key_dup,
  .val_insert_cb = val_dup,
  .key_remove_cb = free,
  .val_remove_cb = free, // Note, may need to make wrapper functions or cast the function pointers
  // Can also specify custom callback data parameter
  //.cb_user_data = NULL,
  .hash_func = custom_key_hash
  // Can also provide calbacks for printing the keys/values which enables
  // printing the hashmap
});
assert(map != NULL);

```

