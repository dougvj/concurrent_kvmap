project('Concurrent Generic Hash Map', 'c',
  version: '1.0',
  license: 'BSD',
  default_options: ['werror=true', 'c_std=gnu99', 'default_library=static', 'b_lto=true'])


if get_option('debug')
  add_project_arguments('-DKV_MAP_DEBUG', language : 'c')
endif

sources = files([
  './kv_map.c',
  './fnv1a_hashes.c'
])


includes = ['./']

install_headers(files('./kv_map.h'))

cc = meson.get_compiler('c')

libkvmap = library(
  'libkvmap',
  sources,
  include_directories: includes,
  install: true)


test_kv_map = executable(
  'kv_tests', 'test/test_kv_map.c',
  include_directories: includes,
  link_with: libkvmap,
)

test('test kv map', test_kv_map)


