project('Concurrent Key/Val Map', 'c',
  version: '1.0',
  license: 'BSD',
  default_options: ['werror=true', 'c_std=gnu99', 'default_library=static', 'b_lto=true'])


if get_option('debug')
  add_project_arguments('-DENABLE_DEBUG', language : 'c')

endif
add_project_arguments('-march=native', language: 'c')

sources = files([
  './concurrent_kv_map.c',
  './fnv1a_hashes.c'
])

refcnt = subproject('refcnt')

includes = ['./', refcnt.get_variable('inc_dirs')]

install_headers(files('./concurrent_kv_map.h'))

cc = meson.get_compiler('c')

atomic = cc.find_library('atomic')



libconcurkvmap = library(
  'libconcurrentkvmap',
  sources,
  dependencies: [atomic],
  include_directories: includes,
  install: true)


test_concurrent_kv_map = executable(
  'concurrent_kv_test', 'test/test_concurrent_kv_map.c',
  include_directories: includes,
  link_with: libconcurkvmap,
)

test('test concurrent kv map', test_concurrent_kv_map)



