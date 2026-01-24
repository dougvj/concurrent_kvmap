project('Concurrent Key/Val Map', 'c',
  version: '1.0',
  license: 'BSD',
  default_options: ['werror=true', 'c_std=gnu99', 'default_library=static', 'b_lto=true'])


if get_option('debug')
  add_project_arguments('-DENABLE_DEBUG', language : 'c')

endif
add_project_arguments('-march=native', language: 'c')

sources = files([
  './ckv_map.c',
  './fnv1a_hashes.c'
])

refcnt = subproject('refcnt')

includes = ['./', refcnt.get_variable('inc_dirs')]

install_headers(files('./ckv_map.h'))

cc = meson.get_compiler('c')

atomic = cc.find_library('atomic')



libckvmap = library(
  'libckvmap',
  sources,
  dependencies: [atomic],
  include_directories: includes,
  install: true)


test_ckv_map = executable(
  'ckv_test', 'test/test_ckv_map.c',
  include_directories: includes,
  link_with: libckvmap,
)

test('test ckv map', test_ckv_map)



