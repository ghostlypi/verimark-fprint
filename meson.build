project('verimark-fprint', 'c',
  version: '0.1.0',
  license: 'LGPL-2.1-or-later',
  meson_version: '>= 0.59.0',
  default_options: [
    'c_std=gnu11',
    'warning_level=2',
    'b_ndebug=if-release',
  ],
)

cc = meson.get_compiler('c')

tod_dep     = dependency('libfprint-2-tod-1')
openssl_dep = dependency('openssl', version: '>= 3.0')
glib_dep    = dependency('glib-2.0')
gmodule_dep = dependency('gmodule-2.0')

add_project_arguments(
  cc.get_supported_arguments([
    '-Wno-unused-parameter',
    '-Wno-cast-function-type',
    '-Wmissing-declarations',
    '-Wpointer-arith',
  ]),
  language: 'c',
)

tod_driver_dir = get_option('tod_driver_dir')
if tod_driver_dir == ''
  tod_driver_dir = get_option('prefix') / get_option('libdir') / 'libfprint-2' / 'tod-1'
endif

subdir('src')

install_data('tools' / 'verimark-diag',
  install_dir: get_option('prefix') / get_option('bindir'),
  install_mode: 'rwxr-xr-x',
)

install_data('tools' / 'verimark-setup',
  install_dir: get_option('prefix') / get_option('bindir'),
  install_mode: 'rwxr-xr-x',
)

summary({
  'TOD driver directory': tod_driver_dir,
  'libfprint-2-tod': tod_dep.version(),
  'OpenSSL': openssl_dep.version(),
}, section: 'Configuration')
