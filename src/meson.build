verimark_sources = files(
  'verimark.c',
  'verimark-sdcp.c',
)

shared_module('fprint-tod-verimark',
  verimark_sources,
  dependencies: [tod_dep, openssl_dep, glib_dep, gmodule_dep],
  name_prefix: 'lib',
  install: true,
  install_dir: tod_driver_dir,
  gnu_symbol_visibility: 'hidden',
)
