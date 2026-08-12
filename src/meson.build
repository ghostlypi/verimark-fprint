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
  # The GType we register outlives the module: libfprint's TOD loader closes
  # the GModule when the context goes away, but callers can still hold a
  # reference to the FpDevice, and finalizing it calls back into our text.
  # Pin the module so dlclose is a no-op.
  link_args: cc.get_supported_link_arguments(['-Wl,-z,nodelete']),
)
