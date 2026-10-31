# SPDX-License-Identifier: BSD-3-Clause

# The UPF datapath as a Bess plugin (D-008: UPF-specific code stays in a
# plugin; the codecs it needs -- core/tunnel/tunnel.h and the packet parse
# types (core/packet_parse.h) -- are installed, experimental, and header-only). Built and loaded
# against the installed `bess-dev` stage, never against BESS's source tree:
#
#   PKG_CONFIG="pkg-config --define-prefix" \
#     PKG_CONFIG_PATH=<stage>/lib/pkgconfig meson setup build
#   ninja -C build && meson install -C build --destdir=<stage-destdir>
#   bessd -modules=<plugin dir> ...
#
# --define-prefix is what derives the stage's own include paths from where
# bess-dev.pc lives: a stage installed with --destdir keeps the configured
# prefix (/usr/local unless BESS was configured with -Dprefix=<stage>), and
# putting the command in PKG_CONFIG is how meson is told to use it.

project('upf_datapath', 'cpp',
  version: '0.1.0',
  default_options: [
    'cpp_std=c++23',
    'buildtype=release',
    'warning_level=1',
  ],
)

bess_dep = dependency('bess-dev', required: true)
protobuf_dep = dependency('protobuf', required: true)
protoc = find_program('protoc', required: true)
modules_dir = get_option('libdir') / 'bess' / 'modules'

# The plugin's wire types, and their descriptor set next to the plugin: the
# controller builds these messages from the PFCP session.
upf_proto = custom_target(
  'upf_datapath_proto',
  input: 'upf_datapath.proto',
  output: ['upf_datapath.pb.cc', 'upf_datapath.pb.h', 'upf_datapath.desc'],
  command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--cpp_out=@OUTDIR@',
            '--descriptor_set_out=@OUTPUT2@', '@INPUT@'],
  install: true,
  install_dir: [false, false, modules_dir],
)

# One plugin, one library: the modules are registered together (BESS_PLUGIN
# names the library, ADD_MODULE the classes), and the manifest loads them by
# class name from this single .so.
# -Dbench=true adds the A/B bench's traffic and digest modules
# (bench/bench_gen.cc) and builds its client (bench/upf_ab.cc); off by default,
# so the shipped plugin carries no bench module.
bench = get_option('bench')
upf_datapath = shared_module(
  'upf_datapath',
  (bench ? ['bench/bench_gen.cc'] : []) +
  ['arp_responder.cc', 'atsss_steer.cc', 'gtpu_decap.cc', 'gtpu_responder.cc', 'gtpu_encap.cc',
   'urr_count.cc',
   # UpfAppliance: the whole user plane in one module; UpfSessionAppliance: the
   # same module with the session-major layout (upf_appliance_sessions.cc).
   'upf_appliance.cc', 'upf_appliance_resources.cc', 'upf_appliance_path.cc',
   'upf_appliance_slow.cc', 'upf_appliance_buffer.cc', 'upf_appliance_selftest.cc',
   'upf_appliance_sessions.cc',
   upf_proto[0], upf_proto[1]],
  include_directories: include_directories('.'),
  dependencies: [bess_dep, protobuf_dep],
  install: true,
  install_dir: modules_dir,
)

# The A/B bench (bench/upf_ab.cc): a BESS C++ SDK client that runs two plugin
# builds (or the graph against the appliance) on identical seeded streams in
# alternating rounds; ci/bench-ab.sh runs it.
if bench
  executable(
    'upf_ab',
    ['bench/upf_ab.cc'],
    include_directories: include_directories('bench'),
    dependencies: [dependency('bess-sdk', required: true), protobuf_dep],
    link_args: ['-Wl,--disable-new-dtags'],
  )
endif

# Focused parser, admission-key, F-TEID and ARP entries resource and outer-wire
# unit tests, and the per-packet helpers the modules and UpfAppliance share
# (packet_helpers_test.cc: GTP-U control, ATSSS selection, ARP proxy). The
# test links bess-dev-static for the RcuDomain and SharedExactIndex the resource
# wraps; the plugin never links those archives (bessd provides the symbols).
gtest_dep = dependency('gtest', required: false)
bess_static_dep = dependency('bess-dev-static', required: false)
if gtest_dep.found() and bess_static_dep.found()
  # DT_RPATH, not RUNPATH: the loader applies RUNPATH only to the binary's own
  # DT_NEEDED, and DPDK's shared libraries load their siblings (librte_kvargs,
  # librte_telemetry, ...) from the same unexported directory.
  gtpu_datapath_test = executable(
    'gtpu_datapath_test',
    ['gtpu_datapath_test.cc', 'packet_helpers_test.cc', 'upf_appliance_frame_test.cc',
     'arp_responder_resource_test.cc', 'upf_appliance_test.cc', upf_proto[0], upf_proto[1]],
    include_directories: include_directories('.'),
    dependencies: [bess_static_dep, protobuf_dep, gtest_dep],
    link_args: ['-Wl,--disable-new-dtags'],
  )
  test('gtpu_datapath', gtpu_datapath_test)

  # UpfSessionAppliance's session store driven through Reserve/Publish under
  # a reader thread. Its token buckets live in the session slots, so it also
  # needs the meter archive, which bess-dev-static does not ship: it is taken
  # from the vendored perf tree (build/bess/fast, ci/vendor-bess.sh) when
  # that is present.
  bess_meter_dep = meson.get_compiler('cpp').find_library('bess_meter', static: true,
    dirs: [meson.project_source_root() / '..' / 'build' / 'bess' / 'fast' / 'core'],
    required: false)
  if bess_meter_dep.found()
    sessions_test = executable(
      'upf_appliance_sessions_test',
      ['upf_appliance_sessions_test.cc', 'upf_appliance_sessions.cc', upf_proto[0], upf_proto[1]],
      include_directories: include_directories('.'),
      dependencies: [bess_meter_dep, bess_static_dep, protobuf_dep, gtest_dep],
      link_args: ['-Wl,--disable-new-dtags'],
    )
    test('upf_appliance_sessions', sessions_test)
  endif
endif
