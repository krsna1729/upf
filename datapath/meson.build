# SPDX-License-Identifier: BSD-3-Clause

# The UPF datapath as a Bess plugin (D-008: UPF-specific code stays in a
# plugin; the codecs it needs -- core/tunnel/tunnel.h and the conntrack parse
# types -- are installed, experimental, and header-only). Built and loaded
# against the installed `bess-dev` stage, never against BESS's source tree:
#
#   PKG_CONFIG_PATH=<stage>/lib/pkgconfig meson setup build \
#     -Dcpp_args="-I<stage>/include/bess -I<stage>/include/bess/core"
#   ninja -C build && meson install -C build --destdir=<stage-destdir>
#   bessd -modules=<plugin dir> ...
#
# The two include directories are what `pkg-config --define-prefix` computes for
# a stage installed with --destdir (the .pc keeps the configured prefix, which
# is /usr/local unless BESS was configured with -Dprefix=<stage>); meson has no
# way to pass --define-prefix through.

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
# names the library, ADD_MODULE the classes), and the manifest loads both by
# class name from this single .so.
upf_datapath = shared_module(
  'upf_datapath',
  ['gtpu_decap.cc', 'gtpu_encap.cc', 'urr_count.cc', upf_proto[0], upf_proto[1]],
  include_directories: include_directories('.'),
  dependencies: [bess_dep, protobuf_dep],
  install: true,
  install_dir: modules_dir,
)
