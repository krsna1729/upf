# SPDX-License-Identifier: BSD-3-Clause
# Sourced after ci/bess-env.sh by the CNTC lanes, from the UPF being tested.
TARGET=${UPF_TARGET:-graph}
case "$TARGET" in
  graph)
    DEFAULT_GRAPH=$ROOT/deploy/session-path.yaml
    TARGET_ARGS=(-target graph -gtpu-decap decap0)
    ;;
  appliance)
    DEFAULT_GRAPH=$ROOT/deploy/session-path-appliance.yaml
    TARGET_ARGS=(-target appliance -appliance upf -urr-interval 1s)
    ;;
  *) echo "UPF_TARGET must be graph or appliance" >&2; exit 2 ;;
esac
export UPF_TARGET=$TARGET GRAPH=${GRAPH:-$DEFAULT_GRAPH} BESS_PORT
export TMPDIR=${TMPDIR:-$ROOT/build/run}
mkdir -p "$TMPDIR"
export GLOG_log_dir=${GLOG_log_dir:-$TMPDIR/glog}
mkdir -p "$GLOG_log_dir"
