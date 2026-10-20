module github.com/krsna1729/upf

go 1.27.2

// The BESS Go SDK is a nested module of the fork:
//
//	github.com/krsna1729/bess/sdk/go
//
// It is required below by pseudo-version, resolved from the public repository, so
// a plain build works with no workspace at all (GOWORK=off). Two ways to build
// against a local checkout instead:
//
//	go.work                              (untracked, machine-local: overrides go.mod)
//	replace ... => ${BESS_SRC}/sdk/go    (ci/build-bess.sh writes go.mod.work)
//
// A release tag, sdk/go/vX.Y.Z, replaces the pseudo-version when the SDK is
// released; the fork's docs/control-sdk.md has the details.

require (
	github.com/krsna1729/bess/sdk/go v0.0.0-20261020103822-c8ffb3badbc7
	github.com/wmnsk/go-pfcp v0.0.24
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
)

// go-pfcp carries every IE parser on the N4 path. The fork is v0.0.24 plus the
// upstream IE parser fixes for #142 and #145, so a malformed PFD Contents,
// SDF Filter or neighbour IE is refused rather than panicking the daemon.
// It keeps the upstream module path, hence the replace form.
replace github.com/wmnsk/go-pfcp => github.com/krsna1729/go-pfcp v0.0.25-upf.2
