module github.com/krsna1729/upf

go 1.24

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
	github.com/wmnsk/go-pfcp v0.0.24
	google.golang.org/protobuf v1.36.10
)

require (
	github.com/krsna1729/bess/sdk/go v0.0.0-20261016142821-0fb10e55b202
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/grpc v1.75.1 // indirect
)
