module github.com/krsna1729/upf

go 1.24

// The BESS Go SDK is a nested module of the fork:
//
//	github.com/krsna1729/bess/sdk/go
//
// It is required once cmd/upfd and internal/bess import it. Until the fork's
// commits are published, point at a local checkout instead of the network:
//
//	replace github.com/krsna1729/bess/sdk/go => ${BESS_SRC}/sdk/go
//
// ci/build-bess.sh writes that replace into go.mod.work once BESS_SRC is set.

require github.com/wmnsk/go-pfcp v0.0.24
