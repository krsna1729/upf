// SPDX-License-Identifier: BSD-3-Clause
//go:build transactiontrace

// Package txtrace marks UPF's work in a diagnostic Go execution trace.
package txtrace

import (
	"context"
	"runtime/trace"
)

func Mark(ctx context.Context, event, id string) { trace.Log(ctx, event, id) }
