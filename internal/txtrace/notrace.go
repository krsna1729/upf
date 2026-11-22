// SPDX-License-Identifier: BSD-3-Clause
//go:build !transactiontrace

package txtrace

import "context"

func Mark(context.Context, string, string) {}
