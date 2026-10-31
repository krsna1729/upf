// SPDX-License-Identifier: BSD-3-Clause

//go:build race

package session

// The race detector's shadow multiplies the heap several times over, and a
// test that holds millions of rules would then outgrow a runner's memory.
func init() { raceEnabled = true }
