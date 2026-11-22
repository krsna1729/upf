// SPDX-License-Identifier: BSD-3-Clause
//go:build linux && transactiontrace

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/trace"
	"syscall"
	"time"
)

// Diagnostic build only. A one-shot signal starts the trace after the
// benchmark has loaded its live population, not during setup or fill.
func init() {
	flag.Func("transaction-trace", "write a one-second Go execution trace here on SIGUSR2 (diagnostic)", armTransactionTrace)
}

func armTransactionTrace(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	trigger := make(chan os.Signal, 1)
	signal.Notify(trigger, syscall.SIGUSR2)
	go func() {
		defer f.Close()
		<-trigger
		defer signal.Stop(trigger)
		if err := trace.Start(f); err != nil {
			fmt.Fprintln(os.Stderr, "upfd: start transaction trace:", err)
			return
		}
		time.Sleep(time.Second)
		trace.Stop()
	}()
	return nil
}
