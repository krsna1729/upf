// Command upfd is the UPF controller: it terminates PFCP (N4) towards the SMF
// and drives BESS over control_v2 with the Go SDK.
//
// This is the N4 node: association and heartbeat. The BESS link and the
// session layer land next, so session requests are refused with a Cause for
// now (see internal/n4).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/krsna1729/upf/internal/n4"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "upfd:", err)
		os.Exit(1)
	}
}

func run() error {
	n4Addr := flag.String("n4", "0.0.0.0:8805", "PFCP (N4) UDP listen address")
	nodeID := flag.String("node-id", "", "Node ID this UP function advertises (IP address or FQDN); default: the -n4 address")
	level := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*level)); err != nil {
		return fmt.Errorf("log level %q: %w", *level, err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	id := *nodeID
	if id == "" {
		host, _, err := net.SplitHostPort(*n4Addr)
		if err != nil {
			return fmt.Errorf("n4 address %q: %w", *n4Addr, err)
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsUnspecified() {
			return fmt.Errorf("n4 address %q carries no address to use as the Node ID: set -node-id", *n4Addr)
		}
		id = ip.String()
	}

	srv, err := n4.New(n4.Config{NodeID: id, Listen: *n4Addr, Logger: log})
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return err
	}
	log.Info("n4 listening", "addr", srv.Addr().String(), "node_id", id)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		srv.Close()
	}()
	return srv.Serve()
}
