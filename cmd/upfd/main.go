// Command upfd is the UPF controller: it terminates PFCP (N4) towards the SMF
// and drives BESS over control_v2 with the Go SDK.
//
// With -bess it dials bessd, reads the daemon's schema, and compiles every
// session the SMF establishes into dataplane resources in one transaction
// (internal/session). Without it the daemon runs as a pure N4 node: session
// messages are refused with a Cause, which is what a test of the wire
// behaviour wants.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/n4"
	"github.com/krsna1729/upf/internal/session"
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

	bessAddr := flag.String("bess", "", "bessd's control_v2 gRPC address (host:port); empty: no datapath, sessions are refused")
	n3Addr := flag.String("n3-addr", "", "the UPF's N3 IPv4 address, advertised as the uplink F-TEID; required with -bess")
	n3MAC := flag.String("n3-mac", "02:00:00:00:00:01", "the N3 port's Ethernet address, for the outer header of a downlink packet")
	peerMAC := flag.String("peer-mac", "02:00:00:00:00:02", "the N3 peer's Ethernet address (the transport next hop)")
	capacity := flag.Uint("capacity", 1<<16,
		"the id spaces the session compiler keeps: the capacity of the graph's "+
			"Meter, ActionTable and GtpuEncap tables, which refuse an id beyond it")
	n6NextHop := flag.Uint("n6-next-hop", 1, "the Router next hop an uplink forward leaves by")
	n3NextHop := flag.Uint("n3-next-hop", 2,
		"the Router next hop a downlink forward leaves by: the encap's gate "+
			"(a chain with an ActionTable fails closed when its action names none)")
	pdrTableUL := flag.String("pdr-table-ul", "pdr_ul",
		"the WildcardMatch module holding the uplink PDR rules")
	pdrTableDL := flag.String("pdr-table-dl", "pdr_dl",
		"the WildcardMatch module holding the downlink PDR rules")
	actionsUL := flag.String("actions-ul", "at_ul", "the uplink ActionTable module")
	metersUL := flag.String("meters-ul", "mt_ul", "the uplink Meter module")
	actionsDL := flag.String("actions-dl", "at_dl", "the downlink ActionTable module")
	metersDL := flag.String("meters-dl", "mt_dl", "the downlink Meter module")
	tunnels := flag.String("tunnels", "enc", "the GtpuEncap module (per-session downlink parameters)")
	teidTable := flag.String("teid-table", "teid",
		"the WildcardMatch module whose rules are the F-TEID match")
	teidGate := flag.Uint("teid-gate", 0,
		"the gate a TEID rule delivers on: the decap's output gate")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := n4.Config{NodeID: id, Listen: *n4Addr, Logger: log}
	if *bessAddr != "" {
		client, err := bess.Dial(ctx, *bessAddr)
		if err != nil {
			return err
		}
		defer client.Close()
		graph, err := graphConfig(graphArgs{
			n3: *n3Addr, n3MAC: *n3MAC, peerMAC: *peerMAC,
			capacity:  uint32(*capacity),
			n6NextHop: uint32(*n6NextHop), n3NextHop: uint32(*n3NextHop),
			pdrTableUL: *pdrTableUL, pdrTableDL: *pdrTableDL,
			teidTable: *teidTable, teidGate: uint32(*teidGate),
			actionsUL: *actionsUL, metersUL: *metersUL,
			actionsDL: *actionsDL, metersDL: *metersDL, tunnels: *tunnels,
		})
		if err != nil {
			return err
		}
		cfg.Sessions = session.New(graph, client, log)
		log.Info("session layer ready", "bess", *bessAddr, "bess_version", client.Version(),
			"daemon_epoch", client.Epoch(), "n3", graph.N3Addr.String())
	} else {
		log.Warn("no -bess address: session messages are refused (no session layer)")
	}

	srv, err := n4.New(cfg)
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return err
	}
	log.Info("n4 listening", "addr", srv.Addr().String(), "node_id", id)

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		srv.Close()
	}()
	return srv.Serve()
}

// graphArgs is the flag set graphConfig turns into a session.Config.
type graphArgs struct {
	n3, n3MAC, peerMAC string
	capacity           uint32
	n6NextHop          uint32
	n3NextHop          uint32
	pdrTableUL         string
	pdrTableDL         string
	teidTable          string
	teidGate           uint32
	actionsUL          string
	metersUL           string
	actionsDL          string
	metersDL           string
	tunnels            string
}

// graphConfig is the deployed graph's shape, from the flags.
func graphConfig(a graphArgs) (session.Config, error) {
	n3, n3MAC, peerMAC := a.n3, a.n3MAC, a.peerMAC
	addr, err := netip.ParseAddr(n3)
	if err != nil || !addr.Is4() {
		return session.Config{}, fmt.Errorf("-n3-addr %q: an IPv4 address is required with -bess", n3)
	}
	// Each table matches the inner IPv4 packet: the UE address on the side the
	// PDI names, and the SDF tuple where a filter constrains it
	// (docs/design.md, "The key").
	fields := []session.Field{session.SrcIP, session.DstIP, session.Proto,
		session.SrcPort, session.DstPort}
	graph := session.Config{
		TEIDTable: a.teidTable,
		TEIDGate:  a.teidGate,
		// The graph's tables and these spaces are one number: the modules
		// refuse an id beyond their capacity.
		MaxActions: a.capacity,
		MaxMeters:  a.capacity,
		MaxTEIDs:   a.capacity,
		// Two chains, because a module has one output gate per path: the
		// uplink's meter feeds the router toward N6, the downlink's feeds the
		// tunnel toward N3. Each chain has its own rule table, so every rule's
		// ActionId is in the resource its table declares.
		Up: session.Direction{
			PDRTable:  a.pdrTableUL,
			PDRFields: fields,
			Actions:   a.actionsUL,
			Meters:    a.metersUL,
			NextHop:   a.n6NextHop,
		},
		Down: session.Direction{
			PDRTable:  a.pdrTableDL,
			PDRFields: fields,
			Actions:   a.actionsDL,
			Meters:    a.metersDL,
			NextHop:   a.n3NextHop,
			Tunnels:   a.tunnels,
		},
		N3Addr: addr,
	}
	if graph.N3MAC, err = parseMAC(n3MAC); err != nil {
		return session.Config{}, fmt.Errorf("-n3-mac: %w", err)
	}
	if graph.PeerMAC, err = parseMAC(peerMAC); err != nil {
		return session.Config{}, fmt.Errorf("-peer-mac: %w", err)
	}
	return graph, nil
}

func parseMAC(s string) ([6]byte, error) {
	var out [6]byte
	hw, err := net.ParseMAC(s)
	if err != nil {
		return out, err
	}
	if len(hw) != 6 {
		return out, fmt.Errorf("%q is not a 6-byte address", s)
	}
	copy(out[:], hw)
	return out, nil
}
