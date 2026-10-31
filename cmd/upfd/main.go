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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/n4"
	"github.com/krsna1729/upf/internal/routing"
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
	var fteidAddresses entryList
	flag.Var(&fteidAddresses, "fteid-address",
		"repeatable endpoint=<id>,reference=<n3|n9>,transport-domain=<id>,source=<access|core>,instance=<name>,ipv4=<addr>,ipv6=<addr>; config/environment entries are ';'-separated")
	capacity := flag.Uint("capacity", 1<<16,
		"the id spaces the session compiler keeps: the capacity of the graph's "+
			"Meter and GtpuEncap tables, which refuse an id beyond it")
	n6NextHop := flag.Uint("n6-next-hop", 1, "the Router next hop an uplink forward leaves by")
	n3NextHop := flag.Uint("n3-next-hop", 2,
		"the Router next hop a downlink forward leaves by: the encap's gate "+
			"(the classifier's result names it)")
	atsss := flag.String("atsss", "",
		"the AtsssSteer module whose policies a MAR-steered PDR uses (TS 29.244 7.5.2.8): "+
			"its \"<name>/policies\" resource is written with the MAR's two access actions, and the "+
			"module writes the selected next hop and tunnel. Empty: this deployment does not "+
			"steer, and a PDR that names a MAR is refused with cause 73")
	accessNextHop := flag.Uint("access-next-hop", 0,
		"the Router next hop a forward whose FAR names Destination Interface Access "+
			"(TS 29.244 8.2.24, value 0) leaves by, whichever direction the PDR is on: the "+
			"encap, on a downlink forward, and the indirect-forwarding tunnel on an uplink "+
			"one. 0 (the default): the downlink direction's own -n3-next-hop, which is what "+
			"a deployment without uplink forwarding needs")
	routeMode := flag.String("route-mode", "hop",
		"how the graph's Router decides a forward's egress: hop (the default) resolves a FAR's "+
			"egress to the next-hop id its action names; destination writes no hop id and lets the "+
			"Router look each packet's own IPv4 destination up in its route domain, so one egress "+
			"can reach many destinations by the deployment's routes. The graph's Router must carry "+
			"the matching `mode` argument, and a destination-mode graph decrements the TTL itself")
	instances := flag.String("instances", "",
		"the deployment's network instances (TS 29.244 8.2.4), ';'-separated, each "+
			"\"name=<instance>,domain=<route domain>[,next-hop=<id>][,tunnel-next-hop=<id>]\"+"+
			"\"[,access-next-hop=<id>][,sgi-lan-next-hop=<id>][,vn-next-hop=<id>][,pool=<prefix>][,arp=<module>]\"+"+
			"\"[,arp-mac=<xx:xx:xx:xx:xx:xx>]\"; the *-next-hop keys are the instance's "+
			"egresses, one per FAR Destination Interface value (8.2.24) and per outer header "+
			"creation: a plain forward toward Core, a tunnel toward Core, a tunnel toward Access "+
			"(N3 or N9), one toward the service LAN and one that re-enters the subscriber side. "+
			"With -route-mode=destination the *-next-hop keys are unnecessary (the Router's "+
			"routes are the egress table) and an instance line may name no egress. empty: the "+
			"one-instance deployment, where no PDI's Network Instance is read")
	maxDomains := flag.Uint("max-domains", 1,
		"the bound on route-domain ids: every -instances domain must be below it. With "+
			"-route-mode=destination it must equal the inner Router's max_domains, or a packet "+
			"classified in a domain the router does not have resolves to no table")
	pdrFieldsUL := flag.String("pdr-fields-ul", "src,dst,proto,sport,dport,fteid,qfi",
		"the uplink PDR table's fields, in the graph's order")
	pdrFieldsDL := flag.String("pdr-fields-dl", "src,dst,proto,sport,dport,domain,fteid,qfi",
		"the downlink PDR table's fields, in the graph's order")
	metersUL := flag.String("meters-ul", "mt_ul", "the uplink Meter module")
	pdrTableUL := flag.String("pdr-table-ul", "pdr_ul",
		"the WildcardMatch module holding the uplink PDR rules")
	pdrTableDL := flag.String("pdr-table-dl", "pdr_dl",
		"the WildcardMatch module holding the downlink PDR rules")
	metersDL := flag.String("meters-dl", "mt_dl", "the downlink Meter module")
	countersUL := flag.String("counters-ul", "cnt_ul",
		"the uplink UrrCount module (per-rule usage counters); empty: the graph charges nothing")
	countersDL := flag.String("counters-dl", "cnt_dl",
		"the downlink UrrCount module (per-rule usage counters); empty: the graph charges nothing")
	tunnels := flag.String("tunnels", "enc", "the GtpuEncap module (per-session downlink parameters)")
	tunnelsUL := flag.String("tunnels-ul", "enc",
		"the GtpuEncap module for uplink forwards that add an outer header of their own "+
			"(Destination Interface Access or Core with an Outer Header Creation: indirect "+
			"forwarding and the uplink of an N9 tunnel). A deployment with one encap module "+
			"names it in both flags, which is what the defaults say; empty means the uplink "+
			"has none, and a FAR that needs one is then refused with cause 73 rather than "+
			"compiled to a rule the encap drops for want of a session record")
	bufferStore := flag.String("buffer-store", "",
		"the packet store module a FAR whose Apply Action is BUFF holds its packets in: with "+
			"-buffer-counter and -buffer-gate, buffering is served end to end -- the first "+
			"buffered packet is reported to the SMF over N4, and the held packets are released "+
			"when the SMF's next instruction moves the path. Empty: such a FAR's rule drops")
	bufferCounter := flag.String("buffer-counter", "",
		"the UrrCount module on the buffering branch, in front of the store: its per-rule "+
			"counters are what marks the first buffered packet of a flow (the Downlink Data "+
			"Report's trigger), read once per -urr-interval tick")
	bufferGate := flag.Uint("buffer-gate", 0,
		"the PDR table gate that delivers on the buffering branch")
	gtpuDecap := flag.String("gtpu-decap", "decap", "the GtpuDecap module whose /fteids resource admits endpoint-scoped F-TEIDs")
	gtpuErrors := flag.String("gtpu-errors", "",
		"the GtpuResponder module whose error table is read once per -urr-interval "+
			"tick: the responder behind GtpuDecap gate 2 receives unknown G-PDUs and "+
			"control messages, including the peer's Error Indications (TS 29.281 7.3.1). A session "+
			"whose FAR sends with a TEID the peer reported is reported to the SMF as "+
			"an Error Indication Report (TS 29.244 5.10). Empty: the graph's responder "+
			"does not track them (its track_errors argument) and no such report is sent")
	gtpuEndMarkers := flag.String("gtpu-end-markers", "",
		"the GtpuResponder module whose End Marker log is drained once per -urr-interval "+
			"tick (its track_end_markers argument). An End Marker on a PDR's local F-TEID is "+
			"reported as a Usage Report with the EMRRE trigger for each URR of that PDR that "+
			"asks for REEMR (TS 29.244 8.2.19, 8.2.41). Empty: a URR that asks for REEMR is refused")
	metricsAddr := flag.String("metrics", "",
		"serve this node's own numbers (Prometheus text format) on host:port; "+
			"empty: no endpoint")
	sessionWorkers := flag.Int("session-workers", 1,
		"how many PFCP session messages are handled at once, each session's in the order "+
			"they arrived (1: one at a time, in the socket's read loop). More lets the "+
			"dataplane transactions of different sessions overlap")
	urrInterval := flag.Duration("urr-interval", 0,
		"how often to read every session's usage counters and report what each URR owes "+
			"over N4 (0: never, so URRs measure and report nothing)")
	checkpointPath := flag.String("checkpoint", "",
		"the session checkpoint file (docs/design.md's restart wall): every applied "+
			"session message is journalled to it before the SMF is answered, and a restart "+
			"replays it before the PFCP socket opens, keeping the sessions and the "+
			"Recovery Time Stamp the SMF knows; empty: every start is a clean slate")
	endMarker := flag.String("end-marker", "",
		"the base graph unix_port path for End Markers; upfd appends .<transport_route_domain> to select the old routed tunnel")
	target := flag.String("target", "graph",
		"what the session compiler writes to: graph (the default) is the module graph, every "+
			"table \"<module>/<table>\" of the module its flag names; appliance is one module "+
			"(-appliance) that runs the whole user plane and owns every table. With appliance the "+
			"module flags (-gtpu-decap, -pdr-table-*, -meters-*, -counters-*, -tunnels*, -atsss, "+
			"-buffer-store, -buffer-counter, -buffer-gate, -gtpu-errors, -gtpu-end-markers) are not "+
			"read: the appliance has every table and buffers, steers and tracks errors and End "+
			"Markers, so -urr-interval must be positive. A nonempty -instances arp= enables "+
			"the appliance's subscriber ARP proxy for that interface")
	applianceModule := flag.String("appliance", "upf",
		"the appliance module's name, with -target appliance")
	// The config file's own flag: its value is read back from the flag set
	// (applyLayers), because it must be layered like any other flag before the
	// file it names is read.
	flag.String(configFlag, "",
		"a JSON config file carrying the same settings as these flags, keyed by flag name: "+
			"{\"n4\": \"0.0.0.0:8805\", \"instances\": \"name=internet,domain=0,next-hop=1\"}. "+
			"Optional: with no path named here (or in UPFD_CONFIG), no file is read, and one "+
			"that is named must be readable. Every flag is also settable in the environment "+
			"as UPFD_<FLAG> (upper case, '-' becomes '_'): the command line wins over the "+
			"environment, which wins over the file, which wins over the flag's own default")
	printConfig := flag.Bool("print-config", false,
		"print the effective settings -- every flag's value after the command line, the "+
			"environment and -config's file were applied -- in -config's own JSON format, "+
			"and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"upfd: the UPF controller -- PFCP (N4) towards the SMF, BESS over control_v2.\n\n"+
				"Settings come from three places, highest first: the command line, the\n"+
				"environment (UPFD_<FLAG>: upper case, '-' as '_'), and the optional JSON\n"+
				"config file -config names. Each fills only the flags the sources above it\n"+
				"left alone, and -print-config prints the result.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Which flags any source named -- the command line, the environment or the
	// config file: an override is a flag a source named, not one whose value
	// happens to differ from its default. It is resolved before anything reads
	// a flag.
	if _, err := applyLayers(flag.CommandLine); err != nil {
		return err
	}
	if *printConfig {
		// The effective settings, in the file's own format, and nothing else:
		// this is the way to see what a deployment resolves to and the way to
		// write the first config file.
		out, err := effectiveConfig(flag.CommandLine)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", out)
		return nil
	}

	mode, err := session.ParseRouteMode(*routeMode)
	if err != nil {
		return fmt.Errorf("-route-mode: %w", err)
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*level)); err != nil {
		return fmt.Errorf("log level %q: %w", *level, err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	applyMemoryLimit(log)

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

	cfg := n4.Config{NodeID: id, Listen: *n4Addr, Logger: log, SessionWorkers: *sessionWorkers}
	// The checkpoint (docs/design.md's restart wall). It is opened first: the
	// Recovery Time Stamp it carries decides what the association answer tells
	// the SMF, and that answer is built before the socket opens.
	var (
		checkpoint *session.Journal
		// restored is whether this run put the journal's sessions back: it
		// decides the Recovery Time Stamp the association answer carries, and
		// the journal's own record is not a second source for it -- a run whose
		// restore failed clears the file and writes the stamp it advertises.
		restored bool
	)
	if *checkpointPath != "" {
		j, err := session.OpenJournal(*checkpointPath)
		if err != nil {
			return err
		}
		defer j.Close()
		checkpoint = j
	}
	// The session layer, when there is one: the metrics endpoint reports what
	// it holds whatever the run, and the reporting loop needs it to exist.
	var compiler *session.Compiler
	if *bessAddr != "" {
		client, err := bess.Dial(ctx, *bessAddr)
		if err != nil {
			return err
		}
		defer client.Close()
		graph, err := graphConfig(graphArgs{
			target:         *target,
			appliance:      *applianceModule,
			fteidAddresses: fteidAddresses,
			capacity:       uint32(*capacity),
			n6NextHop:      uint32(*n6NextHop), n3NextHop: uint32(*n3NextHop),
			accessNextHop: uint32(*accessNextHop),
			atsss:         *atsss,
			routeMode:     mode,
			pdrTableUL:    *pdrTableUL, pdrTableDL: *pdrTableDL,
			pdrFieldsUL: *pdrFieldsUL, pdrFieldsDL: *pdrFieldsDL,
			instances: *instances, maxDomains: uint32(*maxDomains),
			gtpuDecap:      *gtpuDecap,
			gtpuErrors:     *gtpuErrors,
			gtpuEndMarkers: *gtpuEndMarkers,
			endMarker:      *endMarker,
			metersUL:       *metersUL,
			metersDL:       *metersDL, tunnels: *tunnels, tunnelsUL: *tunnelsUL,
			countersUL: *countersUL, countersDL: *countersDL,
			bufferStore: *bufferStore, bufferCounter: *bufferCounter, bufferGate: uint32(*bufferGate),
		})
		if err != nil {
			return err
		}
		// A buffering deployment must say how often its counters are read, and it
		// is refused before anything is swept, replayed or listened on: the
		// guard is a fact about the flags, so it belongs before the first effect.
		if graph.Buffering != nil && *urrInterval <= 0 {
			return fmt.Errorf("buffering (the %q store) needs a positive -urr-interval: the Downlink Data Report is what that loop's reading of the buffering counters owes the SMF",
				graph.Buffering.Store)
		}
		graph.NodeID = id
		if a, err := netip.ParseAddr(id); err == nil {
			graph.N4Addr = a
		} else if host, _, err := net.SplitHostPort(*n4Addr); err == nil {
			// An FQDN Node ID: the F-SEID still carries the address the socket
			// listens on, when it names one.
			if a, err := netip.ParseAddr(host); err == nil && !a.IsUnspecified() {
				graph.N4Addr = a
			}
		}
		cfg.Sessions = session.New(graph, client, log)
		compiler = cfg.Sessions.(*session.Compiler)
		// The restart wall (docs/design.md): the daemon may still hold an
		// earlier controller's sessions, and this process knows none of them --
		// they would match packets with ids nothing here can name. They go
		// before the PFCP socket opens, in transactions of a bounded size
		// (session.Compiler.Sweep). A sweep that fails is fatal, deliberately:
		// it erases in batches, so a failure leaves the tables half-erased and
		// this process cannot tell which of the earlier run's sessions still
		// match packets, and it also fails when the daemon cannot be read back
		// at all -- in both cases what the run would serve PFCP over is unknown.
		// Refusing to start keeps the node out of the association, which the
		// SMF sees and retries, instead of answering for sessions this
		// dataplane does not hold.
		if err := cfg.Sessions.(*session.Compiler).Sweep(ctx); err != nil {
			return fmt.Errorf("the startup sweep did not finish: %w", err)
		}
		// And the checkpoint goes back in, after the sweep: the replay writes
		// the sessions the journal describes, so the dataplane holds those and
		// nothing else. A journal this layer cannot read is not a checkpoint --
		// the sessions replayed from it so far are dropped and the run
		// advertises a new Recovery Time Stamp, so the SMF re-establishes
		// everything rather than the half that fitted.
		if checkpoint != nil {
			// The journal is attached whether or not this run can restore from
			// it: this is the run whose messages have to be recorded, and a
			// first start -- an empty file, nothing to restore -- is exactly the
			// case with everything to write.
			compiler.Checkpoint(checkpoint)
			if _, ok := checkpoint.Recovery(); !ok {
				log.Info("session checkpoint carries no Recovery Time Stamp: "+
					"this run advertises a new one and the SMF re-establishes",
					"path", *checkpointPath)
			} else if err := compiler.Restore(checkpoint); err != nil {
				// A journal this layer cannot read is not a checkpoint: the
				// sessions replayed from it so far are dropped and the run
				// advertises a new Recovery Time Stamp, so the SMF re-establishes
				// everything rather than the half that fitted.
				log.Warn("the checkpoint could not be replayed; starting clean",
					"path", *checkpointPath, "error", err)
				compiler.AssociationEnded("the checkpoint could not be replayed")
			} else {
				restored = true
			}
		}
		// The F-TEID allocation lives in the session layer, so the feature is
		// advertised only in the run that has it: without -bess this node has no
		// session layer at all and refuses every session request, and an
		// association answer promising an F-TEID it cannot allocate would be a
		// claim nothing behind it honours.
		cfg.UPFunctionFeatures[0] = n4.FTUP
		// MNOP (8.2.25 octet 7, bit 5): the session layer's reports carry the
		// packet counts, so the feature is as real as the layer itself.
		cfg.UPFunctionFeatures[2] |= n4.MNOP
		if hasEndMarker(graph) {
			// EMPU advertises End Marker construction (TS 29.244 8.2.25) when
			// the routed End Marker base path is configured.
			cfg.UPFunctionFeatures[1] |= n4.EMPU
		}
		ready := []any{"bess", *bessAddr, "bess_version", client.Version(),
			"daemon_epoch", client.Epoch(), "fteid_endpoints", graph.FTEIDEndpoints, "target", *target,
			"uplink", graph.Up.PDRTable,
			"downlink", graph.Down.PDRTable}
		if graph.Instances != nil {
			ready = append(ready, "network_instances", strings.Join(graph.Instances.Names(), ","))
		}
		log.Info("session layer ready", ready...)
	} else {
		log.Warn("no -bess address: session messages are refused (no session layer)")
	}

	// The stamp the association answer will carry. With no restored checkpoint
	// it is now: the sessions this node holds are none, and an SMF that kept
	// believing in its own would be right to -- which is exactly why the stamp
	// has to move. With a restored one it is the stamp those sessions were
	// created under, and nothing was lost for the SMF to hear about.
	if checkpoint != nil {
		stamp := time.Now()
		if restored {
			// Recovery was ok or Restore would not have run; the value is the
			// one the journal's first record carries.
			stamp, _ = checkpoint.Recovery()
		}
		if err := checkpoint.Start(stamp, restored); err != nil {
			return err
		}
		cfg.RecoveryTimeStamp = stamp
		log.Info("session checkpoint", "path", *checkpointPath, "sessions_restored", restored,
			"recovery_time_stamp", stamp.UTC().Format(time.RFC3339))
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

	// The usage reporting loop: nothing else calls Evaluate, so without this
	// run a URR measures and reports nothing at all (TS 29.244 5.2.2.2.1 --
	// the UP function is what watches the counters, and a quota nobody reads
	// never stops the traffic). It walks every session on each tick and sends
	// what each URR owes over N4, one report at a time.
	reports := &reportStats{}
	if *urrInterval > 0 {
		if compiler == nil {
			return fmt.Errorf("-urr-interval %v needs -bess: without a session layer there is nothing to evaluate", *urrInterval)
		}
		go reportLoop(ctx, compiler, srv, *urrInterval, reports, log)
	}

	// The management endpoint: this node's own numbers, so an operator reads
	// them from the same place a scraper does. It is off unless asked for.
	if *metricsAddr != "" {
		mux, ln, err := metricsServer(*metricsAddr, metricsHandler(compiler, srv, reports))
		if err != nil {
			return err
		}
		go func() {
			if err := mux.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("the metrics endpoint stopped", "addr", ln.Addr().String(), "error", err)
			}
		}()
		go func() {
			<-ctx.Done()
			_ = mux.Close()
		}()
		log.Info("metrics listening", "addr", ln.Addr().String())
	}
	return srv.Serve()
}

// reportLoop is upfd's usage reporting: on every tick, evaluate each session's
// URRs, decide what the SMF must hear, and send it. What the SMF does not
// answer is kept and tried again (reportQueue), because an unanswered send
// leaves the outcome unknown rather than known bad.
// reportSender is the half of the N4 node the reporting loop uses: one Session
// Report Request, the CP function's answer (its Cause, and the Update BAR it may
// carry), and an error when it was not answered.
type reportSender interface {
	Report(ctx context.Context, cpSEID uint64, ies ...*ie.IE) (n4.ReportAnswer, error)
}

// reportQueueDepth bounds one session's reports waiting for an answer: a CP
// function that never answers cannot grow this node's memory past the sessions
// it holds times this. Every session may hold reports -- a tick at the 1M
// target owes a report to every session whose period ends in it -- so the
// queue has no bound of its own on sessions.
const (
	reportQueueDepth = 4
	// reportWindow is how many Session Report Requests the drain keeps in
	// flight at once once the SMF has answered the tick's first: one at a time,
	// a tick's reports cost a round trip each.
	reportWindow = 64
	// reportBackoffCap is the longest a report waits before it is tried again:
	// each attempt costs the n4 layer's whole retry budget, and the tick that
	// makes it also carries the evaluation that enforces every session's quota,
	// so a silent CP function must not be sent to at the tick's rate.
	reportBackoffCap = 30 * time.Second
)

// reportBackoff is how long a held report waits after this many unanswered
// sends: doubling from one tick to the cap.
func reportBackoff(attempts int, every time.Duration) time.Duration {
	d := every
	for i := 0; i < attempts && d < reportBackoffCap; i++ {
		d *= 2
	}
	if d > reportBackoffCap {
		return reportBackoffCap
	}
	return d
}

// backoffLogged says whether an attempt should be logged: the first one, and
// then only when the count doubles -- a report an SMF never answers would
// otherwise write a log line at the tick's rate for as long as it is held.
func backoffLogged(attempts int) bool {
	return attempts == 1 || attempts&(attempts-1) == 0
}

// heldReport is one usage report the SMF has not answered yet.
type heldReport struct {
	report   session.Report
	attempts int
	next     time.Time // the earliest this one is sent again
}

// reportQueue keeps the usage reports a session's SMF has not answered. The
// Session Report Request is the one message this node initiates, and the SMF is
// owed each report it asked for: an unanswered send leaves the outcome unknown
// (the same reason the SDK asks again rather than assuming), so the report is
// kept and sent before the session's next one -- which is what keeps the
// UR-SEQNs the SMF reads in order. A *refusal* is a definite answer and is not
// retried; only silence is. A report the session's queue has no room for is
// not queued, and its usage is not lost: the session layer takes the decision
// back (Compiler.Unreport) or the session's last held report carries it.
type reportQueue struct {
	held map[uint64][]heldReport // by the session's local SEID
}

func newReportQueue() *reportQueue {
	return &reportQueue{held: map[uint64][]heldReport{}}
}

// add queues a report, or hands it back when the session already holds
// reportQueueDepth: the newest is the one turned away, because it is the one
// whose decision can still be taken back.
func (q *reportQueue) add(r session.Report) (refused *session.Report) {
	queue := q.held[r.SEID]
	if len(queue) >= reportQueueDepth {
		return &r
	}
	q.held[r.SEID] = append(queue, heldReport{report: r})
	return nil
}

// absorb adds an undelivered report's usage to the session's newest held one,
// which has not been sent yet whenever the session holds more than its head.
// It reports false when there is nothing held to carry it.
func (q *reportQueue) absorb(r session.Report) bool {
	queue := q.held[r.SEID]
	if len(queue) == 0 {
		return false
	}
	queue[len(queue)-1].report.Absorb(r)
	return true
}

// seids is every session with a report waiting, low SEID first: a drain visits
// them in the order their sessions were established, and a session that keeps
// failing does not delay the others.
func (q *reportQueue) seids() []uint64 {
	out := make([]uint64, 0, len(q.held))
	for seid := range q.held {
		out = append(out, seid)
	}
	slices.Sort(out)
	return out
}

// head is the report the session has owed its SMF longest, with how many times
// it has been sent unsanswered.
func (q *reportQueue) head(seid uint64) (heldReport, bool) {
	queue := q.held[seid]
	if len(queue) == 0 {
		return heldReport{}, false
	}
	return queue[0], true
}

// done takes a session's oldest report out of the queue: the SMF answered it,
// with a Cause or with a refusal.
func (q *reportQueue) done(seid uint64) {
	queue := q.held[seid]
	if len(queue) == 0 {
		return
	}
	if len(queue) == 1 {
		delete(q.held, seid)
		return
	}
	q.held[seid] = queue[1:]
}

// cancel drops every report a session still holds, and returns how many: the
// session layer no longer has the session, so its termination report carries
// that usage instead (finding 20).
func (q *reportQueue) cancel(seid uint64) int {
	held := len(q.held[seid])
	delete(q.held, seid)
	return held
}

// sent records that the session's oldest report went out once more without an
// answer: it stays where it is, and it is tried again after the backoff.
func (q *reportQueue) sent(seid uint64, now time.Time, backoff time.Duration) {
	queue := q.held[seid]
	if len(queue) == 0 {
		return
	}
	queue[0].attempts++
	queue[0].next = now.Add(backoff)
	q.held[seid] = queue
}

// reportLoop evaluates every session on each tick, decides what the SMF must
// hear, and sends it: a report the SMF has not answered is kept and tried again
// on the next tick, before that session's newer ones (see reportQueue).
func reportLoop(ctx context.Context, sessions *session.Compiler, sender reportSender, every time.Duration,
	reports *reportStats, log *slog.Logger) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	queue := newReportQueue()
	acknowledge := func(r session.Report, detail string, attrs ...any) {
		log.Info("usage report "+detail, append([]any{
			"seid", r.SEID, "cp_seid", r.CPSEID, "urr", r.URRID, "seqn", r.Seqn,
			"trigger", r.Trigger.String(), "packets", r.Up.Packets, "octets", r.Up.Octets,
			"down_packets", r.Down.Packets, "down_octets", r.Down.Octets}, attrs...)...)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		for _, report := range sessions.EvaluateAll(ctx, time.Now()) {
			if refused := queue.add(report); refused != nil {
				// The usage stays owed: the decision goes back to the session
				// layer, or rides on the session's newest held report.
				if !sessions.Unreport(*refused) && !queue.absorb(*refused) {
					reports.dropped.Add(1)
				}
				log.Warn("usage report not queued: the SMF has not answered the ones before it",
					"seid", refused.SEID, "cp_seid", refused.CPSEID, "urr", refused.URRID,
					"seqn", refused.Seqn, "trigger", refused.Trigger.String(),
					"octets", refused.Up.Octets, "held", reportQueueDepth)
			}
		}
		// The downlink half of the same tick: the PDRs whose first buffered
		// packet has arrived since the previous tick. A Downlink Data Report is
		// a different message from a usage report (7.5.8.2), so it is sent here
		// rather than queued with them; the flow is marked reported only once
		// the SMF has taken the message, so a send that fails is offered again
		// on the next tick -- and the next tick is also the report's whole
		// latency (docs/design.md: the trigger is a poll of the branch's
		// counters, at this loop's period).
		for _, d := range sessions.EvaluateDownlinks(ctx) {
			answer, err := sender.Report(ctx, d.CPSEID, d.IEs()...)
			if err != nil || answer.Cause != ie.CauseRequestAccepted {
				reports.ddnFailed.Add(1)
				log.Warn("downlink data report not delivered", "seid", d.SEID, "cp_seid", d.CPSEID,
					"pdrs", d.PDRs, "cause", answer.Cause, "error", err)
				continue
			}
			sessions.ConfirmDownlinks(ctx, d.SEID, d.PDRs)
			// The SMF may answer a Downlink Data Report with an Update BAR
			// (5.2.4.1): it extends the holding of the flow the report named,
			// and the session layer applies it to the same model a modification
			// writes. Applied after the report is confirmed, so the episode the
			// numbers belong to is the one just taken.
			sessions.ApplyUpdateBAR(ctx, d.SEID, answer.UpdateBAR)
			reports.ddnSent.Add(1)
			log.Info("downlink data reported: the SMF has been told about packets being held",
				"seid", d.SEID, "cp_seid", d.CPSEID, "pdrs", d.PDRs)
		}

		// One report per session per tick, so a session's reports reach the
		// SMF in order however many sessions' are in flight.
		now := time.Now()
		var due []heldReport
		for _, seid := range queue.seids() {
			if !sessions.Holds(seid) {
				// The session ended while these reports waited: the deletion's
				// termination report carried their usage (finding 20), so they
				// are not sent -- an SMF mid-release may take one and count the
				// usage twice, and one that is already gone answers cause 65.
				if held := queue.cancel(seid); held > 0 {
					reports.cancelled.Add(uint64(held))
					log.Info("usage reports cancelled: the session ended while they waited",
						"seid", seid, "reports", held)
				}
				continue
			}
			if r, ok := queue.head(seid); ok && !r.next.After(now) {
				due = append(due, r)
			}
		}
		for i, res := range sendReports(ctx, sender, due) {
			if !res.tried {
				continue
			}
			r := due[i]
			seid := r.report.SEID
			if res.err != nil {
				reports.held.Add(1)
				backoff := reportBackoff(r.attempts+1, every)
				queue.sent(seid, now, backoff)
				if backoffLogged(r.attempts + 1) {
					log.Warn("usage report not delivered: held and backed off",
						"seid", r.report.SEID, "cp_seid", r.report.CPSEID, "urr", r.report.URRID,
						"trigger", r.report.Trigger.String(), "octets", r.report.Up.Octets,
						"attempts", r.attempts+1, "retry_in", backoff, "error", res.err)
				}
				continue
			}
			answer := res.answer
			queue.done(seid)
			if answer.Cause != ie.CauseRequestAccepted {
				reports.refused.Add(1)
				// A refusal is the SMF's answer and is not sent again; the
				// usage it carried rides on the session's next held report.
				queue.absorb(r.report)
				log.Warn("usage report refused", "seid", r.report.SEID, "cp_seid", r.report.CPSEID,
					"urr", r.report.URRID, "trigger", r.report.Trigger.String(), "cause", answer.Cause)
			} else {
				reports.sent.Add(1)
				// The SMF has the usage this report carried: the URRs' base
				// for the termination report moves up to it (finding 20).
				sessions.ConfirmReport(ctx, r.report)
				acknowledge(r.report, "acknowledged", "attempts", r.attempts+1)
			}
			// An answer may carry an Update BAR whatever it reports (5.2.4.1's
			// named case is the Downlink Data Report, handled above); the
			// session layer owns whether it means anything for this session.
			sessions.ApplyUpdateBAR(ctx, r.report.SEID, answer.UpdateBAR)
			if r.report.Enforcing {
				log.Info("quota spent: the session's traffic is stopped",
					"seid", r.report.SEID, "urr", r.report.URRID)
			}
		}
	}
}

// reportResult is one due report's send: the SMF's answer, or the error that
// says none came. tried is false for a report the drain did not get to.
type reportResult struct {
	answer n4.ReportAnswer
	err    error
	tried  bool
}

// sendReports sends the tick's due reports: the first alone, and once the SMF
// has answered it the rest with up to reportWindow in flight. The first
// transport failure stops further sends -- each costs the n4 layer's whole
// retry budget, and this same tick carries the evaluation that opens windows
// and enforces quotas, so a CP function that has stopped answering must not
// hold it. What is not sent keeps its place (and its backoff).
func sendReports(ctx context.Context, sender reportSender, due []heldReport) []reportResult {
	out := make([]reportResult, len(due))
	send := func(i int) bool {
		// The report is addressed to the CP function, and the header's SEID
		// is the identity the *receiver* looks the session up with: the CP
		// F-SEID, not ours (TS 29.244 7.2.2.4.2).
		r := due[i].report
		answer, err := sender.Report(ctx, r.CPSEID, r.IEs()...)
		out[i] = reportResult{answer: answer, err: err, tried: true}
		return err == nil
	}
	if len(due) == 0 || !send(0) {
		return out
	}
	var failed atomic.Bool
	var wg sync.WaitGroup
	window := make(chan struct{}, reportWindow)
	for i := 1; i < len(due) && !failed.Load(); i++ {
		window <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !send(i) {
				failed.Store(true)
			}
			<-window
		}()
	}
	wg.Wait()
	return out
}

// graphArgs is the flag set graphConfig turns into a session.Config.
type graphArgs struct {
	target         string
	appliance      string
	fteidAddresses entryList
	capacity       uint32
	n6NextHop      uint32
	n3NextHop      uint32
	accessNextHop  uint32
	atsss          string
	routeMode      session.RouteMode
	instances      string
	maxDomains     uint32
	pdrTableUL     string
	pdrTableDL     string
	pdrFieldsUL    string
	pdrFieldsDL    string
	gtpuDecap      string
	gtpuErrors     string
	gtpuEndMarkers string
	metersUL       string
	metersDL       string
	countersUL     string
	bufferStore    string
	bufferCounter  string
	bufferGate     uint32
	countersDL     string
	tunnels        string
	tunnelsUL      string
	endMarker      string
}

// graphConfig is the deployed dataplane's shape, from the flags: the module
// graph's, or the appliance's (-target).
func graphConfig(a graphArgs) (session.Config, error) {
	if a.target != "graph" && a.target != "appliance" {
		return session.Config{}, fmt.Errorf("-target %q is graph or appliance", a.target)
	}
	fteidEndpoints, err := parseFTEIDAddresses(a.fteidAddresses, a.instances != "")
	if err != nil {
		return session.Config{}, fmt.Errorf("-fteid-address: %w", err)
	}
	if len(fteidEndpoints) == 0 {
		return session.Config{}, fmt.Errorf("-fteid-address: at least one local GTP-U endpoint is required with -bess")
	}
	hasN3 := false
	for _, endpoint := range fteidEndpoints {
		hasN3 = hasN3 || endpoint.ReferencePoint == "n3"
	}
	if !hasN3 {
		return session.Config{}, fmt.Errorf("-fteid-address: an N3 endpoint is required")
	}
	// Each table matches the inner IPv4 packet: the UE address on the side the
	// PDI names, and the SDF tuple where a filter constrains it
	// (docs/design.md, "The key"). A graph that also classifies by route domain
	// or by the tunnel the packet arrived on says so in its own field list --
	// the manifests declare the offsets, and these flags mirror them.
	upFields, err := parsePDRFields(a.pdrFieldsUL)
	if err != nil {
		return session.Config{}, fmt.Errorf("-pdr-fields-ul: %w", err)
	}
	downFields, err := parsePDRFields(a.pdrFieldsDL)
	if err != nil {
		return session.Config{}, fmt.Errorf("-pdr-fields-dl: %w", err)
	}
	var domains *routing.Domains
	if a.instances != "" {
		if domains, err = parseInstances(a.instances, a.maxDomains, a.routeMode); err != nil {
			return session.Config{}, fmt.Errorf("-instances: %w", err)
		}
	}
	for _, endpoint := range fteidEndpoints {
		if endpoint.Instance == "" {
			continue
		}
		if domains == nil {
			return session.Config{}, fmt.Errorf("-fteid-address: endpoint %d names instance %q without -instances",
				endpoint.ID, endpoint.Instance)
		}
		if _, ok := domains.Lookup(endpoint.Instance); !ok {
			return session.Config{}, fmt.Errorf("-fteid-address: endpoint %d names unknown instance %q",
				endpoint.ID, endpoint.Instance)
		}
	}
	graph := session.Config{
		RouteMode: a.routeMode,
		GTPUDecap: a.gtpuDecap,
		// The responder that counts the peer's Error Indications, when the
		// graph's has tracking on (TS 29.244 5.10).
		GTPUErrors: a.gtpuErrors,
		// The responder whose End Marker log is drained, when the graph's
		// tracks them (TS 29.244 8.2.19 REEMR).
		GTPUEndMarkers: a.gtpuEndMarkers,
		// The base path for routed End Markers, when the deployment has one.
		EndMarker: a.endMarker,
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
			PDRFields: upFields,
			Meters:    a.metersUL,
			Counters:  a.countersUL,
			// An uplink forward can add an outer header of its own: indirect
			// data forwarding (Destination Interface Access) and the uplink of
			// an N9 tunnel (Destination Interface Core with an Outer Header
			// Creation). Its record goes in the same encap module the downlink
			// uses unless the graph has a second one -- the action ids are the
			// session's, so one table holds both directions' records.
			Tunnels: a.tunnelsUL,
			NextHop: a.n6NextHop,
		},
		Down: session.Direction{
			PDRTable:  a.pdrTableDL,
			PDRFields: downFields,
			Meters:    a.metersDL,
			Counters:  a.countersDL,
			NextHop:   a.n3NextHop,
			Tunnels:   a.tunnels,
		},
		Instances:      domains,
		FTEIDEndpoints: fteidEndpoints,
		// Where a forward whose FAR names Destination Interface Access leaves
		// by, whichever direction the PDR is on: a downlink forward's encap,
		// and the indirect-forwarding tunnel an uplink forward leaves through
		// (8.2.2 NOTE 2). 0 leaves it to the downlink direction's own hop.
		AccessNextHop: a.accessNextHop,
		Atsss:         a.atsss,
	}
	if a.target == "appliance" {
		return applianceConfig(graph, a.appliance)
	}
	if a.bufferStore != "" {
		// The buffering branch is all three names or none: a store collects the
		// packets, the counter in front of it is what the Downlink Data Report
		// is decided from, and the gate is how a BUFF rule reaches them. Half a
		// branch would either hold packets nobody reports or report counters
		// nothing writes.
		if a.bufferCounter == "" {
			return session.Config{}, fmt.Errorf(
				"-buffer-store %q needs -buffer-counter: a store's flows are reported from the branch's counters",
				a.bufferStore)
		}
		graph.Buffering = &session.Buffering{
			Store:   a.bufferStore,
			Counter: a.bufferCounter,
			Gate:    a.bufferGate,
		}
	}
	return graph, nil
}

// applianceConfig is cfg compiled for one appliance module (-target
// appliance): every table is the module's (session.Config.Appliance), and
// every one is in use -- the appliance has them all, so it is the owner each
// module field names, and the flags that say which modules a graph has are not
// read.
func applianceConfig(cfg session.Config, module string) (session.Config, error) {
	if module == "" {
		return session.Config{}, fmt.Errorf("-appliance: -target appliance needs the module's name")
	}
	cfg.Appliance = module
	cfg.GTPUDecap, cfg.GTPUErrors, cfg.GTPUEndMarkers, cfg.Atsss = module, module, module, module
	for _, d := range []*session.Direction{&cfg.Up, &cfg.Down} {
		d.PDRTable, d.Meters, d.Counters, d.Tunnels = module, module, module, module
	}
	cfg.Buffering = &session.Buffering{Store: module, Counter: module, Gate: session.ApplianceBufferGate}
	return cfg, nil
}
