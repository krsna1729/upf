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
	instances := flag.String("instances", "",
		"the deployment's network instances (TS 29.244 8.2.4), ';'-separated, each "+
			"\"name=<instance>,domain=<route domain>,next-hop=<id>,pool=<prefix>[,...]\"; "+
			"empty: the one-instance deployment, where no PDI's Network Instance is read")
	maxDomains := flag.Uint("max-domains", 1,
		"the graph's Router max_domains: every -instances domain must be below it, "+
			"and a packet classified in one the router does not have resolves to no table")
	pdrFieldsUL := flag.String("pdr-fields-ul", "src,dst,proto,sport,dport",
		"the uplink PDR table's fields, in the graph's order: src, dst, proto, sport, "+
			"dport, domain (the vif's route_domain), teid (the decap's upf_teid)")
	pdrFieldsDL := flag.String("pdr-fields-dl", "src,dst,proto,sport,dport",
		"the downlink PDR table's fields, in the graph's order")
	pdrTableUL := flag.String("pdr-table-ul", "pdr_ul",
		"the WildcardMatch module holding the uplink PDR rules")
	pdrTableDL := flag.String("pdr-table-dl", "pdr_dl",
		"the WildcardMatch module holding the downlink PDR rules")
	actionsUL := flag.String("actions-ul", "at_ul", "the uplink ActionTable module")
	metersUL := flag.String("meters-ul", "mt_ul", "the uplink Meter module")
	actionsDL := flag.String("actions-dl", "at_dl", "the downlink ActionTable module")
	metersDL := flag.String("meters-dl", "mt_dl", "the downlink Meter module")
	countersUL := flag.String("counters-ul", "cnt_ul",
		"the uplink UrrCount module (per-rule usage counters); empty: the graph charges nothing")
	countersDL := flag.String("counters-dl", "cnt_dl",
		"the downlink UrrCount module (per-rule usage counters); empty: the graph charges nothing")
	tunnels := flag.String("tunnels", "enc", "the GtpuEncap module (per-session downlink parameters)")
	teidTable := flag.String("teid-table", "teid",
		"the WildcardMatch module whose rules are the F-TEID match")
	teidGate := flag.Uint("teid-gate", 0,
		"the gate a TEID rule delivers on: the decap's output gate")
	metricsAddr := flag.String("metrics", "",
		"serve this node's own numbers (Prometheus text format) on host:port; "+
			"empty: no endpoint")
	urrInterval := flag.Duration("urr-interval", 0,
		"how often to read every session's usage counters and report what each URR owes "+
			"over N4 (0: never, so URRs measure and report nothing)")
	checkpointPath := flag.String("checkpoint", "",
		"the session checkpoint file (docs/design.md's restart wall): every applied "+
			"session message is journalled to it before the SMF is answered, and a restart "+
			"replays it before the PFCP socket opens, keeping the sessions and the "+
			"Recovery Time Stamp the SMF knows; empty: every start is a clean slate")
	endMarker := flag.String("end-marker", "",
		"the graph's unix_port socket an End Marker packet is written to when a "+
			"modification's SNDEM flag moves a tunnel out from under a session "+
			"(TS 29.244 5.3.2); empty: this UPF constructs none and advertises no EMPU")
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
			n3: *n3Addr, n3MAC: *n3MAC, peerMAC: *peerMAC,
			capacity:  uint32(*capacity),
			n6NextHop: uint32(*n6NextHop), n3NextHop: uint32(*n3NextHop),
			pdrTableUL: *pdrTableUL, pdrTableDL: *pdrTableDL,
			pdrFieldsUL: *pdrFieldsUL, pdrFieldsDL: *pdrFieldsDL,
			instances: *instances, maxDomains: uint32(*maxDomains),
			teidTable: *teidTable, teidGate: uint32(*teidGate),
			endMarker: *endMarker,
			actionsUL: *actionsUL, metersUL: *metersUL,
			actionsDL: *actionsDL, metersDL: *metersDL, tunnels: *tunnels,
			countersUL: *countersUL, countersDL: *countersDL,
		})
		if err != nil {
			return err
		}
		cfg.Sessions = session.New(graph, client, log)
		compiler = cfg.Sessions.(*session.Compiler)
		// The restart wall (docs/design.md): the daemon may still hold an
		// earlier controller's sessions, and this process knows none of them --
		// they would match packets with ids nothing here can name. They go
		// before the PFCP socket opens, in one transaction. A daemon that
		// cannot be read back is a warning, not an outage: refusing to serve
		// PFCP because the sweep could not read would take the node down over
		// stale entries the SMF is about to replace anyway.
		if err := cfg.Sessions.(*session.Compiler).Sweep(ctx); err != nil {
			log.Warn("could not take an earlier run's sessions out of the dataplane", "error", err)
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
		if graph.EndMarker != "" {
			// EMPU (TS 29.244 5.3.2, 8.2.25 octet 6 bit 1): this UPF
			// constructs End Marker packets, and says so only where the graph
			// takes them -- the port the flag names is the whole mechanism.
			cfg.UPFunctionFeatures[1] |= n4.EMPU
		}
		ready := []any{"bess", *bessAddr, "bess_version", client.Version(),
			"daemon_epoch", client.Epoch(), "n3", graph.N3Addr.String()}
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
// Report Request, its Cause, and an error when it was not answered.
type reportSender interface {
	Report(ctx context.Context, cpSEID uint64, ies ...*ie.IE) (uint8, error)
}

// reportQueueDepth bounds one session's reports waiting for an answer, and
// reportQueueSessions the sessions with queued reports: a CP function that never
// answers cannot grow this node's memory without bound.
const (
	reportQueueDepth    = 4
	reportQueueSessions = 256
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
// retried; only silence is. What does not fit is logged with its usage when it
// is dropped rather than disappearing quietly.
type reportQueue struct {
	held map[uint64][]heldReport // by the session's local SEID
}

func newReportQueue() *reportQueue {
	return &reportQueue{held: map[uint64][]heldReport{}}
}

// add queues a report, dropping the oldest one this session still holds when the
// session's queue is full (or, for a session with no room at all, refusing to
// hold it): the dropped report is returned for the caller to log.
func (q *reportQueue) add(r session.Report) (dropped *session.Report) {
	if _, ok := q.held[r.SEID]; !ok && len(q.held) >= reportQueueSessions {
		return &r
	}
	queue := append(q.held[r.SEID], heldReport{report: r})
	if len(queue) > reportQueueDepth {
		old := queue[0]
		queue = queue[1:]
		dropped = &old.report
	}
	q.held[r.SEID] = queue
	return dropped
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
			if dropped := queue.add(report); dropped != nil {
				reports.dropped.Add(1)
				log.Warn("usage report dropped: the SMF has not answered the ones before it",
					"seid", dropped.SEID, "cp_seid", dropped.CPSEID, "urr", dropped.URRID,
					"seqn", dropped.Seqn, "trigger", dropped.Trigger.String(),
					"octets", dropped.Up.Octets, "held", reportQueueDepth)
			}
		}
		now := time.Now()
		// One report per session per tick, and the tick's first transport
		// failure ends the drain: each send costs the n4 layer's whole retry
		// budget, and this same tick carries the evaluation that opens windows
		// and enforces quotas -- a CP function that has stopped answering must
		// not hold it. What is not sent now keeps its place (and its backoff).
		for _, seid := range queue.seids() {
			r, ok := queue.head(seid)
			if !ok || r.next.After(now) {
				continue
			}
			// The report is addressed to the CP function, and the header's
			// SEID is the identity the *receiver* looks the session up with:
			// the CP F-SEID, not ours (TS 29.244 7.2.2.4.2).
			cause, err := sender.Report(ctx, r.report.CPSEID, r.report.IEs()...)
			if err != nil {
				reports.held.Add(1)
				backoff := reportBackoff(r.attempts+1, every)
				queue.sent(seid, now, backoff)
				if backoffLogged(r.attempts + 1) {
					log.Warn("usage report not delivered: held and backed off",
						"seid", r.report.SEID, "cp_seid", r.report.CPSEID, "urr", r.report.URRID,
						"trigger", r.report.Trigger.String(), "octets", r.report.Up.Octets,
						"attempts", r.attempts+1, "retry_in", backoff, "error", err)
				}
				break
			}
			queue.done(seid)
			if cause != ie.CauseRequestAccepted {
				reports.refused.Add(1)
				log.Warn("usage report refused", "seid", r.report.SEID, "cp_seid", r.report.CPSEID,
					"urr", r.report.URRID, "trigger", r.report.Trigger.String(), "cause", cause)
			} else {
				reports.sent.Add(1)
				acknowledge(r.report, "acknowledged", "attempts", r.attempts+1)
			}
			if r.report.Enforcing {
				log.Info("quota spent: the session's traffic is stopped",
					"seid", r.report.SEID, "urr", r.report.URRID)
			}
		}
	}
}

// graphArgs is the flag set graphConfig turns into a session.Config.
type graphArgs struct {
	n3, n3MAC, peerMAC string
	capacity           uint32
	n6NextHop          uint32
	n3NextHop          uint32
	instances          string
	maxDomains         uint32
	pdrTableUL         string
	pdrTableDL         string
	pdrFieldsUL        string
	pdrFieldsDL        string
	teidTable          string
	teidGate           uint32
	actionsUL          string
	metersUL           string
	actionsDL          string
	metersDL           string
	countersUL         string
	countersDL         string
	tunnels            string
	endMarker          string
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
		if domains, err = parseInstances(a.instances, a.maxDomains); err != nil {
			return session.Config{}, fmt.Errorf("-instances: %w", err)
		}
	}
	graph := session.Config{
		TEIDTable: a.teidTable,
		TEIDGate:  a.teidGate,
		// The socket an End Marker packet is written to, when the deployment
		// has one (TS 29.244 5.3.2).
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
			Actions:   a.actionsUL,
			Meters:    a.metersUL,
			Counters:  a.countersUL,
			NextHop:   a.n6NextHop,
		},
		Down: session.Direction{
			PDRTable:  a.pdrTableDL,
			PDRFields: downFields,
			Actions:   a.actionsDL,
			Meters:    a.metersDL,
			Counters:  a.countersDL,
			NextHop:   a.n3NextHop,
			Tunnels:   a.tunnels,
		},
		Instances: domains,
		N3Addr:    addr,
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
