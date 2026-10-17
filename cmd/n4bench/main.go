// Command n4bench is a stand-in SMF: it drives a UPF's N4 node with the
// messages an SMF sends (associate, establish, modify, delete) as fast as the
// UPF answers, and reports the rate and the latency distribution.
//
// It exists because the open-source UPFs are tested with functional
// simulators (omec-project/pfcpsim sends one session at a time from a CLI, and
// reports nothing about time): nobody publishes an N4 transaction rate or a
// latency envelope. This does, for one target at a time:
//
//	n4bench -upf 127.0.0.1:8805 -mode bulk -sessions 512 -workers 16
//
// The target matters: the same client against an upfd without -bess measures
// the N4 node alone (its refusal path, since no session layer is configured),
// and against an upfd with -bess it measures the whole control path (PFCP ->
// session compiler -> one control_v2 transaction -> bessd), which is the
// number a deployment cares about.
//
// One socket, one reader, many requests in flight: responses are matched by
// the sequence number this client chose, so the measurement is not the
// round-trip of a serialised client. Heartbeat Requests from the UPF are
// answered, so a long run does not lose the association.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/n4sim"
)

type opKind int

const (
	opAssoc opKind = iota
	opEstablish
	opModify
	opDelete
	opKindCount
)

var opNames = [opKindCount]string{"associate", "establish", "modify", "delete"}

// stats is one operation's samples. Every sample is a full request/response
// round trip.
type stats struct {
	mu       sync.Mutex
	d        []time.Duration
	errs     map[string]int
	attempts int
}

func (s *stats) add(d time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if err != nil {
		if s.errs == nil {
			s.errs = map[string]int{}
		}
		s.errs[err.Error()]++
		return
	}
	s.d = append(s.d, d)
}

// attemptsCount is every request sent, answered or not: the rate a node that
// refuses everything still has to be able to produce.
func (s *stats) attemptsCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// failures counts every request that got no accepted answer, for any reason:
// a cause the UPF sent back, or no answer at all.
func (s *stats) failures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.errs {
		n += c
	}
	return n
}

// quantileP returns the p-quantile of the samples (nearest-rank).
func (s *stats) quantileP(p float64) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.d) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), s.d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	i := int(p * float64(len(sorted)-1))
	return sorted[i]
}

func (s *stats) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.d)
}

// max is the slowest sample, the one a timeout would have cut off.
func (s *stats) max() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m time.Duration
	for _, d := range s.d {
		if d > m {
			m = d
		}
	}
	return m
}

// client is one UDP endpoint speaking to a UPF: the association it made, the
// requests in flight, and the reader that matches answers to them.
type client struct {
	conn  *net.UDPConn
	log   *slog.Logger
	seq   atomic.Uint32
	mu    sync.Mutex
	wait  map[uint32]chan message.Message // by sequence, within one message type
	stats [opKindCount]*stats
}

func dial(target string, log *slog.Logger) (*client, error) {
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	c := &client{conn: conn, log: log, wait: map[uint32]chan message.Message{}}
	for i := range c.stats {
		c.stats[i] = &stats{}
	}
	go c.read()
	return c, nil
}

func (c *client) close() { c.conn.Close() }

// read routes every datagram to the request that is waiting for it, and keeps
// the association alive by answering the UPF's own heartbeats.
func (c *client) read() {
	buf := make([]byte, 65535)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return
		}
		m, err := message.Parse(buf[:n])
		if err != nil {
			c.log.Warn("unparsable datagram", "err", err)
			continue
		}
		if _, ok := m.(*message.HeartbeatRequest); ok {
			hb := n4sim.HeartbeatResponse(m.Sequence())
			b, err := wire(hb)
			if err != nil {
				c.log.Warn("marshalling a heartbeat response", "err", err)
				continue
			}
			if _, err := c.conn.Write(b); err != nil {
				c.log.Warn("answering a heartbeat", "err", err)
			}
			continue
		}
		key := m.Sequence()
		c.mu.Lock()
		ch, ok := c.wait[key]
		if ok {
			delete(c.wait, key)
		}
		c.mu.Unlock()
		if ok {
			ch <- m
		} else {
			c.log.Warn("answer to no request", "type", m.MessageTypeName(), "seq", key)
		}
	}
}

// send registers the sequence before writing, so an answer cannot arrive
// before the waiter exists, and waits for the answer. The sequence number it
// waits under is this client's own counter, and it is put on the message: the
// builders number requests by session index, and with several workers the
// indices and the calls advance in different orders, so a request could carry
// one number while its waiter was registered under another -- the reply then
// matched nothing ("answer to no request") or the wrong request.
func (c *client) send(m message.Message, kind opKind, timeout time.Duration) (message.Message, time.Duration, error) {
	key := c.seq.Add(1)
	m.SetSequenceNumber(key)
	ch := make(chan message.Message, 1)
	c.mu.Lock()
	c.wait[key] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.wait, key)
		c.mu.Unlock()
	}()

	start := time.Now()
	b, err := wire(m)
	if err != nil {
		c.stats[kind].add(0, err)
		return nil, 0, err
	}
	if _, err := c.conn.Write(b); err != nil {
		c.stats[kind].add(0, err)
		return nil, 0, err
	}
	select {
	case resp := <-ch:
		d := time.Since(start)
		cause, err := n4sim.Cause(resp)
		if err != nil {
			c.stats[kind].add(0, err)
			return resp, d, err
		}
		if cause != 1 { // cause 1 = Request accepted
			err := fmt.Errorf("cause %d", cause)
			c.stats[kind].add(0, err)
			return resp, d, err
		}
		c.stats[kind].add(d, nil)
		return resp, d, nil
	case <-time.After(timeout):
		err := errors.New("no answer within " + timeout.String())
		c.stats[kind].add(0, err)
		return nil, 0, err
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "n4bench:", err)
		os.Exit(1)
	}
}

func run() error {
	target := flag.String("upf", "127.0.0.1:8805", "the UPF's N4 (PFCP) UDP address")
	nodeID := flag.String("node-id", "smf.local", "the Node ID this client advertises")
	workers := flag.Int("workers", 16, "concurrent requests in flight")
	sessions := flag.Int("sessions", 512, "sessions the phase covers")
	mode := flag.String("mode", "bulk", "establish | cycle | bulk: what the sessions do")
	rate := flag.Float64("rate", 0, "operations per second (0: as fast as the UPF answers)")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout")
	fteid := flag.Uint("fteid", 0,
		"the F-TEIDs the sessions pin: session i pins value+i, as an SMF does "+
			"(0: the UPF chooses every one, like an SMF that pins none)")
	uePool := flag.String("ue-pool", "10.45.0.0/16", "the UE addresses the sessions use")
	gnb := flag.String("gnb", "10.20.30.2", "the gNB's N3 address (the outer header's destination)")
	n3 := flag.String("n3", "192.0.2.1", "the UPF's N3 address (the F-TEID it is asked for)")
	jsonOut := flag.String("json", "", "write the samples to this file")
	level := flag.String("log-level", "warn", "log level: debug, info, warn, error")
	flag.Parse()

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*level)); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	if *sessions <= 0 || *workers <= 0 {
		return fmt.Errorf("-sessions and -workers must be positive")
	}
	if *workers > *sessions {
		*workers = *sessions
	}
	base, err := poolBase(*uePool, *sessions)
	if err != nil {
		return err
	}

	c, err := dial(*target, log)
	if err != nil {
		return err
	}
	defer c.close()

	// The association is one request: it is reported, and it is required
	// before any session message is answered.
	if _, _, err := c.send(n4sim.Associate(1, *nodeID), opAssoc, *timeout); err != nil {
		return fmt.Errorf("association with %s: %w", *target, err)
	}

	params := sessionParams(*sessions, uint32(*fteid), base, *gnb, *n3)
	seids := make([]uint64, *sessions) // the UPF-side SEID of each session

	phase := newPacer(*rate)
	work := func(kind opKind, n int, fn func(i int) (message.Message, uint64)) {
		start := time.Now()
		var wg sync.WaitGroup
		per := (n + *workers - 1) / *workers
		for w := 0; w < *workers; w++ {
			lo, hi := w*per, (w+1)*per
			if hi > n {
				hi = n
			}
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					phase.wait()
					m, _ := fn(i)
					if m == nil {
						// fn says this session has nothing to send yet: a
						// message naming SEID 0 would ask a different question.
						continue
					}
					resp, _, err := c.send(m, kind, *timeout)
					if err == nil && kind == opEstablish && resp != nil {
						// The answer's header carries *our* SEID (the CP F-SEID,
						// the identity the UPF addresses its answers to); the
						// UPF's own is the F-SEID IE, and every later request
						// must use it (TS 29.244 7.2.2.4.2).
						if r, ok := resp.(*message.SessionEstablishmentResponse); ok && r.UPFSEID != nil {
							if f, err := r.UPFSEID.FSEID(); err == nil {
								seids[i] = f.SEID
							}
						}
					}
				}
			}(lo, hi)
		}
		wg.Wait()
		phase.add(kind, time.Since(start), c.stats[kind])
	}

	switch *mode {
	case "establish":
		work(opEstablish, *sessions, func(i int) (message.Message, uint64) {
			return n4sim.Establish(2+uint32(i), params[i]), 0
		})
	case "cycle":
		work(opEstablish, *sessions, func(i int) (message.Message, uint64) {
			return n4sim.Establish(2+uint32(i), params[i]), 0
		})
		work(opModify, *sessions, func(i int) (message.Message, uint64) {
			if seids[i] == 0 {
				return nil, 0 // never established, so there is no session to name
			}
			s := params[i]
			return n4sim.Modify(2+uint32(*sessions+i), seids[i], 2, s.TEID+1, s.GnBIP), 0
		})
		work(opDelete, *sessions, func(i int) (message.Message, uint64) {
			if seids[i] == 0 {
				return nil, 0 // never established, so there is no session to name
			}
			return n4sim.Delete(2+uint32(2**sessions+i), seids[i]), 0
		})
	case "bulk":
		// Establish all, then modify all, then delete all: each phase is one
		// operation at full rate, which is how an SMF's own load arrives.
		work(opEstablish, *sessions, func(i int) (message.Message, uint64) {
			s := params[i]
			s.TEID = s.TEID + 1
			return n4sim.Establish(2+uint32(i), s), 0
		})
		work(opModify, *sessions, func(i int) (message.Message, uint64) {
			if seids[i] == 0 {
				return nil, 0 // never established, so there is no session to name
			}
			s := params[i]
			return n4sim.Modify(2+uint32(*sessions+i), seids[i], 2, s.TEID+2, s.GnBIP), 0
		})
		work(opDelete, *sessions, func(i int) (message.Message, uint64) {
			if seids[i] == 0 {
				return nil, 0 // never established, so there is no session to name
			}
			return n4sim.Delete(2+uint32(2**sessions+i), seids[i]), 0
		})
	default:
		return fmt.Errorf("-mode %q: want establish, cycle or bulk", *mode)
	}

	fmt.Printf("target %s, %d workers, %d sessions, mode %s\n\n", *target, *workers, *sessions, *mode)
	fmt.Printf("%-10s %8s %10s %10s %10s %10s %12s\n",
		"op", "count", "p50", "p95", "p99", "max", "ops/s")
	var out struct {
		Target   string             `json:"target"`
		Mode     string             `json:"mode"`
		Workers  int                `json:"workers"`
		Sessions int                `json:"sessions"`
		Ops      map[string]opStats `json:"ops"`
	}
	out.Target, out.Mode, out.Workers, out.Sessions = *target, *mode, *workers, *sessions
	out.Ops = map[string]opStats{}
	for k := opAssoc; k < opKindCount; k++ {
		st := c.stats[k]
		if st.count() == 0 && len(st.errs) == 0 {
			continue
		}
		rate := phase.rateOf(k)
		fmt.Printf("%-10s %8d %10s %10s %10s %10s %12.1f\n", opNames[k], st.count(),
			(st.quantileP(0.50)).Round(time.Microsecond), st.quantileP(0.95).Round(time.Microsecond),
			st.quantileP(0.99).Round(time.Microsecond), st.max().Round(time.Microsecond), rate)
		out.Ops[opNames[k]] = opStats{
			Count: st.count(), P50US: st.quantileP(0.50).Seconds() * 1e6,
			P95US: st.quantileP(0.95).Seconds() * 1e6, P99US: st.quantileP(0.99).Seconds() * 1e6,
			MaxUS: st.max().Seconds() * 1e6, PerSec: rate, Errors: st.errs,
		}
	}
	for k := opAssoc; k < opKindCount; k++ {
		for msg, n := range c.stats[k].errs {
			fmt.Printf("%s: %d error(s): %s\n", opNames[k], n, msg)
		}
	}
	if *jsonOut != "" {
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("\nsamples: %s\n", *jsonOut)
	}
	// A run where requests went unanswered is not a measurement: fail, and say
	// how many, so a starved box cannot be read as a slow UPF.
	bad, total := 0, 0
	for k := opAssoc; k < opKindCount; k++ {
		bad += c.stats[k].failures()
		total += c.stats[k].attemptsCount()
	}
	if bad > 0 {
		return fmt.Errorf("%d of %d requests did not get an accepted answer", bad, total)
	}
	return nil
}

// opStats is one operation's result in the JSON report.
type opStats struct {
	Count  int            `json:"count"`
	P50US  float64        `json:"p50_us"`
	P95US  float64        `json:"p95_us"`
	P99US  float64        `json:"p99_us"`
	MaxUS  float64        `json:"max_us"`
	PerSec float64        `json:"per_second"`
	Errors map[string]int `json:"errors,omitempty"`
}

// pacer turns -rate into a wait between operations. With rate 0 every wait is
// free, which is the point: the UPF then decides the rate.
type pacer struct {
	next  time.Time
	mu    sync.Mutex
	gap   time.Duration
	rates [opKindCount]struct {
		d     time.Duration
		count int
	}
}

func newPacer(rate float64) *pacer {
	p := &pacer{}
	if rate > 0 {
		p.gap = time.Duration(float64(time.Second) / rate)
		p.next = time.Now()
	}
	return p
}

func (p *pacer) wait() {
	if p.gap == 0 {
		return
	}
	p.mu.Lock()
	nowT := time.Now()
	if p.next.Before(nowT) {
		p.next = nowT
	}
	at := p.next
	p.next = p.next.Add(p.gap)
	p.mu.Unlock()
	time.Sleep(time.Until(at))
}

func (p *pacer) add(kind opKind, d time.Duration, st *stats) {
	p.rates[kind].d = d
	// attempts, not samples: a node that answers every request with a cause
	// still has to produce that many answers, and the N4-only run below has
	// nothing but refusals to measure.
	p.rates[kind].count = st.attemptsCount()
}

func (p *pacer) rateOf(kind opKind) float64 {
	r := p.rates[kind]
	if r.d <= 0 {
		return 0
	}
	return float64(r.count) / r.d.Seconds()
}

// wire returns the datagram for a message. The message.Message interface has
// MarshalTo and MarshalLen; the two-value Marshal is only on the concrete
// types, so a helper typed on the interface cannot call it.
func wire(m message.Message) ([]byte, error) {
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		return nil, err
	}
	return b, nil
}

// poolBase parses the UE pool into a 32-bit base address.
func poolBase(pool string, sessions int) (uint32, error) {
	ip, ipnet, err := net.ParseCIDR(pool)
	if err != nil {
		return 0, fmt.Errorf("-ue-pool %q: %w", pool, err)
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("-ue-pool %q: an IPv4 pool is required", pool)
	}
	// The pool must hold the sessions the run covers: a /16 is the scenario this
	// bench exists for, but one session against one address (a hand-built test)
	// is a pool too.
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if uint64(1)<<hostBits < uint64(sessions) {
		return 0, fmt.Errorf("-ue-pool %q holds %d addresses, but -sessions is %d",
			pool, uint64(1)<<hostBits, sessions)
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), nil
}

// sessionParams is the phase's sessions: what an SMF would ask for, one per
// index. A pinned F-TEID is the SMF's to make unique, so session i pins
// fteid+i -- one value for the whole phase would have the UPF refuse every
// session after the first (which it should), and the bench would report a wall
// of refusals as if they were the UPF's doing. An fteid of 0 pins nothing:
// every session asks the UPF to choose, which is what an SMF that never pins
// does.
func sessionParams(n int, fteid, base uint32, gnb, n3 string) []n4sim.Session {
	params := make([]n4sim.Session, n)
	for i := range params {
		pinned := uint32(0)
		if fteid > 0 {
			pinned = fteid + uint32(i)
		}
		params[i] = n4sim.Session{
			CPSEID: uint64(0x1000 + i),
			TEID:   uint32(0x100000 + i),
			FTEID:  pinned,
			UEIP:   offsetAddr(base, i),
			GnBIP:  gnb,
			N3IP:   n3,
		}
	}
	return params
}

// offsetAddr is the i-th address of the pool as a string.
func offsetAddr(base uint32, i int) string {
	a := base + uint32(i)
	return fmt.Sprintf("%d.%d.%d.%d", byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
}
