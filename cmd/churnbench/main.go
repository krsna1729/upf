// SPDX-License-Identifier: BSD-3-Clause
// Command churnbench drives bounded, open-loop PFCP churn against a real UPF.
// Establish/delete use a finite extra cohort; modifications and replacement
// use the resident population. HTTP controls separate setup from timed cells.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/krsna1729/upf/internal/n4sim"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const expiryInterval = 100 * time.Millisecond

var requestTimeout = errors.New("timeout")

type slot struct {
	seid, cp                                    uint64
	generation                                  uint32
	pdrGeneration, qerGeneration, urrGeneration uint32
	busy, uncertain                             bool
}
type result struct {
	Mode                                                                                       string  `json:"mode"`
	Target                                                                                     int     `json:"target_cycles_per_second"`
	Duration                                                                                   float64 `json:"offer_seconds"`
	Scheduled, Sent, Completed, BusySkips, UncertainSkips, StateSkips, WindowSkips, PacerSkips int
	WireSent, WireAccepted, TimedOut, Refused                                                  int
	Deleted, Established, Modified                                                             int
	Reports, ReportAcknowledged, ReportBytes, ReportPackets                                    uint64
	Errors                                                                                     map[string]int
	Latency, CycleLatency                                                                      []time.Duration `json:"-"`
	Start, End                                                                                 time.Time
}
type pending struct {
	seq                    uint32
	kind                   byte
	index                  int
	started                time.Time
	phase                  *result
	done                   chan error
	cycleStarted           time.Time
	expiryPrev, expiryNext *pending
}
type driver struct {
	conn                                                    *net.UDPConn
	mu                                                      sync.Mutex
	runMu                                                   sync.Mutex
	slots                                                   []slot
	pending                                                 map[uint32]*pending
	expiryHead, expiryTail                                  *pending
	active                                                  int
	nextSeq                                                 uint32
	base, cohort, probes, maxInFlight                       int
	reports, reportAcknowledged, reportBytes, reportPackets uint64
	receiveBuffer, sendBuffer                               int
	timeout                                                 time.Duration
	ready                                                   bool
	fillErr                                                 string
	out                                                     string
}

func wire(m message.Message) ([]byte, error) {
	b := make([]byte, m.MarshalLen())
	return b, m.MarshalTo(b)
}
func (d *driver) teid(i int, s slot) uint32 {
	return uint32(0x1000+i) + uint32(len(d.slots))*s.generation
}
func (d *driver) params(i int, s slot) n4sim.Session {
	return n4sim.Session{CPSEID: s.cp, TEID: d.teid(i, s),
		FTEID: uint32(0x100000 + i),
		UEIP:  netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String(),
		GnBIP: "10.20.30.2", N3IP: "192.0.2.1"}
}
func (d *driver) establish(i int, s slot) *message.SessionEstablishmentRequest {
	r := n4sim.Establish(0, d.params(i, s))
	children, err := r.CreatePDR[0].CreatePDR()
	if err != nil {
		panic(err)
	}
	r.CreatePDR[0] = ie.NewCreatePDR(append(children, ie.NewURRID(7))...)
	triggers := byte(0)
	if i < d.probes {
		triggers = 1
	}
	parts := []*ie.IE{ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0),
		ie.NewReportingTriggers(triggers, 1), ie.NewVolumeQuota(1, 1<<50, 0, 0)}
	if i < d.probes {
		parts = append(parts, ie.NewMeasurementPeriod(time.Second))
	}
	r.CreateURR = []*ie.IE{ie.NewCreateURR(parts...)}
	return r
}
func (d *driver) modification(mode string, i int, s slot) message.Message {
	if mode == "far" {
		return n4sim.Modify(0, s.seid, 2, d.teid(i, s), "10.20.30.2")
	}
	var update *ie.IE
	switch mode {
	case "pdr":
		port := fmt.Sprint(53 + s.pdrGeneration%65483)
		update = ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, d.params(i, s).UEIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned "+port, "", "", "", 0)))
	case "qer":
		gate := uint8(ie.GateStatusOpen)
		if s.qerGeneration%2 != 0 {
			gate = ie.GateStatusClosed
		}
		update = ie.NewUpdateQER(ie.NewQERID(1),
			ie.NewGateStatus(gate, ie.GateStatusOpen),
			ie.NewMBR(1000+uint64(s.qerGeneration), 2000))
	case "urr":
		update = ie.NewUpdateURR(ie.NewURRID(7),
			ie.NewVolumeQuota(1, uint64(1<<50)+uint64(s.urrGeneration)*(1<<20), 0, 0))
	default:
		panic("invalid modification mode " + mode)
	}
	return message.NewSessionModificationRequest(0, 0, s.seid, 0, 0, update)
}
func (d *driver) emit(kind byte, i int, phase *result, done chan error, cycleStarted time.Time) {
	d.mu.Lock()
	s := d.slots[i]
	d.mu.Unlock()
	var m message.Message
	switch kind {
	case 'e':
		m = d.establish(i, s)
	case 'm':
		m = d.modification(phase.Mode, i, s)
	case 'd':
		m = n4sim.Delete(0, s.seid)
	case 'o':
		s.qerGeneration = 0
		m = d.modification("qer", i, s)
	case 'p':
		s.pdrGeneration = 0
		m = d.modification("pdr", i, s)
	}
	d.mu.Lock()
	for {
		d.nextSeq = (d.nextSeq + 1) & 0xffffff
		if d.nextSeq != 0 && d.pending[d.nextSeq] == nil {
			break
		}
	}
	seq := d.nextSeq
	m.SetSequenceNumber(seq)
	p := &pending{seq: seq, kind: kind, index: i, started: time.Now(), phase: phase, done: done, cycleStarted: cycleStarted}
	if p.cycleStarted.IsZero() {
		p.cycleStarted = p.started
	}
	d.trackPendingLocked(p)
	d.active++
	phase.WireSent++
	d.mu.Unlock()
	b, err := wire(m)
	if err == nil {
		_, err = d.conn.Write(b)
	}
	if err != nil {
		d.mu.Lock()
		if d.pending[seq] == p {
			d.takePendingLocked(seq)
		} else {
			p = nil
		}
		d.mu.Unlock()
		if p != nil {
			d.finish(p, nil, err)
		}
	}
}

// Requests share one timeout and started is assigned under mu, so expiry order
// is insertion order. Acknowledgements unlink their own request in O(1).
func (d *driver) trackPendingLocked(p *pending) {
	d.pending[p.seq] = p
	p.expiryPrev = d.expiryTail
	if d.expiryTail != nil {
		d.expiryTail.expiryNext = p
	} else {
		d.expiryHead = p
	}
	d.expiryTail = p
}

func (d *driver) takePendingLocked(seq uint32) *pending {
	p := d.pending[seq]
	if p == nil {
		return nil
	}
	delete(d.pending, seq)
	if p.expiryPrev != nil {
		p.expiryPrev.expiryNext = p.expiryNext
	} else {
		d.expiryHead = p.expiryNext
	}
	if p.expiryNext != nil {
		p.expiryNext.expiryPrev = p.expiryPrev
	} else {
		d.expiryTail = p.expiryPrev
	}
	p.expiryPrev, p.expiryNext = nil, nil
	return p
}
func (d *driver) finish(p *pending, msg message.Message, err error) {
	var seid uint64
	refused := false
	if err == nil {
		cause, e := n4sim.Cause(msg)
		if e != nil {
			err = e
		} else if cause != ie.CauseRequestAccepted {
			err = fmt.Errorf("cause %d", cause)
			refused = true
		}
		if err == nil && p.kind == 'e' {
			r, ok := msg.(*message.SessionEstablishmentResponse)
			if !ok || r.UPFSEID == nil {
				err = errors.New("accepted establishment lacks UP F-SEID")
			} else {
				f, e := r.UPFSEID.FSEID()
				if e != nil {
					err = e
				} else {
					seid = f.SEID
				}
			}
		}
	}
	replace := false
	d.mu.Lock()
	s := &d.slots[p.index]
	r := p.phase
	if err != nil {
		r.Errors[err.Error()]++
		if refused {
			r.Refused++
		}
		if err.Error() == "timeout" {
			r.TimedOut++
			if p.kind == 'e' || p.kind == 'd' {
				s.uncertain = true
			}
		}
		s.busy = false
	} else {
		r.WireAccepted++
		r.Latency = append(r.Latency, time.Since(p.started))
		switch p.kind {
		case 'e':
			s.seid = seid
			s.pdrGeneration, s.qerGeneration, s.urrGeneration = 0, 0, 0
			s.busy = false
			s.uncertain = false
			r.Established++
			r.Completed++
			r.CycleLatency = append(r.CycleLatency, time.Since(p.cycleStarted))
		case 'm', 'o', 'p':
			s.busy = false
			r.Modified++
			r.Completed++
			r.CycleLatency = append(r.CycleLatency, time.Since(p.cycleStarted))
		case 'd':
			s.seid = 0
			s.cp += uint64(len(d.slots))
			s.generation++
			r.Deleted++
			replace = r.Mode == "replace"
			if !replace {
				s.busy = false
				s.uncertain = false
				r.Completed++
				r.CycleLatency = append(r.CycleLatency, time.Since(p.cycleStarted))
			}
		}
	}
	if !replace {
		d.active--
	}
	d.mu.Unlock()
	if replace {
		d.emit('e', p.index, p.phase, p.done, p.cycleStarted)
		d.mu.Lock()
		d.active--
		d.mu.Unlock()
	} else if p.done != nil {
		p.done <- err
	}
}
func (d *driver) read() {
	b := make([]byte, 65535)
	for {
		n, err := d.conn.Read(b)
		if err != nil {
			return
		}
		msg, err := message.Parse(bytes.Clone(b[:n]))
		if err != nil {
			continue
		}
		switch m := msg.(type) {
		case *message.HeartbeatRequest:
			data, e := wire(n4sim.HeartbeatResponse(m.Sequence()))
			if e == nil {
				d.conn.Write(data)
			}
			continue
		case *message.SessionReportRequest:
			d.mu.Lock()
			d.reports++
			var localSEID uint64
			cause := uint8(ie.CauseSessionContextNotFound)
			if m.SEID() >= 0x1000 {
				i := int((m.SEID() - 0x1000) % uint64(len(d.slots)))
				if d.slots[i].cp == m.SEID() && d.slots[i].seid != 0 {
					localSEID = d.slots[i].seid
					cause = ie.CauseRequestAccepted
				}
			}
			// These are received wire volumes, not deduplicated charging totals.
			for _, usage := range m.UsageReport {
				children, _ := usage.UsageReport()
				for _, child := range children {
					if child.Type != ie.VolumeMeasurement {
						continue
					}
					if vol, err := child.VolumeMeasurement(); err == nil {
						d.reportBytes += vol.TotalVolume
						d.reportPackets += vol.TotalNumberOfPackets
					}
				}
			}
			d.mu.Unlock()
			data, e := wire(message.NewSessionReportResponse(0, 0, localSEID, m.Sequence(), 0, ie.NewCause(cause)))
			if e == nil {
				if _, e = d.conn.Write(data); e == nil && cause == ie.CauseRequestAccepted {
					d.mu.Lock()
					d.reportAcknowledged++
					d.mu.Unlock()
				}
			}
			continue
		}
		d.mu.Lock()
		p := d.takePendingLocked(msg.Sequence())
		d.mu.Unlock()
		if p != nil {
			d.finish(p, msg, nil)
		}
	}
}
func (d *driver) expire() {
	ticker := time.NewTicker(expiryInterval)
	defer ticker.Stop()
	for now := range ticker.C {
		d.expireAt(now)
	}
}

func (d *driver) expireAt(now time.Time) {
	var first, last *pending
	d.mu.Lock()
	for d.expiryHead != nil && now.Sub(d.expiryHead.started) >= d.timeout {
		p := d.takePendingLocked(d.expiryHead.seq)
		if last == nil {
			first = p
		} else {
			last.expiryNext = p
		}
		last = p
	}
	d.mu.Unlock()
	for p := first; p != nil; {
		next := p.expiryNext
		p.expiryNext = nil
		d.finish(p, nil, requestTimeout)
		p = next
	}
}
func newResult(mode string, rate int) *result {
	return &result{Mode: mode, Target: rate, Errors: map[string]int{}, Start: time.Now()}
}
func (d *driver) fill(workers int) error {
	r := newResult("fill", 0)
	jobs := make(chan int, workers)
	var wg sync.WaitGroup
	var first error
	var em sync.Mutex
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan error, 1)
			for i := range jobs {
				d.mu.Lock()
				d.slots[i].busy = true
				d.mu.Unlock()
				d.emit('e', i, r, done, time.Time{})
				if e := <-done; e != nil {
					em.Lock()
					if first == nil {
						first = e
					}
					em.Unlock()
				}
			}
		}()
	}
	for i := range d.base {
		jobs <- i
		if i%10000 == 0 {
			log.Printf("fill offered %d/%d", i, len(d.slots))
		}
	}
	close(jobs)
	wg.Wait()
	r.End = time.Now()
	d.save("fill", r)
	if first != nil {
		return first
	}
	return nil
}
func (d *driver) state() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	held, busy, uncertain := 0, 0, 0
	for _, s := range d.slots {
		if s.seid != 0 {
			held++
		}
		if s.busy {
			busy++
		}
		if s.uncertain {
			uncertain++
		}
	}
	return map[string]any{"ready": d.ready, "fill_error": d.fillErr, "held": held, "busy": busy,
		"uncertain": uncertain, "pending": d.active, "population": d.base, "cohort": d.cohort,
		"probes": d.probes, "max_in_flight": d.maxInFlight, "reports": d.reports,
		"local_udp_address":    d.conn.LocalAddr().String(),
		"receive_buffer_bytes": d.receiveBuffer, "send_buffer_bytes": d.sendBuffer,
		"report_acknowledgements_sent": d.reportAcknowledged,
		"report_wire_bytes":            d.reportBytes, "report_wire_packets": d.reportPackets}
}
func (d *driver) save(name string, r *result) map[string]any {
	d.mu.Lock()
	copyR := *r
	lat := append([]time.Duration(nil), r.Latency...)
	cycles := append([]time.Duration(nil), r.CycleLatency...)
	copyR.Errors = make(map[string]int, len(r.Errors))
	for k, v := range r.Errors {
		copyR.Errors[k] = v
	}
	d.mu.Unlock()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	sort.Slice(cycles, func(i, j int) bool { return cycles[i] < cycles[j] })
	quantile := func(values []time.Duration, p float64) float64 {
		if len(values) == 0 {
			return 0
		}
		return float64(values[int(float64(len(values)-1)*p)]) / float64(time.Microsecond)
	}
	elapsed := r.End.Sub(r.Start).Seconds()
	out := map[string]any{"result": copyR, "p50_us": quantile(lat, .5),
		"p99_us": quantile(lat, .99), "cycle_p50_us": quantile(cycles, .5),
		"cycle_p99_us": quantile(cycles, .99), "state": d.state(),
		"measured_seconds_including_drain":     elapsed,
		"completed_cycles_per_measured_second": float64(copyR.Completed) / elapsed}
	if copyR.Duration > 0 {
		out["sent_cycles_per_offer_second"] = float64(copyR.Sent) / copyR.Duration
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(filepath.Join(d.out, name+".json"), data, 0644); err != nil {
		panic(err)
	}
	return out
}
func (d *driver) run(w http.ResponseWriter, req *http.Request) {
	d.runMu.Lock()
	defer d.runMu.Unlock()
	var spec struct {
		Name, Mode    string
		Rate, Seconds int
	}
	if err := json.NewDecoder(req.Body).Decode(&spec); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	switch spec.Mode {
	case "establish", "delete", "replace", "far", "pdr", "qer", "urr":
	default:
		http.Error(w, "invalid mode", 400)
		return
	}
	if spec.Rate <= 0 || spec.Rate > 1000000 || spec.Seconds <= 0 || spec.Seconds > 300 {
		http.Error(w, "invalid rate or duration", 400)
		return
	}
	d.mu.Lock()
	ready := d.ready && d.active == 0
	reportStart, ackStart, bytesStart, packetsStart := d.reports, d.reportAcknowledged, d.reportBytes, d.reportPackets
	d.mu.Unlock()
	if !ready {
		http.Error(w, "not ready or requests still draining", 409)
		return
	}
	r := newResult(spec.Mode, spec.Rate)
	count := spec.Rate * spec.Seconds
	finite := spec.Mode == "establish" || spec.Mode == "delete"
	if finite && count > d.cohort {
		count = d.cohort
	}
	r.Scheduled = count
	start := time.Now()
	// Allow the final pacing tick, but never extend the offer to clear a backlog.
	deadline := start.Add(time.Duration(count)*time.Second/time.Duration(spec.Rate) + time.Millisecond)
	ticker := time.NewTicker(time.Millisecond)
	next := 0
offer:
	for next < count {
		<-ticker.C
		due := min(count, int(time.Since(start).Seconds()*float64(spec.Rate)))
		for next < due {
			if !time.Now().Before(deadline) {
				break offer
			}
			i := (next * 104729) % d.base
			if finite {
				i = d.base + next
			}
			next++
			d.mu.Lock()
			s := &d.slots[i]
			if s.busy {
				r.BusySkips++
				d.mu.Unlock()
				continue
			}
			if s.uncertain {
				r.UncertainSkips++
				d.mu.Unlock()
				continue
			}
			if (spec.Mode == "establish" && s.seid != 0) || (spec.Mode != "establish" && s.seid == 0) {
				r.StateSkips++
				d.mu.Unlock()
				continue
			}
			if d.active >= d.maxInFlight {
				r.WindowSkips++
				d.mu.Unlock()
				continue
			}
			s.busy = true
			switch spec.Mode {
			case "pdr":
				s.pdrGeneration++
			case "qer":
				s.qerGeneration++
			case "urr":
				s.urrGeneration++
			default:
				s.generation++
			}
			r.Sent++
			d.mu.Unlock()
			kind := byte('m')
			if spec.Mode == "establish" {
				kind = 'e'
			}
			if spec.Mode == "delete" || spec.Mode == "replace" {
				kind = 'd'
			}
			d.emit(kind, i, r, nil, time.Time{})
		}
	}
	ticker.Stop()
	r.PacerSkips = count - next
	r.Duration = time.Since(start).Seconds()
	if !d.drain() {
		http.Error(w, "requests did not finish draining; cell is invalid", http.StatusConflict)
		return
	}
	r.End = time.Now()
	d.mu.Lock()
	r.Reports = d.reports - reportStart
	r.ReportAcknowledged = d.reportAcknowledged - ackStart
	r.ReportBytes = d.reportBytes - bytesStart
	r.ReportPackets = d.reportPackets - packetsStart
	d.mu.Unlock()
	json.NewEncoder(w).Encode(d.save(filepath.Base(spec.Name), r))
}
func (d *driver) drain() bool {
	// A replacement chains two requests; include both expiry ticks and slack.
	deadline := time.Now().Add(2*(d.timeout+expiryInterval) + time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		n := d.active
		d.mu.Unlock()
		if n == 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// operate performs untimed setup/reconciliation with a bounded worker count.
func (d *driver) operate(ids []int, kind byte, r *result) error {
	jobs := make(chan int, 64)
	var wg sync.WaitGroup
	var first error
	var em sync.Mutex
	for range min(64, d.maxInFlight) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan error, 1)
			for i := range jobs {
				d.mu.Lock()
				d.slots[i].busy = true
				d.mu.Unlock()
				d.emit(kind, i, r, done, time.Time{})
				if err := <-done; err != nil {
					em.Lock()
					if first == nil {
						first = err
					}
					em.Unlock()
				}
			}
		}()
	}
	for _, i := range ids {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return first
}
func (d *driver) reconcileState(cohortLive bool, r *result) error {
	var resolve, remove []int
	d.mu.Lock()
	for i, s := range d.slots {
		want := i < d.base || cohortLive
		if s.uncertain || (want && s.seid == 0) {
			resolve = append(resolve, i)
		}
		if !want && s.seid != 0 && !s.uncertain {
			remove = append(remove, i)
		}
	}
	d.mu.Unlock()
	// Repeating a CP F-SEID discovers the accepted session or recreates it after
	// an uncertain delete; only then is its local SEID safe to erase.
	if err := d.operate(resolve, 'e', r); err != nil {
		return err
	}
	for _, i := range resolve {
		if i >= d.base && !cohortLive {
			remove = append(remove, i)
		}
	}
	if err := d.operate(remove, 'd', r); err != nil {
		return err
	}
	probes := make([]int, d.probes)
	for i := range probes {
		probes[i] = i
	}
	// Restore the traffic witnesses outside the measured window. Other
	// sessions retain the policy history of this churn workload.
	if err := d.operate(probes, 'p', newResult("restore-pdr", 0)); err != nil {
		return err
	}
	return d.operate(probes, 'o', newResult("restore-qer", 0))
}
func (d *driver) reconcile(w http.ResponseWriter, req *http.Request) {
	d.runMu.Lock()
	defer d.runMu.Unlock()
	d.drain()
	d.mu.Lock()
	ready := d.ready && d.active == 0
	d.mu.Unlock()
	if !ready {
		http.Error(w, "not ready or requests still draining", 409)
		return
	}
	r := newResult("reconcile", 0)
	err := d.reconcileState(false, r)
	r.End = time.Now()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(d.save("reconcile-"+fmt.Sprint(time.Now().UnixNano()), r))
}
func (d *driver) prepare(w http.ResponseWriter, req *http.Request) {
	d.runMu.Lock()
	defer d.runMu.Unlock()
	mode := req.URL.Query().Get("mode")
	if mode != "establish" && mode != "delete" {
		http.Error(w, "prepare mode must be establish or delete", 400)
		return
	}
	d.drain()
	d.mu.Lock()
	ready := d.ready && d.active == 0
	d.mu.Unlock()
	if !ready {
		http.Error(w, "not ready or requests still draining", 409)
		return
	}
	r := newResult("prepare", 0)
	err := d.reconcileState(mode == "delete", r)
	r.End = time.Now()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(d.save("prepare-"+mode, r))
}
func main() {
	target := flag.String("upf", "127.0.0.1:8805", "UPF N4 UDP endpoint")
	addr := flag.String("http", "127.0.0.1:9901", "local benchmark control endpoint")
	n := flag.Int("sessions", 1000000, "resident session population")
	cohort := flag.Int("cohort", 65536, "extra finite establishment/deletion cohort")
	probes := flag.Int("probes", 16, "resident sessions with periodic usage reports")
	window := flag.Int("max-in-flight", 1<<20, "maximum outstanding PFCP requests (covers 100K/s times the default timeout)")
	workers := flag.Int("workers", 64, "untimed fill workers")
	timeout := flag.Duration("timeout", 5*time.Second, "PFCP request timeout")
	out := flag.String("out", ".", "JSON evidence directory")
	flag.Parse()
	if *n <= 0 || *cohort <= 0 || *n+*cohort > 1<<24 || *probes < 0 || *probes > *n || *window <= 0 || *workers <= 0 || *timeout <= 0 {
		log.Fatal("invalid population, cohort, probes, concurrency or timeout")
	}
	remote, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		log.Fatal(err)
	}
	if err := conn.SetReadBuffer(16 << 20); err != nil {
		log.Fatal(err)
	}
	if err := conn.SetWriteBuffer(4 << 20); err != nil {
		log.Fatal(err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		log.Fatal(err)
	}
	var receiveBuffer, sendBuffer int
	var receiveErr, sendErr error
	if err := raw.Control(func(fd uintptr) {
		receiveBuffer, receiveErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		sendBuffer, sendErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}); err != nil {
		log.Fatal(err)
	}
	if err := errors.Join(receiveErr, sendErr); err != nil {
		log.Fatal(err)
	}
	d := &driver{conn: conn, slots: make([]slot, *n+*cohort), pending: make(map[uint32]*pending),
		base: *n, cohort: *cohort, probes: *probes, maxInFlight: *window, timeout: *timeout, out: *out,
		receiveBuffer: receiveBuffer, sendBuffer: sendBuffer}
	for i := range d.slots {
		d.slots[i].cp = uint64(i) + 0x1000
	}
	os.MkdirAll(*out, 0755)
	// Association is completed before the asynchronous response router starts.
	a := n4sim.Associate(1, "churn.smf")
	data, _ := wire(a)
	conn.Write(data)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65535)
	nr, e := conn.Read(buf)
	if e != nil {
		log.Fatal(e)
	}
	m, e := message.Parse(bytes.Clone(buf[:nr]))
	if e != nil {
		log.Fatal(e)
	}
	cause, e := n4sim.Cause(m)
	if e != nil || cause != 1 {
		log.Fatalf("association cause %d: %v", cause, e)
	}
	conn.SetReadDeadline(time.Time{})
	d.nextSeq = 1
	go d.read()
	go d.expire()
	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(d.state()) })
	mux.HandleFunc("/run", d.run)
	mux.HandleFunc("/reconcile", d.reconcile)
	mux.HandleFunc("/prepare", d.prepare)
	go func() {
		err := d.fill(*workers)
		d.mu.Lock()
		if err != nil {
			d.fillErr = err.Error()
		} else {
			d.ready = true
		}
		d.mu.Unlock()
		log.Printf("fill finished: %v", err)
	}()
	log.Fatal(http.ListenAndServe(*addr, mux))
}
