// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// modelRecords is a copy of every record a session's model names, by kind
// and id: what a test compares a model with after a change that must leave
// it as it was.
type modelRecords struct {
	pdrs map[uint16]pdr
	fars map[uint32]far
	qers map[uint32]qer
	urrs map[uint32]urr
}

func recordsOf(t *testing.T, c *Compiler, seid uint64) modelRecords {
	t.Helper()
	s := sessionOf(t, c, seid)
	c.mu.Lock()
	defer c.mu.Unlock()
	m := modelRecords{map[uint16]pdr{}, map[uint32]far{}, map[uint32]qer{}, map[uint32]urr{}}
	for id, p := range s.PDRs().all() {
		m.pdrs[id] = *p
	}
	for id, f := range s.FARs().all() {
		m.fars[id] = *f
	}
	for id, q := range s.QERs().all() {
		m.qers[id] = *q
	}
	for id, u := range s.URRs().all() {
		m.urrs[id] = *u
	}
	return m
}

func liveRecords(c *Compiler) ([recKinds]int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recs.live(), c.recs.segments()
}

// reshape is a modification that touches every kind of record: a new SDF
// filter and precedence on the downlink PDR (its old form becomes a stale
// one), an outer header on FAR 2, a new rate on QER 1, a new quota on URR 7,
// and a PDR, a FAR and a QER of its own.
func reshape(seid uint64, seq uint32, ue string, port int, precedence uint32) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, seq, 0,
		ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewPrecedence(precedence),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, ue, "", 0, 0),
				ie.NewSDFFilter(fmt.Sprintf("permit out udp from any to assigned %d", port), "", "", "", 0))),
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewUpdateForwardingParameters(
			ie.NewOuterHeaderCreation(0x0100, uint32(0x10000+port), "10.20.30.9", "", 0, 0, 0))),
		ie.NewUpdateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen), ie.NewMBR(uint64(port), 2000)),
		ie.NewUpdateURR(ie.NewURRID(7), ie.NewVolumeQuota(0x01, uint64(port)<<30, 0, 0)),
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(300),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, ue, "", 0, 0),
				ie.NewSDFFilter(fmt.Sprintf("permit out tcp from any to assigned %d", port), "", "", "", 0)),
			ie.NewFARID(3), ie.NewQERID(3)),
		ie.NewCreateFAR(ie.NewFARID(3), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
		ie.NewCreateQER(ie.NewQERID(3), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen)))
}

// TestARefusedModificationRestoresItsRecords: a modification the dataplane
// refuses puts back every record as it was -- the snapshot's copies become
// the model -- and frees the failed model's, so the slabs hold what they held
// before; one that stands frees the snapshot's, and the deletion the rest.
func TestARefusedModificationRestoresItsRecords(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(countedEstablishment(0x7a01, "10.46.0.1")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment cause %d", got)
	}
	seid := upFSEID(t, resp)
	was := recordsOf(t, c, seid)
	held, _ := liveRecords(c)

	rec.fail = &bess.RejectedError{}
	if got := cause(t, c.Modify(reshape(seid, 2, "10.46.0.1", 5353, 50))); got == ie.CauseRequestAccepted {
		t.Fatal("a refused modification was accepted")
	}
	rec.fail = nil
	now := recordsOf(t, c, seid)
	if fmt.Sprint(now) != fmt.Sprint(was) {
		t.Errorf("the refused modification left the records\n%+v\nwant\n%+v", now, was)
	}
	if got, _ := liveRecords(c); got != held {
		t.Errorf("the refused modification left %v records allocated, want the %v before it", got, held)
	}

	if got := cause(t, c.Modify(reshape(seid, 3, "10.46.0.1", 5353, 50))); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification cause %d", got)
	}
	if got, _ := liveRecords(c); got != [recKinds]int{3, 3, 2, 1} {
		t.Errorf("after the modification %v records are allocated, want the model's 3 PDRs, 3 FARs, 2 QERs, 1 URR", got)
	}
	if p := pdrCopy(t, c, seid, 2); p.precedence != 50 {
		t.Errorf("PDR 2's precedence is %d after the modification, want 50", p.precedence)
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 4, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("deletion cause %d", got)
	}
	if got, _ := liveRecords(c); got != [recKinds]int{} {
		t.Errorf("the deletion left %v records allocated", got)
	}
}

// TestSessionChurnGivesBackEverySlabSlot: rounds of establishment,
// modification and deletion hold the same records each round and give every
// one back at its end, reusing the slots rather than adding segments.
func TestSessionChurnGivesBackEverySlabSlot(t *testing.T) {
	const n = 3000
	c := New(testConfig(), &discardApplier{}, quietLogger())
	var first [recKinds]int
	var firstSegs int
	for round := range 3 {
		seids := establishCounted(t, c, n)
		for i, seid := range seids {
			ue := fmt.Sprintf("10.%d.%d.%d", 1+i>>16, i>>8&0xff, i&0xff)
			if got := cause(t, c.Modify(reshape(seid, 2, ue, 1000+round, 40))); got != ie.CauseRequestAccepted {
				t.Fatalf("round %d: modifying session %d answered cause %d", round, i, got)
			}
		}
		live, segs := liveRecords(c)
		if round == 0 {
			first, firstSegs = live, segs
			if live != [recKinds]int{3 * n, 3 * n, 2 * n, n} {
				t.Errorf("%d modified sessions hold %v records, want 3, 3, 2 and 1 each", n, live)
			}
		} else if live != first || segs != firstSegs {
			t.Errorf("round %d holds %v records in %d segments, the first held %v in %d", round, live, segs, first, firstSegs)
		}
		for i, seid := range seids {
			if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, uint32(i+3), 0))); got != ie.CauseRequestAccepted {
				t.Fatalf("round %d: deleting session %d answered cause %d", round, i, got)
			}
		}
		if live, _ := liveRecords(c); live != [recKinds]int{} {
			t.Fatalf("round %d: deleted sessions left %v records", round, live)
		}
	}
}

// TestAFreedRecordHandleIsRefused is the generation check at work: a handle
// a deleted session's PDR had is refused once the session is gone, and still
// refused once another session's PDR takes the slot (the free list is LIFO,
// so the next session's two PDRs take the two slots the deletion freed).
func TestAFreedRecordHandleIsRefused(t *testing.T) {
	c := New(testConfig(), &discardApplier{}, quietLogger())
	seids := establishCounted(t, c, 1)
	s := sessionOf(t, c, seids[0])
	h := locked(c, func() uint32 { return s.PDRs().handle(1) })
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seids[0], 2, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("deletion cause %d", got)
	}
	c.mu.Lock()
	mustPanic(t, "used after it was freed", func() { c.recs.pdrs.at(h) })
	c.mu.Unlock()
	next := establishCounted(t, c, 1)
	s = sessionOf(t, c, next[0])
	c.mu.Lock()
	defer c.mu.Unlock()
	var reused uint32
	for _, id := range []uint16{1, 2} {
		if r := s.PDRs().handle(id); r&recIndexMask == h&recIndexMask {
			reused = r
		}
	}
	if reused == 0 {
		t.Fatalf("no PDR of the next session took the freed slot %d", h&recIndexMask)
	}
	if reused == h {
		t.Fatalf("the slot came back under the same handle %#x: its generation did not move", h)
	}
	mustPanic(t, "used after it was freed", func() { c.recs.pdrs.at(h) })
	if p := c.recs.pdrs.at(reused); p.id != 1 && p.id != 2 {
		t.Errorf("the slot's new record is PDR %d, want one of the next session's", p.id)
	}
}

// oneSessionLedger is a dataplane that takes everything and checks one thing:
// a transaction's PDR rules name one subscriber. A removal that read a slot
// freed and reused under it would erase another session's rule in the same
// transaction as its own. It refuses, once per subscriber, a transaction
// writing a rule of precedence poisonPrecedence with an unknown outcome, so
// the modification's replaced forms stay pending for the next write; and it
// counts every measured rule up by a mebibyte per reading, so each reading
// after the first spends a quota and a tick's evaluation enforces it.
type oneSessionLedger struct {
	mu       sync.Mutex
	t        *testing.T
	poisoned map[netip.Addr]bool
	mixed    int
	reading  atomic.Uint64
}

const poisonPrecedence = 777

func (l *oneSessionLedger) Apply(_ context.Context, changes ...bess.Change) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	subscribers := map[netip.Addr]bool{}
	poison := false
	for _, r := range rules(changes) {
		for _, f := range []int{fieldSrcIP, fieldDstIP} {
			if f >= len(r.values) || len(r.values[f]) != 4 || len(r.masks[f]) != 4 {
				continue
			}
			if v, m := r.value(f), r.mask(f); v[0] == 10 && [4]byte(m) == [4]byte{255, 255, 255, 255} {
				subscribers[netip.AddrFrom4([4]byte(v))] = true
			}
		}
		if r.change.Value != nil && r.priority() == int64(math.MaxUint32)-poisonPrecedence {
			poison = true
		}
	}
	if len(subscribers) > 1 {
		l.mixed++
		l.t.Errorf("one transaction names the rules of %d subscribers: %v", len(subscribers), subscribers)
	}
	if poison && len(subscribers) == 1 {
		for ue := range subscribers {
			if !l.poisoned[ue] {
				l.poisoned[ue] = true
				return context.DeadlineExceeded
			}
		}
	}
	return nil
}

func (l *oneSessionLedger) AppendRuleCounts(_ context.Context, dst []bess.RuleCount, _ string, actionIDs ...uint32) ([]bess.RuleCount, error) {
	n := l.reading.Add(1)
	for _, id := range actionIDs {
		dst = append(dst, bess.RuleCount{ActionID: id, Packets: n, Octets: n << 20})
	}
	return dst, nil
}

func (l *oneSessionLedger) AppendRuleChanges(_ context.Context, dst []uint32, _ string, acknowledge, _, _ uint64) (bess.RuleChangePage, error) {
	return bess.RuleChangePage{Sequence: acknowledge + 1, ActionIDs: dst}, nil
}

// quotaEstablishment is countedEstablishment with a quota of total octets.
func quotaEstablishment(cpSEID uint64, ueIP string, total uint64) *message.SessionEstablishmentRequest {
	req := establishment(cpSEID, ueIP)
	children, err := req.CreatePDR[0].CreatePDR()
	if err != nil {
		panic(err)
	}
	req.CreatePDR[0] = ie.NewCreatePDR(append(children, ie.NewURRID(7))...)
	req.CreateURR = []*ie.IE{ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0),
		ie.NewReportingTriggers(0, 1), ie.NewVolumeQuota(1, total, 0, 0))}
	return req
}

// TestARemovalNeverReadsAnotherSessionsRecord: sessions are established,
// modified -- the last modification's outcome unknown, so its replaced forms
// stay pending -- and deleted by several workers, while a tick evaluates
// every live session. A spent quota makes the tick compile, apply and
// settle the session, which frees those pending forms while the session's
// deletion may be computing its erasures, and the other workers' sessions
// take freed slots at once. Every record read holds the lock, so no
// transaction names two subscribers' rules, the race detector sees no
// unsynchronised read (go test -race), every record goes back to the slabs,
// and no read trips the generation check.
func TestARemovalNeverReadsAnotherSessionsRecord(t *testing.T) {
	workers, rounds := 4, 60
	if raceEnabled {
		rounds = 25
	}
	ledger := &oneSessionLedger{t: t, poisoned: map[netip.Addr]bool{}}
	c := New(testConfig(), ledger, quietLogger())
	var live sync.Map // local SEID -> true while a worker's session exists
	done := make(chan struct{})
	var tick sync.WaitGroup
	tick.Add(1)
	go func() {
		defer tick.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			live.Range(func(k, _ any) bool {
				c.Evaluate(context.Background(), k.(uint64), time.Now())
				return true
			})
		}
	}()
	var work sync.WaitGroup
	for w := range workers {
		work.Add(1)
		go func() {
			defer work.Done()
			for i := range rounds {
				ue := fmt.Sprintf("10.47.%d.%d", w, i+1)
				resp, ok := c.Establish(quotaEstablishment(uint64(0x7b0000+w<<12+i), ue, 1<<20)).(*message.SessionEstablishmentResponse)
				if !ok || cause(t, resp) != ie.CauseRequestAccepted {
					t.Errorf("worker %d: establishment %d was refused", w, i)
					return
				}
				seid := upFSEID(t, resp)
				live.Store(seid, true)
				c.Modify(reshape(seid, 2, ue, 2000+i, 40))
				// The outcome is unknown: the merged model stands, and the
				// replaced form of PDR 2 stays pending until a write lands.
				c.Modify(reshape(seid, 3, ue, 3000+i, poisonPrecedence))
				if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 4, 0))); got != ie.CauseRequestAccepted {
					t.Errorf("worker %d: deletion %d answered cause %d", w, i, got)
				}
				live.Delete(seid)
			}
		}()
	}
	work.Wait()
	close(done)
	tick.Wait()
	if ledger.mixed != 0 {
		t.Errorf("%d transactions named two subscribers' rules", ledger.mixed)
	}
	if got, _ := liveRecords(c); got != [recKinds]int{} {
		t.Errorf("%d workers' deleted sessions left %v records", workers, got)
	}
	if reads := ledger.reading.Load(); reads == 0 {
		t.Error("the tick never read a counter: nothing was enforced")
	}
	if got := len(ledger.poisoned); got != workers*rounds {
		t.Errorf("%d modifications ended with an unknown outcome, want each of the %d sessions' last", got, workers*rounds)
	}
	c.mu.Lock()
	sessions := len(c.sessions)
	c.mu.Unlock()
	if sessions != 0 {
		t.Errorf("%d sessions left", sessions)
	}
}
