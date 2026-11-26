// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"testing"
	"time"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// packetRateConfig is the graph target with both PacketRate modules.
func packetRateConfig() Config {
	cfg := testConfig()
	cfg.Up.PacketRates = "pr_ul"
	cfg.Down.PacketRates = "pr_dl"
	return cfg
}

// bothDirectionsQER caps both directions of QER 1.
func bothDirectionsQER() *ie.IE {
	return ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		packetRateIE(0x03, 1, 100, 0, 200, 0, 0, 0, 0))
}

// TestPacketRateDroppedDirectionReleasesItsID: an Update QER that stops
// capping a direction erases that quota record, so the QER must stop naming
// its id. Kept, the id made the deletion erase a record that is gone, which
// the engine refuses ("not found"): the session could never be deleted.
func TestPacketRateDroppedDirectionReleasesItsID(t *testing.T) {
	cfg := packetRateConfig()
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(packetRateEstablishment(0x7a01, bothDirectionsQER())).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	_, dl := quotaIDs(t, rec.last(), cfg)
	seid := upFSEID(t, resp)

	drop := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdateQER(ie.NewQERID(1), packetRateIE(0x01, 1, 100, 0, 0, 0, 0, 0, 0)))
	if got := cause(t, c.Modify(drop)); got != ie.CauseRequestAccepted {
		t.Fatalf("dropping the downlink rate answered cause %d", got)
	}
	if !c.rates.queued(dl) {
		t.Error("the dropped direction's quota id was not returned once its erase landed")
	}

	// The SMF caps the direction again: a fresh id, since the old one is
	// still retiring (engineering guide §4.2).
	readd := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdateQER(ie.NewQERID(1), packetRateIE(0x03, 1, 100, 0, 300, 0, 0, 0, 0)))
	if got := cause(t, c.Modify(readd)); got != ie.CauseRequestAccepted {
		t.Fatalf("capping the downlink again answered cause %d", got)
	}
	writes := changesFor(rec.last(), ratesRes(cfg.Down))
	if len(writes) != 1 || writes[0].Value == nil {
		t.Fatalf("capping the downlink again wrote %d quota changes, want one write", len(writes))
	}
	if id := keyFieldValue(writes[0].Key, "id").(uint32); id == dl {
		t.Errorf("the re-added direction reused the retiring id %d", id)
	}

	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 4, 0))); got != ie.CauseRequestAccepted {
		t.Errorf("the deletion after a dropped direction answered cause %d", got)
	}
}

// TestPacketRateDroppedDirectionDeletes: the drop alone, then the deletion.
func TestPacketRateDroppedDirectionDeletes(t *testing.T) {
	cfg := packetRateConfig()
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(packetRateEstablishment(0x7a02, bothDirectionsQER())).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	drop := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdateQER(ie.NewQERID(1), packetRateIE(0x01, 1, 100, 0, 0, 0, 0, 0, 0)))
	if got := cause(t, c.Modify(drop)); got != ie.CauseRequestAccepted {
		t.Fatalf("dropping the downlink rate answered cause %d", got)
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 3, 0))); got != ie.CauseRequestAccepted {
		t.Errorf("the deletion after a dropped direction answered cause %d", got)
	}
}

// TestPacketRateRemovedQERErasesOnce: a Remove QER erases its quota records
// in the transaction that removes it, and never again. Erased on every
// compile, they made every later modification and the deletion erase keys
// that were gone, which the engine refuses.
func TestPacketRateRemovedQERErasesOnce(t *testing.T) {
	cfg := packetRateConfig()
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(packetRateEstablishment(0x7a03, bothDirectionsQER())).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	ul, dl := quotaIDs(t, rec.last(), cfg)
	seid := upFSEID(t, resp)

	remove := message.NewSessionModificationRequest(0, 0, seid, 2, 0, ie.NewRemoveQER(ie.NewQERID(1)))
	if got := cause(t, c.Modify(remove)); got != ie.CauseRequestAccepted {
		t.Fatalf("the removal answered cause %d", got)
	}
	if n := len(changesFor(rec.last(), ratesRes(cfg.Up))) + len(changesFor(rec.last(), ratesRes(cfg.Down))); n != 2 {
		t.Errorf("the removal changed %d quota records, want its two erased", n)
	}
	if !c.rates.queued(ul) || !c.rates.queued(dl) {
		t.Error("the removed QER's quota ids were not returned once the removal landed")
	}
	c.mu.Lock()
	removed := len(c.sessions[seid].rare().removedQERs)
	c.mu.Unlock()
	if removed != 0 {
		t.Errorf("the session still holds %d removed QERs after the removal landed", removed)
	}

	// A later modification that rewrites the PDR, then the deletion.
	update := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(50)))
	if got := cause(t, c.Modify(update)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification after the removal answered cause %d", got)
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 4, 0))); got != ie.CauseRequestAccepted {
		t.Errorf("the deletion after the removal answered cause %d", got)
	}
}

// TestPacketRateQuotaExhaustionRefuses: no quota id left is cause 72, as for
// an F-TEID, not a session accepted with its rate control unenforced.
func TestPacketRateQuotaExhaustionRefuses(t *testing.T) {
	cfg := packetRateConfig()
	cfg.MaxMeters = 2 // one id: the downlink finds none
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(packetRateEstablishment(0x7a04, bothDirectionsQER())).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseNoResourcesAvailable {
		t.Errorf("a QER with no quota id left answered cause %d, want no-resources", got)
	}
	if len(rec.txns) != 0 {
		t.Error("the refused session wrote to the dataplane")
	}
	if !c.rates.queued(1) {
		t.Error("the refused establishment kept the quota id it took")
	}
}

// parkAfter lets the transactions through to the fake and then parks the
// n-th one before it returns, so the test can act while that transaction has
// landed but its caller has not settled it.
type parkAfter struct {
	inner   Applier
	n       int
	entered chan struct{}
	release chan struct{}
}

func (p *parkAfter) Apply(ctx context.Context, changes ...bess.Change) error {
	err := p.inner.Apply(ctx, changes...)
	if p.n--; p.n == 0 {
		close(p.entered)
		<-p.release
	}
	return err
}

// TestSettleAfterReleaseReleasesNothing: a transaction that lands after its
// session was released must not release the session's pending ids again --
// releaseSession already did, and another session may hold them by then.
func TestSettleAfterReleaseReleasesNothing(t *testing.T) {
	cfg := packetRateConfig()
	cfg.MaxMeters = 3
	cfg.IDReuseDelay = time.Nanosecond
	rec := &recorder{}
	gate := &parkAfter{inner: rec, n: 2, entered: make(chan struct{}), release: make(chan struct{})}
	c := New(cfg, gate, quietLogger())
	resp := c.Establish(packetRateEstablishment(0x7a05, bothDirectionsQER())).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	_, dl := quotaIDs(t, rec.last(), cfg)
	seid := upFSEID(t, resp)

	done := make(chan message.Message, 1)
	go func() {
		done <- c.Modify(message.NewSessionModificationRequest(0, 0, seid, 2, 0,
			ie.NewUpdateQER(ie.NewQERID(1), packetRateIE(0x01, 1, 100, 0, 0, 0, 0, 0, 0))))
	}()
	<-gate.entered
	// The session goes while the drop is in the air, and its ids go to others.
	c.mu.Lock()
	c.releaseSession(c.sessions[seid])
	time.Sleep(time.Millisecond)
	held := map[uint32]bool{}
	for {
		id, err := c.rates.alloc()
		if err != nil {
			break
		}
		held[id] = true
	}
	c.mu.Unlock()
	if !held[dl] {
		t.Fatalf("the retired id %d did not come back to the pool with the session", dl)
	}
	close(gate.release)
	<-done
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rates.queued(dl) {
		t.Errorf("the quota id %d was released again while another holder has it", dl)
	}
}
