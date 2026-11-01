package session

import (
	"runtime"
	"testing"
	"time"

	"github.com/krsna1729/upf/internal/scaletest"
)

// The contexts pool spans 2^31 and has no grace: its walk outlives the
// process, so a release that waits for the walk to come round is never taken
// back, and the free list grows by one entry per F-TEID context ever released.
func TestAZeroGracePoolReusesAReleasedIDBeforeTheWalkEnds(t *testing.T) {
	p := newIDPool(1<<31, 0)
	for range 1_000_000 {
		id, err := p.alloc()
		if err != nil {
			t.Fatal(err)
		}
		p.release(id)
	}
	if len(p.freed) > 1 || len(p.released) > 1 {
		t.Errorf("1M alloc+release left freed=%d released=%d, want at most 1 each", len(p.freed), len(p.released))
	}
}

// A pool with a grace holds what it released until the walk comes round:
// most of a dataplane table at teardown. That is an id and a bit, not an
// id, a timestamp and a map entry.
func TestAGracePoolHoldsAReleasedIDInAtMostEightBytes(t *testing.T) {
	const n = 4 << 20
	var p *idPool
	perID := scaletest.HeapPerItem(t, n, func(n int) {
		p = newIDPool(uint32(2*n), time.Second)
		now := time.Unix(0, 0)
		p.now = func() time.Time { return now }
		for range n {
			id, err := p.alloc()
			if err != nil {
				t.Fatal(err)
			}
			p.release(id)
		}
	})
	if len(p.freed) != n {
		t.Fatalf("the pool queued %d of %d releases", len(p.freed), n)
	}
	if perID > 8 {
		t.Errorf("the pool holds %.1f B per released id, want at most 8", perID)
	}
	runtime.KeepAlive(p)
}

// G-PDUs sent to a deleted session's F-TEID are still in flight when the
// deletion lands: a TEID handed out again at once would admit them to another
// session. A released TEID waits seconds, not nothing, even once the walk is
// done.
func TestAReleasedTEIDIsNotReusedBeforeItsDelay(t *testing.T) {
	cfg := testConfig()
	cfg.MaxTEIDs = 4
	c := New(cfg, &recorder{}, quietLogger())
	now := time.Unix(0, 0)
	c.teids.now = func() time.Time { return now }
	var held []uint32
	for {
		id, err := c.teids.alloc()
		if err != nil {
			break
		}
		held = append(held, id)
	}
	c.teids.release(held[0])
	early := 0
	for range 4 {
		now = now.Add(time.Second)
		if _, err := c.teids.alloc(); err == nil {
			early++
		}
	}
	if early != 0 {
		t.Errorf("a released TEID was handed out %d times within 4 s of its release", early)
	}
	now = now.Add(time.Minute)
	if id, err := c.teids.alloc(); err != nil || id != held[0] {
		t.Errorf("after the delay the pool answered (%d, %v), want the released %d", id, err, held[0])
	}
}

// The dataplane refuses a publish into a slot removed less than a grace
// period ago: however the releases fall into the pool's coarse epochs, no id
// comes back before its own grace has passed. And the epochs stay a handful
// however long the churn goes on.
func TestAGracePoolNeverReusesAnIDBeforeItsGrace(t *testing.T) {
	const grace = time.Second
	p := newIDPool(64, grace)
	now := time.Unix(0, 0)
	p.now = func() time.Time { return now }
	releasedAt := map[uint32]time.Time{}
	held := map[uint32]bool{}
	var live []uint32
	reused, early := 0, 0
	for range 20_000 {
		now = now.Add(37 * time.Millisecond)
		if len(live) >= 32 {
			id := live[0]
			live = live[1:]
			delete(held, id)
			p.release(id)
			releasedAt[id] = now
		}
		id, err := p.alloc()
		if err != nil {
			continue
		}
		if held[id] {
			t.Fatalf("id %d was handed out while held", id)
		}
		if at, ok := releasedAt[id]; ok {
			reused++
			if now.Sub(at) < grace {
				early++
			}
		}
		held[id] = true
		live = append(live, id)
	}
	if early != 0 {
		t.Errorf("%d of %d reused ids came back before their grace", early, reused)
	}
	if reused == 0 {
		t.Error("no released id came back after its grace")
	}
	if len(p.epochs) > 18 {
		t.Errorf("the pool keeps %d epochs, want at most 18 (one per sixteenth of the grace, plus the aged)", len(p.epochs))
	}
}
