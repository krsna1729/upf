// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/krsna1729/upf/internal/bess"
)

// sweepFake is an applier that can also read its own contents back, the way a
// real dataplane does: what the sweep reads is what an earlier run wrote.
type sweepFake struct {
	contents map[string][]bess.Entry
	changes  [][]bess.Change
	cleared  []string
	// reads is every Contents call's resource list, as made: what the sweep
	// asked the daemon to pack into one response, call by call.
	reads [][]string
	// applies counts every Apply call, a recorded transaction or not, so a
	// test can tell "the sweep stopped" from "the sweep sent nothing".
	applies int
	// failBatch, when non-zero, is the number of the transaction the dataplane
	// refuses: what the daemon does with the one batch that is too big, or the
	// one change in it it will not accept. The batches before it stay
	// recorded, and none after it is sent.
	failBatch int
	err       error
}

func (f *sweepFake) Apply(_ context.Context, changes ...bess.Change) error {
	f.applies++
	if f.err != nil {
		return f.err
	}
	if f.failBatch != 0 && f.applies == f.failBatch {
		return fmt.Errorf("the dataplane refused the batch")
	}
	f.changes = append(f.changes, append([]bess.Change(nil), changes...))
	return nil
}

// ClearStore, ReleaseFlow and DropFlow are StoreCommands: the sweep clears the
// store (a previous run's held packets), and the fake records that it asked.
func (f *sweepFake) ClearStore(_ context.Context, module string) error {
	if f.err != nil {
		return f.err
	}
	f.cleared = append(f.cleared, module)
	return nil
}

func (f *sweepFake) ReleaseFlow(_ context.Context, module string, id uint32) error { return nil }

func (f *sweepFake) DropFlow(_ context.Context, module string, id uint32) error { return nil }

func (f *sweepFake) Contents(_ context.Context, names ...string) (map[string][]bess.Entry, error) {
	f.reads = append(f.reads, append([]string(nil), names...))
	if f.err != nil {
		return nil, f.err
	}
	// The daemon's own refusal, and the reason the sweep reads one resource per
	// call: every resource named is packed into one response, and one above
	// kMaxMessageBytes (64 MiB) is RESOURCE_EXHAUSTED ("name fewer resources").
	// A read naming the whole session layer is what a 1M-session dataplane
	// answers that to.
	if len(names) > 1 {
		return nil, fmt.Errorf("bess: pipeline: rpc error: code = ResourceExhausted desc = the pipeline with its resources is above the 67108864-byte message limit: name fewer resources")
	}
	out := map[string][]bess.Entry{}
	for _, n := range names {
		out[n] = f.contents[n]
	}
	return out, nil
}

// TestSweepNamesTheGraphsResources pins the names a sweep touches: the
// deployment's own spelling, "<module>/<table>", never a bare module name --
// a sweep that reads "pdr_ul" finds no such resource and erases nothing.
func TestSweepNamesTheGraphsResources(t *testing.T) {
	cfg := liveConfig()
	c := New(cfg, &sweepFake{}, quietLogger())
	want := map[string]bool{
		"teid/rules": true, "pdr_ul/rules": true, "pdr_dl/rules": true,
		"at_ul/actions": true, "at_dl/actions": true,
		"mt_ul/meters": true, "mt_dl/meters": true,
		"cnt_ul/counters": true, "cnt_dl/counters": true, "enc/tunnels": true,
	}
	got := map[string]bool{}
	for _, n := range c.resources() {
		got[n] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("the sweep does not read %s", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("the sweep reads %s, which is no session resource", name)
		}
	}
	if len(got) != len(c.resources()) {
		t.Errorf("the sweep names a resource twice: %v", c.resources())
	}

	// A graph that charges nothing declares no counter module: the sweep must
	// leave it out rather than turn the empty name into "/counters".
	cfg.Up.Counters = ""
	cfg.Down.Counters = ""
	for _, n := range New(cfg, &sweepFake{}, quietLogger()).resources() {
		if n == "/counters" || n == "cnt_ul/counters" || n == "cnt_dl/counters" {
			t.Errorf("a graph without counters still sweeps %s", n)
		}
	}
}

// TestSweepClearsTheStoreAndNamesItsCounter pins the buffering half of the
// restart wall: the branch's counter is a session resource like the others, and
// what the store held belongs to the run that ended -- a controller that comes
// up knows neither the flows nor the episodes they were held for, so the store
// is cleared rather than left to hand a later session the previous one's
// packets.
func TestSweepClearsTheStoreAndNamesItsCounter(t *testing.T) {
	cfg := testConfig()
	cfg.Buffering = &Buffering{Store: "buf", Counter: "cnt_buf", Gate: 1}
	fake := &sweepFake{}
	if err := New(cfg, fake, quietLogger()).Sweep(context.Background()); err != nil {
		t.Fatalf("sweeping with a store: %v", err)
	}
	found := false
	for _, name := range New(cfg, fake, quietLogger()).resources() {
		if name == "cnt_buf/counters" {
			found = true
		}
	}
	if !found {
		t.Errorf("the sweep does not read the buffering branch's counter")
	}
	if len(fake.cleared) != 1 || fake.cleared[0] != "buf" {
		t.Errorf("the store was cleared %v, want one clear of buf", fake.cleared)
	}
}

// TestSweepErasesEveryReadEntryInOneTransaction is the restart wall's unit
// half: the sweep reads the session tables, erases exactly the entries it
// found -- the key from the readback, not one it made up -- in one
// transaction, and does not touch a resource it does not own.
func TestSweepErasesEveryReadEntryInOneTransaction(t *testing.T) {
	f := &sweepFake{contents: map[string][]bess.Entry{}}
	c := New(liveConfig(), f, quietLogger())
	names := c.resources()
	for i, name := range names {
		f.contents[name] = []bess.Entry{{Key: map[string]any{"id": uint64(i + 1)}}}
	}
	// The graph's own resource, which no session writes and no sweep may erase.
	f.contents["rt/next_hops"] = []bess.Entry{{Key: map[string]any{"id": uint64(1)}}}

	if err := c.Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	if len(f.changes) != 1 {
		t.Fatalf("the sweep wrote %d transactions, want one", len(f.changes))
	}
	if got := len(f.changes[0]); got != len(names) {
		t.Errorf("the sweep erased %d entries, want one per session table (%d)", got, len(names))
	}
	for _, ch := range f.changes[0] {
		if ch.Resource == "rt/next_hops" {
			t.Error("the sweep erased the graph's own next hops: only session tables are its to empty")
		}
		if ch.Value != nil {
			t.Errorf("the sweep wrote %s with a value: an erase carries a key and no value", ch.Resource)
		}
		if ch.Key == nil {
			t.Errorf("the sweep erased %s with no key", ch.Resource)
		}
	}
}

// TestSweepWithNothingToEraseWritesNothing: an empty transaction is one the
// daemon refuses, so a clean restart must not send one.
func TestSweepWithNothingToEraseWritesNothing(t *testing.T) {
	f := &sweepFake{contents: map[string][]bess.Entry{}}
	c := New(testConfig(), f, quietLogger())
	if err := c.Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	if len(f.changes) != 0 {
		t.Errorf("the sweep wrote %d transactions over empty tables, want none", len(f.changes))
	}
}

// staleEntries fills the session tables with n entries, one per key across
// every resource, the way an earlier run's million sessions would be spread.
func staleEntries(f *sweepFake, names []string, n int) {
	for i := range n {
		name := names[i%len(names)]
		f.contents[name] = append(f.contents[name], bess.Entry{Key: map[string]any{"id": uint64(i + 1)}})
	}
}

// TestSweepErasesInBoundedBatchesAtScale is the restart wall at the size the
// deployment target implies, on both halves of it. The readback is one
// Contents call per resource, never one naming them all: every resource named
// is packed into one response there, and the daemon refuses a response above
// its 64 MiB message limit (RESOURCE_EXHAUSTED, "name fewer resources"), which
// the whole session layer of a 1M-session dataplane is -- so the bound is the
// largest single table, not the sum of the tables. The fake reader answers that
// refusal exactly as the daemon does. And the erase is chunked: 5000 entries
// go out in transactions of at most sweepBatch changes each, never one
// transaction carrying every entry, with every entry read erased exactly once.
func TestSweepErasesInBoundedBatchesAtScale(t *testing.T) {
	const entries = 5000
	f := &sweepFake{contents: map[string][]bess.Entry{}}
	c := New(liveConfig(), f, quietLogger())
	names := c.resources()
	staleEntries(f, names, entries)

	if err := c.Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	// One read per resource, each naming exactly that one: a read naming them
	// all is the message the daemon refuses at this size.
	if len(f.reads) != len(names) {
		t.Errorf("the sweep read the dataplane %d times for %d resources, want one read each",
			len(f.reads), len(names))
	}
	read := map[string]int{}
	for i, got := range f.reads {
		if len(got) != 1 {
			t.Errorf("read %d names %v: one Contents call names one resource, so the 64 MiB message limit bounds a table and not the sum of them",
				i+1, got)
			continue
		}
		read[got[0]]++
	}
	for _, name := range names {
		if read[name] != 1 {
			t.Errorf("the sweep read %s %d times, want once", name, read[name])
		}
	}
	want := (entries + sweepBatch - 1) / sweepBatch
	if len(f.changes) != want {
		t.Fatalf("the sweep wrote %d transactions for %d entries, want %d of at most %d changes each",
			len(f.changes), entries, want, sweepBatch)
	}
	erased := map[string]int{}
	for i, tx := range f.changes {
		if len(tx) > sweepBatch {
			t.Errorf("transaction %d carries %d changes, above the %d-change batch bound",
				i+1, len(tx), sweepBatch)
		}
		for _, ch := range tx {
			if ch.Key == nil {
				t.Errorf("transaction %d erased %s with no key", i+1, ch.Resource)
			}
			if ch.Value != nil {
				t.Errorf("transaction %d wrote %s with a value: an erase carries a key and no value",
					i+1, ch.Resource)
			}
			erased[fmt.Sprintf("%s/%v", ch.Resource, ch.Key["id"])]++
		}
	}
	if len(erased) != entries {
		t.Errorf("the sweep erased %d distinct entries, want the %d it read", len(erased), entries)
	}
	for key, n := range erased {
		if n != 1 {
			t.Errorf("entry %s was erased %d times, want once", key, n)
		}
	}
}

// TestSweepStopsAtTheFirstFailedBatch is the chunked erase's failure mode, and
// the reason a sweep error is fatal to the caller: the batches before the
// refused one are committed, the ones after it are never sent, and the error
// says which batch failed and how much was already erased. A run that came up
// beside that would serve PFCP over a dataplane it half-emptied.
func TestSweepStopsAtTheFirstFailedBatch(t *testing.T) {
	const entries = 5000
	f := &sweepFake{contents: map[string][]bess.Entry{}, failBatch: 3}
	c := New(liveConfig(), f, quietLogger())
	names := c.resources()
	staleEntries(f, names, entries)

	err := c.Sweep(context.Background())
	if err == nil {
		t.Fatal("the sweep reported success after a batch the dataplane refused")
	}
	if f.applies != 3 {
		t.Errorf("the sweep called the dataplane %d times, want 3: it must stop at the first refused batch", f.applies)
	}
	if len(f.changes) != 2 {
		t.Fatalf("the sweep committed %d transactions, want the 2 before the refused one", len(f.changes))
	}
	committed := 0
	for _, tx := range f.changes {
		committed += len(tx)
	}
	for _, want := range []string{
		fmt.Sprintf("batch 3 of %d", (entries+sweepBatch-1)/sweepBatch),
		fmt.Sprintf("%d of %d entries erased", committed, entries),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the sweep's error %q does not say %q: an operator has to know which batch failed and what is already gone",
				err, want)
		}
	}
}

// TestSweepLeavesNothingErasedWhenTheReadbackFails pins the other side of the
// same failure mode: the erase is chunked but the readback is a single call,
// so a reader error happens before any batch exists and nothing at all is
// written. The sweep must not turn "I could not read" into "there was nothing
// there" -- a dataplane it cannot read may still hold an earlier run's
// sessions.
func TestSweepLeavesNothingErasedWhenTheReadbackFails(t *testing.T) {
	f := &sweepFake{
		contents: map[string][]bess.Entry{},
		err:      errors.New("the daemon listed no contents"),
	}
	c := New(liveConfig(), f, quietLogger())
	if err := c.Sweep(context.Background()); err == nil {
		t.Fatal("the sweep reported success over a dataplane it could not read")
	}
	if f.applies != 0 || len(f.changes) != 0 {
		t.Errorf("the sweep wrote %d transactions over %d calls of a dataplane it could not read, want none",
			len(f.changes), f.applies)
	}
}

// TestSweepReportsAnUnreadableDataplane: the readback is what says there is
// something to erase; a dataplane that cannot be read is a failed sweep, not a
// clean one, and an applier that cannot be read at all is refused before
// anything is sent.
func TestSweepReportsAnUnreadableDataplane(t *testing.T) {
	c := New(testConfig(), &sweepFake{err: errors.New("no schema")}, quietLogger())
	if err := c.Sweep(context.Background()); err == nil {
		t.Fatal("the sweep reported success over a dataplane it could not read")
	}
	blind := New(testConfig(), &recorder{}, quietLogger())
	if err := blind.Sweep(context.Background()); err == nil {
		t.Fatal("the sweep reported success over an applier that cannot read back")
	}
}
