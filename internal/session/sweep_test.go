// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"testing"

	"github.com/krsna1729/upf/internal/bess"
)

// sweepFake is an applier that can also read its own contents back, the way a
// real dataplane does: what the sweep reads is what an earlier run wrote.
type sweepFake struct {
	contents map[string][]bess.Entry
	changes  [][]bess.Change
	cleared  []string
	err      error
}

func (f *sweepFake) Apply(_ context.Context, changes ...bess.Change) error {
	if f.err != nil {
		return f.err
	}
	f.changes = append(f.changes, changes)
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
	if f.err != nil {
		return nil, f.err
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
