// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
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
	// resets is every ResetResources call's names: the whole tables the sweep
	// emptied in the daemon.
	resets [][]string
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

func (f *sweepFake) ResetResources(_ context.Context, names ...string) (uint64, error) {
	f.resets = append(f.resets, append([]string(nil), names...))
	if f.err != nil {
		return 0, f.err
	}
	if f.contents == nil {
		f.contents = map[string][]bess.Entry{}
	}
	removed := uint64(0)
	for _, name := range names {
		removed += uint64(len(f.contents[name]))
		f.contents[name] = nil
	}
	return removed, nil
}

func (f *sweepFake) ResourcePages(_ context.Context, name string, visit func(bess.Entry) error) error {
	if f.err != nil {
		return f.err
	}
	for _, e := range f.contents[name] {
		if err := visit(e); err != nil {
			return err
		}
	}
	return nil
}

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

	// The uplink's tunnel module is a session resource too: an uplink forward
	// that adds an outer header writes its record there, and an earlier run's
	// record would name this run's ActionId with the wrong TEID.
	cfg.Up.Tunnels = "enc_ul"
	if got := New(cfg, &sweepFake{}, quietLogger()).resources(); !slices.Contains(got, "enc_ul/tunnels") {
		t.Errorf("the sweep does not read an uplink tunnel module's records: %v", got)
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

// TestTheSweepTakesTheSubscribersARPEntriesAndLeavesTheDeployments is the ARP
// half of the restart wall: the responder's table has two writers -- the graph
// writes the interface's own entry, the session layer writes its subscribers'
// -- and a restarted controller knows only the second. The line between them is
// the interface's pool: the compiler refuses a subscriber address outside it,
// so pool members are exactly what an earlier run's sessions could have
// written, and the deployment's own address is not one.
func TestTheSweepTakesTheSubscribersARPEntriesAndLeavesTheDeployments(t *testing.T) {
	instances := func(t *testing.T, pools ...string) *routing.Domains {
		t.Helper()
		ifc := routing.Interface{
			Instance: "internet", Domain: 0, NextHop: 1,
			ARP: "arp_n6", ARPMAC: [6]byte{2, 0, 0, 0, 0, 1},
		}
		for _, p := range pools {
			ifc.Pool = append(ifc.Pool, netip.MustParsePrefix(p))
		}
		d, err := routing.New([]routing.Interface{ifc}, 4)
		if err != nil {
			t.Fatalf("the deployment was refused: %v", err)
		}
		return d
	}
	entries := []bess.Entry{
		{Key: map[string]any{"ip": "192.0.2.2"}, Value: map[string]any{"mac_addr": "02:00:00:00:06:01"}},
		{Key: map[string]any{"ip": "10.45.0.2"}},
		{Key: map[string]any{"ip": "10.45.0.7"}},
	}

	cfg := liveConfig()
	cfg.Instances = instances(t, "10.45.0.0/16")
	fake := &sweepFake{contents: map[string][]bess.Entry{"arp_n6/entries": entries}}
	if err := New(cfg, fake, quietLogger()).Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep failed: %v", err)
	}
	erased := map[string]bool{}
	for _, batch := range fake.changes {
		for _, ch := range batch {
			if ch.Resource == "arp_n6/entries" {
				ip, _ := ch.Key["ip"].(string)
				erased[ip] = true
			}
		}
	}
	for _, want := range []string{"10.45.0.2", "10.45.0.7"} {
		if !erased[want] {
			t.Errorf("the sweep left the earlier run's entry for %s: %v", want, erased)
		}
	}
	if erased["192.0.2.2"] {
		t.Error("the sweep erased the deployment's own ARP entry: the interface stops answering for itself")
	}

	// An interface that declares no pool serves every address, so an entry in
	// its table cannot be told apart from the deployment's own: the sweep
	// leaves the table alone (and says so in the log).
	fake = &sweepFake{contents: map[string][]bess.Entry{"arp_n6/entries": entries}}
	cfg.Instances = instances(t)
	if err := New(cfg, fake, quietLogger()).Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep failed: %v", err)
	}
	for _, batch := range fake.changes {
		for _, ch := range batch {
			if ch.Resource == "arp_n6/entries" {
				t.Errorf("the sweep erased %v from an interface that declares no pool", ch.Key)
			}
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

// TestSweepResetsOnlyTheSessionTables is the restart wall's unit half: the
// sweep empties the maps the compiler owns in the daemon -- one reset naming
// every map, no key read back -- and does not touch a resource it does not
// own.
func TestSweepResetsOnlyTheSessionTables(t *testing.T) {
	f := &sweepFake{contents: map[string][]bess.Entry{}}
	c := New(liveConfig(), f, quietLogger())
	names := c.resources()
	for i, name := range names {
		f.contents[name] = []bess.Entry{{Key: map[string]any{"id": uint64(i + 1)}}}
	}
	// The graph's own resource, which no session writes and no sweep may erase.
	const graphResource = "rt/next_hops"
	f.contents[graphResource] = []bess.Entry{{Key: map[string]any{"id": uint64(1)}}}

	if err := c.Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	if len(f.resets) != 1 {
		t.Fatalf("the sweep called ResetResources %d times, want once", len(f.resets))
	}
	if got := f.resets[0]; len(got) != len(names) {
		t.Errorf("the reset names %d resources, want the %d session tables", len(got), len(names))
	}
	for _, name := range f.resets[0] {
		if name == graphResource {
			t.Error("the reset names the graph's own next hops: only session tables are its to empty")
		}
	}
	if len(f.changes) != 0 {
		t.Errorf("the sweep also wrote %d key erases for tables it reset", len(f.changes))
	}
	if got := f.contents[graphResource]; len(got) != 1 {
		t.Errorf("the graph's own next hops were emptied: %v", got)
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

// arpSweepConfig is a deployment with one ARP responder whose pool is the
// subscriber prefix: the table the sweep still reads page by page.
func arpSweepConfig(t *testing.T) Config {
	t.Helper()
	d, err := routing.New([]routing.Interface{{
		Instance: "internet", Domain: 0, NextHop: 1,
		ARP: "arp_n6", ARPMAC: [6]byte{2, 0, 0, 0, 0, 1},
		Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")},
	}}, 4)
	if err != nil {
		t.Fatalf("the deployment was refused: %v", err)
	}
	cfg := liveConfig()
	cfg.Instances = d
	return cfg
}

// staleARPEntries fills the responder's table with n subscriber addresses, the
// way an earlier run's sessions would have.
func staleARPEntries(f *sweepFake, n int) {
	for i := range n {
		ip := fmt.Sprintf("10.45.%d.%d", i/256, i%256)
		f.contents["arp_n6/entries"] = append(f.contents["arp_n6/entries"],
			bess.Entry{Key: map[string]any{"ip": ip}})
	}
}

// TestSweepErasesInBoundedBatchesAtScale is the restart wall at the size the
// deployment target implies. The session maps are one ResetResources call (no
// key readback, no 64 MiB ceiling), and the one table that still needs its
// keys -- the ARP responder's, shared with the deployment's own entry -- is
// read through ReadResource's pages and erased in transactions of at most
// sweepBatch changes, with every entry erased exactly once.
func TestSweepErasesInBoundedBatchesAtScale(t *testing.T) {
	const entries = 5000
	f := &sweepFake{contents: map[string][]bess.Entry{}}
	c := New(arpSweepConfig(t), f, quietLogger())
	staleARPEntries(f, entries)

	if err := c.Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	if len(f.resets) != 1 {
		t.Errorf("the sweep reset %d times, want one whole-table call", len(f.resets))
	}
	want := (entries + sweepBatch - 1) / sweepBatch
	if len(f.changes) != want {
		t.Fatalf("the sweep wrote %d transactions for %d ARP entries, want %d of at most %d changes each",
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
			ip, _ := ch.Key["ip"].(string)
			erased[ip]++
		}
	}
	if len(erased) != entries {
		t.Errorf("the sweep erased %d distinct ARP entries, want the %d it read", len(erased), entries)
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
	c := New(arpSweepConfig(t), f, quietLogger())
	staleARPEntries(f, entries)

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
