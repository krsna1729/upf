package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func TestPendingExpiryAfterAcknowledgement(t *testing.T) {
	for _, kind := range []byte{'m', 'd'} {
		for cancelled := 0; cancelled < 3; cancelled++ {
			t.Run(fmt.Sprintf("%c/acknowledged-%d", kind, cancelled), func(t *testing.T) {
				base := time.Now().Add(-time.Hour)
				d := &driver{slots: make([]slot, 3), pending: make(map[uint32]*pending), timeout: 5 * time.Second}
				r := newResult("far", 1)
				if kind == 'd' {
					r.Mode = "delete"
				}
				r.Sent, r.WireSent = 3, 3
				requests := make([]*pending, 3)
				for i := range requests {
					d.slots[i] = slot{seid: uint64(i + 100), cp: uint64(i + 1000), busy: true}
					started := base.Add(time.Duration(i) * time.Second)
					requests[i] = &pending{seq: uint32(i + 1), kind: kind, index: i,
						started: started, cycleStarted: started, phase: r, done: make(chan error, 1)}
					d.trackPendingLocked(requests[i])
					d.active++
				}

				d.expireAt(base.Add(d.timeout - time.Nanosecond))
				if r.TimedOut != 0 || d.active != 3 {
					t.Fatalf("expired before deadline: timeouts=%d active=%d", r.TimedOut, d.active)
				}

				d.mu.Lock()
				acknowledged := d.takePendingLocked(requests[cancelled].seq)
				d.mu.Unlock()
				var response message.Message = message.NewSessionModificationResponse(0, 0,
					d.slots[cancelled].seid, acknowledged.seq, 0, ie.NewCause(ie.CauseRequestAccepted))
				if kind == 'd' {
					response = message.NewSessionDeletionResponse(0, 0,
						d.slots[cancelled].seid, acknowledged.seq, 0, ie.NewCause(ie.CauseRequestAccepted))
				}
				d.finish(acknowledged, response, nil)
				d.expireAt(base.Add(d.timeout + time.Second))
				wantExpired := 2
				if cancelled < 2 {
					wantExpired--
				}
				if r.Completed != 1 || r.WireAccepted != 1 || r.TimedOut != wantExpired || d.active != 2-wantExpired {
					t.Fatalf("mixed acknowledgement/expiry: completed=%d accepted=%d timeouts=%d active=%d",
						r.Completed, r.WireAccepted, r.TimedOut, d.active)
				}
				for i := range requests {
					wantBusy := i == 2 && i != cancelled
					if d.slots[i].busy != wantBusy {
						t.Fatalf("request %d busy=%v, want %v", i, d.slots[i].busy, wantBusy)
					}
				}

				d.expireAt(base.Add(d.timeout + 2*time.Second))
				d.expireAt(base.Add(d.timeout + time.Hour))
				if r.Completed != 1 || r.TimedOut != 2 || d.active != 0 {
					t.Fatalf("final accounting: completed=%d timeouts=%d active=%d", r.Completed, r.TimedOut, d.active)
				}
				for i, p := range requests {
					wantUncertain := kind == 'd' && i != cancelled
					if d.slots[i].busy || d.slots[i].uncertain != wantUncertain {
						t.Fatalf("request %d busy=%v uncertain=%v, want uncertain=%v",
							i, d.slots[i].busy, d.slots[i].uncertain, wantUncertain)
					}
					select {
					case err := <-p.done:
						if (err == nil) != (i == cancelled) {
							t.Fatalf("request %d completion error=%v", i, err)
						}
					default:
						t.Fatalf("request %d has no completion", i)
					}
				}
			})
		}
	}
}

func TestResultFilesCannotClobberEvidence(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dir := t.TempDir()
	protected := filepath.Join(dir, "loaded.json")
	const original = "previous evidence"
	if err := os.WriteFile(protected, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	d := &driver{conn: conn, out: dir}
	records := make(map[string]string)
	for _, mode := range []string{"loaded", "../outside\x00"} {
		r := newResult(mode, 1)
		r.Start, r.End = time.Now().Add(-time.Second), time.Now()
		r.Duration = 1
		saved := d.save(r)
		name := saved["record_file"].(string)
		if filepath.Base(name) != name || name == "loaded.json" {
			t.Fatalf("unsafe result path %q", name)
		}
		if _, duplicate := records[name]; duplicate {
			t.Fatalf("result file reused: %q", name)
		}
		records[name] = mode
	}
	if data, err := os.ReadFile(protected); err != nil || string(data) != original {
		t.Fatalf("previous evidence changed: data=%q err=%v", data, err)
	}
	for name, mode := range records {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var record struct {
			Result result `json:"result"`
		}
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		if record.Result.Mode != mode {
			t.Fatalf("result %q overwritten: mode=%q, want %q", name, record.Result.Mode, mode)
		}
	}
}

func TestSessionSelectionVisitsEveryResident(t *testing.T) {
	for _, population := range []int{1, 104729, 209458, 1000000} {
		t.Run(fmt.Sprint(population), func(t *testing.T) {
			stride := sessionStride(population)
			seen := make([]bool, population)
			for next := 0; next < population; next++ {
				i := (next * stride) % population
				if seen[i] {
					t.Fatalf("selection repeats session %d at opportunity %d", i, next)
				}
				seen[i] = true
			}
		})
	}
}
