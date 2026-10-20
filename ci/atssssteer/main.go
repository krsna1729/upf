// SPDX-License-Identifier: BSD-3-Clause

// Command atssssteer drives the AtsssSteer lane's windows. The graph is
// deploy/atsss-steer.yaml; this process changes the health and policy resources
// and stops the Source between windows, while the shell reads the Dumps.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/krsna1729/upf/internal/bess"
)

const (
	source  = "src"
	policy  = "atsss/policies"
	health  = "atsss/health"
	waitFor = 2 * time.Second
)

func main() {
	target := flag.String("target", "127.0.0.1:10514", "bessd's control_v2 gRPC address")
	handshake := flag.String("handshake", "", "directory for the window handshake files")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := bess.Dial(ctx, *target)
	if err != nil {
		die("dial: %v", err)
	}
	defer client.Close()

	window := func(name string, burst int) {
		if err := setBurst(ctx, client, burst); err != nil {
			die("%s: %v", name, err)
		}
		if burst != 0 {
			time.Sleep(waitFor)
		}
		if err := setBurst(ctx, client, 0); err != nil {
			die("%s: stop: %v", name, err)
		}
		signal(*handshake, name+".done")
		if *handshake != "" {
			for {
				if _, err := os.Stat(filepath.Join(*handshake, name+".go")); err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	set := func(entries ...bess.Change) {
		if err := client.Apply(ctx, entries...); err != nil {
			die("applying resources: %v", err)
		}
	}

	// Both accesses are healthy: the preferred (3GPP) access is selected.
	window("both", 1)

	// The 3GPP access is unavailable: the standby carries the packet.
	set(healthChange(1, false))
	window("failover", 1)

	// Neither access is usable: the packet is dropped, not sent to a guess.
	set(healthChange(2, false))
	window("none", 1)

	// A policy that is gone has no access to select. Make both accesses
	// healthy and publish the policy first, then erase it: if the erase is
	// ignored (an upsert instead), the packet would go to dump_a and fail.
	set(healthChange(1, true), healthChange(2, true), policyChange(1, 0, 1))
	set(policyErase(1))
	window("erased", 1)

	// Republish the policy with the non-3GPP access preferred, both healthy.
	// The access hops stay 1 and 2: only the preferred index changes, so a
	// broken selector that always takes access 0 would still send to dump_a.
	set(policyChange(1, 1, 1))
	window("preferred2", 1)

	// Back to the 3GPP preference, and the 3GPP access keeps working.
	set(policyChange(1, 0, 1))
	window("recovered", 1)
}

func setBurst(ctx context.Context, client *bess.Client, burst int) error {
	return client.Apply(ctx, bess.Change{
		Resource: source + "/settings",
		Value:    map[string]any{"pkt_size": 51, "burst": burst},
	})
}

func healthChange(id int, available bool) bess.Change {
	return bess.Change{
		Resource: health,
		Key:      map[string]any{"health_id": id},
		Value:    map[string]any{"available": available},
	}
}

func policyErase(id int) bess.Change {
	return bess.Change{
		Resource: policy,
		Key:      map[string]any{"policy_id": id},
	}
}

func policyChange(id int, preferred, hop int) bess.Change {
	return bess.Change{
		Resource: policy,
		Key:      map[string]any{"policy_id": id},
		Value: map[string]any{
			"mode":      "ATSSS_ACTIVE_STANDBY",
			"preferred": preferred,
			"access": []any{
				map[string]any{"next_hop_id": hop, "health_id": 1},
				map[string]any{"next_hop_id": 2, "health_id": 2},
			},
		},
	}
}

func signal(dir, name string) {
	if dir == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
		die("writing %s: %v", name, err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "atssssteer: "+format+"\n", args...)
	os.Exit(1)
}
