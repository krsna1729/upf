// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"slices"

	"github.com/krsna1729/upf/internal/bess"
)

// SessionLayout is UpfSessionAppliance's shape (upfd's -target
// session-major): the module's session arguments, which bound what one
// session may hold.
type SessionLayout struct {
	// MaxSessions is session.capacity: session ids are 1..MaxSessions.
	MaxSessions uint32
	// Actions and QERs are session.max_actions and session.max_qers: the
	// actions (one per forwarding, buffering or measured PDR, plus the ATSSS
	// tunnels) and the rate-bearing QER meters one session holds.
	Actions int
	QERs    int
}

// sessionTarget is the appliance with the session-major layout
// (UpfSessionAppliance, docs/datapath.md "Session-major"): the compilation is
// the appliance's, and apply folds each session's F-TEID, PDR, meter,
// counter and tunnel writes into one "<module>/sessions" entry. Every other
// write -- buffer counters, flows, policies, ARP entries -- goes as it is.
type sessionTarget struct {
	applianceTarget
}

// sessionTables are the appliance tables a session's entry carries. The
// meters and tunnels are one resource for both directions (applianceTables):
// the uplink's name stands for it.
var sessionTables = []Table{FTEIDs, PDRUplink, PDRDownlink, MetersUplink, CountersUplink,
	CountersDownlink, TunnelsUplink}

func (t sessionTarget) SweepResources() []string {
	names := []string{t.module + "/sessions"}
	if b := t.cfg.Buffering; b != nil && b.Store != "" && b.Counter != "" {
		names = append(names, t.Resource(BufferCounters), t.Resource(Flows))
	}
	return names
}

// apply writes one session's changes: as they are, or, under -target
// session-major, folded into the session's one entry. gone is the session's
// deletion. A fold refusal is definite (nothing was sent).
func (c *Compiler) apply(ctx context.Context, s *Session, changes []bess.Change, gone bool) error {
	if _, ok := c.target.(sessionTarget); ok {
		folded, err := c.foldSession(s, changes, gone)
		if err != nil {
			return err
		}
		changes = folded
	}
	if len(changes) == 0 {
		return nil
	}
	err := c.ap.Apply(ctx, changes...)
	if _, ok := c.target.(sessionTarget); ok && (err == nil || !definiteRefusal(err)) {
		// What may now be in the dataplane: an unanswered write may have
		// committed, so the deletion erases the entry (and a refusal of that
		// erase for a key that is not there is the leak-safe failure).
		c.mu.Lock()
		s.sessionLive = !gone
		c.mu.Unlock()
	}
	return err
}

// foldSession turns a compile's changes into the session's entry. A compile
// writes every record the session holds (and erases what it no longer does),
// so the entry is its upserts of the session tables; their erases have no
// meaning beyond the entry and are dropped. The deletion erases the entry.
func (c *Compiler) foldSession(s *Session, changes []bess.Change, gone bool) ([]bess.Change, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mine := map[string]Table{}
	for _, t := range sessionTables {
		mine[c.res(t)] = t
	}
	sessionsRes := c.cfg.Appliance + "/sessions"
	out := make([]bess.Change, 0, len(changes)+1)
	var session []bess.Change
	for _, ch := range changes {
		if _, ok := mine[ch.Resource]; ok {
			if ch.Value != nil {
				session = append(session, ch)
			}
			continue
		}
		out = append(out, ch)
	}
	if gone {
		if s.sessionLive {
			out = append(out, bess.Change{Resource: sessionsRes, Key: map[string]any{"session_id": s.sessionID}})
		}
		return out, nil
	}
	value, positions, err := c.sessionValue(s, session, mine)
	if err != nil {
		return nil, err
	}
	if s.sessionID == 0 {
		id, err := c.sessionIDs.alloc()
		if err != nil {
			return nil, fmt.Errorf("%w: session id: %v", errNoResources, err)
		}
		s.sessionID = id
	}
	// The policies' access tunnels are session-local under this layout: the
	// 1-based position of the tunnel's action in the entry. They follow the
	// entry, so a rule's steering never names a tunnel it does not have.
	for i, ch := range out {
		if ch.Resource != c.res(Policies) || ch.Value == nil {
			continue
		}
		v := maps.Clone(ch.Value)
		accesses, _ := v["access"].([]map[string]any)
		local := make([]map[string]any, len(accesses))
		for j, a := range accesses {
			local[j] = maps.Clone(a)
			if id, _ := a["tunnel_id"].(uint32); id != 0 {
				pos, ok := positions[id]
				if !ok {
					return nil, fmt.Errorf("%w: an ATSSS access names tunnel %d, which the session does not hold",
						errNotExpressible, id)
				}
				local[j]["tunnel_id"] = uint32(pos)
			}
		}
		v["access"] = local
		out[i].Value = v
	}
	// The entry first: a policy's tunnels are positions in it.
	return append([]bess.Change{{Resource: sessionsRes,
		Key: map[string]any{"session_id": s.sessionID}, Value: value}}, out...), nil
}

// sessionValue is the UpfSession the session's appliance writes make, and the
// 1-based position of each action id in it. The caller holds the lock.
func (c *Compiler) sessionValue(s *Session, writes []bess.Change, mine map[string]Table) (map[string]any, map[uint32]int, error) {
	var fteids, rules []bess.Change
	meters := map[uint32]map[string]any{}
	tunnels := map[uint32]map[string]any{}
	counted := map[uint32]bool{}
	for _, ch := range writes {
		switch mine[ch.Resource] {
		case FTEIDs:
			fteids = append(fteids, ch)
		case PDRUplink, PDRDownlink:
			rules = append(rules, ch)
		case MetersUplink:
			meters[mapUint(ch.Key, "id")] = ch.Value
		case CountersUplink, CountersDownlink:
			counted[mapUint(ch.Key, "action_id")] = true
		case TunnelsUplink:
			tunnels[mapUint(ch.Key, "action_id")] = ch.Value
		}
	}
	// A dropping rule's result is empty; its PDR says which action it is,
	// and a measured one keeps that action (and so its URR cells) in the
	// entry, as the masked layout keeps its counter entry.
	owners := map[string]*pdr{}
	for _, p := range s.PDRs {
		keys, err := p.ruleKeys(c.direction(p).PDRFields)
		if err != nil {
			return nil, nil, fmt.Errorf("PDR %d: %w", p.id, err)
		}
		for _, key := range keys {
			owners[c.res(pdrTable(p.downlink()))+"\x00"+fmt.Sprint(key)] = p
		}
	}

	// Every meter the session writes is one of its QERs, in id order, named
	// or not: a QER whose rules drop for a while keeps its buckets, as its
	// meter entry does in the masked layout.
	qers := make([]map[string]any, 0, len(meters))
	qerAt := map[uint32]int{}
	for _, id := range slices.Sorted(maps.Keys(meters)) {
		q := maps.Clone(meters[id])
		q["qer_id"] = id
		qers = append(qers, q)
		qerAt[id] = len(qers)
	}
	qer := func(id uint32) (int, error) {
		if id == 0 {
			return 0, nil
		}
		pos, ok := qerAt[id]
		if !ok {
			return 0, fmt.Errorf("%w: a PDR names meter %d, which the session does not write", errNotExpressible, id)
		}
		return pos, nil
	}

	actions := []map[string]any{}
	at := map[uint32]int{}
	action := func(id uint32) map[string]any {
		if pos, ok := at[id]; ok {
			return actions[pos-1]
		}
		a := map[string]any{"action_id": id, "count": counted[id]}
		if t, ok := tunnels[id]; ok {
			a["tunnel"] = t
		}
		actions = append(actions, a)
		at[id] = len(actions)
		return a
	}

	pdrs := make([]map[string]any, 0, len(rules))
	for _, ch := range rules {
		down := mine[ch.Resource] == PDRDownlink
		value, mask, err := packedKey(ch.Key)
		if err != nil {
			return nil, nil, err
		}
		rule := map[string]any{
			"downlink": down, "value": value, "mask": mask,
			"priority": ch.Value["priority"], "gate": ch.Value["gate"],
		}
		if ranges, ok := ch.Key["ranges"]; ok {
			rule["ranges"] = ranges
		}
		result, _ := ch.Value["result"].([]byte)
		id := uint32(0)
		if len(result) >= resultSize {
			id = binary.BigEndian.Uint32(result[resultActionID:])
		}
		if id != 0 {
			a := action(id)
			a["next_hop_id"] = binary.BigEndian.Uint32(result[resultNextHopID:])
			a["route_domain"] = binary.BigEndian.Uint32(result[resultRouteDomain:])
			if down && len(result) >= resultSteeringID+4 {
				a["steering_policy_id"] = binary.BigEndian.Uint32(result[resultSteeringID:])
			}
			for i, field := range []string{"pdr_qer", "session_qer"} {
				pos, err := qer(binary.BigEndian.Uint32(result[resultMeterID+4*i:]))
				if err != nil {
					return nil, nil, err
				}
				a[field] = uint32(pos)
			}
		} else if p := owners[ch.Resource+"\x00"+fmt.Sprint(ch.Key)]; p != nil && counted[p.actionID] {
			id = p.actionID
			action(id)
		}
		if id != 0 {
			rule["action"] = uint32(at[id])
		}
		pdrs = append(pdrs, rule)
	}
	// The ATSSS tunnels no rule names: tunnel-only actions, in id order.
	for _, id := range slices.Sorted(maps.Keys(tunnels)) {
		if _, ok := at[id]; !ok {
			action(id)
		}
	}
	if layout := c.cfg.Sessions; len(actions) > layout.Actions || len(qers) > layout.QERs {
		return nil, nil, fmt.Errorf("%w: the session needs %d actions and %d QER meters; the module holds %d and %d per session (-session-actions, -session-qers)",
			errNotExpressible, len(actions), len(qers), layout.Actions, layout.QERs)
	}
	entries := make([]map[string]any, 0, len(fteids))
	for _, ch := range fteids {
		entries = append(entries, map[string]any{"key": ch.Key, "entry": ch.Value})
	}
	return map[string]any{"fteids": entries, "qers": qers, "actions": actions, "pdrs": pdrs}, at, nil
}

// packedKey is a WildcardMatch rule key's values and masks as the session
// entry's packed bytes, in the table's field order.
func packedKey(key map[string]any) ([]byte, []byte, error) {
	values, _ := key["values"].([]map[string]any)
	masks, _ := key["masks"].([]map[string]any)
	if len(values) != len(masks) {
		return nil, nil, fmt.Errorf("a rule key with %d values and %d masks", len(values), len(masks))
	}
	var value, mask []byte
	for i := range values {
		v, _ := values[i]["value_bin"].([]byte)
		m, _ := masks[i]["value_bin"].([]byte)
		value = append(value, v...)
		mask = append(mask, m...)
	}
	return value, mask, nil
}

func mapUint(m map[string]any, field string) uint32 {
	v, _ := m[field].(uint32)
	return v
}
