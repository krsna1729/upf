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

type sessionEntryWrite uint8

const (
	replaceSessionEntry sessionEntryWrite = iota
	keepSessionEntry
)

// apply writes a compiled model, including its immutable entry decision.
// A fold refusal is definite (nothing was sent).
func (c *Compiler) apply(ctx context.Context, s *Session, write modelWrite) (result error) {
	changes := write.resources
	// Pair every successful compile with completion, even a local fold
	// refusal or a resource-neutral modification. Overlap makes the base
	// uncertain until a later isolated full write completes.
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		s.inflight--
		if result != nil {
			s.rewrite = true
		} else if !s.overlap {
			s.rewrite = false
		}
		if s.inflight == 0 {
			s.overlap = false
		}
	}()
	if _, ok := c.target.(sessionTarget); ok {
		folded, err := c.foldSession(s, changes, write.entry)
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
		s.sessionLive = true
		c.mu.Unlock()
	}
	return err
}

// foldSession folds full records into a replacement entry, drops entry-owned
// deltas when the resolved entry is unchanged, or erases the entry. The mode
// belongs to this compile: concurrent enforcement cannot turn an empty,
// resource-neutral plan into an empty replacement entry.
func (c *Compiler) foldSession(s *Session, changes []bess.Change, mode sessionEntryWrite) ([]bess.Change, error) {
	if mode == keepSessionEntry && len(changes) == 0 {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.foldSessionLocked(s, changes, mode)
}

// foldSessionLocked is foldSession for a caller holding the lock.
func (c *Compiler) foldSessionLocked(s *Session, changes []bess.Change, mode sessionEntryWrite) ([]bess.Change, error) {
	if mode == keepSessionEntry && len(changes) == 0 {
		return nil, nil
	}
	mine := map[string]Table{}
	for _, t := range sessionTables {
		mine[c.res(t)] = t
	}
	sessionsRes := c.cfg.Appliance + "/sessions"
	// Reserve the first slot for the session entry, ahead of its policies.
	out := make([]bess.Change, 1, len(changes)+1)
	for _, ch := range changes {
		if _, ok := mine[ch.Resource]; ok {
			continue
		}
		out = append(out, ch)
	}
	if mode == keepSessionEntry {
		return out[1:], nil
	}
	value, positions, err := c.sessionValue(s, changes, mine)
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
		v, ok := bess.Get[PolicyEntry](ch.Value)
		if !ok {
			return nil, fmt.Errorf("invalid typed policy entry for %s", ch.Resource)
		}
		v.Access = slices.Clone(v.Access)
		for j, a := range v.Access {
			if id := a.TunnelID; id != 0 {
				pos, ok := positions[id]
				if !ok {
					return nil, fmt.Errorf("%w: an ATSSS access names tunnel %d, which the session does not hold", errNotExpressible, id)
				}
				v.Access[j].TunnelID = uint32(pos)
			}
		}
		out[i].Value = bess.Fields(v)
	}
	// The entry first: a policy's tunnels are positions in it.
	out[0] = bess.Change{Resource: sessionsRes,
		Key: bess.Fields(SessionKey{SessionID: s.sessionID}), Value: bess.Fields(value)}
	return out, nil
}

// sessionValue is the UpfSession the session's appliance writes make, and the
// 1-based position of each action id in it. The caller holds the lock.
func (c *Compiler) sessionValue(s *Session, writes []bess.Change, mine map[string]Table) (SessionEntry, map[uint32]int, error) {
	var fteids, rules []bess.Change
	meters := map[uint32]MeterEntry{}
	tunnels := map[uint32]TunnelEntry{}
	counted := map[uint32]bool{}
	for _, ch := range writes {
		t, ok := mine[ch.Resource]
		if !ok || ch.Value == nil {
			continue
		}
		switch t {
		case FTEIDs:
			fteids = append(fteids, ch)
		case PDRUplink, PDRDownlink:
			rules = append(rules, ch)
		case MetersUplink:
			key, _ := bess.Get[IDKey](ch.Key)
			value, _ := bess.Get[MeterEntry](ch.Value)
			meters[key.ID] = value
		case CountersUplink, CountersDownlink:
			key, _ := bess.Get[ActionKey](ch.Key)
			counted[key.ActionID] = true
		case TunnelsUplink:
			key, _ := bess.Get[ActionKey](ch.Key)
			value, _ := bess.Get[TunnelEntry](ch.Value)
			tunnels[key.ActionID] = value
		}
	}
	// A dropping rule's result is empty; its PDR says which action it is,
	// and a measured one keeps that action (and so its URR cells) in the
	// entry, as the masked layout keeps its counter entry.
	owners := map[string]*pdr{}
	for _, p := range s.PDRs().all() {
		if !p.drop || p.buffer || !counted[p.actionID] {
			continue
		}
		keys, err := c.pdrRuleKeys(p)
		if err != nil {
			return SessionEntry{}, nil, fmt.Errorf("PDR %d: %w", p.id, err)
		}
		for _, key := range keys {
			owners[c.res(pdrTable(p.downlink()))+"\x00"+ruleID(key)] = p
		}
	}

	// Every meter the session writes is one of its QERs, in id order, named
	// or not: a QER whose rules drop for a while keeps its buckets, as its
	// meter entry does in the masked layout.
	qers := make([]SessionQER, 0, len(meters))
	qerAt := map[uint32]int{}
	for _, id := range slices.Sorted(maps.Keys(meters)) {
		q := SessionQER{QERID: id, TrTCM: meters[id].TrTCM}
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

	actions := []SessionAction{}
	at := map[uint32]int{}
	action := func(id uint32) *SessionAction {
		if pos, ok := at[id]; ok {
			return &actions[pos-1]
		}
		a := SessionAction{ActionID: id, Count: counted[id]}
		if t, ok := tunnels[id]; ok {
			a.Tunnel = &t
		}
		actions = append(actions, a)
		at[id] = len(actions)
		return &actions[len(actions)-1]
	}

	pdrs := make([]SessionPDR, 0, len(rules))
	for _, ch := range rules {
		down := mine[ch.Resource] == PDRDownlink
		key, _ := bess.Get[RuleKey](ch.Key)
		entry, _ := bess.Get[RuleEntry](ch.Value)
		value, mask, err := packedKey(key)
		if err != nil {
			return SessionEntry{}, nil, err
		}
		rule := SessionPDR{Downlink: down, Value: value, Mask: mask, Priority: entry.Priority, Gate: entry.Gate, Ranges: key.Ranges}
		result := entry.Result
		id := uint32(0)
		if len(result) >= resultSize {
			id = binary.BigEndian.Uint32(result[resultActionID:])
		}
		if id != 0 {
			a := action(id)
			nextHop := binary.BigEndian.Uint32(result[resultNextHopID:])
			a.NextHopID = &nextHop
			domain := binary.BigEndian.Uint32(result[resultRouteDomain:])
			a.RouteDomain = &domain
			if down && len(result) >= resultSteeringID+4 {
				policy := binary.BigEndian.Uint32(result[resultSteeringID:])
				a.SteeringPolicyID = &policy
			}
			for i, field := range []**uint32{&a.PDRQER, &a.SessionQER} {
				pos, err := qer(binary.BigEndian.Uint32(result[resultMeterID+4*i:]))
				if err != nil {
					return SessionEntry{}, nil, err
				}
				position := uint32(pos)
				*field = &position
			}
		} else if p := owners[ch.Resource+"\x00"+ruleID(key)]; p != nil && counted[p.actionID] {
			id = p.actionID
			action(id)
		}
		if id != 0 {
			rule.Action = uint32(at[id])
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
		return SessionEntry{}, nil, fmt.Errorf("%w: the session needs %d actions and %d QER meters; the module holds %d and %d per session (-session-actions, -session-qers)",
			errNotExpressible, len(actions), len(qers), layout.Actions, layout.QERs)
	}
	entries := make([]SessionFTEID, 0, len(fteids))
	for _, ch := range fteids {
		key, _ := bess.Get[FTEIDKey](ch.Key)
		entry, _ := bess.Get[FTEIDEntry](ch.Value)
		entries = append(entries, SessionFTEID{Key: key, Entry: entry})
	}
	return SessionEntry{FTEIDs: entries, QERs: qers, Actions: actions, PDRs: pdrs}, at, nil
}

// packedKey is a WildcardMatch rule key's values and masks as the session
// entry's packed bytes, in the table's field order.
func packedKey(key RuleKey) ([]byte, []byte, error) {
	values, masks := key.Values, key.Masks
	if len(values) != len(masks) {
		return nil, nil, fmt.Errorf("a rule key with %d values and %d masks", len(values), len(masks))
	}
	n := 0
	for _, v := range values {
		n += len(v)
	}
	value, mask := make([]byte, 0, n), make([]byte, 0, n)
	for i := range values {
		value = append(value, values[i]...)
		mask = append(mask, masks[i]...)
	}
	return value, mask, nil
}
