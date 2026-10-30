// SPDX-License-Identifier: BSD-3-Clause
// Received End Markers (TS 29.281 7.3.2). An End Marker from the old I-UPF or
// PSA arrives on N3/N9 on one of this UPF's own local F-TEIDs and reaches the
// GTP-U responder through `GtpuDecap` gate 2, which records it with the
// endpoint it came in on (datapath/gtpu_responder.cc, "drain_end_markers").
// This side drains that log once per tick (Config.GTPUEndMarkers) and does two
// things with each event: relays it through the GTP-U tunnel the F-TEID's PDR
// forwards into, and reports it as a Usage Report with EMRRE (TS 29.244 8.2.19
// REEMR, 8.2.41 EMRRE) for every REEMR URR a PDR on that F-TEID names.
package session

import (
	"slices"

	"github.com/krsna1729/upf/internal/bess"
)

// endMarkerKey is where an End Marker arrived: the logical endpoint and this
// UPF's local TEID on it. A TEID is unique per endpoint, not across them, so
// the endpoint is part of the key exactly as it is of the admission key.
type endMarkerKey struct {
	endpoint uint32
	teid     uint32
}

// endMarkerArrived says an End Marker arrived since the last tick on the local
// F-TEID of a PDR that URR uid measures, when that URR asks for REEMR. The
// caller holds the lock.
func endMarkerArrived(s *Session, uid uint32, markers map[endMarkerKey]bool) bool {
	if len(markers) == 0 || !s.URRs[uid].onEndMarker {
		return false
	}
	for _, p := range pdrsInOrder(s) {
		if p.teid == 0 || p.endpointID == 0 || !slices.Contains(p.urrIDs, uid) {
			continue
		}
		if markers[endMarkerKey{endpoint: p.endpointID, teid: p.teid}] {
			return true
		}
	}
	return false
}

// relayEndMarkers sends each End Marker that arrived on a PDR's local F-TEID
// on through the GTP-U tunnel that PDR's FAR forwards into: an I-UPF's
// transit tunnel, or an indirect data forwarding tunnel. TS 29.244 Table
// 8.2.64-1 NOTE 2 has the I-UPF keep the message type of a GTP-U signalling
// message it forwards, and TS 23.502 4.9.1.3.3 step 10b has the PSA's End
// Markers reach the target RAN through the forwarding tunnels.
//
// The relayed marker is the one this UPF sends on that tunnel itself
// (endMarkerFrame): the FAR's outgoing TEID toward its peer, from the
// tunnel's local address, through its transport's port. Each arrival is
// relayed once per distinct tunnel. A PDR whose FAR adds no outer header (N6,
// 5G VN Internal), drops or buffers relays nothing; the arrival is still
// reported. The relay is as late as the tick that drains the log, never ahead
// of the G-PDUs that preceded the marker on its tunnel: those were forwarded
// when they arrived.
func (c *Compiler) relayEndMarkers(arrived []bess.EndMarker) {
	if !c.endMarkersConfigured() {
		return
	}
	for _, m := range arrived {
		for _, tunnel := range c.relayTunnels(endMarkerKey{endpoint: m.EndpointID, teid: m.TEID}) {
			if err := c.sendTunnelEndMarker(tunnel); err != nil {
				c.stats.markerFailures.Add(1)
				c.log.Warn("session: an end marker was not relayed", "endpoint", m.EndpointID,
					"teid", m.TEID, "tunnel_teid", tunnel.teid, "error", err)
				continue
			}
			c.stats.markers.Add(1)
		}
	}
}

// relayTunnels is every distinct GTP-U tunnel a PDR on the local F-TEID at
// forwards into, as the session holds it now. The F-TEID's admission keys
// name the one session that owns it.
func (c *Compiler) relayTunnels(at endMarkerKey) []tunnelEndMarker {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []tunnelEndMarker
	var owners []*Session
	for key := range c.fteidTEIDKeys[at.teid] {
		s := c.byFTEID[key].session
		if s == nil || slices.Contains(owners, s) {
			continue
		}
		owners = append(owners, s)
		for _, p := range pdrsInOrder(s) {
			// The tunnel's local end is resolved only for a PDR whose FAR
			// forwards with an Outer Header Creation (resolve).
			if p.endpointID != at.endpoint || p.teid != at.teid || p.hasMAR ||
				!p.tunnelLocalAddress.IsValid() || p.transportRouteDomain == 0 {
				continue
			}
			f := s.FARs[p.farID]
			if f == nil || !f.hasOuter || f.teid == 0 {
				continue
			}
			if slices.ContainsFunc(out, func(t tunnelEndMarker) bool {
				return t.teid == f.teid && t.peer == f.peer && t.localAddress == p.tunnelLocalAddress &&
					t.transportRouteDomain == p.transportRouteDomain
			}) {
				continue
			}
			out = append(out, tunnelEndMarker{
				far: *f, localAddress: p.tunnelLocalAddress, transportRouteDomain: p.transportRouteDomain,
			})
		}
	}
	return out
}
