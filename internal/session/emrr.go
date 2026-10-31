// SPDX-License-Identifier: BSD-3-Clause
// Received End Markers (TS 29.281 7.3.2). An End Marker from the old I-UPF or
// PSA arrives on N3/N9 on one of this UPF's own local F-TEIDs. `GtpuDecap`
// relays it in the packet path through the tunnels its F-TEID entry names
// (endMarkerRelays, written with the entry), and sends it on through gate 2
// to the GTP-U responder, which records it with the endpoint it came in on
// (datapath/gtpu_responder.cc, "drain_end_markers"). This side drains that
// log once per tick (Config.GTPUEndMarkers) and reports each End Marker as a
// Usage Report with EMRRE (TS 29.244 8.2.19 REEMR, 8.2.41 EMRRE) for every
// REEMR URR a PDR on that F-TEID names.
package session

import (
	"net/netip"
	"slices"
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

// endMarkerRelays is the end_marker_relays of the session's admission entry
// for the F-TEID (endpoint, teid): every distinct GTP-U tunnel a PDR on that
// F-TEID forwards into -- an I-UPF's transit tunnel, or an indirect data
// forwarding tunnel. TS 29.244 Table 8.2.64-1 NOTE 2 has the I-UPF keep the
// message type of a GTP-U signalling message it forwards, and TS 23.502
// 4.9.1.3.3 step 10b has the PSA's End Markers reach the target RAN through
// the forwarding tunnels.
//
// A relay is the tunnel this UPF's encap writes for the PDR: the FAR's
// outgoing TEID toward its peer, from the tunnel's local address, routed in
// its transport domain. The decap sends one End Marker per relay in the batch
// the received one arrived in, behind the G-PDUs that preceded it. A PDR whose
// FAR adds no outer header (N6, 5G VN Internal), drops, buffers or names a MAR
// relays nothing; the arrival is still reported. The caller holds the lock.
func endMarkerRelays(s *Session, endpoint, teid uint32) []map[string]any {
	type tunnel struct {
		teid        uint32
		local, peer netip.Addr
		domain      uint32
	}
	var seen []tunnel
	var relays []map[string]any
	for _, p := range pdrsInOrder(s) {
		// The tunnel's local end is resolved only for a PDR whose FAR
		// forwards with an Outer Header Creation (resolve).
		if p.endpointID != endpoint || p.teid != teid || p.hasMAR ||
			!p.tunnelLocalAddress.IsValid() || p.transportRouteDomain == 0 {
			continue
		}
		f := s.FARs[p.farID]
		if f == nil || !f.hasOuter || f.teid == 0 {
			continue
		}
		t := tunnel{teid: f.teid, local: p.tunnelLocalAddress, peer: f.peer, domain: p.transportRouteDomain}
		if slices.Contains(seen, t) {
			continue
		}
		seen = append(seen, t)
		relays = append(relays, map[string]any{
			"teid": t.teid, "local_address": t.local.AsSlice(), "peer_address": t.peer.AsSlice(),
			"transport_route_domain": t.domain,
		})
	}
	return relays
}
