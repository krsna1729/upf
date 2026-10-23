// SPDX-License-Identifier: BSD-3-Clause
// End Marker Reception Reports (TS 29.244 8.2.19 REEMR, 8.2.41 EMRRE). An End
// Marker from the old I-UPF arrives on N3/N9 on one of this UPF's own local
// F-TEIDs and reaches the GTP-U responder through `GtpuDecap` gate 2, which
// records it with the endpoint it came in on (datapath/gtpu_responder.cc,
// "drain_end_markers"). This side drains that log once per tick
// (Config.GTPUEndMarkers) and reports each End Marker as a Usage Report with
// EMRRE for every REEMR URR a PDR on that F-TEID names.
package session

import "slices"

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
