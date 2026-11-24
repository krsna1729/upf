// SPDX-License-Identifier: BSD-3-Clause

package session

// Resource payloads mirror runtime message fields without retaining a map per record.
type ActionKey struct {
	ActionID uint32 `json:"action_id"`
}
type IDKey struct {
	ID uint32 `json:"id"`
}
type PolicyKey struct {
	PolicyID uint32 `json:"policy_id"`
}
type SessionKey struct {
	SessionID uint32 `json:"session_id"`
}
type ARPKey struct {
	IP string `json:"ip"`
}
type ARPEntry struct {
	MACAddr string `json:"mac_addr"`
}
type RuleRange struct {
	Field uint32 `json:"field"`
	Low   uint64 `json:"low"`
	High  uint64 `json:"high"`
}
type RuleKey struct {
	Values [][]byte    `json:"values"`
	Masks  [][]byte    `json:"masks"`
	Ranges []RuleRange `json:"ranges,omitempty"`
}
type RuleEntry struct {
	Priority int64  `json:"priority"`
	Gate     uint64 `json:"gate"`
	Result   []byte `json:"result"`
}
type FTEIDEntry struct {
	Direction       uint32        `json:"direction"`
	ContextID       uint32        `json:"context_id"`
	EndMarkerRelays []RelayTunnel `json:"end_marker_relays,omitempty"`
}
type RelayTunnel struct {
	TEID                 uint32 `json:"teid"`
	LocalAddress         []byte `json:"local_address"`
	PeerAddress          []byte `json:"peer_address"`
	TransportRouteDomain uint32 `json:"transport_route_domain"`
}
type TunnelEntry struct {
	TEID                 uint32  `json:"teid"`
	LocalAddress         []byte  `json:"local_address"`
	PeerAddress          []byte  `json:"peer_address"`
	TransportRouteDomain uint32  `json:"transport_route_domain"`
	QFI                  *uint32 `json:"qfi,omitempty"`
	QFIPresent           bool    `json:"qfi_present,omitempty"`
	Marking              *uint32 `json:"marking,omitempty"`
}
type FlowEntry struct {
	TimeoutNS         *uint64 `json:"timeout_ns,omitempty"`
	MaxPacketsPerFlow *uint32 `json:"max_packets_per_flow,omitempty"`
}
type MeterProfile struct {
	CommittedRate  uint64 `json:"committed_rate"`
	CommittedBurst uint64 `json:"committed_burst"`
	PeakRate       uint64 `json:"peak_rate"`
	PeakBurst      uint64 `json:"peak_burst"`
}
type MeterEntry struct {
	TrTCM MeterProfile `json:"tr_tcm"`
}

// PacketRateEntry is one QER direction's packet-rate quota (TS 29.244 8.2.63,
// 8.2.139) as the PacketRate module's value: packets per period, the
// additional packet allowance and its own period, and the seed the CP
// function last enforced.
type PacketRateEntry struct {
	Allowed                 uint32 `json:"allowed,omitempty"`
	PeriodSeconds           uint32 `json:"period_seconds,omitempty"`
	Additional              uint32 `json:"additional,omitempty"`
	AdditionalPeriodSeconds uint32 `json:"additional_period_seconds,omitempty"`
	Epoch                   uint64 `json:"epoch,omitempty"`
	SeedRemaining           uint32 `json:"seed_remaining,omitempty"`
	SeedRemainingAdditional uint32 `json:"seed_remaining_additional,omitempty"`
	SeedValidityUnixNS      uint64 `json:"seed_validity_unix_ns,omitempty"`
}
type PolicyAccess struct {
	NextHopID    uint32 `json:"next_hop_id"`
	TunnelID     uint32 `json:"tunnel_id"`
	AccountingID uint32 `json:"accounting_id"`
	HealthID     uint32 `json:"health_id"`
}
type PolicyEntry struct {
	Mode      uint32         `json:"mode"`
	Preferred uint32         `json:"preferred"`
	Access    []PolicyAccess `json:"access"`
}

type SessionFTEID struct {
	Key   FTEIDKey   `json:"key"`
	Entry FTEIDEntry `json:"entry"`
}
type SessionQER struct {
	QERID uint32       `json:"qer_id"`
	TrTCM MeterProfile `json:"tr_tcm"`
}
type SessionAction struct {
	ActionID         uint32       `json:"action_id"`
	Count            bool         `json:"count"`
	Tunnel           *TunnelEntry `json:"tunnel,omitempty"`
	NextHopID        *uint32      `json:"next_hop_id,omitempty"`
	RouteDomain      *uint32      `json:"route_domain,omitempty"`
	SteeringPolicyID *uint32      `json:"steering_policy_id,omitempty"`
	PDRQER           *uint32      `json:"pdr_qer,omitempty"`
	SessionQER       *uint32      `json:"session_qer,omitempty"`
}
type SessionPDR struct {
	Downlink bool        `json:"downlink"`
	Value    []byte      `json:"value"`
	Mask     []byte      `json:"mask"`
	Priority int64       `json:"priority"`
	Gate     uint64      `json:"gate"`
	Ranges   []RuleRange `json:"ranges,omitempty"`
	Action   uint32      `json:"action,omitempty"`
}
type SessionEntry struct {
	FTEIDs  []SessionFTEID  `json:"fteids"`
	QERs    []SessionQER    `json:"qers"`
	Actions []SessionAction `json:"actions"`
	PDRs    []SessionPDR    `json:"pdrs"`
}
