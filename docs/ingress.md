# UpfIngress: GTP-U decapsulation with admission

The ingest side of the G-PDU path is today a pair: an `ExactMatch` on the bare
TEID, then a `GtpuDecap`. This note pins the contract for `UpfIngress`, the
module that replaces the pair with one admission decision, and for the
compiler and graph changes that carry it. Section references are to the pinned
3GPP Release 16 excerpts in `docs/spec/`.

## Why admission is the decap's business now

A TEID is not an address. TS 29.244 8.2.3 puts an F-TEID in the wire as an
address and a tunnel id together, and nothing in it scopes a TEID space to one
interface: two peers' SMFs may plan the same TEID at two different endpoints,
and 5.2.1 does not forbid it -- what makes the tunnels distinct is the
endpoint. The current table keys on the four bytes alone, so a G-PDU that
arrives anywhere this UPF hears is decapsulated whenever its four bytes name a
tunnel, whichever address it was sent to. That is the silent fallback the
design's admission notes refuse, and it is also the reason the admission
table and the decap became one module: the decision the pair makes now needs
to read the outer destination address, which the decap already parsed and
then threw away.

The decision a UPF actually means is: *a G-PDU arriving at an F-TEID this
node published for a PDR, on the endpoint that F-TEID names, in the direction
that PDR serves* -- 5.2.1's session look-up before the PDR look-up. The pair
(address, teid) is the key; the compiler already writes per-session rules for
it (`teid/rules`, one `{gate}` value per tunnel the pair names), and the
has-been-true part of that contract -- the rule's value is a gate, the
table's miss is the responder -- carries into the new module with the key
widened.

## The module

`UpfIngress` is a plugin module in the usual shape (one `BESS_PLUGIN` per
`.so`, `utils/logging.h` before every other BESS header -- docs/plugin-api.md,
"Logging"). It declares the two metadata attributes `GtpuDecap` declared with
the same names, sizes and access modes -- `upf_teid` (4 bytes, write) and
`qfi` (1 byte, write) -- so the uplink tables' keys and the
MetadataTest readers that make the decap's writes real do not move a byte.

Three output gates; the batch path runs per packet, one segment:

| gate | what leaves, and as what |
|---|---|
| 0 | an admitted uplink T-PDU, decapsulated: the inner frame |
| 1 | an admitted downlink T-PDU, decapsulated: the inner frame (mode 2's entry; nothing feeds it yet -- below) |
| 2 | everything that does not admit -- a control message whatever TEID it carries, a T-PDU no rule names -- whole and untouched |

The creation argument (`UpfIngressArg`) is the GTP-U UDP destination port
(2152) and the default gate (2). The admitted batch's per-packet costs are the
parse and one map lookup; the miss path costs the parse alone.

- Linear first segments only. A chained packet cannot be reframed in place
  and the packet path here makes no copy: it drops, as `GtpuDecap` drops it
  today.
- The outer header parse is `bess::tunnel::DecapGtpu` over the frame with the
  configured port: Ethernet, untagged-IPv4 and IPv6 outers, the UDP and the
  GTP-U header, the fragment and length checks (tunnel.h). A parse failure
  drops, as today.
- *The type decides before the lookup.* A G-PDU that is not a T-PDU (type
  255) -- an Echo Request (TS 29.281 7.2.1), an Error Indication the peer
  sends (7.3.1), an End Marker (type 254, the received half of finding E4)
  -- leaves whole on
  the default gate, even when its TEID names a session. This is load-bearing,
  not hygiene: the erir lane injects the peer's Error Indication whose TEID
  names a session's downlink leg, and a table-routed delivery would decap it
  into the downlink chain instead of the responder that reports it. Type
  dispatch first is what keeps that lane's graph contract true.
- A T-PDU whose `(endpoint, teid)` names a rule decapsulates and leaves by
  the record's gate. The rule's value is `{gate: 0|1}` exactly as the
  compiler writes it today; a record naming any other gate is a drop (the
  module does not guess). The decapsulation is `GtpuDecap`'s, byte for byte:
  `adj` past the outer headers, one Ethernet header prepended in the headroom
  they occupied -- the outer frame's own MAC addresses, the inner version's
  EtherType -- a non-IP inner dropped, `upf_teid` and `qfi` written always
  (a packet's metadata is reused mbuf space; `kNoPduSessionQfi` when the
  extension chain carries no PDU Session Container, 8.2.62), the two offsets
  taken through `attr_offset` so a write-only attribute being unallocated
  makes the write the no-op core/metadata.cc:FillOffsetArrays defines.
- A T-PDU with no rule leaves whole on the default gate: the responder
  behind it answers 7.3.1's Error Indication, which is how the peer learns
  the tunnel is gone. There is no decap without a rule -- no fallback, not
  even a warning-shaped one -- and an empty rules table admits nothing,
  which is what a deployment that named no local F-TEID addresses means.

Carried exactly: the miss path reaches the responder whole, which is where
today's table delivers it; the drop paths (non-linear, malformed, no
headroom, non-IP inner) are today's, unchanged. The cases today's pair
handles badly are fixed on the record:

- A control message whose TEID names an *uplink* rule never reaches the
  responder today: the classifier routes it to the decap, whose type filter
  drops anything that is not a T-PDU, and the frame is lost mid-chain. Type
  before lookup delivers it: an echo to a real tunnel gets its reply instead
  of leaving the peer to read the path as dead, and an Error Indication
  arriving at an uplink TEID is recorded where the erir tick reads it.
- A received End Marker is not content: today it decapsulates into a
  garbage inner frame the uplink table has to drop. It goes to the responder
  whole now (which drops it, as it drops every message type it does not
  answer) -- same residue, and the uplink chain never sees the junk. The
  End Marker Reception Report finding E4 builds on the ingress side becomes
  a control message delivered to a module, not a parse to launder: the
  detection point it needs is this module, and it can ride the gate without
  the datapath learning a second frame shape.
- A T-PDU whose TEID names a *downlink* rule is today answered with an
  Error Indication for a tunnel this node owns -- the table's gate 1 leads
  to the responder. Under the contract above it decapsulates into the
  downlink chain, which is the design's N9 entry (the table reads it
  upstream of the pair). No lane feeds a downlink TEID today, so nothing
  tests against the old answer; the enabler for its frames is what modes 2
  and 4 are.

## The rules resource

`<name>/rules`, a `ResourceTable::Map<bess::pb::ExactMatchRuleKey,
bess::pb::ExactMatchRuleValue>` -- the classifier convention's own wire
shapes, which the compiler already writes for the TEID table and the Go
controller already speaks, with `bess::pb::ExactMatchSettings` registered as
the `<name>/settings` singleton for parity (upfd writes it no more today than
it writes the classifier's; the default gate belongs to the module argument).
A rules key carries one `FieldData`: `value_bin`, twenty bytes:

```text
bytes  0..3    the F-TEID address, network order (see below)
bytes  4..15   zero for the IPv4 endpoints the compiler keys today
bytes 16..19   the TEID, big endian
```

The address half is BESS's frame-parse convention -- `conntrack::ParsedFlowPacket.dst`,
the sixteen bytes an IPv4 lives in the first four of and an IPv6 fills -- so
the module reads the lookup key straight out of the parse it already did, and
the compiler writes the key out of the F-TEID address by the same convention.
An IPv6 outer therefore parses and is read exactly once the compiler keys
IPv6 addresses; today the compiler refuses a PDI whose F-TEID is not local
IPv4 (cause 73), and that refusal is unchanged. Admission is exact: no masks
-- the compiler writes values and the module reads values, and a rule that
carried masks would mean neither side of the pair could say what it admitted.

The resource is one; the table has no per-direction instance, because a
G-PDU's admission question is one question and the direction lives in the
record's gate, not in a second table.

## The compiler's claim

`teidRuleKey(p)` takes the PDR, not a bare TEID: it builds the twenty bytes
above out of `c.fteidAddr(p)` and the PDR's `teid`. The claim map
`c.byTEID` becomes keyed by the pair -- two sessions may own the same TEID
at two endpoints, and the "TEID in use, session SEID" refusal fires when the
same endpoint is claimed twice. The `c.teids` allocator keeps its one
namespace in this commit: a CHOOSE TEID is unique by construction, an
SMF-specified TEID is reserved out of CHOOSE's range globally, and endpoint
scoping is what makes a peer's planned reuse across endpoints legal --
per-address allocator namespaces are the later cut, wanted only when a
deployment needs CHOOSE numbering to reuse a TEID across endpoints it
actually serves. The session-establishment, modification and startup-sweep
writes and erases for `teid/rules` all go through the helper, so they travel
with the key shape; the CreatedPDR's F-TEID reporting and the responder's
roles are untouched, and the uplink field list is untouched with them: the
admission key lives in the ingress module, and the uplink PDR key keeps its
table.

## Graphs and flags

The seven session graphs (`upf`, `session-path`, `session-live`,
`buffer-path`, `route-path`, `iface-path`, `session-instances`) swap
`[teid -> decap0]` for one `ingress` module: gate 0 to the uplink chain
(where `decap0` led), gate 1 to `pdr_dl` -- the design's N9-downlink entry,
a decapsulated core-side frame reclassifying by the downlink table before
its re-encap -- and gate 2 to the GTP-U responder. No lane feeds gate 1
today: the modes that will are 2 and 4, and every one of these graphs keys
its downlink on packet offsets only, so the new producer carries no metadata
claim a second path needs written. `veth-port` keeps the ExactMatch pair
until the multi-domain work: its downlink key reads `route_domain`, an
attribute written only on the Vif path today, so its gate 1 cannot be wired
honest until that question is settled. `smoke-gtpu` keeps
`ExactMatch + GtpuDecap`: it is the datapath's smoke, its rules written raw
by `ci/smoke-gtpu.sh`, and it is the place the classifier conventions stay
proven.

upfd renames `-teid-table` to `-ingress` (`Config.Ingress`), for the module
whose `rules` the compiler claims; `ruleHome()`'s per-direction mapping is
untouched. The erir lane's own test comment -- "ingress gate 2 delivering it
to a responder" -- has been describing where the frame goes since before the
wiring could; after the swap the graph carries what it says.

## What this commit does not decide

Endpoint scoping stops at the address in this cut: igate, VLAN and
destination-MAC discrimination ride with the multi-port work, where a G-PDU
can arrive on an interface whose claim the address half alone cannot
certify. The downlink admission gate is wired but unexercised -- its lanes
arrive with modes 2 and 4. Outbound tunnels are untouched by all of it:
what this node sends the *peer* lives in the encap's records, not in
admission rows.

## Evidence

- The module unit test (the datapath's first test target) exercises the
  decision headless: the dispatch (type before lookup, including an EI and
  an End Marker to a session-known TEID), the admission (endpoint and teid
  keying, hit/miss), and the address-half convention the compiler and the
  parse must agree on.
- The compiler tests: two sessions' equal TEIDs at different endpoints claim
  and coexist; the same endpoint twice refuses with cause; an SMF-specified
  TEID outside CHOOSE's range lands as the rule it names.
- `go test ./cmd/... ./internal/...`, `ninja -C datapath/build`, the lane
  scripts (`ci/session-*.sh`, `ci/interop`) for the swapped graphs -- the
  erir lane's responder delivery, the two-instance lane's two-tunnel
  disambiguation, and the live sessions' uplink carry, each through an
  `ingress` module on their own rules resource.
