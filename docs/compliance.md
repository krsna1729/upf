# Interface conformance

This page records what this UPF does with the two interface values a PFCP rule
names, and with the subscriber's ARP identity. It is the operational reading of
`internal/session/compile.go`; `docs/claims.json` is the machine-checked
contract and names the tests.

Causes are PFCP causes: **66** is "mandatory IE missing", **73** is "rule
creation/modification failure", **75** is "no resources available".

## Source Interface (TS 29.244 8.2.2, Table 8.2.2-1)

The PDI's Source Interface decides which chain a PDR joins. `downSide` is
`srcIfc != Access`: Access is the uplink, every other accepted value is the
downlink.

| Value | Name | What this UPF does |
|---|---|---|
| 0 | Access | Uplink chain (`pdr_ul` or the deployment's matcher). The F-TEID is the session key; an Access PDI that names an F-TEID with TEID 0 is refused. |
| 1 | Core | Downlink chain (`pdr_dl`). The downlink table matches the inner packet after the N6 ingress; a Core PDI is not given a tunnel key. |
| 2 | SGi-LAN/N6-LAN | Downlink chain. The value does not choose an egress by itself: the FAR's Destination Interface does. |
| 3 | CP-function | Refused, cause 73. No user-plane packet is sent on the CP function's path. |
| 4 | LI function | Refused, cause 73. Interception is not implemented. |
| 5 | 5G VN internal | Downlink chain. This is where a packet re-injected by a FAR (Destination Interface 5) re-enters the subscriber side. |
| 6..15 | Spare | Refused, cause 73. |

An absent Source Interface IE is read as 0 (Access). Table 8.2.2-1 makes the IE
mandatory; this is a lenient default, not a claim of conformance. A deployment
that needs the strict reading should refuse the PDI instead of defaulting it.

The source side also chooses the direction's resources: an Access PDR claims
the uplink's matcher, meter, counter and tunnel module; a non-Access PDR claims
the downlink's.

## Destination Interface (TS 29.244 8.2.24, Table 8.2.24-1)

The FAR's Destination Interface, together with whether the FAR carries an Outer
Header Creation, is the key of the deployment's egress table
(`internal/routing.Interface.Hops`). With `-instances`, a deployment declares
`next-hop=`, `tunnel-next-hop=`, `sgi-lan-next-hop=`, `vn-next-hop=` and
`-access-next-hop`; without `-instances`, the single-instance deployment falls
back to the direction's own hop for the values it has always served.

| Value | Name | What this UPF does | Refusal |
|---|---|---|---|
| 0 | Access | Downlink encap, or the access-side hop (`-access-next-hop`, else the downlink direction's hop). A FAR that adds an outer header here is indirect data forwarding (8.2.2 NOTE 2): it needs a tunnel record (`-tunnels-ul` on an uplink PDR, `-tunnels` on a downlink one). | Cause 73 if the tunnel module is unset. |
| 1 | Core | Plain IP: the instance's own next hop, or the declared `next-hop=`. With an Outer Header Creation: the instance's `tunnel-next-hop=`, i.e. N9 or an indirect tunnel. | Cause 73 if the instance declares no such egress, or the tunnel module is unset. |
| 2 | SGi-LAN/N6-LAN | The instance's `sgi-lan-next-hop=` (plain or tunneled by the same key's `Tunnel` bit). The Forwarding Policy IE is mandatory toward this value (Table 7.5.2.3-2). | Cause 66 if the Forwarding Policy is absent; cause 73 if the deployment declares no service-LAN egress. |
| 3 | CP-function | Not served. | Cause 73. |
| 4 | LI function | Not served; an X3 copy is a duplication action, not this forward. | Cause 73. |
| 5 | 5G VN internal | Re-injection into the subscriber side; the instance's `vn-next-hop=`. An outer header is refused: this is the UPF's own chain, not a tunnel. | Cause 73 for a missing egress or an outer header. |
| 6..15 | Spare | Not served. | Cause 73. |

A FAR whose Apply Action forwards must carry Forwarding Parameters (Table
7.5.2.3-1) and a Destination Interface (Table 7.5.2.3-2); either omission is
cause 66. An Update FAR carries only what changes, so the check is made on the
merged FAR, not on the message's own IEs.

Destination Interface 1 with an Outer Header Creation, and Destination Interface
0 with one, are the two indirect-forwarding shapes (8.2.2 NOTE 2, 8.2.24
NOTE 3): the packets leave this UPF in a tunnel toward another UPF or a target
gNB, and the tunnel's parameters are per-session records in the encap module,
not fields of the rule.

## The subscriber's ARP answer

An N6 segment is Ethernet: before a downlink packet addressed to a UE can be
sent, the next hop asks ARP who holds the UE's address. The SMF provisions that
address, and this UPF is what it is reachable through, so the answer must be
this UPF's.

| Item | Behaviour |
|---|---|
| Configuration | Per network instance: `arp=<module>` and `arp-mac=<MAC>` in `-instances`. The MAC is the interface's own, not the UE's. |
| Resources | One `<module>/entries` entry per session per subscriber IPv4 address (`{"ip": ..., "mac_addr": ...}`). |
| Claims | The entry is a compiler claim, like a rule key: two sessions cannot answer for the same address on one interface; the second is refused with cause 73. |
| Lifecycle | The entry is written when a subscriber-side PDR names the address and erased when that PDR or the session goes. A session with downlink PDRs on two instances answers on both. |
| IPv6 | No entry is written for an IPv6 address; no ND responder is implemented. |
| Placement | `UpfArpResponder` answers ARP on gate 0 and passes IPv4 on `ip_gate`; it must sit on N6 ingress before the Vif (`deploy/upf.yaml`, `ci/iface-path.sh`). Other packet types are dropped. |

TS 23.501 6.2.3 makes the ARP/ND responder a UPF function for Ethernet PDU
sessions. For IP PDU sessions this is not an SMF-visible function at all: it is
the deployment's N6 reachability duty. A segment that never learns the UE's MAC
drops the downlink before the packet reaches this UPF, whatever the PFCP rules
say.

## Related documents

- `docs/router.md` — the Router's inventory, and the routing gaps (route
  programming, connected routes, neighbour resolution).
- `docs/datapath.md` — the modules, the graphs and the lanes.
- `docs/claims.json` — the cited evidence for each row above.
