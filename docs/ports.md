# Ports

How a UPF graph gets its ports, what the port exposes to the graph, and what is
proven about it where. `docs/design.md`'s port section ("N3, N6, N9: one port,
three interfaces") is the argument; this file is the surface: the manifest
fields, the drivers in use, the queue model, and the recipe for the one port
this repo can measure without a NIC.

## A port is declared in the manifest, not on the command line

`bessd` has no DPDK-args passthrough: it builds its own EAL argv
(`core/runtime/dpdk.cc`), and a port a manifest declares is hot-plugged by
`rte_dev_probe` (`core/drivers/pmd.cc`). So a port is a graph's business:

```yaml
ports:
  - name: n3                      # the name the graph uses: PortInc/PortOut/
    driver: PMDPort               #   QueueInc/QueueOut name this, not the
    num_rx_queues: 1              #   driver's device
    num_tx_queues: 1
    arg: {port_id: 0}             # or {vdev: "..."} for a software device
```

- `name` is the manifest's; the driver's device is named by `arg` (`port_id`
  for a bound PCI device, `vdev` for a software PMD such as `net_af_packet`).
- `num_rx_queues`/`num_tx_queues` are what the graph gets. For a PMD the
  *device's* queue count is the driver's (`net_af_packet`'s comes from
  `qpairs=` in the vdev string, **not** from the veth's `numrxqueues`), so the
  two are stated separately and checked separately.
- `driver: PMDPort` takes a DPDK device; `driver: UnixSocketPort` is the
  control plane's End Marker socket (no PMD, no NIC); the deployment
  (`deploy/upf.yaml`) uses both.

`deploy/upf.yaml` binds two PMD ports (N3, N6) bound with `dpdk-devbind` before
`bessd` starts; `deploy/veth-port.yaml` is the same declaration over a software
device, which is what this repo can run on a host with no NIC to spare.

## Queues: one task per qid, and the workers start paused

`Num_rx_queues` receive queues are read by `num_rx_queues` `QueueInc` modules,
one per `qid`, each its own task; the transmit side is `QueueOut` per `qid` (or
`PortOut`, which uses queue 0). `PortInc` is the single-queue shorthand.

Two things about this tree that bite an arm:

- **`bessctl resume` is mandatory.** The workers a pipeline creates start
  paused, so a port's rx counter stands at 0 while the interface's own kernel
  counters climb: the frames are in the ring, not in the datapath.
- **The kernel buffers what arrived before the PMD started.** Frames that
  reached the interface before the port was probing are read later, so a
  counter read immediately after `resume` is not yet "this run's traffic".

RSS and one worker per queue are the scale path (`docs/design.md`, the
placement policy; BESS `docs/decisions.md` D-097), and `docs/compliance.md`'s
multi-queue row points here for it.

## One port, three interfaces

The UPF's three reference points are IP-level interfaces, so one port can carry
all three: a `Vif` (`core/modules/vif.{h,cc}`) matches a frame by `(VLAN,
destination MAC)` -- and answers ARP for an interface's address -- and sends it
out that interface's output gate, writing `vif_id` and `route_domain` into the
packet's metadata on the way. The three interfaces are the manifest's, each
with its own MAC, address, route domain and gate.

Two facts a graph must respect:

- **A metadata attribute with no reader gets no offset at all**
  (`core/metadata.cc`, `FillOffsetArrays`), and the `Vif` writes `route_domain`
  only when *both* of its attributes have one (`vif.cc`'s `write_metadata`
  guard). A graph that wants the domain must therefore have a module that reads
  it -- a PDR table declaring `{attr_name: route_domain, num_bytes: 4}` among
  its `fields` does -- and, because the guard covers `vif_id` too, a reader for
  that as well.
- **A router's domains are created eagerly.** `Router` builds every domain's FIB
  in `Init` (`router.cc`'s `CreateDomain` loop), and on this box a `max_domains`
  in the tens fails to build ("route table is full"). A deployment's domain ids
  are small and `max_domains` is just above them; `upfd -max-domains` must
  agree with the graph's.

## What is proven where

**On a veth (`ci/veth-port.sh`, `deploy/veth-port.yaml`; no NIC needed).** The
arm declares one PMD port over a kernel veth (`net_af_packet0`, `qpairs=4`,
`fanout_mode=hash`) with four `QueueInc`s into a three-interface `Vif`
(N3/N6/N9, each with its own address and route domain), applies the graph,
resumes, sends real frames from the peer end, and checks:

| what | how it is checked |
|---|---|
| the port's queue count | `bessctl status` (runtime PortInfo) **and** the active pipeline (`bessctl get -o json`), **and** DPDK's own device telemetry (`/ethdev/info`): four rx/tx queues, all four started |
| real L2 | a frame addressed to an interface's MAC crosses the veth, is read by the port and lands on that interface's gate -- the three gates' counts are exactly the frames sent |
| the vif split with route domains | the domain the port wrote is what the compiler's (`upfd`, over N4) downlink rule is keyed on, and the frame carrying it is selected by that rule and crosses the chain to the encap -- the same frame with no rule yet written is dropped |
| the per-queue spread | `fanout_mode=hash` places a flow on one queue; all four `QueueInc`s move under many flows |

The kernel side of the recipe is part of the arm: the veth is created with
`numrxqueues`/`numtxqueues` (four each) if it is not already there, given an
address on one end so frames have a source, and sent to with **permanent
neighbours** -- the host treats an address local to an interface as its own and
routes it to `lo`, so a ping to the port's own address never leaves the host;
the destinations must be non-local with a neighbour entry naming the interface
MAC the frame should carry. IPv6 on both ends is turned off before they come up
(duplicate address detection and router solicitations are multicast and land on
the `Vif`'s default gate), and the pair is deleted when the run ends.

**On a NIC (not reproducible on a veth).** The placement measurement
`docs/design.md` describes needs a device with an RSS engine: the af_packet PMD
advertises none (`ethdev_rss_hf=0x0`, no hash key, no RETA, no per-queue hash
function), so `RTE_ETH_RSS_LEVEL_INNERMOST` with `L3_SRC_ONLY`/`L3_DST_ONLY`
(as a per-pattern `rte_flow` RSS action, since the two L3 bits are mutually
exclusive in one `rss_hf`) cannot be configured on it, let alone measured at
line rate. On a veth the flows are spread by the kernel's AF_PACKET fanout
hash, which is a flow-to-queue placement but not a NIC's. What a NIC is also
needed for, and what a veth cannot show: driver offloads, descriptor and DMA
behaviour, and absolute throughput or latency -- every packet on a veth crosses
the kernel's veth path and the PMD's mmap rings. Queue count is a further
example of the limit: on a veth it is whatever `qpairs=` says, so it does not
validate that a NIC's advertised queue count was honoured.

**Multi-queue RSS, per-worker tables, RCU rule updates, no locks or allocations
in the packet path** (`docs/compliance.md`'s row) are the engine's, not this
repo's: BESS `docs/decisions.md` and `docs/performance-contract.md` are the
sources, and the placement policy in `docs/design.md` is what a deployment
turns into a port-and-worker layout.
