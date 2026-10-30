// SPDX-License-Identifier: BSD-3-Clause
#include "upf_appliance.h"

#include <bit>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <span>
#include <string>

#include "dataplane/packet_store.h"
#include "dataplane/resource_registry.h"
#include "framework/packet_store_codec.h"
#include <atomic>
#include <rte_ring.h>
#include <rte_ring_elem.h>
#include "utils/rte_ring_alloc.h"
#include "utils/time.h"

namespace {
namespace dp = bess::dataplane;
using upf::appliance::Lane;

struct FreeRing {
  void operator()(rte_ring *ring) const noexcept { std::free(ring); }
};
}  // namespace

struct UpfAppliance::Buffer {
  enum class Kind : uint32_t { kRelease, kDrop, kClear };
  struct Request { Kind kind; uint32_t id; };
  struct Sidecar {
    bess::PacketHandle handle = nullptr;
    State state;
  };

  explicit Buffer(UpfAppliance &module)
      : owner(module), limits(module.init_context().rcu()) {}

  ~Buffer() {
    // Structural teardown has paused workers. The observer must remain valid
    // until the last stored handle is freed, and is detached before sidecars go.
    if (store) {
      store->Clear();
      store->SetDiscardObserver(nullptr, nullptr);
    }
    ClearReleased();
    binding.Reset();
    limits.domain().Drain();
    if (limits.Read() != nullptr) limits.ResetQuiesced();
    resource.reset();
  }

  size_t Home(bess::PacketHandle handle) const noexcept {
    uint64_t key = reinterpret_cast<uintptr_t>(handle) >> 4;
    key ^= key >> 30;
    key *= 0xbf58476d1ce4e5b9ULL;
    key ^= key >> 27;
    key *= 0x94d049bb133111ebULL;
    key ^= key >> 31;
    return static_cast<size_t>(key) & sidecar_mask;
  }

  size_t Find(bess::PacketHandle handle) const noexcept {
    size_t at = Home(handle);
    while (sidecars[at].handle != nullptr && sidecars[at].handle != handle)
      at = (at + 1) & sidecar_mask;
    return at;
  }

  void Save(bess::PacketHandle handle, const State &state) noexcept {
    const size_t at = Find(handle);
    CHECK(sidecars[at].handle == nullptr);
    sidecars[at].state = state;
    sidecars[at].handle = handle;
  }

  State Take(bess::PacketHandle handle) noexcept {
    size_t hole = Find(handle);
    CHECK(sidecars[hole].handle == handle);
    const State result = sidecars[hole].state;
    // Back-shift deletion keeps this bounded map usable after arbitrarily many
    // expiries and evictions; tombstones would eventually fill a fixed table.
    for (size_t next = (hole + 1) & sidecar_mask;
         sidecars[next].handle != nullptr; next = (next + 1) & sidecar_mask) {
      const size_t home = Home(sidecars[next].handle);
      if (((next - home) & sidecar_mask) >= ((next - hole) & sidecar_mask)) {
        sidecars[hole] = sidecars[next];
        hole = next;
      }
    }
    sidecars[hole].handle = nullptr;
    return result;
  }

  static void Discard(void *opaque, bess::PacketHandle handle,
                      dp::PacketStoreDiscardReason reason) noexcept {
    auto &self = *static_cast<Buffer *>(opaque);
    self.Take(handle);
    self.owner.Count(reason == dp::PacketStoreDiscardReason::kExpired
                         ? Reason::kBufferExpired : Reason::kBufferDropped);
    // PacketStore frees the handle after this notification.
  }

  void ClearReleased() noexcept {
    while (released_count != 0) {
      const bess::PacketHandle handle = released[released_head];
      released_head = (released_head + 1) % max_packets;
      --released_count;
      Take(handle);
      bess::PacketFree(handle);
      owner.Count(Reason::kBufferDropped);
    }
    released_head = 0;
  }

  bool Deliver(const Request &request) noexcept {
    Request copy = request;
    // Even while workers are paused, control only posts requests. The store,
    // its sidecars and the release FIFO have exactly one writer: the worker.
    if (rte_ring_sp_enqueue_elem(requests.get(), &copy, sizeof(copy)) == 0)
      return true;
    owner.Count(Reason::kBufferRequestFull);
    return false;
  }

  void ApplySnapshot() {
    if (pending_count == 0) {
      // Snapshot the request count once: commands posted after this point wait
      // for a later run. Hold is synchronous on this same worker, so there is
      // no ingress ring whose preceding packets still need to be drained.
      const unsigned due = rte_ring_count(requests.get());
      pending_count = rte_ring_sc_dequeue_burst_elem(
          requests.get(), pending.get(), sizeof(Request), due, nullptr);
    }
    if (pending_count == 0) return;

    size_t after_clear = 0;
    bool releases = false;
    for (size_t i = 0; i < pending_count; ++i) {
      if (pending[i].kind == Kind::kClear) after_clear = i + 1;
      if (pending[i].kind == Kind::kRelease) releases = true;
    }
    if (after_clear != 0) {
      // Nothing released by preceding commands could have left this snapshot
      // yet. Clear therefore subsumes all of them, including their queued
      // handles, without needing transient room for a release then a clear.
      store->Clear();
      ClearReleased();
    } else if (releases && released_count + store->packets() > max_packets) {
      // A release never loses a packet because another release is still being
      // emitted. Leave this command snapshot pending until the FIFO has room
      // for everything it could release; later commands remain behind it.
      return;
    }
    for (size_t i = after_clear; i < pending_count; ++i) {
      const Request &request = pending[i];
      switch (request.kind) {
        case Kind::kRelease:
          store->Release(request.id, [this](bess::PacketHandle handle) {
            CHECK(released_count < max_packets);
            released[(released_head + released_count) % max_packets] = handle;
            ++released_count;
          });
          break;
        case Kind::kDrop:
          store->Drop(request.id);
          break;
        case Kind::kClear:
          // The last clear was already applied above.
          break;
      }
    }
    pending_count = 0;
  }

  UpfAppliance &owner;
  bess::framework::MemoryLease owner_lease, arrays_lease, ring_lease;
  bess::framework::Sized<dp::PacketStore> store;
  bess::rcu::RcuPtr<dp::PacketStoreLimitsMap> limits;
  bess::framework::Sized<dp::PacketStoreFlowsResource> resource;
  bess::framework::ResourceBinding binding;
  bool registered = false;
  std::unique_ptr<rte_ring, FreeRing> requests;
  std::unique_ptr<Request[]> pending;
  std::unique_ptr<Sidecar[]> sidecars;
  std::unique_ptr<bess::PacketHandle[]> released;
  size_t sidecar_mask = 0, pending_count = 0;
  size_t released_head = 0, released_count = 0;
  uint32_t max_packets = 0;
};

CommandResponse UpfAppliance::InitBuffer(const upf::pb::UpfApplianceArg &arg) {
  const auto &input = arg.buffer();
  dp::PacketStoreConfig config;
  config.max_packets = input.max_packets() ? input.max_packets() : 65536;
  config.max_packets_per_flow = input.max_packets_per_flow()
      ? input.max_packets_per_flow() : 64;
  if (input.has_timeout_ms() &&
      input.timeout_ms() > std::numeric_limits<uint64_t>::max() / 1'000'000ULL)
    return CommandFailure(EINVAL, "buffer timeout_ms overflows nanoseconds");
  config.timeout_ns = input.has_timeout_ms()
      ? input.timeout_ms() * 1'000'000ULL : 5'000'000'000ULL;
  if (config.max_packets > (uint32_t{1} << 30))
    return CommandFailure(EINVAL, "buffer max_packets exceeds 2^30");
  const uint32_t capacity = input.request_capacity() ? input.request_capacity() : 256;
  if (capacity >= (uint32_t{1} << 30))
    return CommandFailure(EINVAL, "buffer request_capacity must be below 2^30");
  const uint32_t slots = std::bit_ceil(capacity + 1);
  const size_t ring_bytes = bess::utils::RingElemBytes(sizeof(Buffer::Request), slots);
  if (ring_bytes == 0)
    return CommandFailure(EINVAL, "invalid buffer request ring size");

  auto &memory = init_context().memory();
  auto owner_lease = memory.Lease("buffer_owner", sizeof(Buffer), sizeof(Buffer));
  auto buffer = std::make_shared<Buffer>(*this);
  buffer->owner_lease = std::move(owner_lease);
  buffer->max_packets = config.max_packets;
  // At most max_packets in the store, max_packets awaiting output, and one
  // arriving handle before Store evicts it or an old packet. This is a map of
  // immutable per-frame continuations, not a second packet store.
  const size_t sidecar_count = dp::PacketStore::FlowCapacity(config.max_packets) * 2;
  buffer->sidecar_mask = sidecar_count - 1;
  const size_t arrays_bytes = sidecar_count * sizeof(Buffer::Sidecar) +
      size_t{config.max_packets} * sizeof(bess::PacketHandle) +
      size_t{slots - 1} * sizeof(Buffer::Request);
  buffer->arrays_lease = memory.Lease("buffer_continuations", arrays_bytes, arrays_bytes);
  buffer->sidecars = std::make_unique<Buffer::Sidecar[]>(sidecar_count);
  buffer->released = std::make_unique<bess::PacketHandle[]>(config.max_packets);
  buffer->pending = std::make_unique<Buffer::Request[]>(slots - 1);
  buffer->ring_lease = memory.Lease("buffer_requests", ring_bytes, ring_bytes);
  buffer->requests.reset(static_cast<rte_ring *>(bess::utils::AllocRingMem(ring_bytes)));
  if (!buffer->requests)
    return CommandFailure(ENOMEM, "buffer request ring allocation failed");
  static std::atomic<uint32_t> next_ring{0};
  const std::string ring_name = "upf_buffer" + std::to_string(next_ring.fetch_add(1));
  if (rte_ring_init(buffer->requests.get(), ring_name.c_str(), slots,
                    RING_F_SP_ENQ | RING_F_SC_DEQ) != 0)
    return CommandFailure(EINVAL, "buffer request ring initialization failed");

  auto lease = memory.LeaseFor<dp::PacketStore>("buffer_store", config);
  auto created = dp::PacketStore::Create(config);
  if (!created) return CommandFailure(EINVAL, "%s", created.error().c_str());
  if (!*created) return CommandFailure(ENOMEM, "buffer packet store allocation failed");
  buffer->store = bess::framework::MemoryScope::Adopt(std::move(lease), std::move(*created));
  buffer->store->SetDiscardObserver(buffer.get(), &Buffer::Discard);
  auto flows_lease = memory.LeaseFor<dp::PacketStoreFlowsResource>("buffer_flows");
  auto flows = std::make_unique<dp::PacketStoreFlowsResource>(
      name() + "/flows", buffer->limits, flows_lease.growth());
  buffer->resource = bess::framework::MemoryScope::Adopt(
      std::move(flows_lease), std::move(flows));
  buffer->binding = init_context().codecs().Bind(
      *buffer->resource, dp::MakePacketStoreFlowsCodec(buffer->limits));
  auto registered = init_context().resources().Register(buffer->resource.get());
  if (!registered) return CommandFailure(EEXIST, "%s", registered.error().c_str());
  buffer->registered = true;
  buffer_ = std::move(buffer);
  return CommandSuccess();
}

void UpfAppliance::ReleaseBuffer() {
  if (!buffer_) return;
  if (buffer_->registered) {
    const std::string resource_name = buffer_->resource->name();
    auto released = init_context().resources().ReleaseForTeardown(
        std::span<const std::string>(&resource_name, 1));
    CHECK(released) << released.error();
    buffer_->registered = false;
  }
  buffer_.reset();
}

void UpfAppliance::Hold(Context *, bess::PacketRef packet, const State &state) {
  Buffer &buffer = *buffer_;
  const bess::PacketHandle handle = packet.handle();
  buffer.Save(handle, state);
  const uint32_t id = state.action_id;
  const dp::PacketStoreLimitsMap *limits = buffer.limits.Read();
  buffer.store->Store(&handle, &id, 1, *limits,
      tsc_to_ns(current_worker.current_tsc()),
      [&buffer](bess::PacketHandle evicted) {
        buffer.Take(evicted);
        buffer.owner.Count(Reason::kBufferEvicted);
        bess::PacketFree(evicted);
      });
}

void UpfAppliance::BufferTask(Context *ctx, bess::PacketBatch *batch) {
  if (!buffer_) return;
  Buffer &buffer = *buffer_;
  const dp::PacketStoreLimitsMap *limits = buffer.limits.Read();
  // Stamps and sweeps use this worker's TSC clock only: PacketStore computes
  // now - stamp unsigned, so a second clock could make every packet expire.
  buffer.store->ExpireBounded(*limits, tsc_to_ns(current_worker.current_tsc()));
  buffer.ApplySnapshot();
  batch->clear();
  State states[bess::PacketBatch::kMaxBurst];
  size_t count = 0;
  while (count < bess::PacketBatch::kMaxBurst && buffer.released_count != 0) {
    const bess::PacketHandle handle = buffer.released[buffer.released_head];
    buffer.released_head = (buffer.released_head + 1) % buffer.max_packets;
    --buffer.released_count;
    states[count] = buffer.Take(handle);
    states[count].lane = states[count].direction ? Lane::kDl : Lane::kUl;
    batch->add(bess::PacketRef(handle));
    ++count;
  }
  if (count != 0) Resume(ctx, batch, states, count);
}

CommandResponse UpfAppliance::CommandRelease(
    const bess::pb::PacketStoreCommandReleaseArg &arg) {
  if (arg.gate() != 0)
    return CommandFailure(EINVAL, "appliance release gate must be 0 (meter continuation)");
  if (!buffer_) return CommandFailure(ENODEV, "buffer is not initialized");
  if (!buffer_->Deliver({Buffer::Kind::kRelease, arg.id()}))
    return CommandFailure(ENOSPC, "buffer request ring is full");
  return CommandSuccess();
}

CommandResponse UpfAppliance::CommandDrop(
    const bess::pb::PacketStoreCommandDropArg &arg) {
  if (!buffer_) return CommandFailure(ENODEV, "buffer is not initialized");
  if (!buffer_->Deliver({Buffer::Kind::kDrop, arg.id()}))
    return CommandFailure(ENOSPC, "buffer request ring is full");
  return CommandSuccess();
}

CommandResponse UpfAppliance::CommandClear(
    const bess::pb::PacketStoreCommandClearArg &) {
  if (!buffer_) return CommandFailure(ENODEV, "buffer is not initialized");
  if (!buffer_->Deliver({Buffer::Kind::kClear, 0}))
    return CommandFailure(ENOSPC, "buffer request ring is full");
  return CommandSuccess();
}
