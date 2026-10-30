// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_ATSSS_SELECT_H_
#define UPF_DATAPATH_ATSSS_SELECT_H_

#include <array>
#include <cstddef>
#include <cstdint>

// ATSSS access selection (TS 29.244 7.5.2.8): which of a session's two
// accesses -- the 3GPP access and the non-3GPP access -- a downlink packet
// leaves on. One implementation for the AtsssSteer module and UpfAppliance;
// each owns its policy and health tables and passes their lookups in.
//
// Selection is active/standby: the preferred access if its health record says
// available, else the other access if it does, else the packet is dropped. A
// missing *policy* is fail-closed. A missing *health* record means "not
// monitored" and counts as available: health is deployment state, not a
// session's, and a deployment that never writes the table must still steer.
// Policy id 0 is the exception -- it means "not steered", and the packet passes
// through with the action table's own next hop and tunnel.

namespace upf::atsss {

// One access of a policy, fixed at programming time. All zero is an access
// the SMF did not provision (active/standby allows one access and no
// standby): selection skips it.
struct AccessAction {
  uint32_t next_hop_id = 0;    // the Router next hop
  uint32_t tunnel_id = 0;      // the GtpuEncap tunnel record
  uint32_t accounting_id = 0;  // the accounting record, 0: none
  uint32_t health_id = 0;      // the access's health record
};

// One session's MAR, keyed by the global policy id the compiler allocates.
struct SteeringPolicy {
  uint8_t mode = 0;        // upf::pb::ATSSS_ACTIVE_STANDBY
  uint32_t preferred = 0;  // index into access
  std::array<AccessAction, 2> access{};
};

// One access's health, shared by every policy that uses the access.
struct AccessHealth {
  bool available = false;
};

// The access `policy` selects, or nullptr when no provisioned access is
// available. `health_of(health_id)` returns the access's const AccessHealth *,
// nullptr when the table holds none.
template <typename HealthOf>
const AccessAction *SelectAccess(const SteeringPolicy &policy, HealthOf &&health_of) noexcept {
  for (size_t n = 0; n < policy.access.size(); n++) {
    const size_t index = (policy.preferred + n) % policy.access.size();
    const AccessAction &access = policy.access[index];
    if (access.health_id == 0) {
      continue;
    }
    const AccessHealth *health = health_of(access.health_id);
    if (health == nullptr || health->available) {
      // No record is "not monitored", not "unusable": a deployment that has
      // not written the health table still steers by its preference.
      return &access;
    }
  }
  return nullptr;
}

enum class SteerVerdict : uint8_t {
  kNotSteered,  // policy id 0: the action table's next hop stands, and the
                // tunnel and accounting overrides are cleared to 0
  kSteered,     // Steering::access is the selected access
  kNoPolicy,    // drop: the policy id names no policy (fail closed)
  kNoAccess,    // drop: no provisioned access is available
};

struct Steering {
  SteerVerdict verdict;
  const AccessAction *access = nullptr;  // set when kSteered
};

// The steering of a packet whose PDR names `policy_id`.
// `policy_of(policy_id)` returns the const SteeringPolicy *, nullptr when the
// table holds none; `health_of` is SelectAccess's.
template <typename PolicyOf, typename HealthOf>
Steering Steer(uint32_t policy_id, PolicyOf &&policy_of, HealthOf &&health_of) noexcept {
  if (policy_id == 0) {
    return {SteerVerdict::kNotSteered};
  }
  const SteeringPolicy *policy = policy_of(policy_id);
  if (policy == nullptr) {
    return {SteerVerdict::kNoPolicy};
  }
  const AccessAction *access = SelectAccess(*policy, health_of);
  if (access == nullptr) {
    return {SteerVerdict::kNoAccess};
  }
  return {SteerVerdict::kSteered, access};
}

}  // namespace upf::atsss

#endif  // UPF_DATAPATH_ATSSS_SELECT_H_
