// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_PACKET_RATE_QUOTA_H_
#define UPF_DATAPATH_PACKET_RATE_QUOTA_H_

#include <atomic>
#include <cstdint>
#include <ctime>

namespace upf::datapath {

// One packet-rate quota's configuration (TS 29.244 8.2.63): a primary
// maximum and an additional maximum, each with its own period -- the IE gives
// the additional rates their own time unit (octets q/r) -- plus the CP's
// seeded Packet Rate Status (8.2.139) when the QER carried one.
struct PacketRateConfig {
  uint32_t allowed = 0;                // packets per primary period
  uint64_t primary_period_ns = 0;
  uint32_t additional = 0;             // packets per additional period
  uint64_t additional_period_ns = 0;
  uint64_t epoch = 0;                  // changes when the quota is reprogrammed
  uint32_t seed_remaining = 0;         // 8.2.139 remaining primary packets
  uint32_t seed_remaining_additional = 0;
  uint64_t seed_validity_unix_ns = 0;  // absolute; 0 = no seed
};

// The mutable half of one quota: two independently rolling fixed windows and
// the CP-seeded phase. A window starts with the first packet charged to it
// (or the config change) and lasts its period, so "10 per minute plus 5 per
// hour" is exact; a token bucket in packets/second cannot express either at
// the small values Serving PLMN and Small Data Rate Control use.
//
// Concurrency: every packet for one quota takes the quota's flag. That is the
// same price BESS's shared meters pay, and it is paid only by a packet whose
// classifier result names a quota; it makes a window boundary exact (no
// reset-versus-add race) and a status read consistent with the counters.
class PacketRateQuota {
 public:
  enum class Verdict { kPass, kDrop };

  struct Reading {
    uint32_t remaining = 0;
    uint32_t remaining_additional = 0;
    uint64_t validity_unix_ns = 0;
    uint32_t used = 0;
    uint32_t used_additional = 0;
  };

  // Charges one packet to the quota. The seed the CP provided is enforced
  // first, until its counts are spent or its validity time passes
  // (5.4.15.2 rule 4); then the primary window, then the additional one.
  Verdict Check(const PacketRateConfig &config, uint64_t now_ns) {
    Lock();
    if (epoch_ != config.epoch) {
      Init(config, now_ns);
    }
    Verdict verdict = Charge(config, now_ns);
    Unlock();
    return verdict;
  }

  // What a Query Packet Rate Status answer carries (7.5.5.4): the remaining
  // counts and the time they are valid until. A window that has not started
  // (no packet since the config, or since the last rollover) reports its full
  // allowance and one period from `wall_unix_ns`.
  Reading Status(const PacketRateConfig &config, uint64_t now_ns,
                 uint64_t wall_unix_ns) const {
    Lock();
    Reading reading = Read(config, now_ns, wall_unix_ns);
    Unlock();
    return reading;
  }

 private:
  Verdict Charge(const PacketRateConfig &config, uint64_t now_ns) {
    if (seed_end_ != 0) {
      if (now_ns < seed_end_) {
        if (seed_used_ < config.seed_remaining) {
          seed_used_++;
          return Verdict::kPass;
        }
        if (seed_used_additional_ < config.seed_remaining_additional) {
          seed_used_additional_++;
          return Verdict::kPass;
        }
      }
      seed_end_ = 0;
    }
    if (TakeWindow(primary_end_, primary_used_, config.allowed,
                   config.primary_period_ns, now_ns)) {
      return Verdict::kPass;
    }
    if (TakeWindow(additional_end_, additional_used_, config.additional,
                   config.additional_period_ns, now_ns)) {
      return Verdict::kPass;
    }
    return Verdict::kDrop;
  }

  bool TakeWindow(uint64_t &end, uint64_t &used, uint32_t limit,
                  uint64_t period_ns, uint64_t now_ns) {
    if (limit == 0 || period_ns == 0) {
      return false;
    }
    if (now_ns >= end) {
      used = 0;
      end = now_ns + period_ns;
    }
    if (used >= limit) {
      return false;
    }
    used++;
    return true;
  }

  Reading Read(const PacketRateConfig &config, uint64_t now_ns,
               uint64_t wall_unix_ns) const {
    Reading reading;
    if (epoch_ != config.epoch) {
      // No packet has run under this config: report what the first packet
      // would find, without starting a window from a control read.
      if (config.seed_validity_unix_ns > wall_unix_ns) {
        reading.remaining = config.seed_remaining;
        reading.remaining_additional = config.seed_remaining_additional;
        reading.validity_unix_ns = config.seed_validity_unix_ns;
      } else {
        uint32_t used = 0;
        uint64_t primary_validity = 0;
        uint64_t additional_validity = 0;
        ReadWindow(config.allowed, 0, 0, config.primary_period_ns, now_ns,
                   wall_unix_ns, &reading.remaining, &used,
                   &primary_validity);
        ReadWindow(config.additional, 0, 0, config.additional_period_ns,
                   now_ns, wall_unix_ns, &reading.remaining_additional, &used,
                   &additional_validity);
        reading.validity_unix_ns =
            Earliest(primary_validity, additional_validity);
      }
      return reading;
    }
    if (seed_end_ != 0 && now_ns < seed_end_) {
      reading.remaining =
          config.seed_remaining > seed_used_ ? config.seed_remaining - seed_used_ : 0;
      reading.remaining_additional =
          config.seed_remaining_additional > seed_used_additional_
              ? config.seed_remaining_additional - seed_used_additional_
              : 0;
      reading.validity_unix_ns = wall_unix_ns + (seed_end_ - now_ns);
      reading.used = static_cast<uint32_t>(seed_used_);
      reading.used_additional = static_cast<uint32_t>(seed_used_additional_);
      return reading;
    }

    reading.remaining = 0;
    reading.remaining_additional = 0;
    reading.used = 0;
    reading.used_additional = 0;
    uint64_t primary_validity = 0;
    uint64_t additional_validity = 0;
    ReadWindow(config.allowed, primary_end_, primary_used_,
               config.primary_period_ns, now_ns, wall_unix_ns,
               &reading.remaining, &reading.used, &primary_validity);
    ReadWindow(config.additional, additional_end_, additional_used_,
               config.additional_period_ns, now_ns, wall_unix_ns,
               &reading.remaining_additional, &reading.used_additional,
               &additional_validity);
    reading.validity_unix_ns = Earliest(primary_validity, additional_validity);
    return reading;
  }

  // One window's reading. A window that has not started or has rolled over
  // reports its full allowance for one period; a live one reports what is
  // left and the end of the window it is in.
  static void ReadWindow(uint32_t limit, uint64_t end, uint64_t used,
                         uint64_t period_ns, uint64_t now_ns,
                         uint64_t wall_unix_ns, uint32_t *remaining,
                         uint32_t *used_out, uint64_t *validity) {
    if (limit == 0 || period_ns == 0) {
      *remaining = 0;
      *used_out = 0;
      *validity = 0;
      return;
    }
    if (end == 0 || now_ns >= end) {
      *remaining = limit;
      *used_out = 0;
      *validity = wall_unix_ns + period_ns;
      return;
    }
    *remaining = used >= limit ? 0 : limit - static_cast<uint32_t>(used);
    *used_out = static_cast<uint32_t>(used);
    *validity = wall_unix_ns + (end - now_ns);
  }

  static uint64_t Earliest(uint64_t a, uint64_t b) {
    if (a == 0) {
      return b;
    }
    if (b == 0) {
      return a;
    }
    return a < b ? a : b;
  }

  void Init(const PacketRateConfig &config, uint64_t now_ns) {
    epoch_ = config.epoch;
    seed_used_ = 0;
    seed_used_additional_ = 0;
    primary_used_ = 0;
    additional_used_ = 0;
    primary_end_ =
        config.primary_period_ns == 0 ? 0 : now_ns + config.primary_period_ns;
    additional_end_ = config.additional_period_ns == 0
                          ? 0
                          : now_ns + config.additional_period_ns;
    seed_end_ = 0;
    if (config.seed_validity_unix_ns != 0) {
      const uint64_t wall = WallNowNs();
      if (config.seed_validity_unix_ns > wall) {
        seed_end_ = now_ns + (config.seed_validity_unix_ns - wall);
      }
    }
  }

  static uint64_t WallNowNs() {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
  }

  void Lock() const {
    while (lock_.test_and_set(std::memory_order_acquire)) {
    }
  }
  void Unlock() const { lock_.clear(std::memory_order_release); }

  mutable std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
  uint64_t epoch_ = 0;
  uint64_t seed_end_ = 0;
  uint64_t seed_used_ = 0;
  uint64_t seed_used_additional_ = 0;
  uint64_t primary_end_ = 0;
  uint64_t primary_used_ = 0;
  uint64_t additional_end_ = 0;
  uint64_t additional_used_ = 0;
};

}  // namespace upf::datapath

#endif  // UPF_DATAPATH_PACKET_RATE_QUOTA_H_
