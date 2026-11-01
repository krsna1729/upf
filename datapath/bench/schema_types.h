// SPDX-License-Identifier: BSD-3-Clause
// Copied from BESS tests/perf/schema_types.h (develop 941feb51); not installed
// by the stage.

// What the perf clients (live_perf, live_transaction_bench) share: the
// daemon's message types from GetSchema, built from protobuf JSON, so they
// need no generated code for module arguments and table entries.

#ifndef BESS_TESTS_PERF_SCHEMA_TYPES_H_
#define BESS_TESTS_PERF_SCHEMA_TYPES_H_

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/util/json_util.h>

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>

#include "bess/sdk/client.h"

namespace bess::perf {

// `in` as base64 (protobuf JSON's bytes encoding).
inline std::string Base64(const std::string &in) {
  static constexpr char kDigits[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  for (size_t i = 0; i < in.size(); i += 3) {
    const auto at = [&](size_t j) { return j < in.size() ? uint8_t(in[j]) : 0u; };
    const uint32_t n = (at(i) << 16) | (at(i + 1) << 8) | at(i + 2);
    out += kDigits[(n >> 18) & 63];
    out += kDigits[(n >> 12) & 63];
    out += i + 1 < in.size() ? kDigits[(n >> 6) & 63] : '=';
    out += i + 2 < in.size() ? kDigits[n & 63] : '=';
  }
  return out;
}

// `v` big-endian, four bytes.
inline std::string Be32(uint32_t v) {
  return {char(v >> 24), char(v >> 16), char(v >> 8), char(v)};
}

class Types {
 public:
  explicit Types(bess::sdk::Client &client) {
    auto schema = client.Schema();
    if (!schema) {
      throw std::runtime_error("GetSchema: " + schema.error().message);
    }
    for (const google::protobuf::FileDescriptorProto &file : schema->descriptors().file()) {
      pool_.BuildFile(file);
    }
    for (const bess::pb::v2::ModuleClassSchema &c : schema->module_classes()) {
      init_types_[c.name()] = c.init_arg_type();
    }
  }
  // A message of `type` (a full name, or one in bess.pb) from protobuf JSON.
  std::unique_ptr<google::protobuf::Message> Make(const std::string &type,
                                                  const std::string &json) {
    const std::string full = type.find('.') == std::string::npos ? "bess.pb." + type : type;
    const google::protobuf::Descriptor *d = pool_.FindMessageTypeByName(full);
    if (d == nullptr) {
      throw std::runtime_error("the daemon has no type " + full);
    }
    std::unique_ptr<google::protobuf::Message> m(factory_.GetPrototype(d)->New());
    if (auto ok = google::protobuf::util::JsonStringToMessage(json, m.get()); !ok.ok()) {
      throw std::runtime_error(full + " " + json + ": " + std::string(ok.message()));
    }
    return m;
  }
  // The Init argument type of module class `mclass`.
  const std::string &InitType(const std::string &mclass) const {
    const auto it = init_types_.find(mclass);
    if (it == init_types_.end() || it->second.empty()) {
      throw std::runtime_error("no module class " + mclass + " with an Init argument type");
    }
    return it->second;
  }

 private:
  std::map<std::string, std::string> init_types_;
  google::protobuf::DescriptorPool pool_;
  google::protobuf::DynamicMessageFactory factory_{&pool_};
};

}  // namespace bess::perf

#endif  // BESS_TESTS_PERF_SCHEMA_TYPES_H_
