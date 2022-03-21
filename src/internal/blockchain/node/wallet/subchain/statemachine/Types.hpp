// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string_view>
#include <tuple>
#include <utility>

#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/crypto/Types.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace api
{
class Session;
}  // namespace api

namespace blockchain
{
namespace node
{
namespace wallet
{
class Work;
}  // namespace wallet
}  // namespace node
}  // namespace blockchain

namespace network
{
namespace zeromq
{
class Frame;
class Message;
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::wallet
{
enum class JobState {
    normal,
    reorg,
    shutdown,
};

enum class ScanState : std::uint8_t {
    dirty = 0,
    scan_clean = 1,
    processed = 2,
    rescan_clean = 3,
};

using Cookie = unsigned long long int;
using BlockMap = UnallocatedMap<Cookie, Work*>;
using Indices = UnallocatedVector<Bip32Index>;
using Result = std::pair<ReadView, Indices>;
using Results = UnallocatedVector<Result>;
using ProgressBatch = UnallocatedVector<
    std::pair<std::reference_wrapper<const block::Position>, std::size_t>>;
using ScanStatus = std::pair<ScanState, block::Position>;

static constexpr auto scan_status_bytes_ = std::size_t{
    sizeof(ScanState) + sizeof(block::Height) +
    sizeof(std::vector<std::uint8_t>) + 32u};

auto decode(
    const api::Session& api,
    network::zeromq::Message& in,
    Set<ScanStatus>& clean,
    Set<block::Position>& dirty) noexcept -> void;
auto encode(
    const Vector<ScanStatus>& in,
    network::zeromq::Message& out) noexcept -> void;
auto extract_dirty(
    const api::Session& api,
    network::zeromq::Message& in,
    Vector<ScanStatus>& out) noexcept -> void;
auto print(JobState) noexcept -> std::string_view;
}  // namespace opentxs::blockchain::node::wallet
