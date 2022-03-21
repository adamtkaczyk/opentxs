// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "internal/blockchain/node/wallet/subchain/statemachine/Process.hpp"

#include <boost/smart_ptr/shared_ptr.hpp>
#include <robin_hood.h>
#include <atomic>
#include <cstddef>
#include <queue>

#include "blockchain/node/wallet/subchain/statemachine/Job.hpp"
#include "internal/blockchain/node/wallet/Types.hpp"
#include "internal/network/zeromq/Types.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/node/BlockOracle.hpp"
#include "opentxs/util/Allocated.hpp"
#include "opentxs/util/Container.hpp"
#include "util/Actor.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace blockchain
{
namespace node
{
namespace wallet
{
class SubchainStateData;
}  // namespace wallet
}  // namespace node
}  // namespace blockchain

namespace network
{
namespace zeromq
{
namespace socket
{
class Raw;
}  // namespace socket
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::wallet
{
class Process::Imp final : public statemachine::Job
{
public:
    auto ProcessReorg(const block::Position& parent) noexcept -> void final;

    Imp(const SubchainStateData& parent,
        const network::zeromq::BatchID batch,
        allocator_type alloc) noexcept;
    Imp() = delete;
    Imp(const Imp&) = delete;
    Imp(Imp&&) = delete;
    Imp& operator=(const Imp&) = delete;
    Imp& operator=(Imp&&) = delete;

    ~Imp() final = default;

private:
    using Waiting = Deque<block::Position>;
    using Downloading = Map<block::Position, BlockOracle::BitcoinBlockFuture>;
    using Index = Map<block::pHash, Downloading::iterator>;

    static constexpr auto download_limit_ = std::size_t{400u};

    network::zeromq::socket::Raw& to_index_;
    Waiting waiting_;
    Downloading downloading_;
    Index index_;
    Downloading downloaded_;
    robin_hood::unordered_flat_set<block::pHash> txid_cache_;

    auto do_startup() noexcept -> void final;
    auto process_block(const block::Hash& block) noexcept -> void final;
    auto process_mempool(Message&& in) noexcept -> void final;
    auto process_update(Message&& msg) noexcept -> void final;
    auto work() noexcept -> bool final;
};
}  // namespace opentxs::blockchain::node::wallet
