// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/smart_ptr/enable_shared_from_this.hpp>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string_view>
#include <tuple>
#include <utility>

#include "internal/blockchain/Blockchain.hpp"
#include "internal/blockchain/block/Block.hpp"
#include "internal/blockchain/node/Node.hpp"
#include "internal/blockchain/node/wallet/Types.hpp"
#include "internal/blockchain/node/wallet/subchain/Subchain.hpp"
#include "internal/blockchain/node/wallet/subchain/statemachine/Index.hpp"
#include "internal/blockchain/node/wallet/subchain/statemachine/Process.hpp"
#include "internal/blockchain/node/wallet/subchain/statemachine/Progress.hpp"
#include "internal/blockchain/node/wallet/subchain/statemachine/Rescan.hpp"
#include "internal/blockchain/node/wallet/subchain/statemachine/Scan.hpp"
#include "internal/blockchain/node/wallet/subchain/statemachine/Types.hpp"
#include "internal/network/zeromq/Types.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/FilterType.hpp"
#include "opentxs/blockchain/bitcoin/cfilter/GCS.hpp"
#include "opentxs/blockchain/block/Block.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/block/bitcoin/Script.hpp"
#include "opentxs/blockchain/crypto/Subaccount.hpp"
#include "opentxs/blockchain/crypto/Types.hpp"
#include "opentxs/blockchain/node/BlockOracle.hpp"
#include "opentxs/blockchain/node/FilterOracle.hpp"
#include "opentxs/core/Data.hpp"
#include "opentxs/core/identifier/Generic.hpp"
#include "opentxs/core/identifier/Nym.hpp"
#include "opentxs/crypto/Types.hpp"
#include "opentxs/util/Allocated.hpp"
#include "opentxs/util/Allocator.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"
#include "util/Actor.hpp"
#include "util/JobCounter.hpp"
#include "util/LMDB.hpp"

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
namespace block
{
namespace bitcoin
{
class Block;
class Transaction;
}  // namespace bitcoin
}  // namespace block

namespace crypto
{
class Element;
class Subaccount;
}  // namespace crypto

namespace node
{
namespace internal
{
struct Mempool;
struct WalletDatabase;
}  // namespace internal

namespace wallet
{
class Index;
class Job;
class ScriptForm;
class Work;
}  // namespace wallet
}  // namespace node
}  // namespace blockchain

namespace network
{
namespace zeromq
{
namespace socket
{
class Push;
class Raw;
}  // namespace socket
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node::wallet
{
class SubchainStateData
    : virtual public Subchain,
      public Actor<SubchainStateData, SubchainJobs>,
      public boost::enable_shared_from_this<SubchainStateData>
{
public:
    using WalletDatabase = node::internal::WalletDatabase;
    using Subchain = WalletDatabase::Subchain;
    using SubchainIndex = WalletDatabase::pSubchainIndex;

    static constexpr auto scan_batch_ = std::size_t{1000u};

    const api::Session& api_;
    const node::internal::Network& node_;
    node::internal::WalletDatabase& db_;
    const node::internal::Mempool& mempool_oracle_;
    const OTNymID owner_;
    const crypto::SubaccountType account_type_;
    const OTIdentifier id_;
    const Subchain subchain_;
    const Type chain_;
    const cfilter::Type filter_type_;
    const SubchainIndex db_key_;
    const block::Position null_position_;
    const block::Position genesis_;
    const CString to_index_endpoint_;
    const CString to_scan_endpoint_;
    const CString to_rescan_endpoint_;
    const CString to_process_endpoint_;
    const CString to_progress_endpoint_;
    const CString shutdown_endpoint_;

    auto ChangeState(const State state, StateSequence reorg) noexcept
        -> bool final;
    auto IndexElement(
        const cfilter::Type type,
        const blockchain::crypto::Element& input,
        const Bip32Index index,
        WalletDatabase::ElementMap& output) const noexcept -> void;
    auto ProcessBlock(
        const block::Position& position,
        const block::bitcoin::Block& block) const noexcept -> void;
    auto ProcessTransaction(
        const block::bitcoin::Transaction& tx) const noexcept -> void;
    virtual auto ReportScan(const block::Position& pos) const noexcept -> void;
    auto Rescan(
        const block::Position best,
        const block::Height stop,
        block::Position& highestTested,
        Vector<ScanStatus>& out) const noexcept
        -> std::optional<block::Position>;
    auto Scan(
        const block::Position best,
        const block::Height stop,
        block::Position& highestTested,
        Vector<ScanStatus>& out) const noexcept
        -> std::optional<block::Position>;

    auto Init(boost::shared_ptr<SubchainStateData> me) noexcept -> void final;
    auto ProcessReorg(
        const Lock& headerOracleLock,
        storage::lmdb::LMDB::Transaction& tx,
        std::atomic_int& errors,
        const block::Position& ancestor) noexcept -> void final;

    ~SubchainStateData() override { signal_shutdown(); }

protected:
    using Transactions =
        Vector<std::shared_ptr<const block::bitcoin::Transaction>>;
    using Task = node::internal::Wallet::Task;
    using Patterns = WalletDatabase::Patterns;
    using UTXOs = Vector<WalletDatabase::UTXO>;
    using Targets = GCS::Targets;
    using Tested = WalletDatabase::MatchingIndices;

    auto get_account_targets(alloc::Resource* alloc) const noexcept
        -> std::tuple<Patterns, UTXOs, Targets>;
    auto get_block_targets(
        const block::Hash& id,
        const UTXOs& utxos,
        alloc::Resource* alloc) const noexcept -> std::pair<Patterns, Targets>;
    auto get_block_targets(
        const block::Hash& id,
        Tested& tested,
        alloc::Resource* alloc) const noexcept
        -> std::tuple<Patterns, UTXOs, Targets, Patterns>;
    auto set_key_data(block::bitcoin::Transaction& tx) const noexcept -> void;
    auto supported_scripts(const crypto::Element& element) const noexcept
        -> UnallocatedVector<ScriptForm>;
    auto translate(
        const Vector<WalletDatabase::UTXO>& utxos,
        Patterns& outpoints) const noexcept -> void;

    virtual auto do_startup() noexcept -> void;
    virtual auto work() noexcept -> bool;

    SubchainStateData(
        const api::Session& api,
        const node::internal::Network& node,
        node::internal::WalletDatabase& db,
        const node::internal::Mempool& mempool,
        const crypto::Subaccount& subaccount,
        const cfilter::Type filter,
        const Subchain subchain,
        const network::zeromq::BatchID batch,
        const std::string_view parent,
        allocator_type alloc) noexcept;

private:
    friend Actor<SubchainStateData, SubchainJobs>;

    using HandledReorgs = Set<StateSequence>;

    std::atomic<State> pending_state_;
    std::atomic<State> state_;
    HandledReorgs reorgs_;
    std::optional<wallet::Progress> progress_;
    std::optional<wallet::Rescan> rescan_;
    std::optional<wallet::Index> index_;
    std::optional<wallet::Process> process_;
    std::optional<wallet::Scan> scan_;
    bool have_children_;

    static auto describe(
        const crypto::Subaccount& account,
        const Subchain subchain,
        allocator_type alloc) noexcept -> CString;

    auto clear_children() noexcept -> void;
    virtual auto get_index(const boost::shared_ptr<const SubchainStateData>& me)
        const noexcept -> Index = 0;
    auto get_targets(
        const Patterns& elements,
        const Vector<WalletDatabase::UTXO>& utxos,
        Targets& targets) const noexcept -> void;
    auto get_targets(
        const Patterns& elements,
        const Vector<WalletDatabase::UTXO>& utxos,
        Targets& targets,
        Patterns& outpoints,
        Tested& tested) const noexcept -> void;
    virtual auto handle_confirmed_matches(
        const block::bitcoin::Block& block,
        const block::Position& position,
        const block::Matches& confirmed) const noexcept -> void = 0;
    virtual auto handle_mempool_matches(
        const block::Matches& matches,
        std::unique_ptr<const block::bitcoin::Transaction> tx) const noexcept
        -> void = 0;
    auto reorg_children() const noexcept -> std::size_t;
    auto scan(
        const bool rescan,
        const block::Position best,
        const block::Height stop,
        block::Position& highestTested,
        Vector<ScanStatus>& out) const noexcept
        -> std::optional<block::Position>;

    auto do_reorg(
        const Lock& headerOracleLock,
        storage::lmdb::LMDB::Transaction& tx,
        std::atomic_int& errors,
        const block::Position ancestor) noexcept -> void;
    auto do_shutdown() noexcept -> void;
    auto pipeline(const Work work, Message&& msg) noexcept -> void;
    auto process_prepare_reorg(Message&& in) noexcept -> void;
    auto state_normal(const Work work, Message&& msg) noexcept -> void;
    auto state_reorg(const Work work, Message&& msg) noexcept -> void;
    auto transition_state_normal() noexcept -> void;
    auto transition_state_reorg(StateSequence id) noexcept -> void;
    auto transition_state_shutdown() noexcept -> void;

    SubchainStateData(
        const api::Session& api,
        const node::internal::Network& node,
        node::internal::WalletDatabase& db,
        const node::internal::Mempool& mempool,
        const crypto::Subaccount& subaccount,
        const cfilter::Type filter,
        const Subchain subchain,
        const network::zeromq::BatchID batch,
        const std::string_view parent,
        CString&& fromChildren,
        CString&& toChildren,
        CString&& toScan,
        CString&& toProgress,
        allocator_type alloc) noexcept;

    SubchainStateData() = delete;
    SubchainStateData(const SubchainStateData&) = delete;
    SubchainStateData(SubchainStateData&&) = delete;
    SubchainStateData& operator=(const SubchainStateData&) = delete;
    SubchainStateData& operator=(SubchainStateData&&) = delete;
};
}  // namespace opentxs::blockchain::node::wallet
