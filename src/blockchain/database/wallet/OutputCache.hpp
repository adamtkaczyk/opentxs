// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/blockchain/BlockchainType.hpp"
// IWYU pragma: no_include "opentxs/blockchain/node/TxoState.hpp"
// IWYU pragma: no_include "opentxs/blockchain/node/TxoTag.hpp"

#pragma once

#include <robin_hood.h>
#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>

#include "blockchain/database/wallet/Output.hpp"
#include "blockchain/database/wallet/Position.hpp"
#include "blockchain/database/wallet/Types.hpp"
#include "internal/blockchain/database/Database.hpp"
#include "internal/util/TSV.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/block/Outpoint.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/crypto/Types.hpp"
#include "opentxs/blockchain/node/TxoState.hpp"
#include "opentxs/blockchain/node/Types.hpp"
#include "opentxs/core/identifier/Generic.hpp"
#include "opentxs/core/identifier/Nym.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"
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
namespace internal
{
struct Output;
}  // namespace internal

class Output;
}  // namespace bitcoin

class Outpoint;
}  // namespace block
}  // namespace blockchain
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::database::wallet
{
constexpr auto accounts_{Table::AccountOutputs};
constexpr auto generation_{Table::GenerationOutputs};
constexpr auto keys_{Table::KeyOutputs};
constexpr auto nyms_{Table::NymOutputs};
constexpr auto output_config_{Table::Config};
constexpr auto output_proposal_{Table::OutputProposals};
constexpr auto outputs_{Table::WalletOutputs};
constexpr auto positions_{Table::PositionOutputs};
constexpr auto proposal_created_{Table::ProposalCreatedOutputs};
constexpr auto proposal_spent_{Table::ProposalSpentOutputs};
constexpr auto states_{Table::StateOutputs};
constexpr auto subchains_{Table::SubchainOutputs};

using Dir = storage::lmdb::LMDB::Dir;
using Mode = storage::lmdb::LMDB::Mode;
using SubchainID = Identifier;
using pSubchainID = OTIdentifier;
using States = UnallocatedVector<node::TxoState>;
using Matches = UnallocatedVector<block::Outpoint>;
using Outpoints = robin_hood::unordered_node_set<block::Outpoint>;
using NymBalances = UnallocatedMap<OTNymID, Balance>;
using Nyms = robin_hood::unordered_node_set<OTNymID>;

auto all_states() noexcept -> const States&;

class OutputCache
{
public:
    auto Exists(const block::Outpoint& id) const noexcept -> bool;
    auto Exists(const SubchainID& subchain, const block::Outpoint& id)
        const noexcept -> bool;
    auto GetAccount(const AccountID& id) const noexcept -> const Outpoints&;
    auto GetKey(const crypto::Key& id) const noexcept -> const Outpoints&;
    auto GetHeight() const noexcept -> block::Height;
    auto GetNym(const identifier::Nym& id) const noexcept -> const Outpoints&;
    auto GetNyms() const noexcept -> const Nyms&;
    auto GetOutput(const block::Outpoint& id) const noexcept(false)
        -> const block::bitcoin::internal::Output&;
    auto GetPosition() const noexcept -> const db::Position&;
    auto GetPosition(const block::Position& id) const noexcept
        -> const Outpoints&;
    auto GetState(const node::TxoState id) const noexcept -> const Outpoints&;
    auto GetSubchain(const SubchainID& id) const noexcept -> const Outpoints&;
    auto Populate() const noexcept -> void;
    auto Print() const noexcept -> void;

    auto AddOutput(
        const block::Outpoint& id,
        MDB_txn* tx,
        std::unique_ptr<block::bitcoin::Output> output) noexcept -> bool;
    auto AddToAccount(
        const AccountID& id,
        const block::Outpoint& output,
        MDB_txn* tx) noexcept -> bool;
    auto AddToKey(
        const crypto::Key& id,
        const block::Outpoint& output,
        MDB_txn* tx) noexcept -> bool;
    auto AddToNym(
        const identifier::Nym& id,
        const block::Outpoint& output,
        MDB_txn* tx) noexcept -> bool;
    auto AddToPosition(
        const block::Position& id,
        const block::Outpoint& output,
        MDB_txn* tx) noexcept -> bool;
    auto AddToState(
        const node::TxoState id,
        const block::Outpoint& output,
        MDB_txn* tx) noexcept -> bool;
    auto AddToSubchain(
        const SubchainID& id,
        const block::Outpoint& output,
        MDB_txn* tx) noexcept -> bool;
    auto ChangePosition(
        const block::Position& oldPosition,
        const block::Position& newPosition,
        const block::Outpoint& output,
        MDB_txn* tx) noexcept -> bool;
    auto ChangeState(
        const node::TxoState oldState,
        const node::TxoState newState,
        const block::Outpoint& output,
        MDB_txn* tx) noexcept -> bool;
    auto Clear() noexcept -> void;
    auto GetOutput(const block::Outpoint& id) noexcept(false)
        -> block::bitcoin::internal::Output&;
    auto GetOutput(
        const SubchainID& subchain,
        const block::Outpoint& id) noexcept(false)
        -> block::bitcoin::internal::Output&;
    auto UpdateOutput(
        const block::Outpoint& id,
        const block::bitcoin::Output& output,
        MDB_txn* tx) noexcept -> bool;
    auto UpdatePosition(const block::Position&, MDB_txn* tx) noexcept -> bool;

    OutputCache(
        const api::Session& api,
        const storage::lmdb::LMDB& lmdb,
        const blockchain::Type chain,
        const block::Position& blank) noexcept;

    ~OutputCache();

private:
    static constexpr std::size_t reserve_{10000u};
    static const Outpoints empty_outputs_;
    static const Nyms empty_nyms_;

    const api::Session& api_;
    const storage::lmdb::LMDB& lmdb_;
    const blockchain::Type chain_;
    const block::Position& blank_;
    std::optional<db::Position> position_;
    robin_hood::unordered_node_map<
        block::Outpoint,
        std::unique_ptr<block::bitcoin::Output>>
        outputs_;
    robin_hood::unordered_node_map<OTIdentifier, Outpoints> accounts_;
    robin_hood::unordered_node_map<crypto::Key, Outpoints> keys_;
    robin_hood::unordered_node_map<OTNymID, Outpoints> nyms_;
    Nyms nym_list_;
    robin_hood::unordered_node_map<block::Position, Outpoints> positions_;
    robin_hood::unordered_node_map<node::TxoState, Outpoints> states_;
    robin_hood::unordered_node_map<OTIdentifier, Outpoints> subchains_;
    bool populated_;

    auto get_position() const noexcept -> const db::Position&;
    auto load_output(const block::Outpoint& id) const noexcept(false)
        -> const block::bitcoin::internal::Output&;
    template <typename MapKeyType, typename MapType>
    auto load_output_index(const MapKeyType& key, MapType& map) const noexcept
        -> const Outpoints&;

    auto load_output(const block::Outpoint& id) noexcept(false)
        -> block::bitcoin::internal::Output&;
    template <typename MapKeyType, typename MapType>
    auto load_output_index(const MapKeyType& key, MapType& map) noexcept
        -> Outpoints&;
    auto populate() noexcept -> void;
    auto write_output(
        const block::Outpoint& id,
        const block::bitcoin::Output& output,
        MDB_txn* tx) noexcept -> bool;
};
}  // namespace opentxs::blockchain::database::wallet
