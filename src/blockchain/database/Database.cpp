// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                      // IWYU pragma: associated
#include "1_Internal.hpp"                    // IWYU pragma: associated
#include "blockchain/database/Database.hpp"  // IWYU pragma: associated

extern "C" {
#include <lmdb.h>
}

#include <memory>

#include "internal/blockchain/node/Factory.hpp"
#include "internal/util/LogMacros.hpp"
#include "internal/util/TSV.hpp"
#include "opentxs/util/Container.hpp"
#include "util/LMDB.hpp"

namespace opentxs::factory
{
auto BlockchainDatabase(
    const api::Session& api,
    const blockchain::node::internal::Network& network,
    const blockchain::database::common::Database& common,
    const blockchain::Type chain,
    const blockchain::cfilter::Type filter) noexcept
    -> std::unique_ptr<blockchain::internal::Database>
{
    using ReturnType = blockchain::implementation::Database;

    return std::make_unique<ReturnType>(api, network, common, chain, filter);
}
}  // namespace opentxs::factory

namespace opentxs::blockchain::implementation
{
const VersionNumber Database::db_version_{1};
const storage::lmdb::TableNames Database::table_names_{
    {database::Config, "config"},
    {database::BlockHeaderMetadata, "block_header_metadata"},
    {database::BlockHeaderBest, "best_header_chain"},
    {database::ChainData, "block_header_data"},
    {database::BlockHeaderSiblings, "block_siblings"},
    {database::BlockHeaderDisconnected, "disconnected_block_headers"},
    {database::BlockFilterBest, "filter_tips"},
    {database::BlockFilterHeaderBest, "filter_header_tips"},
    {database::Proposals, "proposals"},
    {database::SubchainLastIndexed, "subchain_last_indexed"},
    {database::SubchainLastScanned, "subchain_last_scanned"},
    {database::SubchainID, "subchain_id"},
    {database::WalletPatterns, "wallet_patterns"},
    {database::SubchainPatterns, "subchain_patterns"},
    {database::SubchainMatches, "subchain_matches"},
    {database::WalletOutputs, "wallet_outputs"},
    {database::AccountOutputs, "account_outputs"},
    {database::NymOutputs, "nym_outputs"},
    {database::PositionOutputs, "position_outputs"},
    {database::ProposalCreatedOutputs, "proposal_created_outputs"},
    {database::ProposalSpentOutputs, "proposal_spent_outputs"},
    {database::OutputProposals, "output_proposals"},
    {database::StateOutputs, "state_outputs"},
    {database::SubchainOutputs, "subchain_outputs"},
    {database::KeyOutputs, "key_outputs"},
    {database::GenerationOutputs, "generation_outputs"},
};

Database::Database(
    const api::Session& api,
    const node::internal::Network& network,
    const database::common::Database& common,
    const blockchain::Type chain,
    const blockchain::cfilter::Type filter) noexcept
    : api_(api)
    , chain_(chain)
    , common_(common)
    , lmdb_([&] {
        auto lmdb = storage::lmdb::LMDB{
            table_names_,
            common.AllocateStorageFolder(
                std::to_string(static_cast<std::uint32_t>(chain_))),
            {
                {database::Config, MDB_INTEGERKEY},
                {database::BlockHeaderMetadata, 0},
                {database::BlockHeaderBest, MDB_INTEGERKEY},
                {database::ChainData, MDB_INTEGERKEY},
                {database::BlockHeaderSiblings, 0},
                {database::BlockHeaderDisconnected, MDB_DUPSORT},
                {database::BlockFilterBest, MDB_INTEGERKEY},
                {database::BlockFilterHeaderBest, MDB_INTEGERKEY},
                {database::Proposals, 0},
                {database::SubchainLastIndexed, 0},
                {database::SubchainLastScanned, 0},
                {database::SubchainID, 0},
                {database::WalletPatterns, MDB_DUPSORT},
                {database::SubchainPatterns, MDB_DUPSORT},
                {database::SubchainMatches, MDB_DUPSORT},
                {database::WalletOutputs, 0},
                {database::AccountOutputs, MDB_DUPSORT},
                {database::NymOutputs, MDB_DUPSORT},
                {database::PositionOutputs, MDB_DUPSORT | MDB_DUPFIXED},
                {database::ProposalCreatedOutputs, MDB_DUPSORT},
                {database::ProposalSpentOutputs, MDB_DUPSORT},
                {database::OutputProposals, 0},
                {database::StateOutputs, MDB_DUPSORT | MDB_DUPFIXED},
                {database::SubchainOutputs, MDB_DUPSORT},
                {database::KeyOutputs, MDB_DUPSORT},
                {database::GenerationOutputs, MDB_DUPSORT | MDB_DUPFIXED},
            },
            0};
        init_db(lmdb);

        return lmdb;
    }())
    , blocks_(api_, common_, lmdb_, chain_)
    , filters_(api_, common_, lmdb_, chain_)
    , headers_(api_, network, common_, lmdb_, chain_)
    , wallet_(api_, common_, lmdb_, chain_, filter)
    , sync_(api_, common_, lmdb_, chain_)
{
}

auto Database::init_db(storage::lmdb::LMDB& db) noexcept -> void
{
    if (false == db.Exists(database::Config, tsv(database::Key::Version))) {
        const auto stored = db.Store(
            database::Config, tsv(database::Key::Version), tsv(db_version_));

        OT_ASSERT(stored.first);
    }
}
}  // namespace opentxs::blockchain::implementation
