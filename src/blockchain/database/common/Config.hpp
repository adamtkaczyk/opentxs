// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <boost/thread/thread.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <iosfwd>
#include <iterator>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>

#include "internal/blockchain/node/Node.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/Version.hpp"
#include "opentxs/api/session/Client.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/core/Data.hpp"
#include "opentxs/network/p2p/Block.hpp"
#include "opentxs/network/p2p/Data.hpp"
#include "opentxs/network/zeromq/socket/Publish.hpp"
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

namespace network
{
namespace p2p
{
class Block;
class Data;
}  // namespace p2p
}  // namespace network

namespace storage
{
namespace lmdb
{
class LMDB;
}  // namespace lmdb
}  // namespace storage
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::database::common
{
class Configuration
{
public:
    using Endpoints = UnallocatedVector<UnallocatedCString>;

    auto AddSyncServer(const UnallocatedCString& endpoint) const noexcept
        -> bool;
    auto DeleteSyncServer(const UnallocatedCString& endpoint) const noexcept
        -> bool;
    auto GetSyncServers() const noexcept -> Endpoints;

    Configuration(const api::Session& api, storage::lmdb::LMDB& lmdb) noexcept;

private:
    const api::Session& api_;
    storage::lmdb::LMDB& lmdb_;
    const int config_table_;
    const OTZMQPublishSocket socket_;
};
}  // namespace opentxs::blockchain::database::common
