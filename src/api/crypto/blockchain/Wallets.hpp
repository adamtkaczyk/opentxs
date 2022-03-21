// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/blockchain/BlockchainType.hpp"

#pragma once

#include <memory>
#include <mutex>
#include <optional>

#include "blockchain/crypto/AccountIndex.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/api/Context.hpp"
#include "opentxs/api/crypto/Blockchain.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/crypto/Subaccount.hpp"
#include "opentxs/blockchain/crypto/Subchain.hpp"
#include "opentxs/blockchain/crypto/Types.hpp"
#include "opentxs/core/Data.hpp"
#include "opentxs/core/identifier/Generic.hpp"
#include "opentxs/core/identifier/Nym.hpp"
#include "opentxs/crypto/Bip44Type.hpp"
#include "opentxs/crypto/Types.hpp"
#include "opentxs/identity/wot/claim/ClaimType.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace api
{
namespace crypto
{
class Blockchain;
}  // namespace crypto

namespace session
{
class Contacts;
}  // namespace session

class Session;
}  // namespace api

namespace blockchain
{
namespace crypto
{
class Wallet;
}  // namespace crypto
}  // namespace blockchain

namespace identifier
{
class Nym;
}  // namespace identifier
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::api::crypto::blockchain
{
class Wallets
{
public:
    using AccountData = crypto::Blockchain::AccountData;

    auto AccountList(const identifier::Nym& nymID) const noexcept
        -> UnallocatedSet<OTIdentifier>;
    auto AccountList(const opentxs::blockchain::Type chain) const noexcept
        -> UnallocatedSet<OTIdentifier>;
    auto AccountList() const noexcept -> UnallocatedSet<OTIdentifier>;
    auto Get(const opentxs::blockchain::Type chain) noexcept
        -> opentxs::blockchain::crypto::Wallet&;
    auto LookupAccount(const Identifier& id) const noexcept -> AccountData;

    Wallets(
        const api::Session& api,
        const api::session::Contacts& contacts,
        api::crypto::Blockchain& parent) noexcept;

private:
    const api::Session& api_;
    const api::session::Contacts& contacts_;
    api::crypto::Blockchain& parent_;
    opentxs::blockchain::crypto::AccountIndex index_;
    mutable std::mutex lock_;
    mutable bool populated_;
    mutable UnallocatedMap<
        opentxs::blockchain::Type,
        std::unique_ptr<opentxs::blockchain::crypto::Wallet>>
        lists_;

    auto get(const Lock& lock, const opentxs::blockchain::Type chain)
        const noexcept -> opentxs::blockchain::crypto::Wallet&;
    auto populate() const noexcept -> void;
    auto populate(const Lock& lock) const noexcept -> void;
};
}  // namespace opentxs::api::crypto::blockchain
