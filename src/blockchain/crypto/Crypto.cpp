// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                           // IWYU pragma: associated
#include "1_Internal.hpp"                         // IWYU pragma: associated
#include "internal/blockchain/crypto/Crypto.hpp"  // IWYU pragma: associated

#include <robin_hood.h>
#include <cstring>
#include <iosfwd>
#include <iterator>
#include <sstream>
#include <string_view>
#include <type_traits>

#include "internal/util/LogMacros.hpp"
#include "opentxs/api/crypto/Crypto.hpp"
#include "opentxs/api/crypto/Hash.hpp"
#include "opentxs/blockchain/crypto/HDProtocol.hpp"
#include "opentxs/blockchain/crypto/SubaccountType.hpp"
#include "opentxs/blockchain/crypto/Subchain.hpp"
#include "opentxs/blockchain/crypto/Types.hpp"
#include "opentxs/crypto/HashType.hpp"
#include "opentxs/util/Pimpl.hpp"

namespace opentxs::blockchain::crypto
{
auto print(HDProtocol value) noexcept -> std::string_view
{
    using namespace std::literals;
    using Type = HDProtocol;
    static const auto map =
        robin_hood::unordered_flat_map<Type, std::string_view>{
            {Type::Error, "invalid"sv},
            {Type::BIP_32, "BIP-32"sv},
            {Type::BIP_44, "BIP-44"sv},
            {Type::BIP_49, "BIP-49"sv},
            {Type::BIP_84, "BIP-84"sv},
        };

    try {

        return map.at(value);
    } catch (...) {

        return map.at(Type::Error);
    }
}

auto print(SubaccountType type) noexcept -> std::string_view
{
    using namespace std::literals;
    using Type = SubaccountType;
    static const auto map =
        robin_hood::unordered_flat_map<Type, std::string_view>{
            {Type::Error, "invalid"sv},
            {Type::HD, "HD"sv},
            {Type::PaymentCode, "payment code"sv},
            {Type::Imported, "single key"sv},
            {Type::Notification, "payment code notification"sv},
        };

    try {

        return map.at(type);
    } catch (...) {

        return map.at(Type::Error);
    }
}
auto print(Subchain value) noexcept -> std::string_view
{
    using namespace std::literals;
    using Type = Subchain;
    static const auto map =
        robin_hood::unordered_flat_map<Type, std::string_view>{
            {Type::Error, "invalid"sv},
            {Type::Internal, "internal"sv},
            {Type::External, "external"sv},
            {Type::Incoming, "incoming"sv},
            {Type::Outgoing, "outgoing"sv},
            {Type::Notification, "notification"sv},
            {Type::None, "none"sv},
        };

    try {

        return map.at(value);
    } catch (...) {

        return map.at(Type::Error);
    }
}

auto print(const Key& key) noexcept -> UnallocatedCString
{
    const auto& [account, subchain, index] = key;
    auto out = std::stringstream{};
    out << account;
    out << " / ";
    out << print(subchain);
    out << " / ";
    out << std::to_string(index);

    return out.str();
}
}  // namespace opentxs::blockchain::crypto

namespace opentxs
{
auto blockchain_thread_item_id(
    const api::Crypto& crypto,
    const opentxs::blockchain::Type chain,
    const Data& txid) noexcept -> OTIdentifier
{
    auto preimage = UnallocatedCString{};
    const auto hashed = crypto.Hash().HMAC(
        crypto::HashType::Sha256,
        ReadView{reinterpret_cast<const char*>(&chain), sizeof(chain)},
        txid.Bytes(),
        writer(preimage));

    OT_ASSERT(hashed);

    auto id = Identifier::Factory();
    id->CalculateDigest(preimage);

    return id;
}

auto operator==(
    const blockchain::crypto::Key& lhs,
    const blockchain::crypto::Key& rhs) noexcept -> bool
{
    const auto& [lAccount, lSubchain, lIndex] = lhs;
    const auto& [rAccount, rSubchain, rIndex] = rhs;

    if (lAccount != rAccount) { return false; }

    if (lSubchain != rSubchain) { return false; }

    return lIndex == rIndex;
}

auto operator!=(
    const blockchain::crypto::Key& lhs,
    const blockchain::crypto::Key& rhs) noexcept -> bool
{
    const auto& [lAccount, lSubchain, lIndex] = lhs;
    const auto& [rAccount, rSubchain, rIndex] = rhs;

    if (lAccount != rAccount) { return true; }

    if (lSubchain != rSubchain) { return true; }

    return lIndex != rIndex;
}

auto deserialize(const ReadView in) noexcept -> blockchain::crypto::Key
{
    auto out = blockchain::crypto::Key{};
    auto& [id, subchain, index] = out;

    if (in.size() < (sizeof(subchain) + sizeof(index))) { return out; }

    const auto idbytes = in.size() - sizeof(subchain) - sizeof(index);

    auto* i = in.data();
    id.assign(ReadView{i, idbytes});
    std::advance(i, idbytes);
    std::memcpy(&subchain, i, sizeof(subchain));
    std::advance(i, sizeof(subchain));
    std::memcpy(&index, i, sizeof(index));
    std::advance(i, sizeof(index));

    return out;
}

auto serialize(const blockchain::crypto::Key& in) noexcept -> Space
{
    const auto& [id, subchain, index] = in;
    auto out = space(id.size() + sizeof(subchain) + sizeof(index));
    auto* i = out.data();
    std::memcpy(i, id.data(), id.size());
    std::advance(i, id.size());
    std::memcpy(i, &subchain, sizeof(subchain));
    std::advance(i, sizeof(subchain));
    std::memcpy(i, &index, sizeof(index));
    std::advance(i, sizeof(index));

    return out;
}
}  // namespace opentxs
