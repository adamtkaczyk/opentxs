// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iosfwd>
#include <optional>

#include "Proto.hpp"
#include "blockchain/crypto/Deterministic.hpp"
#include "blockchain/crypto/Element.hpp"
#include "blockchain/crypto/Subaccount.hpp"
#include "internal/blockchain/crypto/Crypto.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/Version.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/crypto/Deterministic.hpp"
#include "opentxs/blockchain/crypto/PaymentCode.hpp"
#include "opentxs/blockchain/crypto/Subaccount.hpp"
#include "opentxs/blockchain/crypto/Subchain.hpp"
#include "opentxs/blockchain/crypto/Types.hpp"
#include "opentxs/core/Data.hpp"
#include "opentxs/core/PaymentCode.hpp"
#include "opentxs/core/identifier/Generic.hpp"
#include "opentxs/core/identifier/Nym.hpp"
#include "opentxs/crypto/Types.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Numbers.hpp"
#include "opentxs/util/Time.hpp"
#include "serialization/protobuf/Bip47Channel.pb.h"
#include "serialization/protobuf/HDPath.pb.h"
#include "util/Latest.hpp"

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
class Account;
class PaymentCode;
}  // namespace crypto
}  // namespace blockchain

namespace proto
{
class Bip47Channel;
class HDPath;
}  // namespace proto

class PasswordPrompt;
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::crypto::implementation
{
class PaymentCode final : public internal::PaymentCode, public Deterministic
{
public:
    using Element = implementation::Element;
    using SerializedType = proto::Bip47Channel;

    auto AddNotification(const Txid& tx) const noexcept -> bool final;
    auto InternalPaymentCode() const noexcept -> internal::PaymentCode& final
    {
        return const_cast<PaymentCode&>(*this);
    }
    auto IsNotified() const noexcept -> bool final;
    auto Local() const noexcept -> const opentxs::PaymentCode& final
    {
        return local_;
    }
    auto ReorgNotification(const Txid& tx) const noexcept -> bool final;
    auto Remote() const noexcept -> const opentxs::PaymentCode& final
    {
        return remote_;
    }
    auto PrivateKey(
        const Subchain type,
        const Bip32Index index,
        const PasswordPrompt& reason) const noexcept -> ECKey final;
    using Deterministic::Reserve;
    auto Reserve(
        const Subchain type,
        const std::size_t batch,
        const PasswordPrompt& reason,
        const Identifier& contact,
        const UnallocatedCString& label,
        const Time time) const noexcept -> Batch final;
    auto RootNode(const PasswordPrompt& reason) const noexcept
        -> blockchain::crypto::HDKey final
    {
        return local_.get().Key();
    }

    PaymentCode(
        const api::Session& api,
        const api::session::Contacts& contacts,
        const crypto::Account& parent,
        const opentxs::PaymentCode& local,
        const opentxs::PaymentCode& remote,
        const proto::HDPath& path,
        const opentxs::blockchain::block::Txid& txid,
        const PasswordPrompt& reason,
        Identifier& id) noexcept(false);
    PaymentCode(
        const api::Session& api,
        const api::session::Contacts& contacts,
        const crypto::Account& parent,
        const SerializedType& serialized,
        Identifier& id,
        OTIdentifier&& contact) noexcept(false);

    ~PaymentCode() final = default;

private:
    static constexpr auto internal_type_{Subchain::Outgoing};
    static constexpr auto external_type_{Subchain::Incoming};
    static constexpr auto DefaultVersion = VersionNumber{1};
    static constexpr auto Bip47DirectionVersion = VersionNumber{1};
    static constexpr auto compare_ = [](const opentxs::PaymentCode& lhs,
                                        const opentxs::PaymentCode& rhs) {
        return lhs.ID() == rhs.ID();
    };

    using Compare = std::function<
        void(const opentxs::PaymentCode&, const opentxs::PaymentCode&)>;
    using Latest =
        LatestVersion<opentxs::PaymentCode, opentxs::PaymentCode, Compare>;

    VersionNumber version_;
    mutable UnallocatedSet<opentxs::blockchain::block::pTxid>
        outgoing_notifications_;
    mutable UnallocatedSet<opentxs::blockchain::block::pTxid>
        incoming_notifications_;
    mutable Latest local_;
    Latest remote_;
    const OTIdentifier contact_id_;

    auto account_already_exists(const rLock& lock) const noexcept -> bool final;
    auto get_contact() const noexcept -> OTIdentifier final
    {
        return contact_id_;
    }
    auto has_private(const PasswordPrompt& reason) const noexcept -> bool;
    auto save(const rLock& lock) const noexcept -> bool final;
    auto set_deterministic_contact(
        UnallocatedSet<OTIdentifier>& contacts) const noexcept -> void final
    {
        contacts.emplace(get_contact());
    }

    PaymentCode(const PaymentCode&) = delete;
    PaymentCode(PaymentCode&&) = delete;
    auto operator=(const PaymentCode&) -> PaymentCode& = delete;
    auto operator=(PaymentCode&&) -> PaymentCode& = delete;
};
}  // namespace opentxs::blockchain::crypto::implementation
