// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <opentxs/opentxs.hpp>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string_view>

namespace ot = opentxs;

namespace ottest
{
struct Server;
}  // namespace ottest

namespace ottest
{
class User
{
public:
    const ot::UnallocatedCString words_;
    const ot::UnallocatedCString passphrase_;
    const ot::UnallocatedCString name_;
    const ot::UnallocatedCString name_lower_;
    const ot::api::session::Client* api_;
    bool init_;
    ot::UnallocatedCString seed_id_;
    std::uint32_t index_;
    ot::Nym_p nym_;
    ot::OTNymID nym_id_;
    ot::UnallocatedCString payment_code_;
    ot::Amount expected_balance_ = 0;

    auto Account(std::string_view type) const noexcept -> const ot::Identifier&;
    auto Contact(std::string_view contact) const noexcept
        -> const ot::Identifier&;
    auto PaymentCode() const -> ot::PaymentCode;
    auto Reason() const noexcept -> ot::OTPasswordPrompt;
    auto SetAccount(std::string_view type, std::string_view id) const noexcept
        -> bool;
    auto SetAccount(std::string_view type, const ot::Identifier& id)
        const noexcept -> bool;
    auto SetContact(std::string_view contact, std::string_view id)
        const noexcept -> bool;
    auto SetContact(std::string_view contact, const ot::Identifier& id)
        const noexcept -> bool;

    auto init(
        const ot::api::session::Client& api,
        const ot::identity::Type type = ot::identity::Type::individual,
        const std::uint32_t index = 0,
        const ot::crypto::SeedStyle seed =
            ot::crypto::SeedStyle::BIP39) noexcept -> bool;
    auto init(
        const ot::api::session::Client& api,
        const Server& server,
        const ot::identity::Type type = ot::identity::Type::individual,
        const std::uint32_t index = 0,
        const ot::crypto::SeedStyle seed =
            ot::crypto::SeedStyle::BIP39) noexcept -> bool;
    auto init_custom(
        const ot::api::session::Client& api,
        const Server& server,
        const std::function<void(User&)> custom,
        const ot::identity::Type type = ot::identity::Type::individual,
        const std::uint32_t index = 0,
        const ot::crypto::SeedStyle seed =
            ot::crypto::SeedStyle::BIP39) noexcept -> void;
    auto init_custom(
        const ot::api::session::Client& api,
        const std::function<void(User&)> custom,
        const ot::identity::Type type = ot::identity::Type::individual,
        const std::uint32_t index = 0,
        const ot::crypto::SeedStyle seed =
            ot::crypto::SeedStyle::BIP39) noexcept -> void;

    User(
        std::string_view words,
        std::string_view name,
        std::string_view passphrase = {}) noexcept;

private:
    mutable std::mutex lock_;
    mutable ot::Map<ot::CString, ot::OTIdentifier> contacts_;
    mutable ot::Map<ot::CString, ot::OTIdentifier> accounts_;

    auto init_basic(
        const ot::api::session::Client& api,
        const ot::identity::Type type,
        const std::uint32_t index,
        const ot::crypto::SeedStyle seed) noexcept -> bool;

    User(const User&) = delete;
    User(User&&) = delete;
    User& operator=(const User&) = delete;
    User& operator=(User&&) = delete;
};
}  // namespace ottest
