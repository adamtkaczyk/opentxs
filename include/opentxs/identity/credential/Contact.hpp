// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <cstdint>
#include <string>

#include "opentxs/Types.hpp"
#include "opentxs/identity/credential/Base.hpp"
#include "opentxs/identity/wot/claim/Types.hpp"

namespace opentxs
{
namespace api
{
class Session;
}  // namespace api

namespace proto
{
class Claim;
class ContactItem;
}  // namespace proto
}  // namespace opentxs

namespace opentxs
{
namespace identity
{
namespace credential
{
class OPENTXS_EXPORT Contact : virtual public Base
{
public:
    OPENTXS_NO_EXPORT static auto ClaimID(
        const api::Session& api,
        const std::string& nymid,
        const std::uint32_t section,
        const proto::ContactItem& item) -> std::string;
    static auto ClaimID(
        const api::Session& api,
        const std::string& nymid,
        const wot::claim::SectionType section,
        const wot::claim::ClaimType type,
        const std::int64_t start,
        const std::int64_t end,
        const std::string& value,
        const std::string& subtype) -> std::string;
    OPENTXS_NO_EXPORT static auto ClaimID(
        const api::Session& api,
        const proto::Claim& preimage) -> OTIdentifier;
    OPENTXS_NO_EXPORT static auto asClaim(
        const api::Session& api,
        const String& nymid,
        const std::uint32_t section,
        const proto::ContactItem& item) -> Claim;

    ~Contact() override = default;

protected:
    Contact() noexcept {}  // TODO Signable

private:
    Contact(const Contact&) = delete;
    Contact(Contact&&) = delete;
    auto operator=(const Contact&) -> Contact& = delete;
    auto operator=(Contact&&) -> Contact& = delete;
};
}  // namespace credential
}  // namespace identity
}  // namespace opentxs
