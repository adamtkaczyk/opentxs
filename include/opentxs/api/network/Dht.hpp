// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include <string>

namespace opentxs
{
namespace api
{
namespace network
{
namespace internal
{
class Dht;
}  // namespace internal
}  // namespace network
}  // namespace api
}  // namespace opentxs

namespace opentxs::api::network
{
class OPENTXS_EXPORT Dht
{
public:
    virtual auto GetPublicNym(const std::string& key) const noexcept
        -> void = 0;
    virtual auto GetServerContract(const std::string& key) const noexcept
        -> void = 0;
    virtual auto GetUnitDefinition(const std::string& key) const noexcept
        -> void = 0;
    virtual auto Insert(const std::string& key, const std::string& value)
        const noexcept -> void = 0;
    OPENTXS_NO_EXPORT virtual auto Internal() const noexcept
        -> const internal::Dht& = 0;

    OPENTXS_NO_EXPORT virtual auto Internal() noexcept -> internal::Dht& = 0;

    OPENTXS_NO_EXPORT virtual ~Dht() = default;

protected:
    Dht() = default;

private:
    Dht(const Dht&) = delete;
    Dht(Dht&&) = delete;
    auto operator=(const Dht&) -> Dht& = delete;
    auto operator=(Dht&&) -> Dht& = delete;
};
}  // namespace opentxs::api::network
