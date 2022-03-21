// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <string_view>

#include "internal/api/network/Blockchain.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/util/Container.hpp"

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
namespace zeromq
{
class Context;
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::network::p2p
{
class Server
{
public:
    using Chain = opentxs::blockchain::Type;

    auto Endpoint(const Chain chain) const noexcept -> std::string_view;

    auto Disable(const Chain chain) noexcept -> void;
    auto Enable(const Chain chain) noexcept -> void;
    auto Start(
        const std::string_view sync,
        const std::string_view publicSync,
        const std::string_view update,
        const std::string_view publicUpdate) noexcept -> bool;

    Server(const api::Session& api, const zeromq::Context& zmq) noexcept;

    ~Server();

private:
    class Imp;

    Imp* imp_;

    Server() = delete;
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    auto operator=(const Server&) -> Server& = delete;
    auto operator=(Server&&) -> Server& = delete;
};
}  // namespace opentxs::network::p2p
