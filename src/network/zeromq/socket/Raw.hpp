// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <zmq.h>
#include <chrono>
#include <cstddef>
#include <memory>

#include "internal/network/zeromq/Types.hpp"
#include "internal/network/zeromq/socket/Raw.hpp"
#include "opentxs/network/zeromq/message/Message.hpp"
#include "opentxs/network/zeromq/socket/SocketType.hpp"
#include "opentxs/network/zeromq/socket/Types.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Time.hpp"
#include "util/ByteLiterals.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace network
{
namespace zeromq
{
namespace socket
{
class Raw;
}  // namespace socket

class Context;
class Message;
}  // namespace zeromq
}  // namespace network
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::network::zeromq::socket
{
class Raw::Imp
{
public:
    const SocketID id_{GetSocketID()};

    auto ID() const noexcept -> SocketID { return id_; }
    virtual auto Type() const noexcept -> socket::Type
    {
        return socket::Type::Error;
    }
    virtual auto Bind(const char*) noexcept -> bool { return {}; }
    virtual auto ClearSubscriptions() noexcept -> bool { return {}; }
    virtual auto Close() noexcept -> void {}
    virtual auto Connect(const char*) noexcept -> bool { return {}; }
    virtual auto Disconnect(const char*) noexcept -> bool { return {}; }
    virtual auto DisconnectAll() noexcept -> bool { return {}; }
    virtual auto Native() noexcept -> void* { return nullptr; }
    virtual auto Send(Message&&) noexcept -> bool { return {}; }
    virtual auto SendDeferred(Message&&) noexcept -> bool { return {}; }
    virtual auto SendExternal(Message&&) noexcept -> bool { return {}; }
    virtual auto SetExposedUntrusted() noexcept -> bool { return false; }
    virtual auto SetIncomingHWM(int) noexcept -> bool { return {}; }
    virtual auto SetLinger(int) noexcept -> bool { return {}; }
    virtual auto SetMaxMessageSize(std::size_t) noexcept -> bool { return {}; }
    virtual auto SetMonitor(const char*, int) noexcept -> bool { return {}; }
    virtual auto SetOutgoingHWM(int) noexcept -> bool { return {}; }
    virtual auto SetPrivateKey(ReadView) noexcept -> bool { return {}; }
    virtual auto SetRouterHandover(bool) noexcept -> bool { return {}; }
    virtual auto SetRoutingID(ReadView) noexcept -> bool { return {}; }
    virtual auto SetSendTimeout(std::chrono::milliseconds) noexcept -> bool
    {
        return {};
    }
    virtual auto SetZAPDomain(ReadView) noexcept -> bool { return {}; }
    virtual auto Stop() noexcept -> void {}
    virtual auto Unbind(const char*) noexcept -> bool { return {}; }
    virtual auto UnbindAll() noexcept -> bool { return {}; }

    Imp() = default;

    virtual ~Imp() = default;

private:
    Imp(const Imp&) = delete;
    Imp(Imp&&) = delete;
    auto operator=(const Imp&) -> Imp& = delete;
    auto operator=(Imp&&) -> Imp& = delete;
};
}  // namespace opentxs::network::zeromq::socket

namespace opentxs::network::zeromq::socket::implementation
{
class Raw final : public socket::Raw::Imp
{
public:
    auto Type() const noexcept -> socket::Type final { return type_; }

    auto Bind(const char* endpoint) noexcept -> bool final;
    auto ClearSubscriptions() noexcept -> bool final;
    auto Close() noexcept -> void final;
    auto Connect(const char* endpoint) noexcept -> bool final;
    auto Disconnect(const char* endpoint) noexcept -> bool final;
    auto DisconnectAll() noexcept -> bool final;
    auto Native() noexcept -> void* final { return socket_.get(); }
    auto Send(Message&& msg) noexcept -> bool final;
    auto SendDeferred(Message&& msg) noexcept -> bool final;
    auto SendExternal(Message&& msg) noexcept -> bool final;
    auto SetExposedUntrusted() noexcept -> bool final;
    auto SetIncomingHWM(int value) noexcept -> bool final;
    auto SetLinger(int value) noexcept -> bool final;
    auto SetMaxMessageSize(std::size_t bytes) noexcept -> bool final;
    auto SetMonitor(const char* endpoint, int events) noexcept -> bool final;
    auto SetOutgoingHWM(int value) noexcept -> bool final;
    auto SetPrivateKey(ReadView key) noexcept -> bool final;
    auto SetRouterHandover(bool value) noexcept -> bool final;
    auto SetRoutingID(ReadView key) noexcept -> bool final;
    auto SetSendTimeout(std::chrono::milliseconds value) noexcept -> bool final;
    auto SetZAPDomain(ReadView domain) noexcept -> bool final;
    auto Stop() noexcept -> void final;
    auto Unbind(const char* endpoint) noexcept -> bool final;
    auto UnbindAll() noexcept -> bool final;

    Raw(const Context& context, const socket::Type type) noexcept;

    ~Raw() final;

private:
    using Socket = std::unique_ptr<void, decltype(&::zmq_close)>;
    using Endpoints = UnallocatedSet<UnallocatedCString>;

    static constexpr auto default_hwm_ = int{0};
    static constexpr auto untrusted_hwm_ = int{1024};
    static constexpr auto untrusted_max_message_size_ = std::size_t{32_MiB};
    static constexpr auto default_send_timeout_ = 0ms;

    const socket::Type type_;
    Socket socket_;
    Endpoints bound_endpoints_;
    Endpoints connected_endpoints_;

    auto record_endpoint(Endpoints& out) noexcept -> void;
    auto send(Message&& msg, const int flags) noexcept -> bool;

    Raw() = delete;
    Raw(const Raw&) = delete;
    Raw(Raw&&) = delete;
    auto operator=(const Raw&) -> Raw& = delete;
    auto operator=(Raw&&) -> Raw& = delete;
};
}  // namespace opentxs::network::zeromq::socket::implementation
