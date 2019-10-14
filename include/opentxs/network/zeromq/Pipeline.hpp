// Copyright (c) 2010-2019 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_NETWORK_ZEROMQ_PIPELINE_HPP
#define OPENTXS_NETWORK_ZEROMQ_PIPELINE_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/network/zeromq/socket/Socket.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/Message.hpp"
#include "opentxs/Proto.hpp"

#ifdef SWIG
// clang-format off
%rename(ZMQPipeline) opentxs::network::zeromq::Pipeline;
%template(OTZMQPipeline) opentxs::Pimpl<opentxs::network::zeromq::Pipeline>;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace network
{
namespace zeromq
{
class Pipeline
{
public:
    EXPORT virtual bool Close() const noexcept = 0;
    template <typename Input>
    EXPORT bool Push(const Input& data) const noexcept
    {
        return push(Context().Message(data));
    }
    EXPORT virtual const zeromq::Context& Context() const noexcept = 0;

    EXPORT virtual ~Pipeline() = default;

protected:
    Pipeline() noexcept = default;

private:
    friend OTZMQPipeline;

    virtual Pipeline* clone() const noexcept = 0;
    virtual bool push(network::zeromq::Message& data) const noexcept = 0;

    Pipeline(const Pipeline&) = delete;
    Pipeline(Pipeline&&) = delete;
    Pipeline& operator=(const Pipeline&) = delete;
    Pipeline& operator=(Pipeline&&) = delete;
};
}  // namespace zeromq
}  // namespace network
}  // namespace opentxs
#endif
