// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"    // IWYU pragma: associated
#include "1_Internal.hpp"  // IWYU pragma: associated
#include "blockchain/p2p/bitcoin/message/Cfcheckpt.hpp"  // IWYU pragma: associated

#include <cstddef>
#include <cstring>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <utility>

#include "blockchain/p2p/bitcoin/Header.hpp"
#include "blockchain/p2p/bitcoin/Message.hpp"
#include "internal/blockchain/bitcoin/Bitcoin.hpp"
#include "internal/blockchain/p2p/bitcoin/Bitcoin.hpp"
#include "internal/blockchain/p2p/bitcoin/message/Message.hpp"
#include "internal/util/LogMacros.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/blockchain/p2p/Types.hpp"
#include "opentxs/core/Data.hpp"
#include "opentxs/network/blockchain/bitcoin/CompactSize.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/Pimpl.hpp"

namespace opentxs::factory
{
auto BitcoinP2PCfcheckpt(
    const api::Session& api,
    std::unique_ptr<blockchain::p2p::bitcoin::Header> pHeader,
    const blockchain::p2p::bitcoin::ProtocolVersion version,
    const void* payload,
    const std::size_t size)
    -> blockchain::p2p::bitcoin::message::internal::Cfcheckpt*
{
    namespace bitcoin = blockchain::p2p::bitcoin;
    using ReturnType = bitcoin::message::implementation::Cfcheckpt;

    if (false == bool(pHeader)) {
        LogError()("opentxs::factory::")(__func__)(": Invalid header").Flush();

        return nullptr;
    }

    const auto& header = *pHeader;
    ReturnType::BitcoinFormat raw;
    auto expectedSize = sizeof(raw);

    if (expectedSize > size) {
        LogError()("opentxs::factory::")(__func__)(
            ": Payload too short (begin)")
            .Flush();

        return nullptr;
    }

    auto* it{static_cast<const std::byte*>(payload)};
    std::memcpy(reinterpret_cast<std::byte*>(&raw), it, sizeof(raw));
    it += sizeof(raw);
    expectedSize += sizeof(std::byte);

    if (expectedSize > size) {
        LogError()("opentxs::factory::")(__func__)(
            ": Payload too short (compactsize)")
            .Flush();

        return nullptr;
    }

    std::size_t count{0};
    const bool haveCount =
        network::blockchain::bitcoin::DecodeSize(it, expectedSize, size, count);

    if (false == haveCount) {
        LogError()(__func__)(": CompactSize incomplete").Flush();

        return nullptr;
    }

    UnallocatedVector<blockchain::cfilter::pHash> headers{};

    if (count > 0) {
        for (std::size_t i{0}; i < count; ++i) {
            expectedSize += sizeof(bitcoin::message::HashField);

            if (expectedSize > size) {
                LogError()("opentxs::factory::")(__func__)(
                    ": Filter header entries incomplete at entry index ")(i)
                    .Flush();

                return nullptr;
            }

            headers.emplace_back(
                Data::Factory(it, sizeof(bitcoin::message::HashField)));
            it += sizeof(bitcoin::message::HashField);
        }
    }

    return new ReturnType(
        api,
        std::move(pHeader),
        raw.Type(header.Network()),
        raw.Hash(),
        headers);
}

auto BitcoinP2PCfcheckpt(
    const api::Session& api,
    const blockchain::Type network,
    const blockchain::cfilter::Type type,
    const blockchain::cfilter::Hash& stop,
    const UnallocatedVector<blockchain::cfilter::pHash>& headers)
    -> blockchain::p2p::bitcoin::message::internal::Cfcheckpt*
{
    namespace bitcoin = blockchain::p2p::bitcoin;
    using ReturnType = bitcoin::message::implementation::Cfcheckpt;

    return new ReturnType(api, network, type, stop, headers);
}
}  // namespace opentxs::factory

namespace opentxs::blockchain::p2p::bitcoin::message::implementation
{
Cfcheckpt::Cfcheckpt(
    const api::Session& api,
    const blockchain::Type network,
    const cfilter::Type type,
    const cfilter::Hash& stop,
    const UnallocatedVector<cfilter::pHash>& headers) noexcept
    : Message(api, network, bitcoin::Command::cfcheckpt)
    , type_(type)
    , stop_(stop)
    , payload_(headers)
{
    init_hash();
}

Cfcheckpt::Cfcheckpt(
    const api::Session& api,
    std::unique_ptr<Header> header,
    const cfilter::Type type,
    const cfilter::Hash& stop,
    const UnallocatedVector<cfilter::pHash>& headers) noexcept
    : Message(api, std::move(header))
    , type_(type)
    , stop_(stop)
    , payload_(headers)
{
}

auto Cfcheckpt::payload(AllocateOutput out) const noexcept -> bool
{
    try {
        if (!out) { throw std::runtime_error{"invalid output allocator"}; }

        static constexpr auto fixed = sizeof(BitcoinFormat);
        const auto hashes = payload_.size();
        const auto cs = CompactSize(hashes).Encode();
        const auto bytes = fixed + cs.size() + (hashes * standard_hash_size_);
        auto output = out(bytes);

        if (false == output.valid(bytes)) {
            throw std::runtime_error{"failed to allocate output space"};
        }

        const auto data = BitcoinFormat{header().Network(), type_, stop_};
        auto* i = output.as<std::byte>();
        std::memcpy(i, static_cast<const void*>(&data), fixed);
        std::advance(i, fixed);
        std::memcpy(i, cs.data(), cs.size());
        std::advance(i, cs.size());

        for (const auto& hash : payload_) {
            std::memcpy(i, hash->data(), standard_hash_size_);
            std::advance(i, standard_hash_size_);
        }

        return true;
    } catch (const std::exception& e) {
        LogError()(OT_PRETTY_CLASS())(e.what()).Flush();

        return false;
    }
}
}  // namespace opentxs::blockchain::p2p::bitcoin::message::implementation
