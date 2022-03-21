// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                  // IWYU pragma: associated
#include "1_Internal.hpp"                // IWYU pragma: associated
#include "opentxs/network/p2p/Data.hpp"  // IWYU pragma: associated

#include <memory>
#include <stdexcept>
#include <utility>

#include "Proto.tpp"
#include "internal/network/p2p/Factory.hpp"
#include "internal/serialization/protobuf/Check.hpp"
#include "internal/serialization/protobuf/verify/BlockchainP2PSync.hpp"
#include "internal/util/LogMacros.hpp"
#include "network/p2p/Base.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/api/session/Factory.hpp"
#include "opentxs/api/session/Session.hpp"
#include "opentxs/blockchain/block/Header.hpp"
#include "opentxs/network/p2p/Block.hpp"
#include "opentxs/network/p2p/MessageType.hpp"
#include "opentxs/network/p2p/State.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/util/WorkType.hpp"
#include "serialization/protobuf/BlockchainP2PSync.pb.h"

namespace opentxs::factory
{
auto BlockchainSyncData() noexcept -> network::p2p::Data
{
    using ReturnType = network::p2p::Data;

    return {std::make_unique<ReturnType::Imp>().release()};
}

auto BlockchainSyncData(
    WorkType type,
    network::p2p::State state,
    network::p2p::SyncData blocks,
    ReadView cfheader) noexcept -> network::p2p::Data
{
    using ReturnType = network::p2p::Data;

    return {std::make_unique<ReturnType::Imp>(
                type, std::move(state), std::move(blocks), cfheader)
                .release()};
}

auto BlockchainSyncData_p(
    WorkType type,
    network::p2p::State state,
    network::p2p::SyncData blocks,
    ReadView cfheader) noexcept -> std::unique_ptr<network::p2p::Data>
{
    using ReturnType = network::p2p::Data;

    return std::make_unique<ReturnType>(
        std::make_unique<ReturnType::Imp>(
            type, std::move(state), std::move(blocks), cfheader)
            .release());
}
}  // namespace opentxs::factory

namespace opentxs::network::p2p
{
class Data::Imp final : public Base::Imp
{
public:
    Data* parent_;

    auto asData() const noexcept -> const Data& final
    {
        if (nullptr != parent_) {

            return *parent_;
        } else {

            return Base::Imp::asData();
        }
    }

    Imp() noexcept
        : Base::Imp()
        , parent_(nullptr)
    {
    }
    Imp(WorkType type,
        p2p::State state,
        SyncData blocks,
        ReadView cfheader) noexcept(false)
        : Base::Imp(
              Imp::default_version_,
              translate(type),
              [&] {
                  auto out = StateData{};
                  out.emplace_back(std::move(state));

                  return out;
              }(),
              UnallocatedCString{cfheader},
              std::move(blocks))
        , parent_(nullptr)
    {
        switch (type_) {
            case MessageType::sync_reply: {
            } break;
            case MessageType::new_block_header: {
                if (0 == blocks_.size()) {
                    throw std::runtime_error{"Missing blocks"};
                }
            } break;
            default: {

                throw std::runtime_error{"Incorrect type"};
            }
        }
    }

private:
    Imp(const Imp&) = delete;
    Imp(Imp&&) = delete;
    auto operator=(const Imp&) -> Imp& = delete;
    auto operator=(Imp&&) -> Imp& = delete;
};

Data::Data(Imp* imp) noexcept
    : Base(imp)
    , imp_(imp)
{
    imp_->parent_ = this;
}

auto Data::Add(ReadView data) noexcept -> bool
{
    const auto proto = proto::Factory<proto::BlockchainP2PSync>(data);

    if (false == proto::Validate(proto, VERBOSE)) { return false; }

    auto& blocks = const_cast<UnallocatedVector<Block>&>(imp_->blocks_);

    if (0 < blocks.size()) {
        const auto expected = blocks.back().Height() + 1;
        const auto height =
            static_cast<opentxs::blockchain::block::Height>(proto.height());

        if (height != expected) {
            LogError()(OT_PRETTY_CLASS())("Non-contiguous sync data").Flush();

            return false;
        }
    }

    try {
        blocks.emplace_back(proto);

        return true;
    } catch (const std::exception& e) {
        LogError()(OT_PRETTY_CLASS())(e.what()).Flush();

        return false;
    }
}

auto Data::Blocks() const noexcept -> const SyncData& { return imp_->blocks_; }

auto Data::LastPosition(const api::Session& api) const noexcept
    -> opentxs::blockchain::block::Position
{
    static const auto blank =
        opentxs::blockchain::block::Position{-1, api.Factory().Data()};
#if OT_BLOCKCHAIN
    const auto& blocks = imp_->blocks_;

    if (0u == blocks.size()) { return blank; }

    const auto& last = blocks.back();
    const auto header = api.Factory().BlockHeader(last.Chain(), last.Header());

    if (!header) { return blank; }

    return {last.Height(), header->Hash()};
#else

    return blank;
#endif  // OT_BLOCKCHAIN
}

auto Data::PreviousCfheader() const noexcept -> ReadView
{
    return imp_->endpoint_;
}

auto Data::State() const noexcept -> const p2p::State&
{
    OT_ASSERT(0 < imp_->state_.size());

    return imp_->state_.front();
}

Data::~Data()
{
    if (nullptr != Data::imp_) {
        delete Data::imp_;
        Data::imp_ = nullptr;
        Base::imp_ = nullptr;
    }
}
}  // namespace opentxs::network::p2p
