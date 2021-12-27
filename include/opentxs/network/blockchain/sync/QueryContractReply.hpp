// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/core/contract/ContractType.hpp"

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include "opentxs/core/contract/Types.hpp"
#include "opentxs/network/blockchain/sync/Base.hpp"
#include "opentxs/util/Bytes.hpp"

namespace opentxs
{
class Identifier;
}  // namespace opentxs

namespace opentxs::network::blockchain::sync
{
class OPENTXS_EXPORT QueryContractReply final : public Base
{
public:
    class Imp;

    auto ContractType() const noexcept -> contract::Type;
    auto ID() const noexcept -> const Identifier&;
    auto Payload() const noexcept -> ReadView;

    OPENTXS_NO_EXPORT QueryContractReply(Imp* imp) noexcept;

    ~QueryContractReply() final;

private:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow-field"
    Imp* imp_;
#pragma GCC diagnostic pop

    QueryContractReply(const QueryContractReply&) = delete;
    QueryContractReply(QueryContractReply&&) = delete;
    auto operator=(const QueryContractReply&) -> QueryContractReply& = delete;
    auto operator=(QueryContractReply&&) -> QueryContractReply& = delete;
};
}  // namespace opentxs::network::blockchain::sync
