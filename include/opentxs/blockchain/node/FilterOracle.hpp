// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#include "opentxs/blockchain/bitcoin/cfilter/Types.hpp"
#include "opentxs/blockchain/block/Types.hpp"
#include "opentxs/util/Container.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace blockchain
{
class GCS;
}  // namespace blockchain
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::blockchain::node
{
class OPENTXS_EXPORT FilterOracle
{
public:
    virtual auto DefaultType() const noexcept -> cfilter::Type = 0;
    virtual auto FilterTip(const cfilter::Type type) const noexcept
        -> block::Position = 0;
    virtual auto LoadFilter(const cfilter::Type type, const block::Hash& block)
        const noexcept -> std::unique_ptr<const GCS> = 0;
    virtual auto LoadFilters(
        const cfilter::Type type,
        const Vector<block::pHash>& blocks) const noexcept
        -> Vector<std::unique_ptr<const GCS>> = 0;
    virtual auto LoadFilterHeader(
        const cfilter::Type type,
        const block::Hash& block) const noexcept -> cfilter::pHeader = 0;

    virtual ~FilterOracle() = default;

protected:
    FilterOracle() noexcept = default;

private:
    FilterOracle(const FilterOracle&) = delete;
    FilterOracle(FilterOracle&&) = delete;
    auto operator=(const FilterOracle&) -> FilterOracle& = delete;
    auto operator=(FilterOracle&&) -> FilterOracle& = delete;
};
}  // namespace opentxs::blockchain::node
