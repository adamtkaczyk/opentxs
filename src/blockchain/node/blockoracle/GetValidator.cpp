// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"                     // IWYU pragma: associated
#include "1_Internal.hpp"                   // IWYU pragma: associated
#include "blockchain/node/BlockOracle.hpp"  // IWYU pragma: associated

namespace opentxs::blockchain::node::implementation
{
auto BlockOracle::get_validator(
    [[maybe_unused]] const blockchain::Type chain,
    [[maybe_unused]] const node::HeaderOracle& headers) noexcept
    -> std::unique_ptr<const internal::BlockValidator>
{
    return std::make_unique<internal::BlockValidator>();
}
}  // namespace opentxs::blockchain::node::implementation
