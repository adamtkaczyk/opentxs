// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "internal/serialization/protobuf/verify/VerifyP2P.hpp"  // IWYU pragma: associated

namespace opentxs::proto
{
auto P2PBlockchainHelloAllowedP2PBlockchainChainState() noexcept
    -> const VersionMap&
{
    static const auto output = VersionMap{
        {1, {1, 1}},
    };

    return output;
}
}  // namespace opentxs::proto
