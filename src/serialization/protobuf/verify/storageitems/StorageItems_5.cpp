// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "internal/serialization/protobuf/verify/StorageItems.hpp"  // IWYU pragma: associated

#include "serialization/protobuf/StorageItems.pb.h"
#include "serialization/protobuf/verify/Check.hpp"

#define PROTO_NAME "storage item index"

namespace opentxs::proto
{
auto CheckProto_5(const StorageItems& input, const bool silent) -> bool
{
    OPTIONAL_IDENTIFIER(creds);
    OPTIONAL_IDENTIFIER(nyms);
    OPTIONAL_IDENTIFIER(servers);
    OPTIONAL_IDENTIFIER(units);
    OPTIONAL_IDENTIFIER(seeds);
    OPTIONAL_IDENTIFIER(contacts);
    OPTIONAL_IDENTIFIER(blockchaintransactions);
    OPTIONAL_IDENTIFIER(accounts);
    OPTIONAL_IDENTIFIER(notary);
    CHECK_EXCLUDED(master_secret);

    return true;
}
}  // namespace opentxs::proto
