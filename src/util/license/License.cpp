// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "0_stdafx.hpp"    // IWYU pragma: associated
#include "1_Internal.hpp"  // IWYU pragma: associated
#include "opentxs/OT.hpp"  // IWYU pragma: associated

#include "util/license/License.hpp"

namespace opentxs
{
auto LicenseData() noexcept -> const LicenseMap&
{
    static const auto map = [] {
        auto out = LicenseMap{};
        license_argon(out);
        license_base58(out);
        license_base64(out);
        license_bech32(out);
        license_chaiscript(out);
        license_irrxml(out);
        license_libguarded(out);
        license_lucre(out);
        license_opentxs(out);
        license_packetcrypt(out);
        license_protobuf(out);
        license_secp256k1(out);
        license_simpleini(out);

        return out;
    }();

    return map;
}
}  // namespace opentxs
