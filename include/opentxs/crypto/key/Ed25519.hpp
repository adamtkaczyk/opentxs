// Copyright (c) 2010-2019 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_CRYPTO_KEY_ED25519_HPP
#define OPENTXS_CRYPTO_KEY_ED25519_HPP

#include "opentxs/Forward.hpp"

#if OT_CRYPTO_SUPPORTED_KEY_ED25519
#if OT_CRYPTO_SUPPORTED_KEY_HD
#include "opentxs/crypto/key/HD.hpp"
#else
#include "opentxs/crypto/key/EllipticCurve.hpp"
#endif  // OT_CRYPTO_SUPPORTED_KEY_HD

namespace opentxs
{
namespace crypto
{
namespace key
{
class Ed25519 :
#if OT_CRYPTO_SUPPORTED_KEY_HD
    virtual public HD
#else
    virtual public EllipticCurve
#endif  // OT_CRYPTO_SUPPORTED_KEY_HD
{
public:
    EXPORT ~Ed25519() override = default;

protected:
    Ed25519() = default;

private:
    Ed25519(const Ed25519&) = delete;
    Ed25519(Ed25519&&) = delete;
    Ed25519& operator=(const Ed25519&) = delete;
    Ed25519& operator=(Ed25519&&) = delete;
};
}  // namespace key
}  // namespace crypto
}  // namespace opentxs
#endif  // OT_CRYPTO_SUPPORTED_KEY_ED25519
#endif
