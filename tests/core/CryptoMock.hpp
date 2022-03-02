// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#pragma once

#include <gmock/gmock.h>
#include "internal/api/session/Crypto.hpp"
#include "opentxs/api/crypto/Blockchain.hpp"
#include "internal/crypto/library/OpenSSL.hpp"
#include "internal/crypto/library/Sodium.hpp"
#include "internal/crypto/library/Secp256k1.hpp"

namespace opentxs
{

class CryptoMock final : public api::session::internal::Crypto
{
public:
    CryptoMock() = default;

    MOCK_METHOD(
        const api::crypto::Asymmetric&,
        Asymmetric,
        (),
        (const, noexcept, final));

    MOCK_METHOD(
        const api::crypto::Blockchain&,
        Blockchain,
        (),
        (const, noexcept, final));

    MOCK_METHOD(const api::crypto::Seed&, Seed, (), (const, noexcept, final));

    MOCK_METHOD(
        const api::crypto::Symmetric&,
        Symmetric,
        (),
        (const, noexcept, final));

    MOCK_METHOD(crypto::Bip32&, BIP32, (), (const, noexcept, final));

    MOCK_METHOD(

        crypto::Bip39&,
        BIP39,
        (),
        (const, noexcept, final));

    MOCK_METHOD(api::crypto::Config&, Config, (), (const, noexcept, final));

    MOCK_METHOD(api::crypto::Encode&, Encode, (), (const, noexcept, final));

    MOCK_METHOD(api::crypto::Hash&, Hash, (), (const, noexcept, final));

    MOCK_METHOD(api::crypto::Util&, Util, (), (const, noexcept, final));

    MOCK_METHOD(void, Cleanup, (), (noexcept, final));

    MOCK_METHOD(void, PrepareShutdown, (), (noexcept, final));

    MOCK_METHOD(
        const opentxs::crypto::AsymmetricProvider&,
        AsymmetricProvider,
        (opentxs::crypto::key::asymmetric::Algorithm),
        (const, noexcept, final));

    MOCK_METHOD(
        const opentxs::crypto::EcdsaProvider&,
        EllipticProvider,
        (opentxs::crypto::key::asymmetric::Algorithm),
        (const, noexcept, final));

    MOCK_METHOD(
        const opentxs::crypto::Secp256k1&,
        Libsecp256k1,
        (),
        (const, noexcept, final));

    MOCK_METHOD(
        const opentxs::crypto::Sodium&,
        Libsodium,
        (),
        (const, noexcept, final));

    MOCK_METHOD(
        const opentxs::crypto::OpenSSL&,
        OpenSSL,
        (),
        (const, noexcept, final));

    MOCK_METHOD(
        const opentxs::crypto::SymmetricProvider&,
        SymmetricProvider,
        (opentxs::crypto::key::symmetric::Algorithm),
        (const, noexcept, final));

    MOCK_METHOD(
        const opentxs::crypto::SymmetricProvider&,
        SymmetricProvider,
        (opentxs::crypto::key::symmetric::Source),
        (const, noexcept, final));

    MOCK_METHOD(bool, hasLibsecp256k1, (), (const, noexcept, final));

    MOCK_METHOD(bool, hasOpenSSL, (), (const, noexcept, final));

    MOCK_METHOD(bool, hasSodium, (), (const, noexcept, final));

    MOCK_METHOD(void, Init, (const api::Factory&), (noexcept, final));

    MOCK_METHOD(
        void,
        Init,
        (const std::shared_ptr<const api::crypto::Blockchain>&),
        (noexcept, final));
};

}  // namespace opentxs