// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/crypto/key/asymmetric/Algorithm.hpp"
// IWYU pragma: no_include "opentxs/crypto/key/symmetric/Algorithm.hpp"
// IWYU pragma: no_include "opentxs/crypto/key/symmetric/Source.hpp"

#pragma once

#include <functional>
#include <memory>
#include <mutex>

#include "Proto.hpp"
#include "internal/api/Crypto.hpp"
#include "internal/crypto/library/Null.hpp"
#include "internal/crypto/library/OpenSSL.hpp"
#include "internal/crypto/library/Secp256k1.hpp"
#include "internal/crypto/library/Sodium.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/Version.hpp"
#include "opentxs/api/crypto/Config.hpp"
#include "opentxs/api/crypto/Crypto.hpp"
#include "opentxs/api/crypto/Encode.hpp"
#include "opentxs/api/crypto/Hash.hpp"
#include "opentxs/api/crypto/Util.hpp"
#include "opentxs/crypto/Bip32.hpp"
#include "opentxs/crypto/Bip39.hpp"
#include "opentxs/crypto/key/Types.hpp"
#include "opentxs/crypto/library/AsymmetricProvider.hpp"
#include "opentxs/crypto/library/EcdsaProvider.hpp"
#include "opentxs/crypto/library/SymmetricProvider.hpp"
#include "opentxs/util/Container.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace api
{
namespace crypto
{
class Config;
class Encode;
class Hash;
class Util;
}  // namespace crypto

class Crypto;
class Factory;
class Settings;
}  // namespace api

namespace crypto
{
namespace blank
{
class EcdsaProvider;
}  // namespace blank

namespace key
{
class Symmetric;
}  // namespace key

class HashingProvider;
class OpenSSL;
class Pbkdf2;
class Ripemd160;
class Secp256k1;
class Sodium;
}  // namespace crypto
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::api::imp
{
class Crypto final : public internal::Crypto
{
public:
    auto AsymmetricProvider(opentxs::crypto::key::asymmetric::Algorithm type)
        const noexcept -> const opentxs::crypto::AsymmetricProvider& final;
    auto BIP32() const noexcept -> const opentxs::crypto::Bip32& final;
    auto BIP39() const noexcept -> const opentxs::crypto::Bip39& final;
    auto Config() const noexcept -> const crypto::Config& final;
    auto EllipticProvider(opentxs::crypto::key::asymmetric::Algorithm type)
        const noexcept -> const opentxs::crypto::EcdsaProvider& final;
    auto Encode() const noexcept -> const crypto::Encode& final;
    auto Hash() const noexcept -> const crypto::Hash& final;
    auto Libsecp256k1() const noexcept
        -> const opentxs::crypto::Secp256k1& final;
    auto Libsodium() const noexcept -> const opentxs::crypto::Sodium& final;
    auto OpenSSL() const noexcept -> const opentxs::crypto::OpenSSL& final;
    auto SymmetricProvider(opentxs::crypto::key::symmetric::Algorithm type)
        const noexcept -> const opentxs::crypto::SymmetricProvider& final;
    auto SymmetricProvider(opentxs::crypto::key::symmetric::Source type)
        const noexcept -> const opentxs::crypto::SymmetricProvider& final;
    auto Util() const noexcept -> const crypto::Util& final;
    auto hasLibsecp256k1() const noexcept -> bool final;
    auto hasOpenSSL() const noexcept -> bool final;
    auto hasSodium() const noexcept -> bool final;

    auto Init(const api::Factory& factory) noexcept -> void final;

    Crypto(const api::Settings& settings) noexcept;

    ~Crypto() final;

private:
    using AType = opentxs::crypto::key::asymmetric::Algorithm;
    using SaType = opentxs::crypto::key::symmetric::Algorithm;
    using SsType = opentxs::crypto::key::symmetric::Source;
    using AMap = UnallocatedMap<AType, opentxs::crypto::AsymmetricProvider*>;
    using EMap = UnallocatedMap<AType, opentxs::crypto::EcdsaProvider*>;
    using SaMap = UnallocatedMap<SaType, opentxs::crypto::SymmetricProvider*>;
    using SsMap = UnallocatedMap<SsType, opentxs::crypto::SymmetricProvider*>;

    static const opentxs::crypto::blank::EcdsaProvider blank_;

    std::unique_ptr<api::crypto::Config> config_;
    std::unique_ptr<opentxs::crypto::Sodium> sodium_;
    std::unique_ptr<opentxs::crypto::OpenSSL> ssl_;
    const api::crypto::Util& util_;
    std::unique_ptr<opentxs::crypto::Secp256k1> secp256k1_;
    std::unique_ptr<opentxs::crypto::Bip39> bip39_p_;
    opentxs::crypto::Bip32 bip32_;
    const opentxs::crypto::Bip39& bip39_;
    std::unique_ptr<crypto::Encode> encode_;
    std::unique_ptr<crypto::Hash> hash_;
    const AMap asymmetric_map_;
    const EMap elliptic_map_;
    const SaMap symmetric_algorithm_map_;
    const SsMap symmetric_source_map_;

    auto Init() noexcept -> void;
    auto Init_Libsecp256k1() noexcept -> void;
    auto Init_OpenSSL() noexcept -> void;
    auto Init_Sodium() noexcept -> void;
    auto Cleanup() noexcept -> void;

    Crypto() = delete;
    Crypto(const Crypto&) = delete;
    Crypto(Crypto&&) = delete;
    auto operator=(const Crypto&) -> Crypto& = delete;
    auto operator=(Crypto&&) -> Crypto& = delete;
};
}  // namespace opentxs::api::imp
