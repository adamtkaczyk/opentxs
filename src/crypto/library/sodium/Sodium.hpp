// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "Proto.hpp"
#include "crypto/library/AsymmetricProvider.hpp"
#include "crypto/library/EcdsaProvider.hpp"
#include "crypto/library/Pbkdf2.hpp"
#include "crypto/library/Ripemd160.hpp"
#include "internal/crypto/library/Sodium.hpp"
#include "opentxs/Bytes.hpp"
#include "opentxs/Version.hpp"
#include "opentxs/core/Secret.hpp"
#include "opentxs/crypto/HashType.hpp"
#include "opentxs/crypto/SecretStyle.hpp"
#include "opentxs/crypto/Types.hpp"
#include "opentxs/crypto/key/asymmetric/Role.hpp"
#include "opentxs/crypto/key/symmetric/Algorithm.hpp"
#include "opentxs/crypto/key/symmetric/Source.hpp"
#include "opentxs/identity/Types.hpp"

namespace opentxs
{
namespace api
{
namespace internal
{
struct Core;
}  // namespace internal

class Crypto;
}  // namespace api

namespace crypto
{
namespace key
{
class Asymmetric;
}  // namespace key
}  // namespace crypto

namespace proto
{
class Ciphertext;
}  // namespace proto

class Data;
class NymParameters;
class OTPassword;
class PasswordPrompt;
class Secret;
}  // namespace opentxs

namespace opentxs::crypto::implementation
{
class Sodium final : virtual public crypto::Sodium,
#if OT_CRYPTO_SUPPORTED_KEY_ED25519
                     public AsymmetricProvider,
                     public EcdsaProvider,
#endif  // OT_CRYPTO_SUPPORTED_KEY_ED25519
                     public Ripemd160,
                     public Pbkdf2
{
public:
    auto Digest(
        const crypto::HashType hashType,
        const std::uint8_t* input,
        const size_t inputSize,
        std::uint8_t* output) const -> bool final;
    auto Generate(
        const ReadView input,
        const ReadView salt,
        const std::uint64_t N,
        const std::uint32_t r,
        const std::uint32_t p,
        const std::size_t bytes,
        AllocateOutput writer) const noexcept -> bool final;
    auto HMAC(
        const crypto::HashType hashType,
        const std::uint8_t* input,
        const size_t inputSize,
        const std::uint8_t* key,
        const size_t keySize,
        std::uint8_t* output) const -> bool final;
#if OT_CRYPTO_SUPPORTED_KEY_ED25519
    auto PubkeyAdd(
        const ReadView pubkey,
        const ReadView scalar,
        const AllocateOutput result) const noexcept -> bool final;
    auto RandomKeypair(
        const AllocateOutput privateKey,
        const AllocateOutput publicKey,
        const opentxs::crypto::key::asymmetric::Role role,
        const NymParameters& options,
        const AllocateOutput params) const noexcept -> bool final;
#endif  // OT_CRYPTO_SUPPORTED_KEY_ED25519
    auto RandomizeMemory(void* destination, const std::size_t size) const
        -> bool final;
#if OT_CRYPTO_SUPPORTED_KEY_ED25519
    auto ScalarAdd(
        const ReadView lhs,
        const ReadView rhs,
        const AllocateOutput result) const noexcept -> bool final;
    auto ScalarMultiplyBase(const ReadView scalar, const AllocateOutput result)
        const noexcept -> bool final;
    auto SharedSecret(
        const ReadView publicKey,
        const ReadView privateKey,
        const SecretStyle style,
        Secret& secret) const noexcept -> bool final;
    auto Sign(
        const ReadView plaintext,
        const ReadView key,
        const crypto::HashType hash,
        const AllocateOutput signature) const -> bool final;
    auto Verify(
        const ReadView plaintext,
        const ReadView theKey,
        const ReadView signature,
        const crypto::HashType hashType) const -> bool final;
#endif  // OT_CRYPTO_SUPPORTED_KEY_ED25519

    Sodium(const api::Crypto& crypto) noexcept;

    ~Sodium() final = default;

private:
    static const opentxs::crypto::key::symmetric::Algorithm DEFAULT_MODE{
        opentxs::crypto::key::symmetric::Algorithm::ChaCha20Poly1305};

    static auto blank_private() noexcept -> ReadView;

    auto Decrypt(
        const proto::Ciphertext& ciphertext,
        const std::uint8_t* key,
        const std::size_t keySize,
        std::uint8_t* plaintext) const -> bool final;
    auto DefaultMode() const -> opentxs::crypto::key::symmetric::Algorithm final
    {
        return DEFAULT_MODE;
    }
    auto Derive(
        const std::uint8_t* input,
        const std::size_t inputSize,
        const std::uint8_t* salt,
        const std::size_t saltSize,
        const std::uint64_t operations,
        const std::uint64_t difficulty,
        const crypto::key::symmetric::Source type,
        std::uint8_t* output,
        std::size_t outputSize) const -> bool final;
    auto Encrypt(
        const std::uint8_t* input,
        const std::size_t inputSize,
        const std::uint8_t* key,
        const std::size_t keySize,
        proto::Ciphertext& ciphertext) const -> bool final;
    auto IvSize(const opentxs::crypto::key::symmetric::Algorithm mode) const
        -> std::size_t final;
    auto KeySize(const opentxs::crypto::key::symmetric::Algorithm mode) const
        -> std::size_t final;
    auto SaltSize(const crypto::key::symmetric::Source type) const
        -> std::size_t final;
    auto sha1(
        const std::uint8_t* input,
        const std::size_t inputSize,
        std::uint8_t* output) const -> bool;
    auto TagSize(const opentxs::crypto::key::symmetric::Algorithm mode) const
        -> std::size_t final;

    Sodium() = delete;
    Sodium(const Sodium&) = delete;
    Sodium(Sodium&&) = delete;
    auto operator=(const Sodium&) -> Sodium& = delete;
    auto operator=(Sodium&&) -> Sodium& = delete;
};
}  // namespace opentxs::crypto::implementation
