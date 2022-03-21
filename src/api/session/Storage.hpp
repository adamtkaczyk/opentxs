// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// IWYU pragma: no_include "opentxs/core/UnitType.hpp"

#pragma once

#include <cstdint>
#include <ctime>
#include <iosfwd>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include "Proto.hpp"
#include "internal/api/session/Storage.hpp"
#include "internal/util/Editor.hpp"
#include "internal/util/Flag.hpp"
#include "opentxs/Types.hpp"
#include "opentxs/Version.hpp"
#include "opentxs/api/session/Storage.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/blockchain/Types.hpp"
#include "opentxs/core/Data.hpp"
#include "opentxs/core/Types.hpp"
#include "opentxs/core/identifier/Generic.hpp"
#include "opentxs/core/identifier/Notary.hpp"
#include "opentxs/core/identifier/Nym.hpp"
#include "opentxs/core/identifier/UnitDefinition.hpp"
#include "opentxs/identity/wot/claim/ClaimType.hpp"
#include "opentxs/otx/client/PaymentWorkflowState.hpp"
#include "opentxs/otx/client/PaymentWorkflowType.hpp"
#include "opentxs/otx/client/Types.hpp"
#include "opentxs/util/Bytes.hpp"
#include "opentxs/util/Container.hpp"
#include "opentxs/util/Numbers.hpp"
#include "opentxs/util/Time.hpp"
#include "serialization/protobuf/PaymentWorkflowEnums.pb.h"
#include "util/storage/Config.hpp"

// NOLINTBEGIN(modernize-concat-nested-namespaces)
namespace opentxs  // NOLINT
{
// inline namespace v1
// {
namespace api
{
namespace network
{
class Asio;
}  // namespace network

namespace session
{
class Factory;
}  // namespace session

class Crypto;
}  // namespace api

namespace crypto
{
namespace key
{
class Symmetric;
}  // namespace key
}  // namespace crypto

namespace identifier
{
class Notary;
class Nym;
class UnitDefinition;
}  // namespace identifier

namespace proto
{
class Bip47Channel;
class Ciphertext;
class Contact;
class Context;
class Credential;
class HDAccount;
class Issuer;
class Nym;
class PaymentWorkflow;
class PeerReply;
class PeerRequest;
class Purse;
class Seed;
class ServerContract;
class StorageThread;
class UnitDefinition;
}  // namespace proto

namespace storage
{
namespace driver
{
namespace internal
{
class Multiplex;
}  // namespace internal
}  // namespace driver

class Config;
class Root;
}  // namespace storage

class Data;
class String;
// }  // namespace v1
}  // namespace opentxs
// NOLINTEND(modernize-concat-nested-namespaces)

namespace opentxs::api::session::imp
{
// Content-aware storage module for opentxs
//
// Storage accepts serialized opentxs objects in protobuf form, writes them
// to persistant storage, and retrieves them on demand.
//
// All objects are stored in a key-value database. The keys are always the
// hash of the object being stored.
//
// This class maintains a set of index objects which map logical identifiers
// to object hashes. These index objects are stored in the same K-V namespace
// as the opentxs objects.
//
// The interface to a particular KV database is provided by child classes
// implementing this interface. Implementations need only provide methods for
// storing/retrieving arbitrary key-value pairs, and methods for setting and
// retrieving the hash of the root index object.
//
// The implementation of this interface must support the concept of "buckets"
// Objects are either stored and retrieved from either the primary bucket, or
// the alternate bucket. This allows for garbage collection of outdated keys
// to be implemented.
class Storage final : public internal::Storage
{
public:
    auto AccountAlias(const Identifier& accountID) const
        -> UnallocatedCString final;
    auto AccountList() const -> ObjectList final;
    auto AccountContract(const Identifier& accountID) const -> OTUnitID final;
    auto AccountIssuer(const Identifier& accountID) const -> OTNymID final;
    auto AccountOwner(const Identifier& accountID) const -> OTNymID final;
    auto AccountServer(const Identifier& accountID) const -> OTNotaryID final;
    auto AccountSigner(const Identifier& accountID) const -> OTNymID final;
    auto AccountUnit(const Identifier& accountID) const -> UnitType final;
    auto AccountsByContract(const identifier::UnitDefinition& contract) const
        -> UnallocatedSet<OTIdentifier> final;
    auto AccountsByIssuer(const identifier::Nym& issuerNym) const
        -> UnallocatedSet<OTIdentifier> final;
    auto AccountsByOwner(const identifier::Nym& ownerNym) const
        -> UnallocatedSet<OTIdentifier> final;
    auto AccountsByServer(const identifier::Notary& server) const
        -> UnallocatedSet<OTIdentifier> final;
    auto AccountsByUnit(const UnitType unit) const
        -> UnallocatedSet<OTIdentifier> final;
    auto Bip47Chain(const identifier::Nym& nymID, const Identifier& channelID)
        const -> UnitType final;
    auto Bip47ChannelsByChain(
        const identifier::Nym& nymID,
        const UnitType chain) const -> Bip47ChannelList final;
    auto BlockchainAccountList(
        const UnallocatedCString& nymID,
        const UnitType type) const -> UnallocatedSet<UnallocatedCString> final;
    auto BlockchainSubaccountAccountType(
        const identifier::Nym& owner,
        const Identifier& id) const -> UnitType final;
    auto BlockchainThreadMap(const identifier::Nym& nym, const Data& txid)
        const noexcept -> UnallocatedVector<OTIdentifier> final;
    auto BlockchainTransactionList(const identifier::Nym& nym) const noexcept
        -> UnallocatedVector<OTData> final;
    auto CheckTokenSpent(
        const identifier::Notary& notary,
        const identifier::UnitDefinition& unit,
        const std::uint64_t series,
        const UnallocatedCString& key) const -> bool final;
    auto ContactAlias(const UnallocatedCString& id) const
        -> UnallocatedCString final;
    auto ContactList() const -> ObjectList final;
    auto ContextList(const UnallocatedCString& nymID) const -> ObjectList final;
    auto ContactOwnerNym(const UnallocatedCString& nymID) const
        -> UnallocatedCString final;
    void ContactSaveIndices() const final;
    auto ContactUpgradeLevel() const -> VersionNumber final;
    auto CreateThread(
        const UnallocatedCString& nymID,
        const UnallocatedCString& threadID,
        const UnallocatedSet<UnallocatedCString>& participants) const
        -> bool final;
    auto DeleteAccount(const UnallocatedCString& id) const -> bool final;
    auto DefaultNym() const -> OTNymID final;
    auto DefaultSeed() const -> UnallocatedCString final;
    auto DeleteContact(const UnallocatedCString& id) const -> bool final;
    auto DeletePaymentWorkflow(
        const UnallocatedCString& nymID,
        const UnallocatedCString& workflowID) const -> bool final;
    auto HashType() const -> std::uint32_t final;
    auto IssuerList(const UnallocatedCString& nymID) const -> ObjectList final;
    auto Load(
        const UnallocatedCString& accountID,
        UnallocatedCString& output,
        UnallocatedCString& alias,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& nymID,
        const UnallocatedCString& accountID,
        proto::HDAccount& output,
        const bool checking = false) const -> bool final;
    auto Load(
        const identifier::Nym& nymID,
        const Identifier& channelID,
        proto::Bip47Channel& output,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& id,
        proto::Contact& contact,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& id,
        proto::Contact& contact,
        UnallocatedCString& alias,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& nym,
        const UnallocatedCString& id,
        proto::Context& context,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& id,
        proto::Credential& cred,
        const bool checking = false) const -> bool final;
    auto Load(
        const identifier::Nym& id,
        proto::Nym& nym,
        const bool checking = false) const -> bool final;
    auto Load(
        const identifier::Nym& id,
        proto::Nym& nym,
        UnallocatedCString& alias,
        const bool checking = false) const -> bool final;
    auto LoadNym(
        const identifier::Nym& id,
        AllocateOutput destination,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& nymID,
        const UnallocatedCString& id,
        proto::Issuer& issuer,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& nymID,
        const UnallocatedCString& workflowID,
        proto::PaymentWorkflow& workflow,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& nymID,
        const UnallocatedCString& id,
        const StorageBox box,
        UnallocatedCString& output,
        UnallocatedCString& alias,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& nymID,
        const UnallocatedCString& id,
        const StorageBox box,
        proto::PeerReply& request,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& nymID,
        const UnallocatedCString& id,
        const StorageBox box,
        proto::PeerRequest& request,
        std::time_t& time,
        const bool checking = false) const -> bool final;
    auto Load(
        const identifier::Nym& nym,
        const identifier::Notary& notary,
        const identifier::UnitDefinition& unit,
        proto::Purse& output,
        const bool checking) const -> bool final;
    auto Load(
        const UnallocatedCString& id,
        proto::Seed& seed,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& id,
        proto::Seed& seed,
        UnallocatedCString& alias,
        const bool checking = false) const -> bool final;
    auto Load(
        const identifier::Notary& id,
        proto::ServerContract& contract,
        const bool checking = false) const -> bool final;
    auto Load(
        const identifier::Notary& id,
        proto::ServerContract& contract,
        UnallocatedCString& alias,
        const bool checking = false) const -> bool final;
    auto Load(
        const UnallocatedCString& nymId,
        const UnallocatedCString& threadId,
        proto::StorageThread& thread) const -> bool final;
    auto Load(proto::Ciphertext& output, const bool checking = false) const
        -> bool final;
    auto Load(
        const identifier::UnitDefinition& id,
        proto::UnitDefinition& contract,
        const bool checking = false) const -> bool final;
    auto Load(
        const identifier::UnitDefinition& id,
        proto::UnitDefinition& contract,
        UnallocatedCString& alias,
        const bool checking = false) const -> bool final;
    auto LocalNyms() const -> const UnallocatedSet<UnallocatedCString> final;
    void MapPublicNyms(NymLambda& lambda) const final;
    void MapServers(ServerLambda& lambda) const final;
    void MapUnitDefinitions(UnitLambda& lambda) const final;
    auto MarkTokenSpent(
        const identifier::Notary& notary,
        const identifier::UnitDefinition& unit,
        const std::uint64_t series,
        const UnallocatedCString& key) const -> bool final;
    auto MoveThreadItem(
        const UnallocatedCString& nymId,
        const UnallocatedCString& fromThreadID,
        const UnallocatedCString& toThreadID,
        const UnallocatedCString& itemID) const -> bool final;
    auto NymBoxList(const UnallocatedCString& nymID, const StorageBox box) const
        -> ObjectList final;
    auto NymList() const -> ObjectList final;
    auto PaymentWorkflowList(const UnallocatedCString& nymID) const
        -> ObjectList final;
    auto PaymentWorkflowLookup(
        const UnallocatedCString& nymID,
        const UnallocatedCString& sourceID) const -> UnallocatedCString final;
    auto PaymentWorkflowsByAccount(
        const UnallocatedCString& nymID,
        const UnallocatedCString& accountID) const
        -> UnallocatedSet<UnallocatedCString> final;
    auto PaymentWorkflowsByState(
        const UnallocatedCString& nymID,
        const otx::client::PaymentWorkflowType type,
        const otx::client::PaymentWorkflowState state) const
        -> UnallocatedSet<UnallocatedCString> final;
    auto PaymentWorkflowsByUnit(
        const UnallocatedCString& nymID,
        const UnallocatedCString& unitID) const
        -> UnallocatedSet<UnallocatedCString> final;
    auto PaymentWorkflowState(
        const UnallocatedCString& nymID,
        const UnallocatedCString& workflowID) const
        -> std::pair<
            otx::client::PaymentWorkflowType,
            otx::client::PaymentWorkflowState> final;
    auto RelabelThread(
        const UnallocatedCString& threadID,
        const UnallocatedCString& label) const -> bool final;
    auto RemoveBlockchainThreadItem(
        const identifier::Nym& nym,
        const Identifier& thread,
        const opentxs::blockchain::Type chain,
        const Data& txid) const noexcept -> bool final;
    auto RemoveNymBoxItem(
        const UnallocatedCString& nymID,
        const StorageBox box,
        const UnallocatedCString& itemID) const -> bool final;
    auto RemoveServer(const UnallocatedCString& id) const -> bool final;
    auto RemoveThreadItem(
        const identifier::Nym& nym,
        const Identifier& thread,
        const UnallocatedCString& id) const -> bool final;
    auto RemoveUnitDefinition(const UnallocatedCString& id) const -> bool final;
    auto RenameThread(
        const UnallocatedCString& nymId,
        const UnallocatedCString& threadId,
        const UnallocatedCString& newID) const -> bool final;
    void RunGC() const final;
    auto SeedList() const -> ObjectList final;
    auto ServerAlias(const UnallocatedCString& id) const
        -> UnallocatedCString final;
    auto ServerList() const -> ObjectList final;
    auto SetAccountAlias(
        const UnallocatedCString& id,
        const UnallocatedCString& alias) const -> bool final;
    auto SetContactAlias(
        const UnallocatedCString& id,
        const UnallocatedCString& alias) const -> bool final;
    auto SetDefaultNym(const identifier::Nym& id) const -> bool final;
    auto SetDefaultSeed(const UnallocatedCString& id) const -> bool final;
    auto SetNymAlias(const identifier::Nym& id, const UnallocatedCString& alias)
        const -> bool final;
    auto SetPeerRequestTime(
        const UnallocatedCString& nymID,
        const UnallocatedCString& id,
        const StorageBox box) const -> bool final;
    auto SetReadState(
        const UnallocatedCString& nymId,
        const UnallocatedCString& threadId,
        const UnallocatedCString& itemId,
        const bool unread) const -> bool final;
    auto SetSeedAlias(
        const UnallocatedCString& id,
        const UnallocatedCString& alias) const -> bool final;
    auto SetServerAlias(
        const identifier::Notary& id,
        const UnallocatedCString& alias) const -> bool final;
    auto SetThreadAlias(
        const UnallocatedCString& nymId,
        const UnallocatedCString& threadId,
        const UnallocatedCString& alias) const -> bool final;
    auto SetUnitDefinitionAlias(
        const identifier::UnitDefinition& id,
        const UnallocatedCString& alias) const -> bool final;
    auto Store(
        const UnallocatedCString& accountID,
        const UnallocatedCString& data,
        const UnallocatedCString& alias,
        const identifier::Nym& ownerNym,
        const identifier::Nym& signerNym,
        const identifier::Nym& issuerNym,
        const identifier::Notary& server,
        const identifier::UnitDefinition& contract,
        const UnitType unit) const -> bool final;
    auto Store(
        const UnallocatedCString& nymID,
        const identity::wot::claim::ClaimType type,
        const proto::HDAccount& data) const -> bool final;
    auto Store(
        const identifier::Nym& nymID,
        const Identifier& channelID,
        const proto::Bip47Channel& data) const -> bool final;
    auto Store(const proto::Contact& data) const -> bool final;
    auto Store(const proto::Context& data) const -> bool final;
    auto Store(const proto::Credential& data) const -> bool final;
    auto Store(const proto::Nym& data, const UnallocatedCString& alias = {})
        const -> bool final;
    auto Store(const ReadView& data, const UnallocatedCString& alias = {}) const
        -> bool final;
    auto Store(const UnallocatedCString& nymID, const proto::Issuer& data) const
        -> bool final;
    auto Store(
        const UnallocatedCString& nymID,
        const proto::PaymentWorkflow& data) const -> bool final;
    auto Store(
        const UnallocatedCString& nymid,
        const UnallocatedCString& threadid,
        const UnallocatedCString& itemid,
        const std::uint64_t time,
        const UnallocatedCString& alias,
        const UnallocatedCString& data,
        const StorageBox box,
        const UnallocatedCString& account = {}) const -> bool final;
    auto Store(
        const identifier::Nym& nym,
        const Identifier& thread,
        const opentxs::blockchain::Type chain,
        const Data& txid,
        const Time time) const noexcept -> bool final;
    auto Store(
        const proto::PeerReply& data,
        const UnallocatedCString& nymid,
        const StorageBox box) const -> bool final;
    auto Store(
        const proto::PeerRequest& data,
        const UnallocatedCString& nymid,
        const StorageBox box) const -> bool final;
    auto Store(const identifier::Nym& nym, const proto::Purse& purse) const
        -> bool final;
    auto Store(const proto::Seed& data) const -> bool final;
    auto Store(
        const proto::ServerContract& data,
        const UnallocatedCString& alias = {}) const -> bool final;
    auto Store(const proto::Ciphertext& serialized) const -> bool final;
    auto Store(
        const proto::UnitDefinition& data,
        const UnallocatedCString& alias = {}) const -> bool final;
    auto ThreadList(const UnallocatedCString& nymID, const bool unreadOnly)
        const -> ObjectList final;
    auto ThreadAlias(
        const UnallocatedCString& nymID,
        const UnallocatedCString& threadID) const -> UnallocatedCString final;
    auto UnaffiliatedBlockchainTransaction(
        const identifier::Nym& recipient,
        const Data& txid) const noexcept -> bool final;
    auto UnitDefinitionAlias(const UnallocatedCString& id) const
        -> UnallocatedCString final;
    auto UnitDefinitionList() const -> ObjectList final;
    auto UnreadCount(
        const UnallocatedCString& nymId,
        const UnallocatedCString& threadId) const -> std::size_t final;
    void UpgradeNyms() final;

    Storage(
        const api::Crypto& crypto,
        const network::Asio& asio,
        const session::Factory& factory,
        const Flag& running,
        const opentxs::storage::Config& config);

    ~Storage() final;

private:
    static const std::uint32_t HASH_TYPE;

    const api::Crypto& crypto_;
    const api::session::Factory& factory_;
    const network::Asio& asio_;
    const Flag& running_;
    std::int64_t gc_interval_;
    mutable std::mutex write_lock_;
    mutable std::unique_ptr<opentxs::storage::Root> root_;
    mutable OTFlag primary_bucket_;
    const opentxs::storage::Config config_;
    std::unique_ptr<opentxs::storage::driver::internal::Multiplex> multiplex_p_;
    opentxs::storage::driver::internal::Multiplex& multiplex_;

    auto root() const -> opentxs::storage::Root*;
    auto Root() const -> const opentxs::storage::Root&;
    auto verify_write_lock(const Lock& lock) const -> bool;

    auto blockchain_thread_item_id(
        const opentxs::blockchain::Type chain,
        const Data& txid) const noexcept -> UnallocatedCString;
    void Cleanup();
    void Cleanup_Storage();
    void CollectGarbage() const;
    void InitBackup() final;
    void InitEncryptedBackup(opentxs::crypto::key::Symmetric& key) final;
    void InitPlugins();
    auto mutable_Root() const -> Editor<opentxs::storage::Root>;
    void RunMapPublicNyms(NymLambda lambda) const;
    void RunMapServers(ServerLambda lambda) const;
    void RunMapUnits(UnitLambda lambda) const;
    void save(opentxs::storage::Root* in, const Lock& lock) const;
    void start() final;

    Storage(const Storage&) = delete;
    Storage(Storage&&) = delete;
    auto operator=(const Storage&) -> Storage& = delete;
    auto operator=(Storage&&) -> Storage& = delete;
};
}  // namespace opentxs::api::session::imp
