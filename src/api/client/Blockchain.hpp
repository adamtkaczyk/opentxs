// Copyright (c) 2010-2019 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#if OT_CRYPTO_SUPPORTED_KEY_HD
namespace opentxs::api::client::implementation
{
class Blockchain : virtual public internal::Blockchain
{
public:
    const blockchain::BalanceTree& Account(
        const identifier::Nym& nymID,
        const Chain chain) const noexcept(false) final;
    std::set<OTIdentifier> AccountList(
        const identifier::Nym& nymID,
        const Chain chain) const noexcept final;
    const api::internal::Core& API() const noexcept final { return api_; }
    bool AssignContact(
        const identifier::Nym& nymID,
        const Identifier& accountID,
        const blockchain::Subchain subchain,
        const Bip32Index index,
        const Identifier& contactID) const noexcept final;
    bool AssignLabel(
        const identifier::Nym& nymID,
        const Identifier& accountID,
        const blockchain::Subchain subchain,
        const Bip32Index index,
        const std::string& label) const noexcept final;
    std::string CalculateAddress(
        const Chain chain,
        const blockchain::AddressStyle format,
        const Data& pubkey) const noexcept final;
    const api::client::Contacts& Contacts() const noexcept { return contacts_; }
    const TxoDB& DB() const noexcept { return txo_db_; }
    std::tuple<OTData, Style, Chain> DecodeAddress(
        const std::string& encoded) const noexcept final;
    std::string EncodeAddress(
        const Style style,
        const Chain chain,
        const Data& data) const noexcept final;
    const blockchain::HD& HDSubaccount(
        const identifier::Nym& nymID,
        const Identifier& accountID) const noexcept(false) final;
    OTIdentifier NewHDSubaccount(
        const identifier::Nym& nymID,
        const BlockchainAccountType standard,
        const Chain chain,
        const PasswordPrompt& reason) const noexcept final;
    bool StoreTransaction(
        const identifier::Nym& nymID,
        const Chain chain,
        const proto::BlockchainTransaction& transaction,
        const PasswordPrompt& reason) const noexcept final;
    OTData PubkeyHash(const Chain chain, const Data& pubkey) const
        noexcept(false) final;
    std::shared_ptr<proto::BlockchainTransaction> Transaction(
        const std::string& id) const noexcept final;
    bool UpdateTransactions(const std::map<OTData, OTIdentifier>& changed) const
        noexcept final;

    ~Blockchain() final = default;

private:
    enum class Prefix {
        Unknown = 0,
        BitcoinP2PKH,
        BitcoinP2SH,
        BitcoinTestnetP2PKH,
        BitcoinTestnetP2SH,
        LitecoinP2PKH,
    };

    using IDLock = std::map<OTIdentifier, std::mutex>;
    using TXOs = std::vector<blockchain::Activity>;
    /// Unspent, spent
    using ParsedTransaction = std::pair<TXOs, TXOs>;
    using AddressMap = std::map<Prefix, std::string>;
    using AddressReverseMap = std::map<std::string, Prefix>;
    using StylePair = std::pair<Style, Chain>;
    using StyleMap = std::map<StylePair, Prefix>;
    using StyleReverseMap = std::map<Prefix, StylePair>;
    using TransactionMap = std::
        map<std::string, std::shared_ptr<const proto::BlockchainTransaction>>;
    using TransactionContactMap = std::map<std::string, std::set<OTIdentifier>>;
    using NymTransactionMap = std::map<OTNymID, TransactionContactMap>;

    friend opentxs::Factory;

    struct BalanceLists {
        client::blockchain::internal::BalanceList& Get(
            const Chain chain) noexcept;

        BalanceLists(api::client::internal::Blockchain& parent) noexcept;

    private:
        api::client::internal::Blockchain& parent_;
        std::mutex lock_;
        std::map<
            Chain,
            std::unique_ptr<client::blockchain::internal::BalanceList>>
            lists_;
    };
    struct Txo final : virtual public internal::Blockchain::TxoDB {
        bool AddSpent(
            const identifier::Nym& nym,
            const blockchain::Coin txo,
            const std::string txid) const noexcept final;
        bool AddUnspent(
            const identifier::Nym& nym,
            const blockchain::Coin txo,
            const std::vector<OTData>& elements) const noexcept final;
        bool Claim(const identifier::Nym& nym, const blockchain::Coin txo) const
            noexcept final;
        std::vector<Status> Lookup(
            const identifier::Nym& nym,
            const Data& element) const noexcept final;

        Txo(api::client::internal::Blockchain& parent);

    private:
        api::client::internal::Blockchain& parent_;
        mutable std::mutex lock_;
    };

    static const AddressMap address_prefix_map_;
    static const AddressReverseMap address_prefix_reverse_map_;
    static const StyleMap address_style_map_;
    static const StyleReverseMap address_style_reverse_map_;

    const api::internal::Core& api_;
    const api::client::Activity& activity_;
    const api::client::Contacts& contacts_;
    mutable std::mutex lock_;
    mutable IDLock nym_lock_;
    mutable BalanceLists balance_lists_;
    mutable Txo txo_db_;

    OTData address_prefix(const Style style, const Chain chain) const
        noexcept(false);
    bool assign_transactions(
        const blockchain::internal::BalanceElement& element) const noexcept;
    bool assign_transactions(
        const identifier::Nym& nymID,
        const std::set<OTIdentifier> contacts,
        const TransactionMap& transactions) const noexcept;
    bool assign_transactions(
        const identifier::Nym& nymID,
        const Identifier& contactID,
        const TransactionMap& transactions) const noexcept;
    Bip44Type bip44_type(const proto::ContactItemType type) const noexcept;
    void init_path(
        const std::string& root,
        const proto::ContactItemType chain,
        const Bip32Index account,
        const BlockchainAccountType standard,
        proto::HDPath& path) const noexcept;
    bool move_transactions(
        const blockchain::internal::BalanceElement& element,
        const Identifier& fromContact) const noexcept;
    ParsedTransaction parse_transaction(
        const identifier::Nym& nym,
        const proto::BlockchainTransaction& transaction,
        const blockchain::internal::BalanceTree& tree,
        std::set<OTIdentifier>& contacts) const noexcept;
    std::string p2pkh(const Chain chain, const Data& pubkeyHash) const noexcept;
    std::string p2sh(const Chain chain, const Data& scriptHash) const noexcept;
    bool update_transactions(
        const Lock& lock,
        const identifier::Nym& nym,
        const TransactionContactMap& transactions) const noexcept;
    bool validate_nym(const identifier::Nym& nymID) const noexcept;

    Blockchain(
        const api::internal::Core& api,
        const api::client::Activity& activity,
        const api::client::Contacts& contacts) noexcept;
    Blockchain() = delete;
    Blockchain(const Blockchain&) = delete;
    Blockchain(Blockchain&&) = delete;
    Blockchain& operator=(const Blockchain&) = delete;
    Blockchain& operator=(Blockchain&&) = delete;
};
}  // namespace opentxs::api::client::implementation
#endif  // OT_CRYPTO_SUPPORTED_KEY_HD
