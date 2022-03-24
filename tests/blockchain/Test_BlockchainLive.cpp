// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#include <gtest/gtest.h>
#include "common/Client.hpp"
#include "opentxs/OT.hpp"
#include "api/network/Network.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/blockchain/node/Manager.hpp"
#include "internal/api/session/Client.hpp"
#include "opentxs/crypto/Parameters.hpp"
#include "opentxs/api/session/Crypto.hpp"
#include "opentxs/api/crypto/Blockchain.hpp"
#include "opentxs/util/Log.hpp"
#include "opentxs/blockchain/crypto/HDProtocol.hpp"
#include "opentxs/blockchain/Blockchain.hpp"
#include "opentxs/blockchain/crypto/Account.hpp"
#include "opentxs/blockchain/crypto/HD.hpp"
#include "opentxs/blockchain/node/Wallet.hpp"
#include "internal/core/Amount.hpp"
#include "opentxs/api/session/UI.hpp"

#include <chrono>
#include <thread>


namespace ot = opentxs;

namespace ottest
{

class Test_BlockchainLive : public Client_fixture
{
public:
    Test_BlockchainLive()
        : chain_type_(opentxs::blockchain::Type::PKT)
    {

    }

protected:
    const ot::blockchain::Type chain_type_;
    static constexpr auto seed_id_key_{"seedid"};
    static constexpr auto nym_id_key_{"nymid"};
    static constexpr auto wallet_name_{"test"};
    const ot::identity::Type individual{ot::identity::Type::individual};
};

TEST_F(Test_BlockchainLive, init)
{
//    const ot::blockchain::Type btc_chain = opentxs::blockchain::Type::Bitcoin;
    std::unique_ptr<ot::OTPasswordPrompt> reason_p{nullptr};

    opentxs::Options arg;
    arg.SetTestMode(false);
    arg.SetIpv4ConnectionMode(opentxs::Options::ConnectionMode::on);
    auto& client = StartClient(arg, 1);

    const ot::UnallocatedCString fingerprint{};

    auto id = client.InternalClient().Exec().Wallet_ImportSeed("worry myself exile unit believe climb pitch theme two truly alter daughter","");
    const_cast<ot::UnallocatedCString&>(fingerprint) = id;

    {
        auto notUsed{false};
        const auto config = client.Config().Set_str(
            ot::String::Factory(wallet_name_),
            ot::String::Factory(seed_id_key_),
            ot::String::Factory(id),
            notUsed);
        EXPECT_TRUE(config);
    }

    reason_p.reset(new ot::OTPasswordPrompt{
        client.Factory().PasswordPrompt(__func__)});

    std::unique_ptr<ot::OTNymID> nym_p = nullptr;
    nym_p.reset(new ot::OTNymID{
        client.Wallet()
            .Nym({fingerprint, 0}, individual, *reason_p, wallet_name_)
            ->ID()});

    const ot::identifier::Nym& nym = nym_p->get();

    {
        bool notUsed{false};
        const auto config = client.Config().Set_str(
            ot::String::Factory(wallet_name_),
            ot::String::Factory(nym_id_key_),
            ot::String::Factory(nym.str()),
            notUsed);

        EXPECT_TRUE(config);
    }

    client.Network().Blockchain().Enable(chain_type_);

    using Chain = ot::blockchain::Type;
    using Protocol = ot::blockchain::crypto::HDProtocol;

    const auto want = [&] {
        auto out = std::set<Protocol>{};
        out.emplace(Protocol::BIP_44);

        if (ot::blockchain::HasSegwit(chain_type_)) {
            out.emplace(Protocol::BIP_49);
            out.emplace(Protocol::BIP_84);
        }

        return out;
    }();

    const auto have = [&] {
        auto out = std::set<Protocol>{};
        const auto& account = client.Crypto().Blockchain().Account(nym, chain_type_);

        for (const auto& hd : account.GetHD()) {
            out.emplace(hd.Standard());
        }

        return out;
    }();
    const auto need = [&] {
        auto out = std::vector<Protocol>{};
        std::set_difference(
            want.begin(),
            want.end(),
            have.begin(),
            have.end(),
            std::back_inserter(out));

        return out;
    }();

    for (const auto& type : need) {
        std::cout << "need type: " << static_cast<int>(type) << std::endl;
        const auto reason = client.Factory().PasswordPrompt(__func__);
        const auto subaccount_id = [&] {
            if ((Chain::PKT == chain_type_) && (Protocol::BIP_84 == type)) {
                // TODO only do this if the primary seed is a pktwallet type
                return client.Crypto().Blockchain().NewHDSubaccount(
                    nym, type, Chain::Bitcoin, chain_type_, reason);
            } else {
                return client.Crypto().Blockchain().NewHDSubaccount(
                    nym, type, chain_type_, reason);
            }
        }();

        if (subaccount_id->empty()) {
            return;
        }
    }

    client.UI().BlockchainStatisticsQt();

    int i = 0;
    while(i < 100) {
        std::this_thread::sleep_for(std::chrono::seconds(15));
        i++;
        const auto& network = client.Network().Blockchain().GetChain(chain_type_);
        const auto& wallet = network.Wallet();
        auto balance = wallet.GetBalance();
        if(balance.first > 0) {
            opentxs::LogConsole()()("Wallet balance not empty").Flush();
        } else {
            opentxs::LogConsole()()("Wallet balance empty").Flush();
        }

        if(balance.second > 0) {
            opentxs::LogConsole()()("Wallet balance not empty").Flush();
        } else {
            opentxs::LogConsole()()("Wallet balance empty").Flush();
        }
        
//        std::cout << "BALANCE: " << balance.first.Internal().ExtractInt64() << std::endl;
//        std::cout << "BALANCE: " << balance.second.Internal().ExtractInt64() << std::endl;
    }
    EXPECT_TRUE(client.Instance() > 0);
}

}