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

    auto& client = StartClient(1);

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
//
//    auto list = client.Crypto().Blockchain().SubaccountList(nym, pkt_chain);
//
//    std::cout << list.size() << std::endl;

//    account_id.Assign(client.Crypto().Blockchain().NewHDSubaccount(
//        alex_,
//        ot::blockchain::crypto::HDProtocol::BIP_32,
//        btc_chain_,
//        reason_));

//    auto& manager = client.Network().Blockchain().GetChain(test_chain);

//    EXPECT_TRUE(manager.GetType() == test_chain);
    EXPECT_TRUE(client.Instance() > 0);
}

}