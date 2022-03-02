// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include "opentxs/util/Options.hpp"
#include "opentxs/blockchain/BlockchainType.hpp"

namespace ot = opentxs;

namespace ottest
{

TEST(Options, BlockchainWalletEnabled)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string blockchain_wallet_opt = "--blockchain_wallet";
    std::string blockchain_wallet_opt_false = "--blockchain_wallet=false";
    value[0] = app_name.data();
    value[1] = blockchain_wallet_opt.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_TRUE(opt.BlockchainWalletEnabled());

    value[1] = blockchain_wallet_opt_false.data();
    auto opt_false = opentxs::Options(2, value);
    EXPECT_FALSE(opt_false.BlockchainWalletEnabled());
}

TEST(Options, ProvideBlockchainSyncServer)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string params = "--provide_sync_server";
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_TRUE(opt.ProvideBlockchainSyncServer());
    EXPECT_FALSE(opt.BlockchainWalletEnabled());
}

TEST(Options, BlockchainStorageLevel)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string params = "--blockchain_storage=2";
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.BlockchainStorageLevel(), 2);
}

TEST(Options, BlockchainBindIpv4)
{
    char* value[4];
    std::string app_name = "opentxs";
    std::vector<std::string> blockchain_bind_ipv4_to_compare = {
        "10.0.20.1", "10.0.20.2"};
    std::string params = "--blockchain_bind_ipv4";

    value[0] = app_name.data();
    value[1] = params.data();
    size_t index = 2;
    for (auto& ipv4 : blockchain_bind_ipv4_to_compare) {
        value[index++] = ipv4.data();
    }

    auto opt = opentxs::Options(index, value);
    auto& blockchain_bind_ipv4 = opt.BlockchainBindIpv4();
    EXPECT_EQ(
        blockchain_bind_ipv4.size(), blockchain_bind_ipv4_to_compare.size());
    for (auto ipv4 : blockchain_bind_ipv4_to_compare) {
        EXPECT_TRUE(
            blockchain_bind_ipv4.find(ipv4.c_str()) !=
            blockchain_bind_ipv4.end());
    }
}

TEST(Options, BlockchainBindIpv6)
{
    char* value[4];
    std::string app_name = "opentxs";
    std::vector<std::string> blockchain_bind_ipv6_to_compare = {
        "2345:0425:2CA1:0000:0000:0567:5673:23b5",
        "FE80:CD00:0000:0CDE:1257:0000:211E:729C"};
    std::string params = "--blockchain_bind_ipv6";

    value[0] = app_name.data();
    value[1] = params.data();
    size_t index = 2;
    for (auto& ipv6 : blockchain_bind_ipv6_to_compare) {
        value[index++] = ipv6.data();
    }

    auto opt = opentxs::Options(index, value);
    auto& blockchain_bind_ipv6 = opt.BlockchainBindIpv6();
    EXPECT_EQ(
        blockchain_bind_ipv6.size(), blockchain_bind_ipv6_to_compare.size());
    for (auto ipv6 : blockchain_bind_ipv6_to_compare) {
        EXPECT_TRUE(
            blockchain_bind_ipv6.find(ipv6.c_str()) !=
            blockchain_bind_ipv6.end());
    }
}

TEST(Options, DefaultMintKeyBytes)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string params = "--mint_key_default_bytes=512";
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.DefaultMintKeyBytes(), 512);
}

TEST(Options, DisabledBlockchains)
{
    char* value[4];
    std::string app_name = "opentxs";
    std::vector<std::pair<std::string, opentxs::blockchain::Type>>
        disabled_blockchain_to_compare = {
            {"BTC", opentxs::blockchain::Type::Bitcoin},
            {"PKT", opentxs::blockchain::Type::PKT}};
    std::string params = "--disable_blockchain";
    value[0] = app_name.data();
    value[1] = params.data();
    size_t index = 2;
    for (auto& chain : disabled_blockchain_to_compare) {
        value[index++] = chain.first.data();
    }

    auto opt = opentxs::Options(index, value);
    auto& disabled_blockchains = opt.DisabledBlockchains();
    EXPECT_EQ(
        disabled_blockchains.size(), disabled_blockchain_to_compare.size());
    for (auto chain : disabled_blockchain_to_compare) {
        EXPECT_TRUE(
            disabled_blockchains.find(chain.second) !=
            disabled_blockchains.end());
    }
}

TEST(Options, Experimental)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string params = "--ot_experimental=true";
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_TRUE(opt.Experimental());
}

TEST(Options, Home)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string ot_home = "/home/ot/test/";
    std::string params = "--ot_home=" + ot_home;
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.Home(), ot_home);
}

TEST(Options, Ipv4ConnectionMode)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string params = "--ipv4_connection_mode=-1";
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt_off = opentxs::Options(2, value);
    EXPECT_EQ(
        opt_off.Ipv4ConnectionMode(), opentxs::Options::ConnectionMode::off);

    params = "--ipv4_connection_mode=0";
    value[1] = params.data();
    auto opt_automatic = opentxs::Options(2, value);
    EXPECT_EQ(
        opt_automatic.Ipv4ConnectionMode(),
        opentxs::Options::ConnectionMode::automatic);

    params = "--ipv4_connection_mode=1";
    value[1] = params.data();
    auto opt_on = opentxs::Options(2, value);
    EXPECT_EQ(
        opt_on.Ipv4ConnectionMode(), opentxs::Options::ConnectionMode::on);
}

TEST(Options, Ipv6ConnectionMode)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string params = "--ipv6_connection_mode=-1";
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt_off = opentxs::Options(2, value);
    EXPECT_EQ(
        opt_off.Ipv6ConnectionMode(), opentxs::Options::ConnectionMode::off);

    params = "--ipv6_connection_mode=0";
    value[1] = params.data();
    auto opt_automatic = opentxs::Options(2, value);
    EXPECT_EQ(
        opt_automatic.Ipv6ConnectionMode(),
        opentxs::Options::ConnectionMode::automatic);

    params = "--ipv6_connection_mode=1";
    value[1] = params.data();
    auto opt_on = opentxs::Options(2, value);
    EXPECT_EQ(
        opt_on.Ipv6ConnectionMode(), opentxs::Options::ConnectionMode::on);
}

TEST(Options, LogLevel)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string params = "--log_level=5";
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.LogLevel(), 5);
}

TEST(Options, NotaryBindIP)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string bind_ip = "10.0.20.10";
    std::string params = "--notary_bind_ip=" + bind_ip;
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.NotaryBindIP(), bind_ip);
}

TEST(Options, NotaryBindPort)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::uint16_t port = 6545;
    std::string params = "--notary_bind_port=" + std::to_string(port);
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.NotaryBindPort(), port);
}

TEST(Options, NotaryInproc)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string params = "--notary_inproc=false";
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt_false = opentxs::Options(2, value);
    EXPECT_FALSE(opt_false.NotaryInproc());

    params = "--notary_inproc=true";
    auto opt_true = opentxs::Options(2, value);
    EXPECT_FALSE(opt_true.NotaryInproc());
}

TEST(Options, NotaryName)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string name = "notary_test_name";
    std::string params = "--notary_name=" + name;
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.NotaryName(), name);
}
TEST(Options, NotaryPublicEEP)
{
    char* value[4];
    std::string app_name = "opentxs";
    std::vector<std::string> notary_public_eep_to_compare = {
        "address1", "address2"};
    std::string params = "--notary_public_eep";

    value[0] = app_name.data();
    value[1] = params.data();
    size_t index = 2;
    for (auto& ipv6 : notary_public_eep_to_compare) {
        value[index++] = ipv6.data();
    }

    auto opt = opentxs::Options(index, value);
    auto& notary_public_eep = opt.NotaryPublicEEP();
    EXPECT_EQ(notary_public_eep.size(), notary_public_eep_to_compare.size());
    for (auto ipv6 : notary_public_eep_to_compare) {
        EXPECT_TRUE(
            notary_public_eep.find(ipv6.c_str()) != notary_public_eep.end());
    }
}

TEST(Options, NotaryPublicIPv4)
{
    char* value[4];
    std::string app_name = "opentxs";
    std::vector<std::string> notary_public_ipv4_to_compare = {
        "10.0.20.1", "10.0.20.2"};
    std::string params = "--notary_public_ipv4";

    value[0] = app_name.data();
    value[1] = params.data();
    size_t index = 2;
    for (auto& ipv6 : notary_public_ipv4_to_compare) {
        value[index++] = ipv6.data();
    }

    auto opt = opentxs::Options(index, value);
    auto& notary_public_ipv4 = opt.NotaryPublicIPv4();
    EXPECT_EQ(notary_public_ipv4.size(), notary_public_ipv4_to_compare.size());
    for (auto ipv6 : notary_public_ipv4_to_compare) {
        EXPECT_TRUE(
            notary_public_ipv4.find(ipv6.c_str()) != notary_public_ipv4.end());
    }
}

TEST(Options, NotaryPublicIPv6)
{
    char* value[4];
    std::string app_name = "opentxs";
    std::vector<std::string> notary_public_ipv6_to_compare = {
        "2345:0425:2CA1:0000:0000:0567:5673:23b5",
        "FE80:CD00:0000:0CDE:1257:0000:211E:729C"};
    std::string params = "--notary_public_ipv6";

    value[0] = app_name.data();
    value[1] = params.data();
    size_t index = 2;
    for (auto& ipv6 : notary_public_ipv6_to_compare) {
        value[index++] = ipv6.data();
    }

    auto opt = opentxs::Options(index, value);
    auto& notary_public_ipv6 = opt.NotaryPublicIPv6();
    EXPECT_EQ(notary_public_ipv6.size(), notary_public_ipv6_to_compare.size());
    for (auto ipv6 : notary_public_ipv6_to_compare) {
        EXPECT_TRUE(
            notary_public_ipv6.find(ipv6.c_str()) != notary_public_ipv6.end());
    }
}

TEST(Options, NotaryPublicOnion)
{
    char* value[4];
    std::string app_name = "opentxs";
    std::vector<std::string> notary_public_onion_to_compare = {
        "http:/fsfsdfsdfsdfs.onion", "http:/fsfsdfsddfdsfdsf.onion"};
    std::string params = "--notary_public_onion";

    value[0] = app_name.data();
    value[1] = params.data();
    size_t index = 2;
    for (auto& onion : notary_public_onion_to_compare) {
        value[index++] = onion.data();
    }

    auto opt = opentxs::Options(index, value);
    auto& notary_public_onion = opt.NotaryPublicOnion();
    EXPECT_EQ(
        notary_public_onion.size(), notary_public_onion_to_compare.size());
    for (auto onion : notary_public_onion_to_compare) {
        EXPECT_TRUE(
            notary_public_onion.find(onion.c_str()) !=
            notary_public_onion.end());
    }

    std::string new_address = "http:/fsfsjsdfnfsdfs.onion";
    opt.AddNotaryPublicOnion(new_address);
    EXPECT_EQ(
        opt.NotaryPublicOnion().size(),
        notary_public_onion_to_compare.size() + 1);
}

TEST(Options, NotaryPublicPort)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::uint16_t port = 6545;
    std::string params = "--notary_command_port=" + std::to_string(port);
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.NotaryPublicPort(), port);
}

TEST(Options, NotaryTerms)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string notary_terms_ = "test_notary_terms";
    std::string params = "--notary_terms=" + notary_terms_;
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.NotaryTerms(), notary_terms_);
}

TEST(Options, RemoteBlockchainSyncServers)
{
    char* value[4];
    std::string app_name = "opentxs";
    std::vector<std::string> blockchain_sync_server_to_compare = {
        "10.0.20.101", "10.0.20.102"};
    std::string params = "--blockchain_sync_server";

    value[0] = app_name.data();
    value[1] = params.data();
    size_t index = 2;
    for (auto& onion : blockchain_sync_server_to_compare) {
        value[index++] = onion.data();
    }

    auto opt = opentxs::Options(index, value);
    auto& blockchain_sync_server = opt.RemoteBlockchainSyncServers();
    EXPECT_EQ(
        blockchain_sync_server.size(),
        blockchain_sync_server_to_compare.size());
    for (auto onion : blockchain_sync_server_to_compare) {
        EXPECT_TRUE(
            blockchain_sync_server.find(onion.c_str()) !=
            blockchain_sync_server.end());
    }

    std::string new_address = "10.0.20.103";
    opt.AddBlockchainSyncServer(new_address);
    EXPECT_EQ(
        opt.RemoteBlockchainSyncServers().size(),
        blockchain_sync_server_to_compare.size() + 1);
}

TEST(Options, RemoteLogEndpoint)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string log_endpoint = "10.0.30.1";
    std::string params = "--log_endpoint=" + log_endpoint;
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.RemoteLogEndpoint(), log_endpoint);
}

TEST(Options, StoragePrimaryPlugin)
{
    char* value[2];
    std::string app_name = "opentxs";
    std::string ot_storage_plugin = "test_storage_plugin";
    std::string params = "--ot_storage_plugin=" + ot_storage_plugin;
    value[0] = app_name.data();
    value[1] = params.data();
    auto opt = opentxs::Options(2, value);
    EXPECT_EQ(opt.StoragePrimaryPlugin(), ot_storage_plugin);
}

TEST(Options, TestMode)
{
    char* value[1];
    std::string app_name = "opentxs";
    auto opt = opentxs::Options(2, value);
    EXPECT_FALSE(opt.TestMode());
    opt.SetTestMode(true);
    EXPECT_TRUE(opt.TestMode());
}

}  // namespace ottest