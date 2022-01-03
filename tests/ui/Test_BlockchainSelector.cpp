// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#if OT_QT
#include <QObject>
#include <QString>
#include <QVariant>
#endif  // OT_QT
#include <gtest/gtest.h>
#include <atomic>
#include <string>

#include "opentxs/OT.hpp"
#include "opentxs/api/Context.hpp"
#include "opentxs/api/session/Client.hpp"
#include "opentxs/api/session/UI.hpp"
#include "opentxs/blockchain/Blockchain.hpp"  // IWYU pragma: keep
#include "opentxs/blockchain/BlockchainType.hpp"
#include "opentxs/core/ui/BlockchainSelection.hpp"
#include "opentxs/core/ui/Blockchains.hpp"
#if OT_QT
#include "opentxs/core/ui/qt/BlockchainSelection.hpp"
#endif  // OT_QT
#include "ui/Helpers.hpp"

namespace ottest
{
Counter counter_full_{};
Counter counter_main_{};
Counter counter_test_{};

class Test_BlockchainSelector : public ::testing::Test
{
public:
    using Type = ot::blockchain::Type;

    const ot::api::session::Client& client_;
    const ot::ui::BlockchainSelection& full_;
    const ot::ui::BlockchainSelection& main_;
    const ot::ui::BlockchainSelection& test_;

    Test_BlockchainSelector()
        : client_(ot::Context().StartClientSession(0))
        , full_([&]() -> auto& {
            static std::atomic_bool init{true};
            static auto cb =
                make_cb(counter_full_, "Blockchain selector (full)");

            if (init) {
                counter_full_.expected_ = 7;
                init = false;
            }

            return client_.UI().BlockchainSelection(
                ot::ui::Blockchains::All, cb);
        }())
        , main_([&]() -> auto& {
            static std::atomic_bool init{true};
            static auto cb =
                make_cb(counter_main_, "Blockchain selector (main)");

            if (init) {
                counter_main_.expected_ = 4;
                init = false;
            }

            return client_.UI().BlockchainSelection(
                ot::ui::Blockchains::Main, cb);
        }())
        , test_([&]() -> auto& {
            static std::atomic_bool init{true};
            static auto cb =
                make_cb(counter_test_, "Blockchain selector (test)");

            if (init) {
                counter_test_.expected_ = 3;
                init = false;
            }

            return client_.UI().BlockchainSelection(
                ot::ui::Blockchains::Test, cb);
        }())
    {
    }
};

TEST_F(Test_BlockchainSelector, initialize_opentxs) {}

TEST_F(Test_BlockchainSelector, initial_state)
{
    const auto expectedA = BlockchainSelectionData{{
        {"Bitcoin", false, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};
    const auto expectedM = BlockchainSelectionData{{
        {"Bitcoin", false, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
    }};
    const auto expectedT = BlockchainSelectionData{{
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};

    ASSERT_TRUE(wait_for_counter(counter_full_));
    ASSERT_TRUE(wait_for_counter(counter_main_));
    ASSERT_TRUE(wait_for_counter(counter_test_));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Test, expectedT));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Test, expectedT));
}

TEST_F(Test_BlockchainSelector, disable_disabled)
{
    {
        counter_full_.expected_ += 0;
        counter_main_.expected_ += 0;

        EXPECT_TRUE(full_.Disable(Type::Bitcoin));
    }

    const auto expectedA = BlockchainSelectionData{{
        {"Bitcoin", false, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};
    const auto expectedM = BlockchainSelectionData{{
        {"Bitcoin", false, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
    }};
    const auto expectedT = BlockchainSelectionData{{
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};

    ASSERT_TRUE(wait_for_counter(counter_full_));
    ASSERT_TRUE(wait_for_counter(counter_main_));
    ASSERT_TRUE(wait_for_counter(counter_test_));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Test, expectedT));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Test, expectedT));
}

TEST_F(Test_BlockchainSelector, enable_disabled)
{
    {
        counter_full_.expected_ += 1;
        counter_main_.expected_ += 1;

        EXPECT_TRUE(full_.Enable(Type::Bitcoin));
    }

    const auto expectedA = BlockchainSelectionData{{
        {"Bitcoin", true, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};
    const auto expectedM = BlockchainSelectionData{{
        {"Bitcoin", true, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
    }};
    const auto expectedT = BlockchainSelectionData{{
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};

    ASSERT_TRUE(wait_for_counter(counter_full_));
    ASSERT_TRUE(wait_for_counter(counter_main_));
    ASSERT_TRUE(wait_for_counter(counter_test_));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Test, expectedT));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Test, expectedT));
}

TEST_F(Test_BlockchainSelector, enable_enabled)
{
    {
        counter_full_.expected_ += 0;
        counter_main_.expected_ += 0;

        EXPECT_TRUE(full_.Enable(Type::Bitcoin));
    }

    const auto expectedA = BlockchainSelectionData{{
        {"Bitcoin", true, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};
    const auto expectedM = BlockchainSelectionData{{
        {"Bitcoin", true, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
    }};
    const auto expectedT = BlockchainSelectionData{{
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};

    ASSERT_TRUE(wait_for_counter(counter_full_));
    ASSERT_TRUE(wait_for_counter(counter_main_));
    ASSERT_TRUE(wait_for_counter(counter_test_));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Test, expectedT));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Test, expectedT));
}

TEST_F(Test_BlockchainSelector, disable_enabled)
{
    {
        counter_full_.expected_ += 1;
        counter_main_.expected_ += 1;

        EXPECT_TRUE(full_.Disable(Type::Bitcoin));
    }

    const auto expectedA = BlockchainSelectionData{{
        {"Bitcoin", false, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};
    const auto expectedM = BlockchainSelectionData{{
        {"Bitcoin", false, false, Type::Bitcoin},
        {"Bitcoin Cash", false, false, Type::BitcoinCash},
        {"Litecoin", false, false, Type::Litecoin},
        {"PKT", false, false, Type::PKT},
    }};
    const auto expectedT = BlockchainSelectionData{{
        {"Bitcoin (testnet3)", false, true, Type::Bitcoin_testnet3},
        {"Bitcoin Cash (testnet3)", false, true, Type::BitcoinCash_testnet3},
        {"Litecoin (testnet4)", false, true, Type::Litecoin_testnet4},
    }};

    ASSERT_TRUE(wait_for_counter(counter_full_));
    ASSERT_TRUE(wait_for_counter(counter_main_));
    ASSERT_TRUE(wait_for_counter(counter_test_));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::All, expectedA));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Main, expectedM));
    EXPECT_TRUE(check_blockchain_selection(
        client_, ot::ui::Blockchains::Test, expectedT));
    EXPECT_TRUE(check_blockchain_selection_qt(
        client_, ot::ui::Blockchains::Test, expectedT));
}

TEST_F(Test_BlockchainSelector, shutdown)
{
    EXPECT_EQ(counter_full_.expected_, counter_full_.updated_);
    EXPECT_EQ(counter_main_.expected_, counter_main_.updated_);
    EXPECT_EQ(counter_test_.expected_, counter_test_.updated_);
}
}  // namespace ottest
