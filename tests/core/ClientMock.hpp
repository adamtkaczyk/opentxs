// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#pragma once

#include <gmock/gmock.h>

#include "internal/api/session/Client.hpp"
#include "opentxs/api/session/Activity.hpp"
#include "internal/api/Legacy.hpp"
#include "internal/otx/client/Pair.hpp"
#include "internal/otx/client/ServerAction.hpp"
#include "internal/otx/client/obsolete/OTAPI_Exec.hpp"
#include "StorageMock.hpp"

namespace opentxs
{

class ClientMock final : public api::session::internal::Client
{
private:
    api::session::Storage& storage_;

public:
    ClientMock(api::session::Storage& storage)
        : storage_(storage)
    {
    }

    MOCK_METHOD(const api::session::Activity&, Activity, (), (const, final));
    MOCK_METHOD(const api::session::Contacts&, Contacts, (), (const, final));
    MOCK_METHOD(const api::session::OTX&, OTX, (), (const, final));
    MOCK_METHOD(const api::session::UI&, UI, (), (const, final));
    MOCK_METHOD(const api::session::Workflow&, Workflow, (), (const, final));
    MOCK_METHOD(const api::network::ZMQ&, ZMQ, (), (const, final));
    MOCK_METHOD(bool, Cancel, (const int task), (const, final));
    MOCK_METHOD(
        bool,
        Reschedule,
        (const int, const std::chrono::seconds&),
        (const, final));

    MOCK_METHOD(
        int,
        ScheduleHelper,
        (const std::chrono::seconds,
         const PeriodicTask&,
         const std::chrono::seconds&),
        (const));

    auto Schedule(
        const std::chrono::seconds& interval,
        const PeriodicTask& task,
        const std::chrono::seconds& last = std::chrono::seconds(0)) const
        -> int final
    {
        return ScheduleHelper(interval, task, last);
    }

    MOCK_METHOD(api::Settings&, Config, (), (const, noexcept, final));
    MOCK_METHOD(
        const api::session::Crypto&,
        Crypto,
        (),
        (const, noexcept, final));
    MOCK_METHOD(
        const UnallocatedCString&,
        DataFolder,
        (),
        (const, noexcept, final));
    MOCK_METHOD(
        const api::session::Endpoints&,
        Endpoints,
        (),
        (const, noexcept, final));
    MOCK_METHOD(
        const api::session::Factory&,
        Factory,
        (),
        (const, noexcept, final));
    MOCK_METHOD(const Options&, GetOptions, (), (const, noexcept, final));
    MOCK_METHOD(int, Instance, (), (const, noexcept, final));
    MOCK_METHOD(
        const api::network::Network&,
        Network,
        (),
        (const, noexcept, final));
    MOCK_METHOD(QObject*, QtRootObject, (), (const, noexcept, final));
    MOCK_METHOD(
        void,
        SetMasterKeyTimeout,
        (const std::chrono::seconds&),
        (const, noexcept, final));
    MOCK_METHOD(
        const api::session::Wallet&,
        Wallet,
        (),
        (const, noexcept, final));

    auto Storage() const noexcept -> const api::session::Storage& final
    {
        return storage_;
    }

    MOCK_METHOD(
        INTERNAL_PASSWORD_CALLBACK*,
        GetInternalPasswordCallback,
        (),
        (const, final));

    MOCK_METHOD(
        bool,
        GetSecretHelper,
        (const opentxs::Lock&,
         Secret&,
         const PasswordPrompt&,
         const bool,
         const UnallocatedCString&),
        (const));

    auto GetSecret(
        const opentxs::Lock& lock,
        Secret& secret,
        const PasswordPrompt& reason,
        const bool twice,
        const UnallocatedCString& key = "") const -> bool final
    {
        return GetSecretHelper(lock, secret, reason, twice, key);
    }

    MOCK_METHOD(const api::Legacy&, Legacy, (), (const, noexcept, final));

    MOCK_METHOD(std::mutex&, Lock, (), (const, final));

    MOCK_METHOD(
        std::recursive_mutex&,
        Lock,
        (const identifier::Nym&, const identifier::Notary&),
        (const, final));

    MOCK_METHOD(
        const opentxs::crypto::key::Symmetric&,
        MasterKey,
        (const opentxs::Lock&),
        (const, final));

    MOCK_METHOD(
        void,
        NewNym,
        (const identifier::Nym&),
        (const, noexcept, final));

    MOCK_METHOD(
        const OTAPI_Exec&,
        ExecHelper,
        (const UnallocatedCString&),
        (const));

    virtual auto Exec(const UnallocatedCString& wallet = "") const
        -> const OTAPI_Exec& final
    {
        return ExecHelper(wallet);
    }

    MOCK_METHOD(
        const OT_API&,
        OTAPIHelper,
        (const UnallocatedCString&),
        (const));

    virtual auto OTAPI(const UnallocatedCString& wallet = "") const
        -> const OT_API& final
    {
        return OTAPIHelper(wallet);
    }

    MOCK_METHOD(const otx::client::Pair&, Pair, (), (const, final));

    MOCK_METHOD(
        const otx::client::ServerAction&,
        ServerAction,
        (),
        (const, final));

    MOCK_METHOD(void, Init, (), (final));
};

}  // namespace opentxs

//}