// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>

#include "api/session/Factory.hpp"

namespace opentxs
{
namespace api
{
namespace session
{
class Factory;
class Notary;
}  // namespace session
}  // namespace api

class OTCron;
}  // namespace opentxs

namespace opentxs::api::session::server
{
class Factory final : public session::imp::Factory
{
public:
    auto Cron() const -> std::unique_ptr<OTCron> final;

    Factory(const api::session::Notary& parent);

    ~Factory() final = default;

private:
    const api::session::Notary& server_;

    Factory() = delete;
    Factory(const Factory&) = delete;
    Factory(Factory&&) = delete;
    auto operator=(const Factory&) -> Factory& = delete;
    auto operator=(Factory&&) -> Factory& = delete;
};
}  // namespace opentxs::api::session::server
