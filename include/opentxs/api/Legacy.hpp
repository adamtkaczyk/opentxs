// Copyright (c) 2010-2019 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_API_LEGACY_HPP
#define OPENTXS_API_LEGACY_HPP

#include "opentxs/Forward.hpp"

#include <string>

namespace opentxs
{
namespace api
{
class Legacy
{
public:
    EXPORT virtual const char* Account() const noexcept = 0;
    EXPORT virtual const char* Cert() const noexcept = 0;
    EXPORT virtual std::string ClientConfigFilePath(const int instance) const
        noexcept = 0;
    EXPORT virtual std::string ClientDataFolder(const int instance) const
        noexcept = 0;
    EXPORT virtual const char* Common() const noexcept = 0;
    EXPORT virtual const char* Contract() const noexcept = 0;
    EXPORT virtual const char* Cron() const noexcept = 0;
    EXPORT virtual std::string CryptoConfigFilePath() const noexcept = 0;
    EXPORT virtual const char* ExpiredBox() const noexcept = 0;
    EXPORT virtual const char* Inbox() const noexcept = 0;
    EXPORT virtual std::string LogConfigFilePath() const noexcept = 0;
    EXPORT virtual const char* Market() const noexcept = 0;
    EXPORT virtual const char* Mint() const noexcept = 0;
    EXPORT virtual const char* Nym() const noexcept = 0;
    EXPORT virtual const char* Nymbox() const noexcept = 0;
    EXPORT virtual const char* Outbox() const noexcept = 0;
    EXPORT virtual std::string PIDFilePath() const noexcept = 0;
    EXPORT virtual const char* PaymentInbox() const noexcept = 0;
    EXPORT virtual const char* Purse() const noexcept = 0;
    EXPORT virtual const char* Receipt() const noexcept = 0;
    EXPORT virtual const char* RecordBox() const noexcept = 0;
    EXPORT virtual std::string ServerConfigFilePath(const int instance) const
        noexcept = 0;
    EXPORT virtual std::string ServerDataFolder(const int instance) const
        noexcept = 0;
    EXPORT virtual const char* Spent() const noexcept = 0;
    EXPORT virtual const char* UserAcct() const noexcept = 0;

    EXPORT virtual ~Legacy() = default;

protected:
    Legacy() noexcept = default;

private:
    Legacy(const Legacy&) = delete;
    Legacy(Legacy&&) = delete;
    Legacy& operator=(const Legacy&) = delete;
    Legacy& operator=(Legacy&&) = delete;
};
}  // namespace api
}  // namespace opentxs
#endif
