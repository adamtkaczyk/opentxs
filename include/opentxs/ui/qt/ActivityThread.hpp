// Copyright (c) 2010-2021 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_ACTIVITYTHREADQT_HPP
#define OPENTXS_UI_ACTIVITYTHREADQT_HPP

#include <QIdentityProxyModel>
#include <QObject>
#include <QString>
#include <QValidator>
#include <QVariant>

#include "opentxs/opentxs_export.hpp"  // IWYU pragma: keep

class QObject;
class QValidator;

namespace opentxs
{
namespace ui
{
namespace implementation
{
class ActivityThread;
}  // namespace implementation

class ActivityThreadQt;
}  // namespace ui
}  // namespace opentxs

class OPENTXS_EXPORT opentxs::ui::ActivityThreadQt final
    : public QIdentityProxyModel
{
    Q_OBJECT
    Q_PROPERTY(bool canMessage READ canMessage NOTIFY canMessageUpdate)
    Q_PROPERTY(QString displayName READ displayName NOTIFY displayNameUpdate)
    Q_PROPERTY(QString draft READ draft WRITE setDraft NOTIFY draftUpdate)
    Q_PROPERTY(QObject* draftValidator READ draftValidator CONSTANT)
    Q_PROPERTY(QString participants READ participants CONSTANT)
    Q_PROPERTY(QString threadID READ threadID CONSTANT)

signals:
    void updated() const;
    void canMessageUpdate(bool) const;
    void displayNameUpdate() const;
    void draftUpdate() const;

public slots:
    void setDraft(QString);

public:
    enum Roles {
        IntAmountRole = Qt::UserRole + 0,     // int
        StringAmountRole = Qt::UserRole + 1,  // QString
        LoadingRole = Qt::UserRole + 2,       // bool
        MemoRole = Qt::UserRole + 3,          // QString
        PendingRole = Qt::UserRole + 4,       // bool
        PolarityRole = Qt::UserRole + 5,      // int, -1, 0, or 1
        TextRole = Qt::UserRole + 6,          // QString
        TimeRole = Qt::UserRole + 7,          // QDateTime
        TypeRole = Qt::UserRole + 8,          // int, opentxs::StorageBox
    };
    enum Columns {
        TimeColumn = 0,
        TextColumn = 1,
        AmountColumn = 2,
        MemoColumn = 3,
        LoadingColumn = 4,
        PendingColumn = 5,
    };

    auto canMessage() const noexcept -> bool;
    auto displayName() const noexcept -> QString;
    auto draft() const noexcept -> QString;
    auto draftValidator() const noexcept -> QValidator*;
    auto headerData(
        int section,
        Qt::Orientation orientation,
        int role = Qt::DisplayRole) const -> QVariant final;
    auto participants() const noexcept -> QString;
    auto threadID() const noexcept -> QString;
    Q_INVOKABLE auto pay(
        const QString& amount,
        const QString& sourceAccount,
        const QString& memo = "") const noexcept -> bool;
    Q_INVOKABLE auto paymentCode(const int currency) const noexcept -> QString;
    Q_INVOKABLE auto sendDraft() const noexcept -> bool;

    ActivityThreadQt(implementation::ActivityThread& parent) noexcept;

    ~ActivityThreadQt() final;

private:
    struct Imp;

    Imp* imp_;

    ActivityThreadQt() = delete;
    ActivityThreadQt(const ActivityThreadQt&) = delete;
    ActivityThreadQt(ActivityThreadQt&&) = delete;
    ActivityThreadQt& operator=(const ActivityThreadQt&) = delete;
    ActivityThreadQt& operator=(ActivityThreadQt&&) = delete;
};
#endif
