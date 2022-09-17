/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "DatabaseEdit.h"

#include "Utils.h"
#include "cli/Create.h"
#include "keys/ChallengeResponseKey.h"
#include "keys/FileKey.h"
#include "keys/PasswordKey.h"

#include <QCommandLineParser>
#include <QFileInfo>

const QCommandLineOption DatabaseEdit::UnsetPasswordOption =
    QCommandLineOption(QStringList() << "unset-password", QObject::tr("Unset the password for the database."));
const QCommandLineOption DatabaseEdit::UnsetKeyFileOption =
    QCommandLineOption(QStringList() << "unset-key-file", QObject::tr("Unset the key file for the database."));

DatabaseEdit::DatabaseEdit()
{
    name = QString("db-edit");
    description = QObject::tr("Edit a database.");
    options.append(Create::SetKeyFileOption);
    options.append(Create::SetPasswordOption);
    options.append(DatabaseEdit::UnsetKeyFileOption);
    options.append(DatabaseEdit::UnsetPasswordOption);
}

int DatabaseEdit::executeWithDatabase(QSharedPointer<Database> database, QSharedPointer<QCommandLineParser> parser)
{
    auto& out = Utils::STDOUT;
    auto& err = Utils::STDERR;

    const QStringList args = parser->positionalArguments();
    bool databaseWasChanged = false;

    if (parser->isSet(Create::SetPasswordOption) && parser->isSet(DatabaseEdit::UnsetPasswordOption)) {
        err << QObject::tr("Cannot use %1 and %2 at the same time.")
                   .arg(Create::SetPasswordOption.names().at(0))
                   .arg(DatabaseEdit::UnsetPasswordOption.names().at(0))
            << endl;
        return EXIT_FAILURE;
    }

    if (parser->isSet(Create::SetKeyFileOption) && parser->isSet(DatabaseEdit::UnsetKeyFileOption)) {
        err << QObject::tr("Cannot use %1 and %2 at the same time.")
                   .arg(Create::SetKeyFileOption.names().at(0))
                   .arg(DatabaseEdit::UnsetKeyFileOption.names().at(0))
            << endl;
        return EXIT_FAILURE;
    }

    bool hasKeyChange =
        (parser->isSet(Create::SetPasswordOption) || parser->isSet(Create::SetKeyFileOption)
         || parser->isSet(DatabaseEdit::UnsetPasswordOption) || parser->isSet(DatabaseEdit::UnsetKeyFileOption));

    if (hasKeyChange) {
        auto newDatabaseKey = getNewDatabaseKey(database,
                                                parser->isSet(Create::SetPasswordOption),
                                                parser->isSet(DatabaseEdit::UnsetPasswordOption),
                                                parser->value(Create::SetKeyFileOption),
                                                parser->isSet(DatabaseEdit::UnsetKeyFileOption));
        if (newDatabaseKey.isNull()) {
            err << QObject::tr("Could not change the database key.") << endl;
            return EXIT_FAILURE;
        }
        database->setKey(newDatabaseKey);
        databaseWasChanged = true;
    }

    if (!databaseWasChanged) {
        out << QObject::tr("Database was not modified.") << endl;
        return EXIT_SUCCESS;
    }

    QString errorMessage;
    if (!database->save(Database::Atomic, {}, &errorMessage)) {
        err << QObject::tr("Writing the database failed: %1").arg(errorMessage) << endl;
        return EXIT_FAILURE;
    }

    out << QObject::tr("Successfully edited the database.") << endl;
    return EXIT_SUCCESS;
}

QSharedPointer<CompositeKey> DatabaseEdit::getNewDatabaseKey(QSharedPointer<Database> database,
                                                             bool updatePassword,
                                                             bool removePassword,
                                                             QString newFileKeyPath,
                                                             bool removeKeyFile)
{
    auto& err = Utils::STDERR;
    auto newDatabaseKey = QSharedPointer<CompositeKey>::create();

    if (removePassword) {
        if (!database->key()->hasKey(PasswordKey::UUID)) {
            err << QObject::tr("Cannot remove password: The database does not have a password.") << endl;
            return {};
        }
    }
    if (removeKeyFile) {
        if (!database->key()->hasKey(FileKey::UUID)) {
            err << QObject::tr("Cannot remove file key: The database does not have a file key.") << endl;
            return {};
        }
    }

    QSharedPointer<PasswordKey> newPasswordKey;
    if (updatePassword) {
        newPasswordKey = Utils::getConfirmedPassword();
        if (newPasswordKey.isNull()) {
            err << QObject::tr("Failed to set database password.") << endl;
            return {};
        }
    }

    QSharedPointer<FileKey> newFileKey;
    if (!newFileKeyPath.isEmpty()) {
        newFileKey = QSharedPointer<FileKey>::create();
        QString errorMessage;
        if (!Utils::loadFileKey(newFileKeyPath, newFileKey)) {
            err << QObject::tr("Loading the new key file failed: %1").arg(errorMessage) << endl;
            return {};
        }
    }

    for (const auto& key : database->key()->keys()) {
        if (key->uuid() == PasswordKey::UUID) {
            if (removePassword) {
                continue;
            }

            if (!updatePassword) {
                newDatabaseKey->addKey(key);
                continue;
            }

            newDatabaseKey->addKey(newPasswordKey);
            continue;
        }

        if (key->uuid() == FileKey::UUID) {
            if (removeKeyFile) {
                continue;
            }

            if (newFileKeyPath.isEmpty()) {
                newDatabaseKey->addKey(key);
                continue;
            }

            newDatabaseKey->addKey(newFileKey);
            continue;
        }

        // Not sure that we should ever get here.
        newDatabaseKey->addKey(key);
    }

    for (const auto& key : database->key()->challengeResponseKeys()) {
        if (key->uuid() == ChallengeResponseKey::UUID) {
            newDatabaseKey->addKey(key);
        }
    }

    if (!newDatabaseKey->hasKey(PasswordKey::UUID) && updatePassword) {
        newDatabaseKey->addKey(newPasswordKey);
    }

    if (!newDatabaseKey->hasKey(FileKey::UUID) && !newFileKeyPath.isEmpty()) {
        newDatabaseKey->addKey(newFileKey);
    }

    if (newDatabaseKey->keys().isEmpty()) {
        err << QObject::tr("Cannot remove all the keys from a database.") << endl;
        return {};
    }

    return newDatabaseKey;
}
