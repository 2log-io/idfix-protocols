/*   2log.io
 *   Copyright (C) 2021 - 2log.io | mail@2log.io,  sascha@2log.io
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "WebSocketEventHandler.h"

namespace IDFix
{
    namespace Protocols
    {
        WebSocketEventHandler::~WebSocketEventHandler()
        {

        }

        void WebSocketEventHandler::webSocketConnected()
        {

        }

        void WebSocketEventHandler::webSocketDisconnected()
        {

        }

        void WebSocketEventHandler::webSocketTextMessageReceived(const std::string &message)
        {

        }

        void WebSocketEventHandler::webSocketTextMessageFragmentReceived(const std::string &message, bool lastFragment)
        {

        }

        void WebSocketEventHandler::webSocketBinaryMessageReceived(const char *data, int length)
        {

        }

        void WebSocketEventHandler::webSocketBinaryMessageFragmentReceived(const char *data, int fragmentLength, int fragmentOffset, int messageLength)
        {

        }
    }
}
