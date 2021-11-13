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

#ifndef WEBSOCKETEVENTHANDLER_H
#define WEBSOCKETEVENTHANDLER_H

#include <string>
#include "WebSocket.h"

namespace IDFix
{
    namespace Protocols
    {
        /**
         * @brief The WebSocketEventHandler class provides an interface to handle websocket events
         */
        class WebSocketEventHandler
        {
            public:

                virtual         ~WebSocketEventHandler();

                /**
                 * @brief This event is triggerd after the websocket connection was successfully established.
                 */
                virtual void	webSocketConnected(void);

                /**
                 * @brief This event is triggerd if the websocket connection could not be established or a connected
                 * socket was disconnected.
                 */
                virtual void	webSocketDisconnected(void);

                /**
                 * @brief This event is triggered when a new text message is received by the websocket.
                 *
                 * @param message           the received text message
                 */
                virtual void	webSocketTextMessageReceived(const std::string &message);

                /**
                 * @brief This event is triggered when a part of a fragmented text message is received by the websocket.
                 *
                 * @param message           the received part of the fragmented message
                 * @param lastFragment      true if this is the last part of the fragmented message
                 */
                virtual void	webSocketTextMessageFragmentReceived(const std::string &message, bool lastFragment = false);

                /**
                 * @brief This event is triggered when a new binary message is received by the websocket.
                 *
                 * @param message           the received binary message
                 */
                virtual void	webSocketBinaryMessageReceived(const char* data, int length);

                /**
                 * @brief This event is triggered when a part of a fragmented binary message is received by the websocket.
                 *
                 * @param message           the received part of the fragmented message
                 * @param lastFragment      true if this is the last part of the fragmented message
                 */
                virtual void	webSocketBinaryMessageFragmentReceived(const char* data, int fragmentLength, int fragmentOffset, int messageLength);
        };
    }
}

#endif // WEBSOCKETEVENTHANDLER_H
