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

#ifndef TLSSOCKETEVENTHANDLER_H
#define TLSSOCKETEVENTHANDLER_H

#include <ByteArray.h>
#include "auxiliary.h"

namespace IDFix
{
	namespace Protocols
	{
		class TLSSocket;

        /**
         * @brief The TLSSocketEventHandler class provides an interface the handle TLSSocket events
         */
		class TLSSocketEventHandler
		{
			public:

				virtual			~TLSSocketEventHandler();

                /**
                 * @brief This event is called every time new bytes are received by the TLSSocket.
                 *
                 * @param tlsSocket     the TLSSocket which received the bytes
                 * @param bytes         the received bytes as \c ByteArray
                 */
				virtual void	socketBytesReceived(TLSSocket& tlsSocket, ByteArray &bytes);

                /**
                 * @brief The event is called when the socket has been disconnected.
                 *
                 * @param tlsSocket     the TLSSocket which was disconnected
                 */
				virtual void	socketDisconnected(TLSSocket& tlsSocket);
		};
	}
}

#endif
