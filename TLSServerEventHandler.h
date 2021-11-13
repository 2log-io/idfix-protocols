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

#ifndef TLSSERVEREVENTHANDLER_H
#define TLSSERVEREVENTHANDLER_H

#include "auxiliary.h"

namespace IDFix
{
	namespace Protocols
	{
		DeclarePointers(TLSSocket);

        /**
         * @brief The TLSServerEventHandler class provides an interface the handle TLSServer events
         */
		class TLSServerEventHandler
		{
			public:

				virtual			~TLSServerEventHandler();

                /**
                 * @brief This event is called if a new incomming TLS connection is fully established and
                 *          provides the TLSSocket object that handles this connection.
                 *
                 * @param socket    the TLSSocket that handles the new incomming connection
                 */
				virtual void	tlsNewConnection(TLSSocket_weakPtr socket) = 0;
		};
	}
}

#endif
