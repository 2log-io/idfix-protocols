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

#ifndef TLSSOCKET_H
#define TLSSOCKET_H

#include "TLSSocketEventHandler.h"
#include "Mutex.h"

extern "C"
{
	#include <stddef.h>
	#include "openssl/ssl.h"
	#include <stdint.h>
}

namespace IDFix
{
	namespace Protocols
	{
		class TLSServer;

        /**
         * @brief The TLSSocket class provides an TLS encrypted socket for incomming client connections.
         *
         * TLSSocket represents an TLS encrypted connection incomming from a TLSServer. It is used as an
         * interface to receive and send encrypted data over the connection.
         */
		class TLSSocket
		{
			friend class TLSServer;

            public:
                /**
                 * @brief Constructs a TLSSocket object
                 *
                 * A TLSSocket is generally managed by a TLSServer and is therefore only constructed by a TLSServer on an incomming TCP connection.
                 *
                 * @param socketDescriptor      the socket descriptor of the incomming connection
                 * @param tlsPeer               the SSL peer context
                 * @param owner                 the TLSServer which manages this TLSSocket
                 */
				TLSSocket(int socketDescriptor, SSL *tlsPeer, TLSServer *owner);

                /**
                 * @brief A TLSSocket is managed by a TLSServer and therefore cannot be copied
                 */
				TLSSocket(const TLSSocket&) = delete;

				~TLSSocket();

                /**
                 * @brief Set the event handler which handles events of this TLSSocket
                 *
                 * @param eventHandler  the TLSSocketEventHandler implementation which handles events for this TLSSocket
                 */
				void			setEventHandler(TLSSocketEventHandler* eventHandler);

                /**
                 * @brief Write bytes to a TLS connection
                 *
                 * @param bytes     the buffer containing the data to write
                 * @param len       the number of bytes to write
                 *
                 * @return          >  \c 0 if write operation was successful, the value is the number of bytes actually written to the connection
                 * @return          <= \c 0 if the write operation failed, because either the connection was closed or an error occured
                 */
				int				write(const char* bytes, size_t len);

                /**
                 * @brief Convenient method to write a NULL-terminated string to a TLS connection.
                 *
                 * @param string    a NULL-terminated string
                 *
                 * @return          >  \c 0 if write operation was successful, the value is the number of bytes actually written to the connection
                 * @return          <= \c 0 if the write operation failed, because either the connection was closed or an error occured
                 */
				int				write(const char* string);

                /**
                 * @brief Close the TLS connection
                 */
				void			close(void);

			protected:

                /**
                 * @brief This method is called from the TLSServer managing this TLSSocket to indicate that new data arrived at the socket.
                 *
                 * It reads the arrived bytes and calls the provided event handler. If this method returns a value <= \c 0 (which indicates an error or
                 * a closed socket) the calling server will close the TLSSocket.
                 *
                 * @return          >  \c 0 if read operation was successful, the value is the number of bytes actually read from the connection
                 * @return          <= \c 0 if the write operation failed, because either the connection was closed or an error occured
                 */
				int				socketReadyRead(void);

                /**
                 * @brief Accept an incomming TLS connection and process the handshake.
                 *
                 * If a TLSServer constructed a TLSSocket the TLS handshake will not be processed immediately (this would block the server in case the handshake
                 * has not yet been received from the client). Instead it waits until the first data is received and \c socketReadyRead is called. On the first call
                 * of \c socketReadyRead it will then call \c acceptSSL.
                 *
                 * @return      \c 1 on success
                 * @return      <= \c 0 if the TLS handshake failed
                 */
				int				acceptSSL(void);

                /**
                 * @brief Invalidate the pointer to the managing TLSServer.
                 *
                 * This method is called from the managing TLSServer to indicate that the socket is no longer managed by the server (either because the socket was closed
                 * or the server was shut down). Invalidating the owner pointer ensures the following concerns
                 *
                 * - It prevents calling TLSServer::removeSocket() if the socket was already removed from the server.
                 * - The TLSSocket will not send a new connection event if the TLSServer was shut down (e.g. during a TLS handshake).
                 */
				void			releaseOwner(void);

                /**
                 * @brief Add a NULL byte as termination in the ByteArray after \c bytesRead bytes
                 * @param bytes             the ByteArray to be terminated
                 * @param bytesRead         the number of bytes after which the termination should be inserted.
                 */
				void			addNullTermination(ByteArray &bytes, unsigned long bytesRead);

			protected:

				TLSServer				*_owner;
				int						_socketDescriptor;
				SSL						*_tlsPeer;
				bool					_sslAccepted = { false };
				TLSSocketEventHandler	*_eventHandler = { nullptr };
				Mutex					_mutex = { Mutex::Recursive };
		};
	}
}

#endif
