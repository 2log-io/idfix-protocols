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

#ifndef TLSSERVER_H
#define TLSSERVER_H

extern "C"
{
	#include <stddef.h>
	#include "openssl/ssl.h"
}

#include "IDFixTask.h"
#include "auxiliary.h"
#include <map>
#include "Mutex.h"

namespace IDFix
{
	namespace Protocols
	{
		DeclarePointers(TLSSocket);
		class TLSServerEventHandler;
		class TLSSocket;

		typedef std::map<int, TLSSocket_sharedPtr>	TLSSocketMap;

        /**
         * @brief The TLSServer class provides a TCP-based TLS server.
         */
		class TLSServer : private Task
		{
			friend class TLSSocket;

			public:

								TLSServer(TLSServerEventHandler *eventHandler);

                /**
                 * @brief Initializes the TLSServer
                 * @return  true on success
                 * @return  false on failure
                 */
				bool			init(void);

                /**
                 * @brief Start the TLSServer and listen for incomming connections.
                 *
                 * This method starts the general processing loop for the TLSServer which handles incomming connections and
                 * handles incoming data events from connected TLSSockets.
                 *
                 * @param port  the TCP port on which the server will listen
                 *
                 * @return  true on success
                 * @return  false on failure
                 */
				bool			listen(uint16_t port);

                /**
                 * @brief Shuts down the server. The server will no longer listen for incoming connections.
                 */
				void			shutdown();

                /**
                 * @brief Sets the private key for the server.
                 *
                 * The private key and the certificate are used by the server to provide it's identity to the TLS client.
                 *
                 * @param key           the private key in PEM format as null-terminated string.
                 * @param keyLength     the length of the private key in bytes.
                 *
                 * @return  true on success
                 * @return  false on failure
                 */
				bool			setPrivateKey(const unsigned char *key, long keyLength);

                /**
                 * @brief Sets the X.509 certificate for the server
                 *
                 * The certificate is used together with the private key to provide the server's identity to the TLS client.
                 *
                 * @param cert          the X.509 certificate in PEM format as null-terminated string.
                 * @param certLength    the length of the certificate key in bytes.
                 *
                 * @return  true on success
                 * @return  false on failure
                 */
				bool			setCertificate(const unsigned char *cert, long certLength);

			protected:

                /**
                 * @brief Starts the servers handling loop
                 */
				virtual void	run() override;

                /**
                 * @brief Overrides the default stopTask method to perform proper resource deallocation
                 */
				virtual void	stopTask() override;

                /**
                 * @brief Removes the socket from the server handling.
                 *
                 * This method is used by the TLSSocket when it is closing. It will remove the socket from all
                 * internal containers and stops handling any event on the socket. It will also call \c releaseOwner
                 * on the TLSSocket to indicate that the server is no longer managing the socket.
                 *
                 * @param tlsSocket pointer to the TLSSocket to remove
                 */
				void			removeSocket(TLSSocket* tlsSocket);

                /**
                 * @brief Calls the servers event handler when a new TLS connection is fully established.
                 *
                 * While handling of the TLS handshake is managed by the TLSSocket itself, new connection
                 * events are handled by the servers event handler. Therefore TLSSocket uses this method
                 * to call the servers event handler when a new TLS connection is fully established.
                 *
                 * @param newTLSSocket  pointer to the TLSSocket which established a new connection.
                 */
				void			sendNewConnectionEvent(TLSSocket* newTLSSocket);

				TLSServerEventHandler	*_eventHandler;
				SSL_CTX					*_tlsContext	= { nullptr };
				int						_serverSocket	= { -1 };
				uint16_t				_serverPort		= { 0 };
				bool					_serverIsRunning = { false };
				bool					_serverIsShutdown = { true };

				/** \brief fd_set to hold the currently open sockets  */
				fd_set					_activeDescriptors;

				/** \brief  Maps a socket descriptor to it's TLSSocket object */
				TLSSocketMap			_socketMap = {};

				Mutex					_mutex = { Mutex::Recursive };
		};
	}
}

#endif
