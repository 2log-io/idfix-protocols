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

#include "TLSServer.h"

#include "TLSServerEventHandler.h"
#include "TLSSocket.h"
#include "MutexLocker.h"

extern "C"
{
	#include <esp_log.h>
	#include "lwip/sockets.h"
	#include <mbedtls/ssl.h>
}

namespace
{
	const char* LOG_TAG = "IDFix::TLSServer";
}

namespace IDFix
{
	namespace Protocols
	{

		TLSServer::TLSServer(TLSServerEventHandler *eventHandler)
            : Task("tls-server", 4072), _eventHandler(eventHandler)
		{

		}

		bool TLSServer::init()
		{
			MutexLocker	locker(_mutex);

			_tlsContext = SSL_CTX_new( TLSv1_2_server_method() );

			if ( !_tlsContext )
			{
				ESP_LOGE(LOG_TAG, "Could not create TLS context at file %s:%d.", __FILE__, __LINE__);
				return false;
			}

			return true;
		}

		bool TLSServer::listen(uint16_t port)
		{
			MutexLocker locker(_mutex);

			if ( ! _serverIsShutdown )
			{
				// server is already running or not yet completely shut down
				return false;
			}

			_serverSocket = socket(AF_INET, SOCK_STREAM, 0);

			if ( _serverSocket < 0 )
			{
				ESP_LOGE(LOG_TAG, "Could not create socket at file %s:%d.", __FILE__, __LINE__);
				return false;
			}

			_serverPort = port;

			struct sockaddr_in socketAddress;
			memset(&socketAddress, 0, sizeof(socketAddress) );
			socketAddress.sin_family		= AF_INET;
			socketAddress.sin_addr.s_addr	= INADDR_ANY;
			socketAddress.sin_port			= htons( _serverPort );

			int result = bind(_serverSocket, reinterpret_cast<struct sockaddr *>(&socketAddress), sizeof (socketAddress) );
			if ( result )
			{
				ESP_LOGE(LOG_TAG, "Could not bind socket to port %d at file %s:%d.", _serverPort, __FILE__, __LINE__);
				close( _serverSocket );
				_serverSocket = -1;
				return false;
			}

			result = ::listen(_serverSocket, 32);
			if ( result )
			{
				ESP_LOGE(LOG_TAG, "Could not set socket to listen at file %s:%d.", __FILE__, __LINE__);
				close( _serverSocket );
				_serverSocket = -1;
				return false;
			}

			_serverIsRunning = true;
			_serverIsShutdown = false;

			locker.unlock();

			startTask();

			return true;
		}

		void TLSServer::shutdown()
		{
			_mutex.lock();
				// we indicate a shutdown to the task (closing the server socket will cause select() to unblock)
				// cleanup will be done after the task finishes

				if ( _serverIsRunning && ! _serverIsShutdown )
				{
					_serverIsRunning = false;
					close(_serverSocket);
				}

			_mutex.unlock();
		}

		bool TLSServer::setPrivateKey(const unsigned char *key, long keyLength)
		{
			MutexLocker	locker(_mutex);

			if ( ! SSL_CTX_use_PrivateKey_ASN1(0, _tlsContext, key, keyLength) )
			{
				ESP_LOGE(LOG_TAG, "SSL_CTX_use_PrivateKey_ASN1() failed at file %s:%d.", __FILE__, __LINE__);
				return false;
			}
			return true;
		}

		bool TLSServer::setCertificate(const unsigned char *cert, long certLength)
		{
			MutexLocker	locker(_mutex);

			if ( ! SSL_CTX_use_certificate_ASN1(_tlsContext, static_cast<int>(certLength), cert) )
			{
				ESP_LOGE(LOG_TAG, "SSL_CTX_use_certificate_ASN1() failed at file %s:%d.", __FILE__, __LINE__);
				return false;
			}
			return true;
		}

		void TLSServer::run()
		{
			SSL					*tlsPeer;
			int					newClientSocket;
			struct sockaddr_in	peerSocketAddress;
			socklen_t			peerSocketAddressLength;

			int					maxDescriptor, newMaxDescriptor;
			int					currentDescriptor;
			fd_set				readReadyDescriptors;
			bool				continueRunning;

			// Initialize the set of active sockets

			_mutex.lock();
				FD_ZERO(&_activeDescriptors);
				FD_SET(_serverSocket, &_activeDescriptors);
				continueRunning = _serverIsRunning;
			_mutex.unlock();

			maxDescriptor = _serverSocket;

			while ( continueRunning )
			{
				// compiler generates asign operator, so readReadyDescriptors will be an independent copy
				_mutex.lock();
					readReadyDescriptors = _activeDescriptors;
				_mutex.unlock();

				// block until input arrives on one or more active sockets
				if ( select(maxDescriptor + 1, &readReadyDescriptors, nullptr, nullptr, nullptr) < 0 )
				{
					ESP_LOGW(LOG_TAG, "select() failed at file %s:%d.", __FILE__, __LINE__);

					_mutex.lock();

						if ( _serverIsRunning )
						{
							// select did not fail because of closed server socket ( _serverIsRunning => shutdown not intended )
							// as shutdown was not intended by user ( shutdown() was not called ) close the socket here
							_serverIsRunning = false;
							close(_serverSocket);
						}

					_mutex.unlock();

					// select may be fail by "Bad file descriptor" e.g. a socket was closed but not removed from activeDescriptors
					// TODO: update activeDescriptors (by TLSClients in map) and try to recover from error (if no shutdown indicated)
					return;
				}

				_mutex.lock();
					continueRunning = _serverIsRunning;
				_mutex.unlock();

				if ( ! continueRunning )
				{
					// if we want to shut down the server, we set _serverIsRunning = false and
					// close the server socket, which causes select() to return (e.g. unblock)
					ESP_LOGI(LOG_TAG, "Exiting server loop. Reason: shutdown");
					return;
				}

				// handle possible pending connection request on server socket
				if ( FD_ISSET(_serverSocket, &readReadyDescriptors) )
				{
					peerSocketAddressLength = sizeof(peerSocketAddress);
					newClientSocket = accept(_serverSocket, reinterpret_cast<struct sockaddr *>(&peerSocketAddress), &peerSocketAddressLength);

					if ( newClientSocket < 0 )
					{
						ESP_LOGE(LOG_TAG, "accept() failed at file %s:%d.", __FILE__, __LINE__);
					}
					else
					{
						struct sockaddr_in peerAddr;
						socklen_t addrSize = sizeof(struct sockaddr_in);
						getpeername(newClientSocket, reinterpret_cast<struct sockaddr *>(&peerAddr), &addrSize);

						char clientip[20];
						strcpy(clientip, inet_ntoa(peerAddr.sin_addr));
						ESP_LOGI(LOG_TAG, "Incomming TCP connection from %s (newClientSocket: %d)", clientip, newClientSocket);

						tlsPeer = SSL_new(_tlsContext);
						if ( ! tlsPeer )
						{
							ESP_LOGE(LOG_TAG, "Could not create TLS peer at file %s:%d.", __FILE__, __LINE__);
							close(newClientSocket);
						}
						else
						{
							SSL_set_fd(tlsPeer, newClientSocket);

							// Do not call SSL_accept yet, as it waits for any incomming data
							// instead create the socket and wait for any incomming data
							// SSL_accept will be called delayed

							TLSSocket_sharedPtr newTLSSocket = std::make_shared<TLSSocket>(newClientSocket, tlsPeer, this);
							_mutex.lock();
								_socketMap.insert( TLSSocketMap::value_type(newClientSocket, newTLSSocket) );
								FD_SET(newClientSocket, &_activeDescriptors);
							_mutex.unlock();

							if ( newClientSocket > maxDescriptor )
							{
								maxDescriptor = newClientSocket;
							}
							ESP_LOGV(LOG_TAG, "maxDescriptor = %d ", maxDescriptor);

							// As we don't call SSL_accept yet, we don't send the event yet
							// the event will be send by the socket indirectly when SSL_accept was called
						}
					}

					// we remove the server socket from the input pending fd_set so it will not be processed
					// again in the following loop
					FD_CLR (_serverSocket, &readReadyDescriptors);
				}

				newMaxDescriptor = _serverSocket;

				// loop through all possible descriptors up to maxDescriptor
				for (currentDescriptor = 0; currentDescriptor <= maxDescriptor; currentDescriptor++)
				{
					TLSSocket_sharedPtr currentSocket;

					_mutex.lock();
						if ( ! FD_ISSET(currentDescriptor, &_activeDescriptors) )
						{
							// if this descriptor is currently not actively used, skip it
							_mutex.unlock();
							continue;
						}
					_mutex.unlock();

					// up to this point we have an active descriptor
					// as we iterate ascending, it can be considered the current maximum descriptor
					newMaxDescriptor = currentDescriptor;

					// is there any input pending on this descriptor
					if ( FD_ISSET(currentDescriptor, &readReadyDescriptors) )
					{
						_mutex.lock();
							currentSocket = _socketMap.at(currentDescriptor);
						_mutex.unlock();

						if ( currentSocket != nullptr )
						{
							if ( currentSocket->socketReadyRead() <= 0 )
							{
								// socket was closed
								currentSocket->close();
								currentSocket.reset();

								// as the socket was closed, newMaxDescriptor may stay at an uncorrect value
								// however, it does not do any harm and will be corrected in the next loop
							}
						}
					}
				}

				maxDescriptor = newMaxDescriptor;
				ESP_LOGV(LOG_TAG, "maxDescriptor = %d ", maxDescriptor);

				_mutex.lock();
					continueRunning = _serverIsRunning;
				_mutex.unlock();
			}
			ESP_LOGI(LOG_TAG, "Exiting server loop. Reason: shutdown");
		}

		void TLSServer::stopTask()
		{
			ESP_LOGI(LOG_TAG, "TLSServer task has finished. Do cleanup and call base class stop()");

			_mutex.lock();

				TLSSocket_sharedPtr tlsSocket;

				// first make sure all current TLSSockets are closed
				for (auto const& x : _socketMap)
				{
					tlsSocket = x.second;

					ESP_LOGI(LOG_TAG, "Closing socket: %d", tlsSocket->_socketDescriptor);

					FD_CLR(tlsSocket->_socketDescriptor, &_activeDescriptors);

					// first release owner (this TLSServer) from socket, to prevent calling TLSServer::removeSocket
					// by closing the socket, as removeSocket would alter current iterating _socketMap
					tlsSocket->releaseOwner();

					tlsSocket->close();

					// as task will be immediately deleted afterwards, the destructor of the last shared pointer
					// instance will not be called. so delete this (local) shared pointer here explicitly
					tlsSocket.reset();
				}

				// now delete all TLSSockets
				_socketMap.clear();

			_mutex.unlock();

			Task::stopTask();
		}

		void TLSServer::removeSocket(TLSSocket *tlsSocket)
		{
			_mutex.lock();

				if ( ! _serverIsRunning )
				{
					// if server is not running (anymore) don't remove the sockets this way
					// if server is shut down, sockets will be removed in separate clean up
					_mutex.unlock();
					return;
				}

				FD_CLR(tlsSocket->_socketDescriptor, &_activeDescriptors);
				_socketMap.erase(tlsSocket->_socketDescriptor);
			_mutex.unlock();

			tlsSocket->releaseOwner();
		}

		void TLSServer::sendNewConnectionEvent(TLSSocket *newTLSSocket)
		{
			_mutex.lock();

				// don't emit new connections when we're about to shut down
				if ( _eventHandler && _serverIsRunning )
				{
					// we have to send the (original) shared pointer stored by the server
					TLSSocket_sharedPtr sharedPointer = _socketMap.at(newTLSSocket->_socketDescriptor);
					_eventHandler->tlsNewConnection(sharedPointer);
				}

			_mutex.unlock();
		}

	}
}
