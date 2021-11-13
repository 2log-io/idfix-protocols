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

#include "TLSSocket.h"
#include "auxiliary.h"
#include "MutexLocker.h"
#include "TLSServer.h"

extern "C"
{
	#include <string.h>
	#include <esp_log.h>
	#include "lwip/sockets.h"
}

namespace
{
	const char*			LOG_TAG				= "IDFix::TLSSocket";
	const unsigned long INITIAL_BUFFER_SIZE	= 256;
}

namespace IDFix
{
	namespace Protocols
	{

		TLSSocket::TLSSocket(int socketDescriptor, SSL *tlsPeer, TLSServer *owner)
			: _owner(owner), _socketDescriptor(socketDescriptor), _tlsPeer(tlsPeer)
		{

		}

		TLSSocket::~TLSSocket()
		{
			close();
			ESP_LOGV(LOG_TAG, "~TLSSocket destructed");
		}

		void TLSSocket::setEventHandler(TLSSocketEventHandler *eventHandler)
		{
			if ( _mutex.lock() )
			{
				_eventHandler = eventHandler;
				_mutex.unlock();
			}
		}

		int TLSSocket::write(const char *bytes, size_t len)
		{
			MutexLocker locker(_mutex);

			ESP_LOGV(LOG_TAG, "TLSSocket::write - %.*s", static_cast<int>(len), bytes);

			return SSL_write(_tlsPeer, bytes, static_cast<int>(len) );
		}

		int TLSSocket::write(const char *string)
		{
			return write(string, strlen(string) );
		}

		void TLSSocket::close()
		{
			_mutex.lock();

				bool disconnectedNow = false;

				if ( _socketDescriptor != -1 )
				{
					if ( _owner != nullptr )
					{
						// remove this socket from the server handling
						// caution: _owner will be released (nullptr) after this call
						_owner->removeSocket(this);
					}

					if ( _sslAccepted )
					{
						// shut down only if connection was an accepted SSL connection
						SSL_shutdown(_tlsPeer);
					}

					shutdown(_socketDescriptor, SHUT_WR);
					::close(_socketDescriptor);
					_socketDescriptor = -1;

					SSL_free(_tlsPeer);
					disconnectedNow = true;
				}

			_mutex.unlock();

			if ( _eventHandler && disconnectedNow )
			{
				_eventHandler->socketDisconnected(*this);
			}
		}

		int TLSSocket::socketReadyRead()
		{
			ByteArray		bytes(INITIAL_BUFFER_SIZE);
			int				result = 0;
			unsigned long	bytesRead = 0;
			unsigned long	pendingBytes;
			MutexLocker		locker(_mutex);

			if ( ! _sslAccepted )
			{
				// SSL connection was not yet accepted (as we waited for any incomming data)
				return acceptSSL();
			}

			// SSL_pending(_tlsPeer) is only valid AFTER the first call on SSL_read
			// so we don't know the final buffer size in before
			// bytes is initialized with INITIAL_BUFFER_SIZE so bytes.capacity should => bytes.size

			do
			{
				result = SSL_read(_tlsPeer, bytes.data() + bytesRead, static_cast<int>(bytes.size() - bytesRead) );
				ESP_LOGI(LOG_TAG, "SSL_read result = %d ", result);
				ESP_LOGI(LOG_TAG, "SSL_pending(_tlsPeer) = %d ", SSL_pending(_tlsPeer));

				if ( result <= 0 )
				{
					// result < 0 means socket was closed
					// check if any bytes was read up to this point, send event and return
					if ( bytesRead != 0 && _eventHandler != nullptr )
					{
						bytes.reserve( bytesRead + 1 );
						bytes.resize(bytesRead);

						addNullTermination(bytes, bytesRead);

						locker.unlock();
						_eventHandler->socketBytesReceived(*this, bytes);
					}

					return result;
				}
				else
				{
					pendingBytes = static_cast<unsigned long>( SSL_pending(_tlsPeer) );
					bytesRead += static_cast<unsigned long>( result );

					if ( pendingBytes > 0 )
					{
						// we reserve +1 byte, while keeping the actual size() exactly at number of bytes read
						// we 0 terminate the data afterwards in the additional reserved byte
						// on binary transfered data, size() will reflect the exact number of transfered bytes - ignoring the 0 termination
						// however, adding a "transparent" zero termination, allows using bytes.data() for string functions ( strcat, strlen )
						bytes.reserve(bytesRead + pendingBytes + 1);
						bytes.resize(bytesRead + pendingBytes);
					}
					else
					{
						bytes.reserve( bytesRead + 1 );
						bytes.resize(bytesRead);

						// TODO: does it make sense to shrink the array?
						// not sure if one of the two possibilities prevent/benefit memory fragmentation
						// bytes.shrink_to_fit();

						// as a first approach, shrink the array if it wastes more than 200 bytes (caused by the initial buffer size)
						if ( (bytes.capacity() - bytes.size() ) > 200 )
						{
							// reserving +1 byte before shrinking for 0 termination
							bytes.resize( bytesRead + 1 );
							bytes.shrink_to_fit();

							// keeping the array exact the size of bytes read
							bytes.resize( bytesRead );
						}
					}

				}

			}
			while( pendingBytes > 0 );

			addNullTermination(bytes, bytesRead);

			ESP_LOGD(LOG_TAG, "number of bytes read = %lu ", bytesRead);
			ESP_LOGV(LOG_TAG, "TLSSocket::read - %.*s", static_cast<int>(bytesRead), bytes.data());

			locker.unlock();

			if ( _eventHandler )
			{
				_eventHandler->socketBytesReceived(*this, bytes);
			}

			return result;
		}

		int TLSSocket::acceptSSL()
		{
			if ( ! SSL_accept(_tlsPeer) )
			{
				ESP_LOGE(LOG_TAG, "SSL_accept() failed at file %s:%d.", __FILE__, __LINE__);

				// disable event handler since this was not a fully established connection
				// we do not want to send any events
				_eventHandler = nullptr;

				// signals the server that SSL_accept failed so it closes and removes the socket
				return -2;
			}
			else
			{
				_sslAccepted = true;

				if ( _owner != nullptr )
				{
					// as the tls connection now is fully established, send the new connection event (through the server)
					_owner->sendNewConnectionEvent(this);
				}

				// signals the server that connection is good
				return 1;
			}
		}

		void TLSSocket::releaseOwner()
		{
			if ( _mutex.lock() )
			{
				_owner = nullptr;
				_mutex.unlock();
				ESP_LOGV(LOG_TAG, "owner released");
			}
		}

		void TLSSocket::addNullTermination(ByteArray &bytes, unsigned long bytesRead)
		{
			if ( bytes.capacity() >= bytes.size()+1 )
			{
                bytes.data()[bytesRead] = static_cast<char>('\0');
			}
			else
			{
				ESP_LOGE(LOG_TAG, "Failed to set transparent 0 termination");
				ESP_LOGE(LOG_TAG, "bytes.capacity() = %zu ", bytes.capacity() );
				ESP_LOGE(LOG_TAG, "bytes.size() = %zu ", bytes.size() );
			}
		}

	}
}
