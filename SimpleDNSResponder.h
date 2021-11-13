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

#ifndef SIMPLEDNSRESPONDER_H
#define SIMPLEDNSRESPONDER_H

#include "IDFixTask.h"
#include "Mutex.h"

extern "C"
{
	#include <arpa/inet.h>
	#include <stdint.h>
	#include <stddef.h>
}

namespace IDFix
{
	namespace Protocols
	{
        /**
         * @brief The SimpleDNSResponder class provides a simple DNS server.
         *
         * The SimpleDNSResponder class provides a simple DNS server which responds to all DNS A-Record queries with the specified IP address.
         * All other queries will be rejected. The implementation does not support EDNS but it's tolerant by safely ignoring any appended ENDS queries.
         */
		class SimpleDNSResponder : private Task
		{

			public:

								SimpleDNSResponder();

                /**
                 * @brief Start the DNS server
                 * @param ipAddress     the ip address which is used as A record query response
                 * @param port          the UDP port on which the server will be listening
                 *
                 * @return  \c 0 on success
                 * @return  \c -1 if server is already running
                 * @return  \c -2 if server could not be started
                 */
				int				start(ip4_addr ipAddress, uint16_t port);

                /**
                 * @brief Stop the DNS server
                 */
				void            stop();


			private:

				const uint16_t	DNS_MAX_MESSAGE_SIZE = 512;

				virtual void	run() override;

				int				_serverPort = { 0 };
				int				_serverSocket = { 0 };
				bool			_serverIsRunning = { false };
				Mutex			_mutex;
				ip4_addr		_ipAddress = { };

				typedef struct __attribute__((__packed__)) DNSMessageHeader
				{
					uint16_t	ID;				// identification number
					uint8_t		RD		: 1;	// recursion desired
					uint8_t		TC		: 1;	// truncated message
					uint8_t		AA		: 1;	// authoritive answer
					uint8_t		OPCode	: 4;	// message_type
					uint8_t		QR		: 1;	// query/response flag
					uint8_t		RCode	: 4;	// response code
					uint8_t		Z		: 3;	// its z! reserved
					uint8_t		RA		: 1;	// recursion available
					uint16_t	QDCount;		// number of question entries
					uint16_t	ANCount;		// number of answer entries
					uint16_t	NSCount;		// number of authority entries
					uint16_t	ARCount;		// number of resource entries
				} DNSMessageHeader;

				typedef struct __attribute__((__packed__)) DNSResourceRecordTypeA
				{
					uint16_t NAME;		// for the sake of simplicity only 16 bit pointers are supported
					uint16_t TYPE;		// Unsigned 16 bit value. The resource record types - determines the content of the RDATA field.
					uint16_t CLASS;		// Class of response.
					uint32_t TTL;		// The time in seconds that the record may be cached. A value of 0 indicates the record should not be cached.
					uint16_t RDLENGTH;	// Unsigned 16-bit value that defines the length in bytes of the RDATA record.
					uint32_t RDATA;		// For the sake of simplicity only ipv4 is supported, and as such it's a unsigned 32 bit
				} DNSResourceRecordTypeA;

				enum
				{
					DNS_OPCODE_QUERY = 0,
					DNS_OPCODE_IQUERY = 1,
					DNS_OPCODE_STATUS = 2
				} DNSOpcode;

				enum
				{
					DNS_QUERY		= 0,
					DNS_RESPONSE	= 1
				};

				enum CLASS
				{
					DNS_CLASS_IN	= 1,
					DNS_CLASS_ANY	= 255
				};

				enum TYPE
				{
					DNS_TYPE_A		= 1,
					DNS_TYPE_ALL	= 255
				};

				enum class DNSResponseCode
				{
					DNS_RESPONSE_NO_ERROR			= 0,
					DNS_RESPONSE_FORMAT_ERROR		= 1,
					DNS_RESPONSE_SERVER_FAILURE		= 2,
					DNS_RESPONSE_NAME_ERROR			= 3,
					DNS_RESPONSE_NOT_IMPLEMENTED	= 4,
					DNS_RESPONSE_REFUSED			= 5
				};

                /**
                 * @brief Processes the DNS message in \c buffer and builds the response message.
                 *
                 * Processes the DNS message in \c buffer and appends the response "in place" to the same
                 * buffer. Therefore \c buffer needs to be at least of #DNS_MAX_MESSAGE_SIZE size.
                 *
                 * @param buffer        the buffer with the DNS query message. Response is appended. Must be at least of #DNS_MAX_MESSAGE_SIZE size
                 * @param messageSize   the size of the query message
                 *
                 * @return  \c 0 if query could not be processed
                 * @return  if > \c 0 the size of the response message irrespectif of answer or error response
                 */
				size_t processMessage(uint8_t *buffer, uint16_t messageSize);

                /**
                 * @brief Generates an error response message
                 * @param header            pointer to the message header
                 * @param responseCode      the #DNSResponseCode to use
                 * @param messageSize       the size of the message parsed by now
                 *
                 * @return                  the size of the response message
                 */
				size_t processError(DNSMessageHeader* header, DNSResponseCode responseCode, size_t messageSize);
		};
	}
}

#endif
