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

#include "SimpleDNSResponder.h"
#include "MutexLocker.h"

extern "C"
{
	#include <string.h>
	#include <arpa/inet.h>
	#include <sys/socket.h>
	#include <esp_log.h>
}

namespace
{
	const char* LOG_TAG = "IDFix::SimpleDNSResponder";
}

namespace IDFix
{
	namespace Protocols
	{

		SimpleDNSResponder::SimpleDNSResponder() : Task("dnsresponder_task")
		{

		}

		int SimpleDNSResponder::start(ip4_addr ipAddress, uint16_t port)
		{
			MutexLocker locker(_mutex);

			if ( _serverIsRunning )
			{
				ESP_LOGW(LOG_TAG, "Server is already running...");
				return -1;
			}

			_serverSocket = socket(AF_INET, SOCK_DGRAM, 0);

			if ( _serverSocket < 0 )
			{
				ESP_LOGE(LOG_TAG, "Could not create socket at file %s:%d.", __FILE__, __LINE__);
				return -2;
			}

			_serverPort = port;
			_ipAddress = ipAddress;

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
				_ipAddress.addr = INADDR_NONE;
				return -2;
			}

			ESP_LOGI(LOG_TAG, "DNS Responder starting on port %u.", _serverPort);

			_serverIsRunning = true;

			locker.unlock();

			Task::startTask();

			return 0;
		}

		void SimpleDNSResponder::stop()
		{
			volatile MutexLocker locker(_mutex);

			if ( _serverIsRunning )
			{
				_serverIsRunning = false;
				close(_serverSocket);
				_serverSocket = -1;
				_ipAddress.addr = INADDR_NONE;

				Task::stopTask();
			}
		}

		void SimpleDNSResponder::run()
		{
			uint8_t messageBuffer[DNS_MAX_MESSAGE_SIZE];
			int messageSize;

			struct sockaddr_in	clientSocketAddress;
			socklen_t			socketAddressLen = sizeof(clientSocketAddress);
			size_t				responseMessageSize;

			while ( true )
			{
				messageSize = recvfrom(_serverSocket, messageBuffer, DNS_MAX_MESSAGE_SIZE, 0, reinterpret_cast<struct sockaddr *>(&clientSocketAddress), &socketAddressLen);

				responseMessageSize = processMessage(messageBuffer, messageSize);

				if ( responseMessageSize > 0 )
				{
					sendto(_serverSocket, messageBuffer, responseMessageSize, 0, reinterpret_cast<struct sockaddr *>(&clientSocketAddress), socketAddressLen);
				}
			}
		}

		size_t SimpleDNSResponder::processMessage(uint8_t *buffer, uint16_t messageSize)
		{
			if ( messageSize < sizeof(DNSMessageHeader) )
			{
				ESP_LOGW(LOG_TAG, "Received incomplete DNS header!");
				// received incomplete DNS header, ignore message
				return 0;
			}

			DNSMessageHeader *header = reinterpret_cast<DNSMessageHeader*>(buffer);

			if ( header->QR != DNS_QUERY )
			{
				ESP_LOGW(LOG_TAG, "Only queries expected!");
				// message is not a query, ignore it
				return 0;
			}

			if ( header->OPCode != DNS_OPCODE_QUERY )
			{
				ESP_LOGW(LOG_TAG, "Only standard queries expected!");
				return processError(header, DNSResponseCode::DNS_RESPONSE_FORMAT_ERROR, sizeof(DNSMessageHeader) );
			}

			if ( ( ntohs(header->ANCount) != 0) || ( ntohs(header->NSCount) != 0)  )
			{
				ESP_LOGW(LOG_TAG, "Only questions expected!");

				return processError(header, DNSResponseCode::DNS_RESPONSE_FORMAT_ERROR, sizeof(DNSMessageHeader) );
			}

			if ( ntohs(header->QDCount) != 1 )
			{
				// multiple questions in one query are actually never used
				// see https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query/4083071#4083071

				ESP_LOGW(LOG_TAG, "Only single questions expected!");

				return processError(header, DNSResponseCode::DNS_RESPONSE_FORMAT_ERROR, sizeof(DNSMessageHeader) );
			}

			size_t labelLength = 0;

			uint8_t *currentBufferPointer = buffer + sizeof(DNSMessageHeader);
			uint8_t *messageEnd = buffer + messageSize;

			do
			{
				if ( currentBufferPointer >= messageEnd )
				{
					ESP_LOGW(LOG_TAG, "Unexpected end of message (in QNAME)!");
					return processError(header, DNSResponseCode::DNS_RESPONSE_FORMAT_ERROR, sizeof(DNSMessageHeader) );
				}

				labelLength = *currentBufferPointer;

				if ( labelLength > 63 )
				{
					// labels are not allowed to be larger than 63 octets, moreorver if the first two bits are set,
					// this part is actually a pointer. As we expect only one question in a message, pointers should
					// actually never be expected and we handle this as format error

					ESP_LOGW(LOG_TAG, "Unexpected label length or name pointer!");
					return processError(header, DNSResponseCode::DNS_RESPONSE_FORMAT_ERROR, sizeof(DNSMessageHeader) );
				}

				// we dump the domain name only for debugging, if we would need it later
				// we should copy the labels here
				if ( (currentBufferPointer + labelLength < messageEnd) && (labelLength > 1) )
				{
					// e.g.
					// std::string domainName; domainName.reserve(255 / 2 /* most domains will be smaller than maximum */); domainName.append(...)
					// printf("%.*s.", static_cast<int>(labelLength), currentBufferPointer + 1);
				}

				// if this is the last NULL label, we skip also the NULL byte, so after the loop currentBufferPointer points to the first byte after the name
				currentBufferPointer += labelLength + 1;
			}
			while( labelLength != 0 );
			//printf("\n");


			if ( currentBufferPointer + 4 > messageEnd )
			{
				// we expectedt at least two 16 bit fields for QTYPE and QCLASS
				ESP_LOGW(LOG_TAG, "Unexpected end of message (in QTYPE/QCLASS!");
				return processError(header, DNSResponseCode::DNS_RESPONSE_FORMAT_ERROR, sizeof(DNSMessageHeader) );
			}

			size_t questionLength = ( currentBufferPointer - buffer - sizeof(DNSMessageHeader) + 4 );
			//ESP_LOGD(LOG_TAG, "questionLength: %d", questionLength);

			uint16_t qType;
			uint16_t qClass;

			memcpy(&qType,	currentBufferPointer, sizeof(uint16_t) );
			currentBufferPointer += sizeof(uint16_t);
			memcpy(&qClass,	currentBufferPointer, sizeof(uint16_t) );
			currentBufferPointer += sizeof(uint16_t);

			//ESP_LOGD(LOG_TAG, "qType: %d",	ntohs(qType) );
			//ESP_LOGD(LOG_TAG, "qClass: %d",	ntohs(qClass) );

			if ( ntohs(qType) != TYPE::DNS_TYPE_A && ntohs(qType) != TYPE::DNS_TYPE_ALL )
			{
				return processError(header, DNSResponseCode::DNS_RESPONSE_NAME_ERROR, sizeof(DNSMessageHeader) + questionLength );
			}

			if ( ntohs(qClass) != CLASS::DNS_CLASS_IN && ntohs(qClass) != CLASS::DNS_CLASS_ANY )
			{
				return processError(header, DNSResponseCode::DNS_RESPONSE_NAME_ERROR, sizeof(DNSMessageHeader) + questionLength );
			}

			if ( header->ARCount != 0 )
			{
				// there could be some additional data at the end of the question section for EDNS
				// it may be not RFC compliant, but until now it seems we could savely ignore the additional data
				// at least if we set the ARCount to zero and ignore the trailing data
				header->ARCount = 0;
			}

			size_t responseMessageSize = sizeof(DNSMessageHeader) + questionLength + sizeof(DNSResourceRecordTypeA);

			if ( responseMessageSize > DNS_MAX_MESSAGE_SIZE )
			{
				ESP_LOGW(LOG_TAG, "Not enough memory left to store resource record");

				// as we expect only one question and domain names are restricted to 255 octets
				// this should actually never happen, if so the message seems to be malformed
				return processError(header, DNSResponseCode::DNS_RESPONSE_FORMAT_ERROR, sizeof(DNSMessageHeader) + questionLength );
			}

			DNSResourceRecordTypeA *answer = reinterpret_cast<DNSResourceRecordTypeA*>(currentBufferPointer);

			// we use a pointer to the question section rather than repeating the name here
			// for pointers the top two bits must be set to 11 (0xC0) and the question starts right after the message header
			answer->NAME		= htons( 0xC000 | sizeof(DNSMessageHeader) );
			answer->TYPE		= htons( DNS_TYPE_A );
			answer->CLASS		= htons( DNS_CLASS_IN );
			answer->TTL			= 0; // no caching. Avoids DNS poisoning since this is a DNS hijack
			answer->RDLENGTH	= htons( sizeof(DNSResourceRecordTypeA::RDATA) );
			answer->RDATA		= _ipAddress.addr;

			header->ANCount		= htons(1);
			header->RA			= htons(1);
			header->QR          = DNS_RESPONSE;

			return responseMessageSize;
		}

		size_t SimpleDNSResponder::processError(SimpleDNSResponder::DNSMessageHeader *header, SimpleDNSResponder::DNSResponseCode responseCode, size_t messageSize)
		{
			ESP_LOGW(LOG_TAG, "DNS message error: %d", static_cast<uint8_t>(responseCode));

			header->QR = DNS_RESPONSE;
			header->RCode = static_cast<uint8_t>(responseCode);
			header->RA = 1;

			if ( messageSize > sizeof(DNSMessageHeader) )
			{
				header->QDCount = htons(1);
			}
			else
			{
				header->QDCount = 0;
			}

			header->ANCount = 0;
			header->NSCount = 0;
			header->ARCount = 0;

			return messageSize;
		}
	}
}
