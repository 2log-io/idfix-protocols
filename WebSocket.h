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

#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <string>
#include "IDFixTask.h"
#include "Mutex.h"

extern "C"
{
    #include <esp_event.h>
    #include <esp_transport.h>
    #include "esp_transport_tcp.h"
    #include "esp_transport_ssl.h"
    #include "esp_transport_ws.h"
    #include <freertos/queue.h>
}

namespace IDFix
{
	namespace Protocols
	{
		class WebSocketEventHandler;

        /**
         * @brief The WebSocket class provides a web socket client
         */
        class WebSocket : private IDFix::Task
		{
			public:

                                WebSocket(WebSocketEventHandler *eventHandler);
                                ~WebSocket();

                /**
                 * @brief Initializes the websocket client and starts the task.
                 *
                 * \note    Must be called before any other method.
                 *
                 * @return true on success
                 * @return false on failure
                 */
                bool            start(void);

                /**
                 * @brief Dispatch a stop request to the task and order the client to stop.
                 *
                 * The actual shutdown of the websocket client will be done asynchronously.
                 *
                 * @return true on success
                 * @return false on failure
                 */
                bool            stop(void);

                /**
                 * @brief Sets the websocket's URL to connect
                 * @param url
                 *
                 * @return true on success
                 * @return false on failure
                 */
                bool            setURL(const std::string &url);

                /**
                 * @brief Sets the used certificate authority's root certificate to trust
                 * @param certificate   the root CA X.509 certificate in PEM format as null-terminated string.
                 *
                 * @return true on success
                 * @return false on failure
                 */
                bool            setCaCertificate(const char *certificate);

                /**
                 * @brief Sets the size for the receiving and transmit buffer.
                 *
                 * \note    This method can only be called if the socket is stopped.
                 *
                 * @param bufferSize    the new buffer size in bytes.
                 *
                 * @return true on success
                 * @return false on failure
                 */
                bool            setBufferSize(const int bufferSize);

                /**
                 * @brief Attempts to connect the websocket.
                 *
                 * @param delayTime an optional time to delay the connection attempt in milliseconds
                 *
                 * @return      true if connection attempt was queued
                 * @return      false if connection attempt could not be queued - connect must be called again
                 */
                bool            connect(uint32_t delayTime = 0);

                /**
                 * @brief Attempts to disconnect the websocket
                 *
                 * @return      true if disconnect attempt was queued
                 * @return      false if disconnect attempt could not be queued - disconnect must be called again
                 */
                bool            disconnect(void);

                /**
                 * @brief Returns true if the WebSocket is connected.
                 *
                 * @return  true if the WebSocket is connected.
                 */
                bool            isConnected(void);

                /**
                 * @brief Sends the given message as text message.
                 *
                 * @param message   the text message to send
                 *
                 * @return          >  \c 0 if write operation was successful, the value is the number of bytes actually written to the connection
                 * @return          <= \c 0 if the write operation failed, because either the connection was closed or an error occured
                 */
                int             sendTextMessage(const std::string &message);

                /**
                 * @brief Sends the given data as binary message.
                 *
                 * @param data      the binary data to send.
                 * @param length    the length of the data in bytes.
                 *
                 * @return          >  \c 0 if write operation was successful, the value is the number of bytes actually written to the connection
                 * @return          <= \c 0 if the write operation failed, because either the connection was closed or an error occured
                 */
                int             sendBinaryMessage(const char* data, int length);

            private:

                enum class WebSocketAction
                {
                    Connect,
                    Disconnect,
                    Stop
                };

                /**
                 * @brief The WebSocketEvent struct is used to enque action requests into the internal websocket queue.
                 */
                struct WebSocketEvent
                {
                    WebSocketAction action;          /**< The action to be enqued */
                    uint32_t        delay = {0};     /**< Optinal a delay time in milliseconds */

                };

                struct SendMessageEvent
                {
                    uint32_t        length;
                    const char*     data;
                };

                enum class WebSocketState
                {
                    Stopped,
                    Idle,
                    Connecting,
                    Connected,
                    Disconnecting,
                    Stopping
                };

                enum class WebSocketURLSchema
                {
                    WS,
                    WSS,
                    Invalid
                };

                virtual void	run() override;

                /**
                 * @brief Free any allocated memory
                 */
                void            cleanup(void);

                void            setWebsocketState(WebSocketState state);
                WebSocketState  getWebsocketState(void);

                bool            initTransportList(void);

                /**
                 * @brief Parse the URL and apply the connection details
                 *
                 * @param websocketURL  the URL to set
                 *
                 * @return      true if URL was correctly parsed and set
                 * @return      false if URL could not be parsed or is not supported
                 */
                bool            parseURL(const std::string &websocketURL);

                void            connectTransport(void);

                /**
                 * @brief Wait for an websocket event on the internal queue and process it
                 */
                void            waitForWebsocketEvent(void);

                /**
                * @brief Wait for an sendMessage event on the internal queue and process it
                */

                void            waitForSendMessageEvent(void);

                /**
                 * @brief Read available data from the idf transport stream
                 *
                 * @return      \c true if available data was completely read
                 * @return      \c false if data could not be read
                 */
                bool            readData(void);

                /**
                 * @brief       Disconnect the idf transport stream and reset the internal state
                 */
                void            abortConnection(void);

                /**
                 * @brief       Check non-blocking for a user queued disconnect request and process it
                 */
                void            checkForDisconnectEvent(void);

                /**
                 * @brief       Send the data with given opcode
                 *
                 * @param opcode    the opcode to use
                 * @param data      the data to send
                 * @param len       length of the data in bytes
                 * @param timeout   transfer timeout in milliseconds
                 *
                 * @return          the number of send bytes
                 * @return          ESP_FAIL if data could not be sent
                 */
                int             sendWithOpcode(ws_transport_opcodes_t opcode, const char *data, int len, int timeout);

			private:

                WebSocketState                  _websocketState = { WebSocketState::Stopped };
                Mutex                           _websocketMutex;
                Mutex                           _stateMutex;

                WebSocketEventHandler*          _eventHandler = {};
                QueueHandle_t                   _webSocketEventQueue = { nullptr };
                QueueHandle_t                   _sendMessageEventQueue = { nullptr };

                const char*                     _websocketCert = { nullptr };
                int                             _bufferSize;
                esp_transport_list_handle_t     _transportList = { nullptr };
                esp_transport_handle_t          _websocketTransport = { nullptr };
                char*                           _rxBuffer = { nullptr };
                char*                           _txBuffer = { nullptr };

                int                             _networkTimeoutMS;

                WebSocketURLSchema              _schema = { WebSocketURLSchema::Invalid };
                int                             _port = { 0 };
                std::string                     _host = {};
		};
	}
}

#endif // WEBSOCKET_H
