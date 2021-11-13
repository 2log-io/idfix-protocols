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


#include "MutexLocker.h"
#include "WebSocket.h"
#include "WebSocketEventHandler.h"
#include "auxiliary.h"

extern "C"
{
    #include <esp_log.h>
    #include "http_parser.h"
}

namespace
{
    const char*     LOG_TAG                         = "IDFix::WebSocket";
    const int       WEBSOCKET_TCP_DEFAULT_PORT      = 80;
    const int       WEBSOCKET_SSL_DEFAULT_PORT      = 443;
    const int       WEBSOCKET_BUFFER_SIZE           = 1024;
    const int       WEBSOCKET_NETWORK_TIMEOUT       = 5*1000; // ms
    const int       TRANSPORT_POLL_TIMEOUT          = 1000; // ms
}

namespace IDFix
{
	namespace Protocols
	{
        WebSocket::WebSocket(WebSocketEventHandler *eventHandler) : IDFix::Task("idfix_websocket", 5120),
                                                                    _websocketMutex(Mutex::Recursive), _stateMutex(Mutex::Recursive),
                                                                    _eventHandler(eventHandler), _bufferSize(WEBSOCKET_BUFFER_SIZE),
                                                                    _networkTimeoutMS(WEBSOCKET_NETWORK_TIMEOUT)
		{

        }

        WebSocket::~WebSocket()
        {
            bool stopTheTask = false;

            _stateMutex.lock();
                _websocketMutex.lock();

                    if ( _websocketState != WebSocketState::Stopped )
                    {
                        _websocketState = WebSocketState::Stopped;
                        stopTheTask = true;
                    }

                    cleanup();

                _websocketMutex.unlock();
            _stateMutex.unlock();

            if ( stopTheTask )
            {
                stopTask();
            }
        }

        bool WebSocket::start()
        {
            if ( getWebsocketState() == WebSocketState::Stopped )
            {
                MutexLocker websocketLocker(_websocketMutex);

                _eventQueue = xQueueCreate( 1, sizeof( WebSocketEvent ) );
                if ( !_eventQueue )
                {
                    ESP_LOGE(LOG_TAG, "Error create event queue");
                    return false;
                }

                if ( ! initTransportList() )
                {
                    cleanup();
                    return false;
                }

                _rxBuffer = new char [ _bufferSize ];
                if ( !_rxBuffer )
                {
                    ESP_LOGE(LOG_TAG, "Failed to allocate rx buffer");
                    cleanup();
                    return false;
                }

                _txBuffer = new char [ _bufferSize ];
                if ( !_txBuffer )
                {
                    ESP_LOGE(LOG_TAG, "Failed to allocate tx buffer");
                    cleanup();
                    return false;
                }

                websocketLocker.unlock();

                setWebsocketState(WebSocketState::Idle);

                startTask();

                return true;
            }
            else
            {
                ESP_LOGW(LOG_TAG, "Websocket already running!");
            }

            return false;
        }

        bool WebSocket::stop()
        {
            if ( ! _stateMutex.tryLock() )
            {
                ESP_LOGW(LOG_TAG, "Failed to lock _stateMutex!");
                return false;
            }

                WebSocketState currentState = _websocketState;

            _stateMutex.unlock();

            if ( currentState == WebSocketState::Idle )
            {                
                WebSocketEvent  event;
                event.action = WebSocketAction::Stop;

                if ( xQueueSend(_eventQueue, &event, 0) != pdPASS )
                {
                    ESP_LOGE(LOG_TAG, "Failed to queue Stop event!");
                    return false;
                }

                return true;
            }
            else
            {
                ESP_LOGE(LOG_TAG, "Websocket not in idle state");
                return false;
            }
        }

        void WebSocket::cleanup()
        {
            volatile MutexLocker websocketLocker(_websocketMutex);

            if ( _transportList )
            {
                esp_transport_list_destroy(_transportList);
                _transportList = nullptr;
            }

            if ( _rxBuffer )
            {
                delete [] _rxBuffer;
            }

            if ( _txBuffer )
            {
                delete [] _txBuffer;
            }

            if ( _eventQueue )
            {
                vQueueDelete(_eventQueue);
                _eventQueue = nullptr;
            }
        }

        void WebSocket::setWebsocketState(WebSocket::WebSocketState newState)
        {
            volatile MutexLocker locker(_stateMutex);

            _websocketState = newState;
        }

        WebSocket::WebSocketState WebSocket::getWebsocketState()
        {
            volatile MutexLocker locker(_stateMutex);

            return _websocketState;
        }

        bool WebSocket::setURL(const std::string &url)
        {
            if ( getWebsocketState() == WebSocketState::Idle )
            {
                return parseURL(url);
            }

            ESP_LOGE(LOG_TAG, "websocket not in idle state");
            return false;
        }

        bool WebSocket::setCaCertificate(const char *certificate)
        {
            if ( getWebsocketState() == WebSocketState::Idle )
            {
                esp_transport_handle_t sslTransport;

                _websocketMutex.lock();

                    sslTransport = esp_transport_list_get_transport(_transportList, "_ssl");
                    esp_transport_ssl_set_cert_data(sslTransport, certificate, strlen(certificate) );

                _websocketMutex.unlock();

                return true;
            }

            ESP_LOGE(LOG_TAG, "websocket not in idle state");
            return false;
        }

        bool WebSocket::setBufferSize(const int bufferSize)
        {
            bool result = false;

            _stateMutex.lock();
                if ( _websocketState == WebSocketState::Stopped )
                {
                    _websocketMutex.lock();
                        _bufferSize = bufferSize;
                    _websocketMutex.unlock();

                    result = true;
                }
            _stateMutex.unlock();

            return result;
        }

        bool WebSocket::connect(uint32_t delayTime)
        {

            if ( ! _stateMutex.tryLock() )
            {
                ESP_LOGE(LOG_TAG, "Failed to lock _stateMutex!");
                return false;
            }

                WebSocketState currentState = _websocketState;

            _stateMutex.unlock();

            if ( currentState == WebSocketState::Idle )
            {
                WebSocketEvent  event;
                event.action    = WebSocketAction::Connect;
                event.delay     = delayTime;

                if ( xQueueSend(_eventQueue, &event, 0) != pdPASS )
                {
                    ESP_LOGW(LOG_TAG, "Failed to queue Connect event!");
                    return false;
                }

                ESP_LOGI(LOG_TAG, "Queued connect event!");
                return true;
            }
            else
            {
                ESP_LOGE(LOG_TAG, "Websocket not in idle state");
                return false;
            }
        }

        bool WebSocket::disconnect()
        {

            if ( ! _stateMutex.tryLock() )
            {
                ESP_LOGE(LOG_TAG, "Failed to lock _stateMutex!");
                return false;
            }

                WebSocketState currentState = _websocketState;

            _stateMutex.unlock();

            if ( (currentState == WebSocketState::Connecting) || (currentState == WebSocketState::Connected) )
            {
                WebSocketEvent  event;
                event.action = WebSocketAction::Disconnect;

                if ( xQueueSend(_eventQueue, &event, 0) != pdPASS )
                {
                    ESP_LOGW(LOG_TAG, "Failed to queue Disconnect event!");
                    return false;
                }

                ESP_LOGI(LOG_TAG, "Queued disconnect event!");
                return true;
            }
            else
            {
                ESP_LOGE(LOG_TAG, "Websocket not in connecting or connected state");
                return false;
            }
        }

        bool WebSocket::isConnected()
        {
            volatile MutexLocker locker(_stateMutex);

            return _websocketState == WebSocketState::Connected;
        }

        int WebSocket::sendWithOpcode(ws_transport_opcodes_t opcode, const char *data, int len, int timeout)
        {
            if ( data == nullptr || len <= 0 )
            {
                ESP_LOGE(LOG_TAG, "Invalid arguments");
                return ESP_FAIL;
            }

            if ( getWebsocketState() != WebSocketState::Connected )
            {
                ESP_LOGE(LOG_TAG, "Websocket client is not connected");
                return ESP_FAIL;
            }

            _websocketMutex.lock();
                if ( _websocketTransport == nullptr )
                {
                    _websocketMutex.unlock();
                    ESP_LOGE(LOG_TAG, "Invalid transport");
                    return ESP_FAIL;
                }

                int needWrite = len;
                int writeLen = 0, writeIndex = 0;

                uint32_t currentOpcode = opcode;
                while (writeIndex < len)
                {
                    if (needWrite > _bufferSize)
                    {
                        needWrite = _bufferSize;
                    }
                    else
                    {
                        currentOpcode |= 0x80; // WS_TRANSPORT_OPCODES_FIN is currently only defined in ESP32-IDF
                    }

                    memcpy(_txBuffer, data + writeIndex, needWrite);

                    // send with ws specific way and specific opcode
                    writeLen = esp_transport_ws_send_raw(_websocketTransport, static_cast<ws_transport_opcodes_t>(currentOpcode), _txBuffer, needWrite, timeout);

                    if (writeLen <= 0)
                    {
                        _websocketMutex.unlock();

                        ESP_LOGE(LOG_TAG, "Network error: esp_transport_write() returned %d, errno=%d", writeLen, errno);

                        abortConnection();

                        return writeLen;
                    }

                    currentOpcode = 0; // set the opcode only for the first fragment
                    writeIndex += writeLen;
                    needWrite = len - writeIndex;
                }
            _websocketMutex.unlock();

            return writeIndex;
        }

        int WebSocket::sendTextMessage(const std::string &message)
        {
            if ( getWebsocketState() != WebSocketState::Connected )
            {
                return -1;
            }

            return sendWithOpcode(WS_TRANSPORT_OPCODES_TEXT, message.c_str(), static_cast<int>( message.length() ), _networkTimeoutMS);
        }

        int WebSocket::sendBinaryMessage(const char *data, int length)
        {
            if ( getWebsocketState() != WebSocketState::Connected )
            {
                return -1;
            }

            //ESP_LOGV(LOG_TAG, "sendBinaryMessage: %s - running in task: %s", std::string(data, length).c_str(), Task::getRunningTaskName().c_str() );
            return sendWithOpcode(WS_TRANSPORT_OPCODES_BINARY, data, length, _networkTimeoutMS);
        }

        void WebSocket::run()
        {
            ESP_LOGV(LOG_TAG, "Start websocket loop");

            while (true)
            {
                switch (_websocketState)
                {
                    case WebSocketState::Idle:

                        waitForEvent();
                        break;

                    case WebSocketState::Stopping:

                        _websocketMutex.lock();

                            setWebsocketState(WebSocketState::Stopped);
                            cleanup();

                        _websocketMutex.unlock();

                        stopTask();

                        break;

                    case WebSocketState::Connecting:

                        connectTransport();
                        break;

                    case WebSocketState::Connected:

                        {
                            _websocketMutex.lock();
                                int readSelect = esp_transport_poll_read(_websocketTransport, TRANSPORT_POLL_TIMEOUT);
                            _websocketMutex.unlock();

                            // readSelect == 0 => no data to process

                            if ( readSelect < 0 )
                            {
                                ESP_LOGE(LOG_TAG, "Network error: esp_transport_poll_read() returned %d, errno=%d", readSelect, errno);

                                abortConnection();

                                break;
                            }

                            if ( readSelect > 0 )
                            {
                                if ( readData() == false )
                                {
                                    abortConnection();
                                }
                            }

                        }
                        break;

                    default:
                        break;
                }

                checkForDisconnectEvent();
            }
        }

        bool WebSocket::initTransportList()
        {
            volatile MutexLocker websocketLocker(_websocketMutex);

            _transportList = esp_transport_list_init();
            if ( !_transportList )
            {
                ESP_LOGE(LOG_TAG, "Failed to init transport list");
                return false;
            }

            esp_transport_handle_t tcpTransport = esp_transport_tcp_init();
            if ( !tcpTransport )
            {
                ESP_LOGE(LOG_TAG, "Failed to init transport tcp");
                return false;
            }

            esp_transport_set_default_port(tcpTransport, WEBSOCKET_TCP_DEFAULT_PORT);
            esp_transport_list_add(_transportList, tcpTransport, "_tcp");

                    esp_transport_handle_t wsTransport = esp_transport_ws_init(tcpTransport);
                    if ( !wsTransport )
                    {
                        ESP_LOGE(LOG_TAG, "Failed to init transport ws");
                        return false;
                    }

                    esp_transport_set_default_port(wsTransport, WEBSOCKET_TCP_DEFAULT_PORT);
                    esp_transport_list_add(_transportList, wsTransport, "ws");


            esp_transport_handle_t sslTransport = esp_transport_ssl_init();
            if ( !sslTransport )
            {
                ESP_LOGE(LOG_TAG, "Failed to init transport ssl");
                return false;
            }

            esp_transport_set_default_port(sslTransport, WEBSOCKET_SSL_DEFAULT_PORT);
            esp_transport_list_add(_transportList, sslTransport, "_ssl");

                    esp_transport_handle_t wssTransport = esp_transport_ws_init(sslTransport);
                    if ( !wssTransport )
                    {
                        ESP_LOGE(LOG_TAG, "Failed to init transport wss");
                        return false;
                    }

                    esp_transport_set_default_port(wssTransport, WEBSOCKET_SSL_DEFAULT_PORT);
                    esp_transport_list_add(_transportList, wssTransport, "wss");

                    return true;
        }

        bool WebSocket::parseURL(const std::string &websocketURL)
        {
            volatile MutexLocker locker(_websocketMutex);

            const char *uri = websocketURL.c_str();

            ESP_LOGI(LOG_TAG, "Parsing URL %s", uri);

            struct http_parser_url puri;
            http_parser_url_init(&puri);

            if( http_parser_parse_url(uri, strlen(uri), 0, &puri) != 0 )
            {
                ESP_LOGE(LOG_TAG, "Failed to parse URL %s", websocketURL.c_str() );
                return false;
            }

            if ( puri.field_data[UF_SCHEMA].len )
            {
                bool supportedSchema = false;

                if ( puri.field_data[UF_SCHEMA].len == 2 )
                {
                    if ( memcmp(uri + puri.field_data[UF_SCHEMA].off, "ws", 2) == 0 )
                    {
                        _schema = WebSocketURLSchema::WS;
                        supportedSchema = true;
                    }
                }
                else if ( puri.field_data[UF_SCHEMA].len == 3 )
                {
                    if ( memcmp(uri + puri.field_data[UF_SCHEMA].off, "wss", 3) == 0 )
                    {
                        _schema = WebSocketURLSchema::WSS;
                        supportedSchema = true;
                    }
                }

                if ( !supportedSchema )
                {
                    ESP_LOGE(LOG_TAG, "URL schema not supported");
                    return false;
                }
            }
            else
            {
                ESP_LOGE(LOG_TAG, "No URL schema given");
                return false;
            }

            if ( puri.field_data[UF_HOST].len )
            {
                _host.assign(uri + puri.field_data[UF_HOST].off, puri.field_data[UF_HOST].len);
            }
            else
            {
                ESP_LOGE(LOG_TAG, "No host given");
                return false;
            }

            if ( puri.field_data[UF_PORT].off )
            {
                _port = strtol( static_cast<const char*>(uri + puri.field_data[UF_PORT].off), nullptr, 10);
            }

            return true;
        }

        void WebSocket::connectTransport()
        {
            MutexLocker locker(_websocketMutex);

            _websocketTransport = nullptr;

            if ( _schema == WebSocketURLSchema::WS )
            {
                _websocketTransport = esp_transport_list_get_transport(_transportList, "ws");
            }
            else if ( _schema == WebSocketURLSchema::WSS )
            {
                _websocketTransport = esp_transport_list_get_transport(_transportList, "wss");
            }

            if ( _websocketTransport == nullptr )
            {
                // should actually never happen
                setWebsocketState(WebSocketState::Idle);
                return;
            }

            if ( _port == 0 )
            {
                _port = esp_transport_get_default_port(_websocketTransport);
            }

            ESP_LOGI(LOG_TAG, "Transport connecting to %s:%d", _host.c_str(), _port);
            if ( esp_transport_connect(_websocketTransport, _host.c_str(), _port, 10*1000) < 0 )
            {
                ESP_LOGE(LOG_TAG, "Error transport connect");

                esp_transport_close(_websocketTransport);

                setWebsocketState(WebSocketState::Idle);
                locker.unlock();

                if ( _eventHandler )
                {
                    _eventHandler->webSocketDisconnected();
                }

                return;
            }

            locker.unlock();

            ESP_LOGI(LOG_TAG, "Transport connected");
            setWebsocketState(WebSocketState::Connected);

            if ( _eventHandler )
            {
                _eventHandler->webSocketConnected();
            }
        }

        void WebSocket::waitForEvent()
        {
            WebSocketEvent event;

            if( xQueuePeek(_eventQueue, &event, portMAX_DELAY) == pdTRUE )
            {
                switch (event.action)
                {
                    case WebSocketAction::Connect:

                        // prevent multiple connects, by keeping the queue full
                        // until a _state != idle prevents connect() from sending further connects
                        setWebsocketState(WebSocketState::Connecting);

                        // now we remove the event from the queue (e.g. clear the queue)
                        xQueueReset(_eventQueue);

                        if ( event.delay > 0 )
                        {
                            ESP_LOGI(LOG_TAG, "Connect delayed for %d ms", event.delay);
                            delay(event.delay);
                        }

                        break;

                    case WebSocketAction::Stop:

                        setWebsocketState(WebSocketState::Stopping);
                        xQueueReset(_eventQueue);

                        break;

                    default:

                        break;
                }

            }
            else
            {
                ESP_LOGW(LOG_TAG, "waitForEvent: xQueuePeek timeout!");
            }
        }

        bool WebSocket::readData()
        {
            int bytesRead;
            int payloadLength;
            ws_transport_opcodes opcode;
            bool moreDataToRead = false;
            int payloadOffset = 0;

            do
            {
                _websocketMutex.lock();
                    bytesRead = esp_transport_read(_websocketTransport, _rxBuffer, _bufferSize, _networkTimeoutMS);
                _websocketMutex.unlock();

                if ( bytesRead < 0 )
                {
                    ESP_LOGE(LOG_TAG, "Error read data");
                    return false;
                }

                _websocketMutex.lock();
                    payloadLength   = esp_transport_ws_get_read_payload_len(_websocketTransport);
                    opcode          = esp_transport_ws_get_read_opcode(_websocketTransport);
                _websocketMutex.unlock();

                if ( (payloadOffset + bytesRead) < payloadLength )
                {
                    // websocket payload did not fit into our rx buffer, so we have to process the payload partially
                    moreDataToRead = true;

                    if ( _eventHandler )
                    {
                            if ( opcode == WS_TRANSPORT_OPCODES_BINARY )
                            {
                                _eventHandler->webSocketBinaryMessageFragmentReceived(_rxBuffer, bytesRead, payloadOffset, payloadLength);
                            }
                            else if ( opcode == WS_TRANSPORT_OPCODES_TEXT )
                            {
                                _eventHandler->webSocketTextMessageFragmentReceived( std::string(_rxBuffer, static_cast<unsigned long>(bytesRead) ) );
                            }
                    }

                    payloadOffset = payloadOffset + bytesRead;
                }
                else
                {
                    moreDataToRead = false;

                    if ( payloadOffset == 0) // we have an unsegmented payload
                    {
                        // as ping/pong frames are limited to 125 bytes they should actually only occure in unsegmented payloads
                        if ( opcode == WS_TRANSPORT_OPCODES_PING )
                        {
                            const char* pongPayload = (payloadLength == 0) ? nullptr : _rxBuffer;

                            _websocketMutex.lock();
                                esp_transport_ws_send_raw(_websocketTransport, WS_TRANSPORT_OPCODES_PONG, pongPayload, payloadLength, _networkTimeoutMS);
                            _websocketMutex.unlock();

                            return true;
                        }

                        if ( (_eventHandler != nullptr) && (payloadLength > 0) )
                        {
                            if ( opcode == WS_TRANSPORT_OPCODES_BINARY )
                            {
                                //ESP_LOGW(LOG_TAG, "binaryMessageReceived: %s", std::string(_rxBuffer, static_cast<unsigned long>(payloadLength) ).c_str() );
                                _eventHandler->webSocketBinaryMessageReceived(_rxBuffer, payloadLength);
                            }
                            else if ( opcode == WS_TRANSPORT_OPCODES_TEXT )
                            {
                                //ESP_LOGV(LOG_TAG, "textMessageReceived: %s", std::string(_rxBuffer, static_cast<unsigned long>(payloadLength) ).c_str() );
                                _eventHandler->webSocketTextMessageReceived( std::string(_rxBuffer, static_cast<unsigned long>(payloadLength) ) );
                            }
                        }

                    }
                    else // we have the last part of a segmented payload
                    {
                        if ( _eventHandler )
                        {
                            if ( opcode == WS_TRANSPORT_OPCODES_BINARY )
                            {
                                //ESP_LOGV(LOG_TAG, "binaryMessageFragmentReceived: %s", std::string(_rxBuffer, static_cast<unsigned long>(bytesRead) ).c_str() );
                                _eventHandler->webSocketBinaryMessageFragmentReceived(_rxBuffer, bytesRead, payloadOffset, payloadLength);
                            }
                            else if ( opcode == WS_TRANSPORT_OPCODES_TEXT )
                            {
                                //ESP_LOGV(LOG_TAG, "textMessageFragmentReceived: %s", std::string(_rxBuffer, static_cast<unsigned long>(bytesRead) ).c_str() );
                                _eventHandler->webSocketTextMessageFragmentReceived( std::string(_rxBuffer, static_cast<unsigned long>(bytesRead) ), true );
                            }
                        }
                    }
                }


             }
            while( moreDataToRead );

            return true;
        }

        void WebSocket::abortConnection()
        {
            _websocketMutex.lock();
                esp_transport_close(_websocketTransport);
            _websocketMutex.unlock();

            setWebsocketState(WebSocketState::Idle);
            xQueueReset(_eventQueue);

            if ( _eventHandler )
            {
                _eventHandler->webSocketDisconnected();
            }
        }

        void WebSocket::checkForDisconnectEvent()
        {
            WebSocketEvent event;

            if( xQueuePeek(_eventQueue, &event, 0) == pdTRUE )
            {
                switch (event.action)
                {
                    case WebSocketAction::Disconnect:

                        ESP_LOGI(LOG_TAG, "Received queued disconnect event");
                        xQueueReset(_eventQueue);

                        abortConnection();

                        break;

                    default:

                        break;
                }

            }

        }

	}
}


