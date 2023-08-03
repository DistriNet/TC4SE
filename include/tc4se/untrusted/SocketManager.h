#pragma once

#ifndef CORE_UNTRUSTED_SOCKETMANAGER_H
#define CORE_UNTRUSTED_SOCKETMANAGER_H

#include <arpa/inet.h>
#include <sys/socket.h>

#include <string>

#include <tc4se/ErrorCode.h>

namespace tc4se::untrusted
{
    enum class SocketType : uint8_t
    {
        RAW_SOCKET = 0x00,
        TCP_SOCKET = 0x10,
        UDP_SOCKET = 0x20,
    };

    namespace SocketManagerUtil
    {
        uint64_t shutdownAndClose(int32_t endpoint);
        Expect<int32_t> openConnection(std::string const& hostname, uint16_t port);
        Expect<int32_t> openTCPServerConnection(int16_t port, bool blockingState);

        // Refer to https://man7.org/linux/man-pages/man2/socket.2.html
        Expect<int32_t> createSocket(SocketType socketType, bool blockingState, uint32_t protocol = 0);

        // Refer to https://man7.org/linux/man-pages/man2/listen.2.html
        Expect<void> listenSocket(int32_t socketEndpoint, int32_t maximumConnection = SOMAXCONN);

        // Refer to https://man7.org/linux/man-pages/man2/bind.2.html
        Expect<void> bindSocket(int32_t socketEndpoint, uint32_t port);

        // Refer to https://man7.org/linux/man-pages/man2/accept.2.html
        Expect<int32_t> acceptConection(int32_t socketEndpoint);
    } // namespace SocketManagerUtil

    class SocketManager
    {
      private:
        int32_t socketEndpoint;

      public:
        SocketManager() = default;
        SocketManager(int32_t socketEndpoint): socketEndpoint(socketEndpoint) {}
        ~SocketManager();

        // Refer to https://man7.org/linux/man-pages/man2/socket.2.html
        Expect<void> createSocket(SocketType socketType, bool blockingState, uint32_t protocol = 0);

        // Refer to https://man7.org/linux/man-pages/man2/listen.2.html
        Expect<void> listenSocket(int32_t maximumConnection = SOMAXCONN);

        // Refer to https://man7.org/linux/man-pages/man2/bind.2.html
        Expect<void> bindSocket(uint32_t port);

        // Refer to https://man7.org/linux/man-pages/man2/accept.2.html
        Expect<int32_t> acceptConection();

        int32_t getSocketEndpoint() const
        {
            return this->socketEndpoint;
        }
    };
} // namespace tc4se::untrusted

#endif