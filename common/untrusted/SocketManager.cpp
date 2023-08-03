#include <csignal>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ostream>
#include <sys/socket.h>
#include <unistd.h>
#include <memory>

#include <tc4se/Constants.h>
#include <tc4se/untrusted/SocketManager.h>

using namespace tc4se;
using namespace tc4se::untrusted;

Expect<int32_t> SocketManagerUtil::createSocket(SocketType socketType, bool blockingState, uint32_t protocol)
{
    /* Reference: https://man7.org/linux/man-pages/man7/ip.7.html
     * tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
     * udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
     * raw_socket = socket(AF_INET, SOCK_RAW, protocol);
     */

    int32_t type;
    switch (socketType)
    {
    case SocketType::TCP_SOCKET:
        type = blockingState ? (SOCK_STREAM) : (SOCK_STREAM | SOCK_NONBLOCK);
        break;
    case SocketType::UDP_SOCKET:
        type = blockingState ? (SOCK_DGRAM) : (SOCK_DGRAM | SOCK_NONBLOCK);
        break;
    case SocketType::RAW_SOCKET:
        type = blockingState ? (SOCK_RAW) : (SOCK_RAW | SOCK_NONBLOCK);
        break;
    default:
        break;
    }

    auto socketEndpoint {socket(AF_INET, type, protocol)};
    const int32_t enable = 1;
    if (setsockopt(socketEndpoint, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
    {
        std::cout << "Set SO_REUSEADDR failed!" << std::endl;
        return ErrorCode::SOCKET_GENERIC_ERROR;
    }

    if (socketEndpoint == -1)
    {
        std::cout << "Could not create socket!" << std::endl;
        return ErrorCode::SOCKET_CREATE_FAILED;
    }

    return socketEndpoint;
}

Expect<void> SocketManagerUtil::listenSocket(int32_t socketEndpoint, int32_t maximumConnection)
{
    if (listen(socketEndpoint, maximumConnection) == -1)
    {
        std::cout << "Socket listen failed!" << std::endl;
        return ErrorCode::SOCKET_LISTEN_FAILED;
    }
    return success;
}

Expect<void> SocketManagerUtil::bindSocket(int32_t socketEndpoint, uint32_t port)
{
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(socketEndpoint, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) < 0)
    {
        std::cout << "The port is already in use by another process!" << std::endl;
        return ErrorCode::SOCKET_PORT_OCCUPIED;
    }
    return success;
}

Expect<int32_t> SocketManagerUtil::acceptConection(int32_t socketEndpoint)
{
    sockaddr_in addr {};
    uint32_t addrSize {sizeof(addr)};
    int32_t peerEndpoint {accept(socketEndpoint, reinterpret_cast<sockaddr*>(&addr), &addrSize)};
    if (peerEndpoint <= 0)
    {
        std::cout << "Socket accept failed!" << std::endl;
        return ErrorCode::SOCKET_ACCEPT_FAILED;
    }
    return peerEndpoint;
}

uint64_t SocketManagerUtil::shutdownAndClose(int32_t endpoint)
{
    shutdown(endpoint, SHUT_RDWR);
    if (0 != close(endpoint))
    {
        std::cout << "Socket close failed!" << std::endl;
        return to_underlying(ErrorCode::SOCKET_CLOSED_FAILED);
    }
    return to_underlying(ErrorCode::SUCCESS);
}

Expect<int32_t> SocketManagerUtil::openConnection(std::string const& hostname, uint16_t port)
{
    // https://stackoverflow.com/questions/52727565/client-in-c-use-gethostbyname-or-getaddrinfo
    // with modification

    int sd, err;
    addrinfo hints      = {};
    addrinfo* addrs     = nullptr;
    std::string portStr = std::to_string(port);

    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_protocol   = IPPROTO_TCP;

    err                 = getaddrinfo(hostname.data(), portStr.data(), &hints, &addrs);
    if (err != 0)
    {
        std::cout << "Failed to get address info" << std::endl;
        return ErrorCode::SOCKET_CANNOT_FIND_HOST;
    }

    std::unique_ptr<addrinfo,
                    decltype(
                        [](auto x)
                        {
                            freeaddrinfo(x);
                        })>
        addrInfoPtr {addrs};

    for (addrinfo* addr = addrs; addr != NULL; addr = addr->ai_next)
    {
        sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sd == -1)
            continue;

        if (connect(sd, addr->ai_addr, addr->ai_addrlen) == 0)
            break;

        // err = errno; <- get the errno
        close(sd);
        sd = -1;
    }

    if (sd == -1)
    {
        std::cout << "Failed to get socket" << std::endl;
        return ErrorCode::SOCKET_CANNOT_CONNECT_TO_HOST;
    }

    return sd;
}

Expect<int32_t> SocketManagerUtil::openTCPServerConnection(int16_t port, bool blockingState)
{
    BOOST_OUTCOME_TRY(auto socketFd, SocketManagerUtil::createSocket(SocketType::TCP_SOCKET, blockingState));
    BOOST_OUTCOME_TRY(SocketManagerUtil::bindSocket(socketFd, port));
    BOOST_OUTCOME_TRY(SocketManagerUtil::listenSocket(socketFd));
    return socketFd;
}

SocketManager::~SocketManager()
{
    SocketManagerUtil::shutdownAndClose(this->socketEndpoint);
}

Expect<void> SocketManager::createSocket(SocketType socketType, bool blockingState, uint32_t protocol)
{
    BOOST_OUTCOME_TRY(this->socketEndpoint,  SocketManagerUtil::createSocket(socketType, blockingState, protocol));
    return success;
}

Expect<void> SocketManager::listenSocket(int32_t maximumConnection)
{
    return SocketManagerUtil::listenSocket(this->socketEndpoint, maximumConnection);
}

Expect<void> SocketManager::bindSocket(uint32_t port)
{
    return SocketManagerUtil::bindSocket(this->socketEndpoint, port);
}

Expect<int32_t> SocketManager::acceptConection()
{
    return SocketManagerUtil::acceptConection(this->socketEndpoint);
}

extern "C"
{
    uint32_t ratls_core_SocketManager_openTCPServerConnection(int16_t port, int32_t* serverFd)
    {
        auto outcomeServerFd {SocketManagerUtil::openTCPServerConnection(port, true)};
        if (outcomeServerFd.has_error())
            return to_underlying(outcomeServerFd.assume_error());

        *serverFd = outcomeServerFd.assume_value();

        return to_underlying(ErrorCode::SUCCESS);
    }

    uint32_t ratls_core_SocketManager_acceptConnection(int32_t serverFd, int32_t* clientFd)
    {
        auto outcomeClientFd {SocketManagerUtil::acceptConection(serverFd)};
        if (outcomeClientFd.has_error())
            return to_underlying(outcomeClientFd.assume_error());

        *clientFd = outcomeClientFd.assume_value();

        return to_underlying(ErrorCode::SUCCESS);
    }

    void ratls_core_SocketManager_closeConnection(uint32_t socketFd)
    {
        SocketManagerUtil::shutdownAndClose(socketFd);
    }

    uint32_t ratls_core_SocketManager_openConnection(const char* host, uint16_t port, int32_t* socketFdRet)
    {
        auto outcomeSocketFdRet {SocketManagerUtil::openConnection(host, port)};
        if (outcomeSocketFdRet.has_error())
            return to_underlying(outcomeSocketFdRet.assume_error());

        *socketFdRet = outcomeSocketFdRet.assume_value();

        return to_underlying(ErrorCode::SUCCESS);
    }
}