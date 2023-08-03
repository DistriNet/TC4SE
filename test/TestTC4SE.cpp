#include <boost/outcome/try.hpp>
#include <gtest/gtest.h>

#include <thread>
#include <iostream>

#include <tc4se/OpenSSL.h>
#include <tc4se/SGXHandler.h>
#include <tc4se/untrusted/SocketManager.h>
#include <tc4se/untrusted/CurlUtil.h>
#include <tc4se/AttestationService.h>

#include <fmt/format.h>


using namespace tc4se;
using namespace tc4se::untrusted;

#ifdef MEASUREMENT_HANDSHAKE_PACKET
std::map<int32_t, uint64_t> totalBytesWritten;
std::map<int32_t, uint64_t> countWriteCall;
#endif



TEST(TC4SE, GetPCK)
{
    auto res = AttestationService::getPCKId();
    ASSERT_TRUE(res.has_value()) << "Get PCK ID failed: " << (uint64_t)res.assume_error();

    auto platformInfo = std::move(res.assume_value());
    
    auto attestationMaterialRes = AttestationService::getAttestationMaterials(platformInfo, INTEL_API_KEY);
    ASSERT_TRUE(attestationMaterialRes) << "Get Attestation Material failed";

    auto attestationMaterial { std::move(attestationMaterialRes.assume_value()) };

    ASSERT_TRUE(AttestationService::setMachinePCK(attestationMaterial.first));

    AttestationService::setCollateralCertQueryFunc([collateral = std::move(attestationMaterial.second.getCollateralCerts())] () -> Expect<QuoteCollateralCertificates> {
        return collateral;
    });

    AttestationService::setTCBInfoQueryFunction([tcbInfo = std::move(attestationMaterial.second.getTCBInfo())]  (const std::string& fmspc) -> Expect<TCBInfo> {
        return tcbInfo;
    });

    using Clock = std::chrono::system_clock;
    using Duration = Clock::duration;
    std::cout << Duration::period::num << " , " << Duration::period::den << '\n';
}

sgx::EnclaveHandler serverEnclave { SERVER_ENCLAVE_PATH },
                    clientEnclave { CLIENT_ENCLAVE_PATH }; 

TEST(TC4SE, TrustExchange)
{
    // Initialize server enclave
    ASSERT_TRUE(serverEnclave.ecall<tc4se_test_prepareServer>() == ErrorCode::SUCCESS) << "Error Initializing Server";

    // Initialize client enclave
    ASSERT_TRUE(clientEnclave.ecall<tc4se_test_prepareClient>() == ErrorCode::SUCCESS) << "Error Initializing Client";

    // Create server socket
    untrusted::SocketManager serverSocket;
    auto socketOutcome = serverSocket.createSocket(SocketType::TCP_SOCKET, true);

    ASSERT_FALSE(socketOutcome.has_error()) << "Create Server Socket Failed";
    ASSERT_FALSE(serverSocket.bindSocket(7890).has_error()) << "Bind Server Socket Failed";
    ASSERT_FALSE(serverSocket.listenSocket(SOMAXCONN).has_error()) << "Listen Socket Failed";

    
    ErrorCode serverError = ErrorCode::UNREACHABLE, clientError = ErrorCode::UNREACHABLE;
    {
        // Start server thread, waiting for client connection
        std::jthread serverThread {
            [&] {
                if(auto res = serverSocket.acceptConection(); res.has_value())
                {
                    std::cout << "Accept client in server: " << res.assume_value() << std::endl;
                    // Dispatch accepted socket into enclave
                    serverError = serverEnclave.ecall<tc4se_test_acceptTrustExchange>(res.assume_value());
                    std::cout << "Done processing server\n";

                    #ifdef MEASUREMENT_HANDSHAKE_PACKET
                    std::stringstream ss;
                    ss << "Server TrustExchange " << totalBytesWritten[res.assume_value()] << " " << countWriteCall [res.assume_value()];
                    tc4se_printDebug(ss.str().c_str());
                    #endif
                }
                else std::cout << "Server error\n";
            }
        };

        // Start client thread, initiate connection to server socket
        std::jthread clientThread {
            [&] {
                
                if(auto res = SocketManagerUtil::openConnection("localhost", 7890); res.has_value())
                {
                    std::cout << "Begin send client: " << res.assume_value() << std::endl;
                    // Dispatch client socket into enclave
                    clientError = clientEnclave.ecall<tc4se_test_initiateTrustExchange>(res.assume_value());
                    std::cout << "Done processing client\n";
                    SocketManagerUtil::shutdownAndClose(res.assume_value());

                    #ifdef MEASUREMENT_HANDSHAKE_PACKET
                    std::stringstream ss;
                    ss << "Client TrustExchange " << totalBytesWritten[res.assume_value()] << " " << countWriteCall [res.assume_value()];
                    tc4se_printDebug(ss.str().c_str());
                    #endif
                }
                else std::cout << "Client error\n";
            }
        };

        // End of scope, join all thread
    }
    #ifdef MEASUREMENT_HANDSHAKE_PACKET
    totalBytesWritten.clear();
    countWriteCall.clear();
    #endif

    // Result of the operation
    EXPECT_EQ(serverError, ErrorCode::SUCCESS);
    EXPECT_EQ(clientError, ErrorCode::SUCCESS);
}

TEST(TC4SE, TrustedChannel)
{
    // Create server socket
    untrusted::SocketManager serverSocket;
    auto socketOutcome = serverSocket.createSocket(SocketType::TCP_SOCKET, true);

    ASSERT_FALSE(socketOutcome.has_error()) << "Create Server Socket Failed";
    ASSERT_FALSE(serverSocket.bindSocket(7891).has_error()) << "Bind Server Socket Failed";
    ASSERT_FALSE(serverSocket.listenSocket(SOMAXCONN).has_error()) << "Listen Socket Failed";

    ErrorCode serverError = ErrorCode::UNREACHABLE, clientError = ErrorCode::UNREACHABLE;
    {
        // Start server thread, waiting for client connection
        std::jthread serverThread {
            [&] {
                if(auto res = serverSocket.acceptConection(); res.has_value())
                {
                    std::cout << "Accept client in server: " << res.assume_value() << std::endl;
                    // Dispatch accepted socket into enclave
                    serverError = serverEnclave.ecall<tc4se_test_acceptTrustedChannelPeer>(res.assume_value(), "Hellaw Juga Client");
                    std::cout << "Done processing server\n";

                    #ifdef MEASUREMENT_HANDSHAKE_PACKET
                    std::stringstream ss;
                    ss << "Server TrustedChannel " << totalBytesWritten[res.assume_value()] << " " << countWriteCall [res.assume_value()];
                    tc4se_printDebug(ss.str().c_str());
                    #endif
                }
                else std::cout << "Server error\n";
            }
        };

        // Start client thread, initiate connection to server socket
        std::jthread clientThread {
            [&] {
                
                if(auto res = SocketManagerUtil::openConnection("localhost", 7891); res.has_value())
                {
                    std::cout << "Begin send client: " << res.assume_value() << std::endl;
                    // Dispatch client socket into enclave
                    clientError = clientEnclave.ecall<tc4se_test_connectTrustedChannelPeer>(res.assume_value(), "Hellaw Server");
                    std::cout << "Done processing client\n";
                    SocketManagerUtil::shutdownAndClose(res.assume_value());

                    #ifdef MEASUREMENT_HANDSHAKE_PACKET
                    std::stringstream ss;
                    ss << "Client TrustedChannel " << totalBytesWritten[res.assume_value()] << " " << countWriteCall [res.assume_value()];
                    tc4se_printDebug(ss.str().c_str());
                    #endif
                }
                else std::cout << "Client error\n";
            }
        };

        // End of scope, join all thread
    }

    // Result of the operation
    EXPECT_EQ(serverError, ErrorCode::SUCCESS);
    EXPECT_EQ(clientError, ErrorCode::SUCCESS);
}

extern "C"
{
    size_t u_sgxssl_write(int fd, const void* buf, size_t n)
    {
        #ifdef MEASUREMENT_HANDSHAKE_PACKET
        if(!totalBytesWritten.contains(fd))
        {
            totalBytesWritten[fd] = 0;
            countWriteCall[fd] = 0;
        }

        totalBytesWritten[fd] += n;
        countWriteCall[fd] += 1;
        #endif

        return write(fd, buf, n);
    }
    size_t u_sgxssl_read(int fd, void* buf, size_t n)
    {
        return read(fd, buf, n);
    }
    int u_sgxssl_close(int fd)
    {
        return close(fd);
    }
}