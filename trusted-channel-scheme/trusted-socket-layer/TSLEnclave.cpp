
#include <TSLEnclave_t.h>
#include <algorithm>
#include <cstdint>

#include <optional>
#include <string>
#include <string_view>
#include <tc4se/OpenSSL.h>
#include <tc4se/ErrorCode.h>

#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "openssl/x509_vfy.h"
#include "sgx_error.h"
#include "sgx_trts.h"
#include "sys/stdint.h"
#include "tc4se/AttestationService.h"
#include "tc4se/Constants.h"

using namespace tc4se;

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

namespace
{
    struct GlobalContext {
        std::optional<openssl::KeyPair> pkey;
        std::optional<openssl::SSLContext> sslCtx;

        int NID_QuoteData;
    } globalContext;

    Expect<void> generateCertificateForServer(SSL* ssl, std::span<uint8_t const> clientHello)
    {
        // Compute the client hello hash
        auto clientHelloHash = BOOST_OUTCOME_TRYX(openssl::computeSHA256Hash(clientHello));

        // Quote the client hello value
        auto quote = BOOST_OUTCOME_TRYX(AttestationService::createAttestationQuote(clientHelloHash));

        // Generate self-signed cert to attach the quote
        openssl::X509Certificate cert { *globalContext.pkey };

        BOOST_OUTCOME_TRY(cert.addNameEntry(openssl::CertificateDN {
            "AQ", 
            "Antartica", 
            "Antartic Ocean", 
            "TSL", 
            "TSL Server Certificate", 
            "TSL Server Certificate", 
            "mail@example.com"
        }));
        BOOST_OUTCOME_TRY(cert.addExtension(NID_basic_constraints, "critical,CA:TRUE,pathlen:1"));
        BOOST_OUTCOME_TRY(cert.addExtension(NID_key_usage, "critical,keyCertSign,digitalSignature,cRLSign"));
        BOOST_OUTCOME_TRY(cert.addExtension(openssl::OpenSSLRef { OBJ_nid2obj(globalContext.NID_QuoteData) }, quote));
        BOOST_OUTCOME_TRY(cert.setValidity(1753630370));
        BOOST_OUTCOME_TRY(cert.selfSign(*globalContext.pkey));

        auto res = SSL_use_PrivateKey(ssl, *globalContext.pkey);
        res = SSL_use_certificate(ssl, cert);
        res = SSL_check_private_key(ssl);

        return success;
    }

    const std::string_view keyMaterialLabel { "EXPERIMENTAL" };
    const uint64_t context = 0xDEADBEEF;

    Expect<void> generateCertificateForClient(SSL* ssl)
    {
        // Generate self-signed cert to attach the quote
        openssl::X509Certificate cert { *globalContext.pkey };

        BOOST_OUTCOME_TRY(cert.addNameEntry(openssl::CertificateDN {
            "AQ", 
            "Antartica", 
            "Antartic Ocean", 
            "TSL", 
            "TSL Client Certificate", 
            "TSL Client Certificate", 
            "mail@example.com"
        }));
        BOOST_OUTCOME_TRY(cert.addExtension(NID_basic_constraints, "critical,CA:TRUE,pathlen:1"));
        BOOST_OUTCOME_TRY(cert.addExtension(NID_key_usage, "critical,keyCertSign,digitalSignature,cRLSign"));
        

        // Compute the export material
        std::array<uint8_t, 256> serverRandomBuffer {0, };
        auto exportState = SSL_get_server_random(ssl, serverRandomBuffer.data(), serverRandomBuffer.size());

        if(exportState != 0)
        {
            auto tlsExportHash = BOOST_OUTCOME_TRYX(openssl::computeSHA256Hash(serverRandomBuffer));
            // Quote the key material
            auto quote = BOOST_OUTCOME_TRYX(AttestationService::createAttestationQuote(tlsExportHash));
            BOOST_OUTCOME_TRY(cert.addExtension(openssl::OpenSSLRef { OBJ_nid2obj(globalContext.NID_QuoteData) }, quote));
        }

        BOOST_OUTCOME_TRY(cert.setValidity(1753630370));
        BOOST_OUTCOME_TRY(cert.selfSign(*globalContext.pkey));

        auto res = SSL_use_PrivateKey(ssl, *globalContext.pkey);
        res = SSL_use_certificate(ssl, cert);
        res = SSL_check_private_key(ssl);

        return success;
    }

    constexpr uint64_t preSharedKey = 0xDEADBEEF;
    constexpr std::string_view pskIdentity = "PSK-TrustedSocketLayer";

    Expect<void> initializeCertificates(bool server)
    {
        globalContext.NID_QuoteData = OBJ_create("1.2.3.4", "Quote", "Quote Data");

        // Generate keypair
        globalContext.pkey.emplace(BOOST_OUTCOME_TRYX(openssl::keygen::ECDSA()));

        // Generate SSL Context
        globalContext.sslCtx.emplace(BOOST_OUTCOME_TRYX(openssl::SSLContext::createSSLContext(true)));

        SSL_CTX_set_msg_callback(*globalContext.sslCtx, [] 
            (int write_p, int version, int content_type, 
            const void *buf, size_t len, SSL *ssl, void *arg) {            

            if(SSL_is_server(ssl) && SSL_get_state(ssl) == TLS_ST_SR_CLNT_HELLO && content_type != SSL3_RT_HEADER)
            {
                // Generate server certificate
                auto genCert = generateCertificateForServer(ssl, { reinterpret_cast<uint8_t const*>(buf), len});
            }
            else if(!SSL_is_server(ssl) && SSL_get_state(ssl) == TLS_ST_CW_CLNT_HELLO && content_type != SSL3_RT_HEADER)
            {
                // Compute and store client hello hash
                std::span clientHelloBuf { reinterpret_cast<uint8_t const*>(buf), len};
                auto clientHelloHash = openssl::computeSHA256Hash(clientHelloBuf).assume_value();

                // This must be manually freed
                auto clientHelloHashVal = new uint8_t[constants::SHA256_HASH_LENGTH];
                std::copy(clientHelloHash.begin(), clientHelloHash.end(), clientHelloHashVal);

                SSL_set_app_data(ssl, clientHelloHashVal);
            }

            
        });

        SSL_CTX_set_cert_cb(*globalContext.sslCtx, [] (SSL *ssl, void *arg) -> int {
            if(!SSL_is_server(ssl))
            {
                auto res = generateCertificateForClient(ssl);
                if(res.has_error())
                    return 0;
            }
            return 1;
        }, nullptr);

        SSL_CTX_set_verify(*globalContext.sslCtx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
            [] (int preverify_ok, X509_STORE_CTX* ctxStore) -> int {
                if(preverify_ok == 0)
                {
                    // Allow the self-signed certificate and continue the verification
                    auto err = X509_STORE_CTX_get_error(ctxStore);
                    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
                        return 1;
                }
                auto ssl = reinterpret_cast<SSL*>(X509_STORE_CTX_get_ex_data(ctxStore, SSL_get_ex_data_X509_STORE_CTX_idx()));

                // Verify the piggy-backed certificate and quote
                openssl::OpenSSLRef certHandle { X509_STORE_CTX_get_current_cert(ctxStore), openssl::UP_REF };
                if (certHandle == nullptr)
                    return 0;
                
                openssl::X509Certificate cert { std::move(certHandle) };

                return [&] () -> Expect<void> {
                    if(SSL_is_server(ssl))
                    {
                        // Compute the export material
                        std::array<uint8_t, 256> serverRandomBuffer {0, };
                        auto exportState = SSL_get_server_random(ssl, serverRandomBuffer.data(), serverRandomBuffer.size());


                        if(exportState == 0)
                            return ErrorCode::OPENSSL_X509_VERIFY_FAILED;

                        auto tlsExportHash = BOOST_OUTCOME_TRYX(openssl::computeSHA256Hash(serverRandomBuffer));
                        
                        // Get piggy-backed quote in the certificate
                        auto quoteData = BOOST_OUTCOME_TRYX(cert.extensions()[globalContext.NID_QuoteData]);
                        std::span certQuote { quoteData.second->data, static_cast<size_t>(quoteData.second->length)};

                        auto authenticatedData = BOOST_OUTCOME_TRYX(AttestationService::verifyAttestationQuote(certQuote));

                        // Check if it is from our enclave (correct MRSIGNER)
                        BOOST_OUTCOME_TRY(AttestationService::verifyEnclaveSigner(certQuote));
                        
                         // Check certificate hash from the quote
                        if(!std::equal(tlsExportHash.begin(), tlsExportHash.end(), authenticatedData.begin()))
                            return ErrorCode::CERTIFICATE_VERIFICATION_FAILED;

                        return success;
                    }
                    else 
                    {
                        // Client verification
                        // Get previous hash value
                        std::unique_ptr<uint8_t[]> hashBuf { reinterpret_cast<uint8_t*>(SSL_get_app_data(ssl)) };
                        SSL_set_app_data(ssl, nullptr);

                        if(hashBuf == nullptr)
                            return ErrorCode::CERTIFICATE_VERIFICATION_FAILED;

                        std::span clientHelloHash { hashBuf.get(), constants::SHA256_HASH_LENGTH };

                        // Get piggy-backed quote in the certificate
                        auto quoteData = BOOST_OUTCOME_TRYX(cert.extensions()[globalContext.NID_QuoteData]);
                        std::span certQuote { quoteData.second->data, static_cast<size_t>(quoteData.second->length)};

                        auto authenticatedData = BOOST_OUTCOME_TRYX(AttestationService::verifyAttestationQuote(certQuote));

                        // Check if it is from our enclave (correct MRSIGNER)
                        BOOST_OUTCOME_TRY(AttestationService::verifyEnclaveSigner(certQuote));
                        
                        // Check certificate hash from the quote
                        if(!std::equal(clientHelloHash.begin(), clientHelloHash.end(), authenticatedData.begin()))
                            return ErrorCode::CERTIFICATE_VERIFICATION_FAILED;

                        return success;
                    }
                }().has_value() ? 1 : 0;
            });
        
        return success;
    }

    Expect<void> acceptTrustedChannelPeer(int32_t socketFd, std::string_view payloadToSend)
    {
        // Accept the connection
        auto conn = BOOST_OUTCOME_TRYX(globalContext.sslCtx->accept(socketFd));

        // Get the payload
        auto payload = BOOST_OUTCOME_TRYX(conn.read());

        // process.. bla.. bla..
        // Send the response
        BOOST_OUTCOME_TRY(conn.write(std::span { reinterpret_cast<uint8_t const*>(payloadToSend.data()), payloadToSend.size() }));

        return success;
    }

    Expect<void> connectTrustedChannelPeer(int32_t socketFd, std::string_view payloadToSend)
    {
        std::array<uint8_t, 32> earlyData;
        sgx_read_rand(earlyData.data(), earlyData.size());

        // Establish the connection
        auto conn = BOOST_OUTCOME_TRYX(globalContext.sslCtx->connect(socketFd));

        // Send the payload
        BOOST_OUTCOME_TRY(conn.write(std::span { reinterpret_cast<uint8_t const*>(payloadToSend.data()), payloadToSend.size() }));
    
        // Get the response
        auto payload = BOOST_OUTCOME_TRYX(conn.read());

        return success;
    }
}

extern "C"
{


    ERRORCODE_T tc4se_test_prepareServer()
    {
        #ifdef MEASUREMENT_PREPARATION
        uint64_t start, end;
        tc4se_getCurrentTime(&start);
        #endif

        auto res = initializeCertificates(true);

        #ifdef MEASUREMENT_PREPARATION
        tc4se_getCurrentTime(&end);
        auto elapsed = end - start;
        std::string debug { "initializeCertificate-Server " };
        debug.append(std::to_string(elapsed));
        tc4se_printDebug(debug.c_str());
        #endif

        if(res.has_error())
            return res.assume_error();

        return ErrorCode::SUCCESS;
    }

    ERRORCODE_T tc4se_test_prepareClient()
    {
        #ifdef MEASUREMENT_PREPARATION
        uint64_t start, end;
        tc4se_getCurrentTime(&start);
        #endif

        auto res = initializeCertificates(false);

         #ifdef MEASUREMENT_PREPARATION
        tc4se_getCurrentTime(&end);
        auto elapsed = end - start;
        std::string debug { "initializeCertificate-Client " };
        debug.append(std::to_string(elapsed));
        tc4se_printDebug(debug.c_str());
        #endif

        if(res.has_error())
            return res.assume_error();

        return ErrorCode::SUCCESS;
    }

    ERRORCODE_T tc4se_test_acceptPeer(int32_t socketFd, const char* payload)
    {
        if(auto var = acceptTrustedChannelPeer(socketFd, payload); var.has_error())
            return var.assume_error();
        else
            return ErrorCode::SUCCESS;
    }

    ERRORCODE_T tc4se_test_connectPeer(int32_t socketFd, const char* payload)
    {
        if(auto var = connectTrustedChannelPeer(socketFd, payload); var.has_error())
            return var.assume_error();
        else
            return ErrorCode::SUCCESS;
    }
}
