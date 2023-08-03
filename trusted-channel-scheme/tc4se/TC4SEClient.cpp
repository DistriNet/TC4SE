#include "TC4SEClient_t.h"
#include "openssl/ssl.h"
#include "tc4se/Constants.h"
#include "tc4se/ErrorCode.h"
#include <iterator>
#include <tc4se/AttestationService.h>
#include <tc4se/OpenSSL.h>
#include <optional>
#include <vector>

using namespace tc4se;

namespace
{
    struct ServerContext {
        std::optional<openssl::KeyPair> privateKey;
        std::optional<openssl::X509CertificateSigningRequest> csr;
        std::optional<std::vector<uint8_t>> csrQuote;
        std::optional<openssl::X509Certificate> cert;
        std::optional<openssl::X509CertificateStore> certStore;
        std::optional<openssl::SSLContext> sslCtxTrustExchange;
        std::optional<openssl::SSLContext> sslCtxTrustedChannel;

        int NID_CACertData;
        int NID_CACertQuoteData;
    } ctx;

    int verifyServerQuote(int preverify_ok, X509_STORE_CTX* ctxStore)
    {
        if(preverify_ok == 0)
        {
            // Allow the self-signed certificate and continue the verification
            auto err = X509_STORE_CTX_get_error(ctxStore);
            if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
                return 1;
        }

        // Verify the piggy-backed certificate and quote
        openssl::OpenSSLRef certHandle { X509_STORE_CTX_get_current_cert(ctxStore), openssl::UP_REF };
        if (certHandle == nullptr)
            return 0;
        
        openssl::X509Certificate cert { std::move(certHandle) };
        return [&] () -> Expect<void> {
            auto caCertData = BOOST_OUTCOME_TRYX(cert.extensions()[ctx.NID_CACertData]);
            auto caCertQuote = BOOST_OUTCOME_TRYX(cert.extensions()[ctx.NID_CACertQuoteData]);

            std::span certDER { caCertData.second->data, static_cast<size_t>(caCertData.second->length)};
            std::span certQuote { caCertQuote.second->data, static_cast<size_t>(caCertQuote.second->length)};

            auto authenticatedData = BOOST_OUTCOME_TRYX(AttestationService::verifyAttestationQuote(certQuote));

            // Check if it is from our enclave (correct MRSIGNER)
            BOOST_OUTCOME_TRY(AttestationService::verifyEnclaveSigner(certQuote));

            // Check certificate hash from the quote
            auto certSHA = BOOST_OUTCOME_TRYX(openssl::computeSHA256Hash(certDER));
            if(!std::equal(certSHA.begin(), certSHA.end(), authenticatedData.begin()))
                return ErrorCode::CERTIFICATE_VERIFICATION_FAILED;

            // Check if the public key of the inner certificate is equals to the parent certificate
            auto innerCert = BOOST_OUTCOME_TRYX(openssl::X509Certificate::fromDER(certDER));
            auto innerCertPubKey = innerCert.getPubKey();
            auto certPubKey = cert.getPubKey();

            if(innerCertPubKey != certPubKey)
                return ErrorCode::CERTIFICATE_VERIFICATION_FAILED;

            // If everything is successful, then we can trust the server
            return success;
        }().has_value() ? 1 : 0;
    }

    Expect<void> generateKeypairForClient()
    {
        ctx.NID_CACertData = OBJ_create("1.2.3.4", "CACert", "Attested CA Certificate Data");
        ctx.NID_CACertQuoteData = OBJ_create("1.2.3.5", "CACertQuote", "CA Certificate Quote Data");

        // Generate keypair
        auto keypair = BOOST_OUTCOME_TRYX(openssl::keygen::ECDSA());

        // Generate CSR
        openssl::X509Certificate cert { keypair };
        BOOST_OUTCOME_TRY(cert.addNameEntry(openssl::CertificateDN {
            "AQ", 
            "Antartica", 
            "Antartic Ocean", 
            "TC4SE", 
            "TC4SE Client Certificate", 
            "TC4SE Client Certificate", 
            "mail@example.com"
        }));
        BOOST_OUTCOME_TRYX(cert.selfSign(keypair));
        ctx.csr.emplace(BOOST_OUTCOME_TRYX(cert.toCSR(keypair)));
        
        auto csrData = BOOST_OUTCOME_TRYX(ctx.csr->toDER());
        auto csrSHA = BOOST_OUTCOME_TRYX(openssl::computeSHA256Hash(csrData));        
        ctx.csrQuote = BOOST_OUTCOME_TRYX(AttestationService::createAttestationQuote(csrSHA));
        
        ctx.privateKey.emplace(std::move(keypair));

        // Store in local context within enclave
        // it can be persisted by serializing the key and cert to PEM, then seal to the enclave
        // using SGX sealing
        
        // Instantiate certStore
        ctx.certStore.emplace();

        // Create the SSL context for the trust exchange. For the trusted channel will be made later
        // after the certificate is available
        auto sslContext = BOOST_OUTCOME_TRYX(openssl::SSLContext::createSSLContext(true));
        // The client part must verify the server certificate and the attached quote as the means to establish
        // the trust to the server
        SSL_CTX_set_verify(sslContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, &verifyServerQuote);
        ctx.sslCtxTrustExchange.emplace(std::move(sslContext));
        return success;
    }

    Expect<void> initiateTrustExchange(int32_t socketFd)
    {
        // Create payload
        std::vector<uint8_t> payload;
        auto csrData = BOOST_OUTCOME_TRYX(ctx.csr->toDER());
        
        // The payload is the serialized CSR and Quote binary, the header consists of the length of each payload
        // to compute the offset
        struct 
        {
            size_t csr;
            size_t quote;
        } offset {  csrData.size(), ctx.csrQuote->size() };
        std::span header { reinterpret_cast<uint8_t const*>(&offset), sizeof(offset) };
        std::copy(header.begin(), header.end(), std::back_inserter(payload)); // Header
        std::copy(csrData.begin(), csrData.end(), std::back_inserter(payload)); // CSR data
        std::copy(ctx.csrQuote->begin(), ctx.csrQuote->end(), std::back_inserter(payload)); // Quote Data

        auto dataLen = payload.size();

        // Connect to the server via the trust exchange context, where the server certificate
        // and the attached quote will be verified during the handshake
        openssl::SSLConnection conn = BOOST_OUTCOME_TRYX(ctx.sslCtxTrustExchange->connect(socketFd));

        // Upon reaching this point, the server is basically trusted and attested
        // we can register the server into our trusted store in here
        auto serverCert = BOOST_OUTCOME_TRYX(conn.getPeerCertificate());
        auto caCertData = BOOST_OUTCOME_TRYX(serverCert.extensions()[ctx.NID_CACertData]);
        
        BOOST_OUTCOME_TRY(ctx.certStore->addCertificate(
            BOOST_OUTCOME_TRYX(openssl::X509Certificate::fromDER({ 
                caCertData.second->data, 
                static_cast<size_t>(caCertData.second->length)}))));

        // Send the CSR payload
        if(auto writeRes = conn.write(payload); writeRes.has_error())
            return writeRes.assume_error();

        // Get the Certificate response
        auto signedCertData = BOOST_OUTCOME_TRYX(conn.read());
        auto cert = BOOST_OUTCOME_TRYX(openssl::X509Certificate::fromDER(signedCertData));

        // Verify the Certificate response with our trusted certificate and store upon successful
        BOOST_OUTCOME_TRYX(ctx.certStore->verifyCertificate(cert));
        ctx.cert.emplace(std::move(cert));

        // Create the SSL Context for the trusted channel
        auto sslCtxTrustedChannel = BOOST_OUTCOME_TRYX(openssl::SSLContext::createSSLContext(std::vector { *ctx.cert }, *ctx.privateKey, true));
        SSL_CTX_set1_cert_store(sslCtxTrustedChannel, *ctx.certStore); // Set the trusted store
        ctx.sslCtxTrustedChannel.emplace(std::move(sslCtxTrustedChannel));

        return success;
    }

    Expect<void> connectTrustedChannelPeer(int32_t socketFd, std::string_view payloadToSend)
    {
        // Establish the connection
        auto conn = BOOST_OUTCOME_TRYX(ctx.sslCtxTrustedChannel->connect(socketFd));

        // Send the payload
        BOOST_OUTCOME_TRY(conn.write(std::span { reinterpret_cast<uint8_t const*>(payloadToSend.data()), payloadToSend.size() }));
    
        // Get the response
        auto payload = BOOST_OUTCOME_TRYX(conn.read());

        return success;
    }
}

extern "C"
{
    ERRORCODE_T tc4se_test_prepareClient()
    {
        #ifdef MEASUREMENT_PREPARATION
        uint64_t start, end;
        tc4se_getCurrentTime(&start);
        #endif

        auto var = generateKeypairForClient();

        #ifdef MEASUREMENT_PREPARATION
        tc4se_getCurrentTime(&end);
        auto elapsed = end - start;
        std::string debug { "Client TrustGeneration " };
        debug.append(std::to_string(elapsed));
        tc4se_printDebug(debug.c_str());
        #endif

        if( var.has_error())
            return var.assume_error();
        else
            return ErrorCode::SUCCESS;
    }

    ERRORCODE_T tc4se_test_initiateTrustExchange(int32_t socketFd)
    {
        #ifdef MEASUREMENT_PREPARATION
        uint64_t start, end;
        tc4se_getCurrentTime(&start);
        #endif

        auto var = initiateTrustExchange(socketFd);

        #ifdef MEASUREMENT_PREPARATION
        tc4se_getCurrentTime(&end);
        auto elapsed = end - start;
        std::string debug { "Client TrustExchange " };
        debug.append(std::to_string(elapsed));
        tc4se_printDebug(debug.c_str());
        #endif

        if(var.has_error())
            return var.assume_error();
        else
            return ErrorCode::SUCCESS;
    }

    ERRORCODE_T tc4se_test_connectTrustedChannelPeer(int32_t socketFd, const char* payload)
    {
        if(auto var = connectTrustedChannelPeer(socketFd, payload); var.has_error())
            return var.assume_error();
        else
            return ErrorCode::SUCCESS;
    }
}