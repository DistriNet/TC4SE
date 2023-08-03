#include "TC4SEServer_t.h"
#include "openssl/objects.h"
#include "openssl/ossl_typ.h"
#include "openssl/ssl.h"
#include "sys/stdint.h"
#include "tc4se/ErrorCode.h"
#include <algorithm>
#include <tc4se/AttestationService.h>
#include <tc4se/OpenSSL.h>
#include <optional>

using namespace tc4se;

namespace
{
    struct ServerContext {
        std::optional<openssl::KeyPair> privateKey;
        std::optional<openssl::X509Certificate> cert;
        std::optional<std::vector<uint8_t>> certQuote;
        std::optional<openssl::X509Certificate> certWithQuote;
        std::optional<openssl::SSLContext> sslCtxTrustExchange;
        std::optional<openssl::SSLContext> sslCtxTrustedChannel;
        std::optional<openssl::X509CertificateStore> certStore;

        int NID_CACertData;
        int NID_CACertQuoteData;
    } ctx;

    Expect<void> generateKeypairForCA()
    {
        ctx.NID_CACertData = OBJ_create("1.2.3.4", "CACert", "Attested CA Certificate Data");
        ctx.NID_CACertQuoteData = OBJ_create("1.2.3.5", "CACertQuote", "CA Certificate Quote Data");

        // Generate keypair
        auto keypair = BOOST_OUTCOME_TRYX(openssl::keygen::ECDSA());

        // Generate self-signed cert for CA
        openssl::X509Certificate cert { keypair };
        BOOST_OUTCOME_TRY(cert.addNameEntry(openssl::CertificateDN {
            "AQ", 
            "Antartica", 
            "Antartic Ocean", 
            "TC4SE", 
            "TC4SE Server Certificate", 
            "TC4SE Server Certificate", 
            "mail@example.com"
        }));
        BOOST_OUTCOME_TRY(cert.addExtension(NID_basic_constraints, "critical,CA:TRUE,pathlen:1"));
        BOOST_OUTCOME_TRY(cert.addExtension(NID_key_usage, "critical,keyCertSign,digitalSignature,cRLSign"));
        BOOST_OUTCOME_TRY(cert.setValidity(1753630370));
        BOOST_OUTCOME_TRY(cert.selfSign(keypair));

        // Generate quote for the CA certificate
        auto certData = BOOST_OUTCOME_TRYX(cert.toDER());
        auto certSHA = BOOST_OUTCOME_TRYX(openssl::computeSHA256Hash(certData));
        ctx.certQuote = BOOST_OUTCOME_TRYX(AttestationService::createAttestationQuote(certSHA));
        ctx.cert.emplace(cert);

        // Generate certificate for trust exchange purpose
        // the certificate serves as the container for attestation quote and original certificate during trust exchange
        // so the server/CA certificate validation can piggyback the initial TLS handshake for the trust exchange purpose
        BOOST_OUTCOME_TRY(cert.addExtension(openssl::OpenSSLRef { OBJ_nid2obj(ctx.NID_CACertData) }, certData));
        BOOST_OUTCOME_TRY(cert.addExtension(openssl::OpenSSLRef { OBJ_nid2obj(ctx.NID_CACertQuoteData) }, *ctx.certQuote));
        BOOST_OUTCOME_TRY(cert.selfSign(keypair));
        ctx.certWithQuote.emplace(std::move(cert));

        // Store the private key
        ctx.privateKey.emplace(std::move(keypair));

        // Store the CA certificate to our trusted store
        ctx.certStore.emplace();
        BOOST_OUTCOME_TRY(ctx.certStore->addCertificate(*ctx.cert));

        // Store in local context within enclave
        // it can be persisted by serializing the key and cert to PEM, then seal to the enclave
        // using SGX sealing

        // Create SSL Context for two cases: the trust exchange and the trusted channel
        auto sslContext = BOOST_OUTCOME_TRYX(openssl::SSLContext::createSSLContext(std::vector { *ctx.certWithQuote }, *ctx.privateKey, false));
        ctx.sslCtxTrustExchange.emplace(std::move(sslContext));

        sslContext = BOOST_OUTCOME_TRYX(openssl::SSLContext::createSSLContext(std::vector { *ctx.cert }, *ctx.privateKey, true));
        SSL_CTX_set1_cert_store(sslContext, *ctx.certStore); // Set the trusted store
        ctx.sslCtxTrustedChannel.emplace(std::move(sslContext));

        return success;
    }

    Expect<void> acceptTrustExchange(int32_t socketFd)
    {
        // Accept the connection
        auto conn = BOOST_OUTCOME_TRYX(ctx.sslCtxTrustExchange->accept(socketFd));

        // Get the CSR request
        auto csrPayload = BOOST_OUTCOME_TRYX(conn.read());

        if(csrPayload.empty())
            return ErrorCode::X509_GENERATION_FAILED;

        // Read payload
        struct Offset
        {
            size_t csr;
            size_t quote;
        } *offset = reinterpret_cast<Offset*>(&csrPayload[0]);
        size_t csrSize = csrPayload[0];
        std::span payloadView { csrPayload };
        std::span csrData { payloadView.subspan(sizeof(Offset), offset->csr) };
        std::span quote { payloadView.subspan(sizeof(Offset) + offset->csr, offset->quote) };

        // Verify the quote and get the authenticated data
        auto authenticatedData = BOOST_OUTCOME_TRYX(AttestationService::verifyAttestationQuote(quote));
        auto csrSHA = BOOST_OUTCOME_TRYX(openssl::computeSHA256Hash(csrData)); 

        // the authenticated data is 64 bytes long, but the SHA256 is only 32 bytes. So the remainder of the quote is zero
        if(std::equal(csrSHA.begin(), csrSHA.end(), authenticatedData.begin()))
        {
            auto csr = BOOST_OUTCOME_TRYX(openssl::X509CertificateSigningRequest::fromDER(csrData));
            
            auto clientCert = BOOST_OUTCOME_TRYX(csr.sign(1753630370, *ctx.privateKey, *ctx.cert, []
                (openssl::X509Certificate& newCert) -> Expect<void> { 
                    BOOST_OUTCOME_TRY(newCert.addExtension(NID_key_usage, "critical,digitalSignature"));
                    return success;
                }));
            auto clientCertData = BOOST_OUTCOME_TRYX(clientCert.toDER());
            
            BOOST_OUTCOME_TRY(conn.write(clientCertData));
        }

        return success;
    }

    Expect<void> acceptTrustedChannelPeer(int32_t socketFd, std::string_view payloadToSend)
    {
        // Accept the connection
        auto conn = BOOST_OUTCOME_TRYX(ctx.sslCtxTrustedChannel->accept(socketFd));

        // Get the payload
        auto payload = BOOST_OUTCOME_TRYX(conn.read());

        // process.. bla.. bla..
        // Send the response
        BOOST_OUTCOME_TRY(conn.write(std::span { reinterpret_cast<uint8_t const*>(payloadToSend.data()), payloadToSend.size() }));

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

        auto var = generateKeypairForCA();

        #ifdef MEASUREMENT_PREPARATION
        tc4se_getCurrentTime(&end);
        auto elapsed = end - start;
        std::string debug { "Server TrustGeneration " };
        debug.append(std::to_string(elapsed));
        tc4se_printDebug(debug.c_str());
        #endif

        if( var.has_error())
            return var.assume_error();
        else
            return ErrorCode::SUCCESS;
    }

    ERRORCODE_T tc4se_test_acceptTrustExchange(int32_t socketFd)
    {
        #ifdef MEASUREMENT_PREPARATION
        uint64_t start, end;
        tc4se_getCurrentTime(&start);
        #endif

        auto var = acceptTrustExchange(socketFd); 

        #ifdef MEASUREMENT_PREPARATION
        tc4se_getCurrentTime(&end);
        auto elapsed = end - start;
        std::string debug { "Server TrustExchange " };
        debug.append(std::to_string(elapsed));
        tc4se_printDebug(debug.c_str());
        #endif
        if(var.has_error())
            return var.assume_error();
        else
            return ErrorCode::SUCCESS;
    }

    ERRORCODE_T tc4se_test_acceptTrustedChannelPeer(int32_t socketFd, const char* payload)
    {
        if(auto var = acceptTrustedChannelPeer(socketFd, payload); var.has_error())
            return var.assume_error();
        else
            return ErrorCode::SUCCESS;
    }
}