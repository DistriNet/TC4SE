#include "openssl/ossl_typ.h"
#include "openssl/ssl.h"
#include "openssl/x509_vfy.h"
#include "sgx_trts.h"
#include "tc4se/AttestationService.h"
#include "tc4se/ErrorCode.h"
#include <array>
#include <string>
#include <tc4se/OpenSSL.h>

sgx_status_t SGX_CDECL tc4se_printDebug(const char* str);

namespace tc4se::openssl
{
    SSLContext& SSLContext::operator=(SSLContext&& other)
    {
        this->context = std::move(other.context);
        this->sslKeypair.emplace(std::move(*other.sslKeypair));
        other.sslKeypair.reset();
        return *this;
    }

    Expect<SSLContext> SSLContext::createSSLContext(bool verifyPeer)
    {
        SSLContext sslContextObject {};

        auto& sslContext {sslContextObject.context};

        sslContext = {SSL_CTX_new(TLS_method()), NO_UP_REF};
        if (sslContext == nullptr)
            return ErrorCode::SSL_CTX_NEW_FAILED;

        if (!SSL_CTX_set_min_proto_version(sslContext, TLS1_3_VERSION))
            return ErrorCode::TLS1_3_UNAVAILABLE;

        if (!SSL_CTX_set_max_proto_version(sslContext, TLS1_3_VERSION))
            return ErrorCode::TLS1_3_UNAVAILABLE;

        if (!SSL_CTX_set_ciphersuites(sslContext, constants::AVAILABLE_CIPHERSUITES))
            return ErrorCode::SSL_SET_CIPHERSUITES_FAILED;

        if (verifyPeer)
            SSL_CTX_set_verify(sslContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

        std::array<uint8_t, 32> sessionIdContext;
        sgx_read_rand(sessionIdContext.data(), sessionIdContext.size());
        SSL_CTX_set_session_id_context(sslContext, sessionIdContext.data(), sessionIdContext.size());

        return sslContextObject;
    }

    Expect<SSLContext> SSLContext::createSSLContext(std::span<openssl::X509Certificate const> cert,
                                                    openssl::KeyPair const& keypair, bool verifyPeer)
    {
        SSLContext sslContextObject = BOOST_OUTCOME_TRYX(createSSLContext(verifyPeer));
        sslContextObject.sslKeypair.emplace(keypair);

        auto& sslContext {sslContextObject.context};

        if (SSL_CTX_use_PrivateKey(sslContext, keypair) != 1)
            return ErrorCode::SSL_USE_PRIVATEKEY_FAILED;

        if (!cert.empty())
        {
            if (cert.size() > 1)
            {
                openssl::X509CertificateStore certStore {};
                for (auto certIter = cert.begin() + 1; certIter != cert.end(); ++certIter)
                {
                    BOOST_OUTCOME_TRY(certStore.addCertificate(*certIter));
                }
                SSL_CTX_set1_cert_store(sslContext, certStore);
            }

            auto certStatus = SSL_CTX_use_certificate(sslContext, cert.front());
            if (certStatus != 1)
                return ErrorCode::SSL_USE_CERTIFICATE_FAILED;
        }

        if (SSL_CTX_check_private_key(sslContext) != 1)
            return ErrorCode::SSL_PRIVATEKEY_MISMATCHED;

        return sslContextObject;
    }

    Expect<SSLConnection> SSLContext::createSSL() const
    {
        SSLConnection connection {};

        auto& sslObj {connection.ssl};

        sslObj = {SSL_new(this->context), NO_UP_REF};
        if (sslObj == nullptr)
            return ErrorCode::SSL_NEW_FAILED;

        return std::move(connection);
    }

    Expect<SSLConnection> SSLContext::accept(int32_t peerFd, bool waitEarlyData) const
    {
        BOOST_OUTCOME_TRY(decltype(auto) connection, this->createSSL());

        if (SSL_set_fd(connection.ssl, peerFd) == false)
            return ErrorCode::SSL_SET_FD_FAILED;

#ifdef MEASUREMENT_HANDSHAKE
        auto start = getCurrentTime();
#endif

        if (waitEarlyData)
        {
            SSL_set_accept_state(connection.ssl);
            auto earlyData = BOOST_OUTCOME_TRYX(connection.readEarlyData());
        }

        auto err = SSL_accept(connection.ssl);

#ifdef MEASUREMENT_HANDSHAKE
        auto elapsed = getCurrentTime() - start;
        std::string str {"SSL_accept "};
        str.append(std::to_string(peerFd));
        str.append(" ");
        str.append(std::to_string(elapsed));
        tc4se_printDebug(str.c_str());
#endif

        if (err <= 0)
        {
            return ErrorCode::SSL_ACCEPT_FAILED;
        }

        return std::move(connection);
    }

    Expect<SSLConnection> SSLContext::connect(int32_t peerFd, std::optional<std::span<uint8_t const>> earlyData) const
    {
        BOOST_OUTCOME_TRY(decltype(auto) connection, this->createSSL());

        if (SSL_set_fd(connection.ssl, peerFd) == false)
            return ErrorCode::SSL_SET_FD_FAILED;

#ifdef MEASUREMENT_HANDSHAKE
        auto start = getCurrentTime();
#endif

        // auto sess = SSL_get0_session(connection.ssl);

        // auto earlyDataStatus = SSL_get_early_data_status(connection.ssl);

        if (earlyData.has_value())
        {
            SSL_set_connect_state(connection.ssl);
            // if(SSL_set_max_early_data(connection.ssl, earlyData->size()) != 1)
            //     return ErrorCode::SSL_CONNECT_FAILED;
            size_t written = 0;
            if (auto err = SSL_write_early_data(connection.ssl, earlyData->data(), earlyData->size(), &written);
                err != 1)
            {
                auto errCode = SSL_get_error(connection.ssl, err);
                return ErrorCode::SSL_CONNECT_FAILED;
            }
        }

        auto err = SSL_connect(connection.ssl);

#ifdef MEASUREMENT_HANDSHAKE
        auto elapsed = getCurrentTime() - start;
        std::string str {"SSL_connect "};
        str.append(std::to_string(peerFd));
        str.append(" ");
        str.append(std::to_string(elapsed));
        tc4se_printDebug(str.c_str());
#endif

        if (err <= 0)
        {
            return ErrorCode::SSL_ACCEPT_FAILED;
        }

        return std::move(connection);
    }

    SSLConnection& SSLConnection::operator=(SSLConnection&& other)
    {
        this->ssl = std::move(other.ssl);
        return *this;
    }

    SSLConnection::~SSLConnection()
    {
        if (this->ssl != nullptr)
            SSL_shutdown(this->ssl);
    }

    Expect<std::vector<uint8_t>> SSLConnection::readEarlyData() const
    {
        std::vector<uint8_t> completeData;

        int earlyDataState = SSL_READ_EARLY_DATA_ERROR;

        do
        {
            std::array<uint8_t, constants::MAX_READ_PER_CHUNK> buffer;

            // By default, OpenSSL enables the SSL_MODE_AUTO_RETRY, so OpenSSL will try read until the bytes are
            // exhausted from the network buffer. So, we can assume that this call will always return full buffer size,
            // and if it is not, all data has been obtained and we should exit the loop
            size_t readSize;
            earlyDataState = SSL_read_early_data(this->ssl, buffer.data(), buffer.size(), &readSize);

            if (readSize < buffer.size())
                completeData.insert(completeData.end(), buffer.begin(), buffer.begin() + readSize);
            else
                completeData.insert(completeData.end(), buffer.begin(), buffer.end());
        } while (earlyDataState == SSL_READ_EARLY_DATA_SUCCESS);

        return completeData;
    }

    Expect<std::vector<uint8_t>> SSLConnection::read() const
    {
        std::vector<uint8_t> completeData;
        int32_t actualSize {};

        do
        {
            std::array<uint8_t, constants::MAX_READ_PER_CHUNK> buffer;

            // By default, OpenSSL enables the SSL_MODE_AUTO_RETRY, so OpenSSL will try read until the bytes are
            // exhausted from the network buffer. So, we can assume that this call will always return full buffer size,
            // and if it is not, all data has been obtained and we should exit the loop
            actualSize = SSL_read(this->ssl, buffer.data(), buffer.size());

            if (actualSize < buffer.size())
                completeData.insert(completeData.end(), buffer.begin(), buffer.begin() + actualSize);
            else
                completeData.insert(completeData.end(), buffer.begin(), buffer.end());
        } while (actualSize == constants::MAX_READ_PER_CHUNK and completeData.size() <= constants::MAX_DATA_READ_WRITE);

        if (completeData.empty())
            return ErrorCode::HTTP_NO_DATA_READ;
        if (completeData.size() > constants::MAX_DATA_READ_WRITE)
            return ErrorCode::HTTP_PAYLOAD_TOO_LARGE;
        return completeData;
    }

    Expect<openssl::X509Certificate> SSLConnection::getPeerCertificate() const
    {
        OpenSSLRef clientCertificate {SSL_get_peer_certificate(this->ssl), NO_UP_REF};
        if (clientCertificate == nullptr)
            return ErrorCode::OPENSSL_X509_VERIFY_FAILED;
        return clientCertificate;
    }

    Expect<void> SSLConnection::verifyPeer() const
    {
        BOOST_OUTCOME_TRY(this->getPeerCertificate());
        if (SSL_get_verify_result(this->ssl) != X509_V_OK)
            return ErrorCode::OPENSSL_X509_VERIFY_FAILED;
        return success;
    }

    Expect<void> SSLConnection::write(std::span<uint8_t const> data) const
    {
        int32_t writeStatus {SSL_write(this->ssl, data.data(), data.size())};
        if (writeStatus <= 0)
            return ErrorCode::SSL_WRITE_FAILED;
        return success;
    }

    Expect<std::array<uint8_t, constants::SHA256_HASH_LENGTH>> computeSHA256Hash(std::span<uint8_t const> message)
    {
        std::array<uint8_t, constants::SHA256_HASH_LENGTH> digest;

        OpenSSLRef ctx {EVP_MD_CTX_new(), NO_UP_REF};

        if (ctx == nullptr)
            return ErrorCode::MEMORY_ALLOCATION_FAILED;
        if ((1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) or
            (1 != EVP_DigestUpdate(ctx, message.data(), message.size())) or
            (1 != EVP_DigestFinal_ex(ctx, digest.data(), nullptr)))
            return ErrorCode::HASHING_FAILED;

        return digest;
    }
} // namespace tc4se::openssl
