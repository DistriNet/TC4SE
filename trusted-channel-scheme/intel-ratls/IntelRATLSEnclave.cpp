
#include <IntelRATLSEnclave_t.h>
#include <cstdint>

#include <tc4se/OpenSSL.h>
#include <tc4se/ErrorCode.h>

#include "openssl/ssl.h"
#include "openssl_utility.h"
#include "sgx_error.h"
#include "sys/stdint.h"

using namespace tc4se;

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

namespace
{
    struct GlobalContext {
        openssl::OpenSSLRef<SSL_CONF_CTX> confCtx;
        openssl::OpenSSLRef<SSL_CTX> sslCtx;
        openssl::OpenSSLRef<X509> cert;
        openssl::OpenSSLRef<EVP_PKEY> pkey;
    } globalContext;

    Expect<void> initializeCertificates(bool server)
    {
        openssl::OpenSSLRef<SSL_CONF_CTX> confCtx { SSL_CONF_CTX_new() };
        openssl::OpenSSLRef<SSL_CTX> sslCtx { SSL_CTX_new(server ? TLS_server_method(): TLS_client_method()), tc4se::openssl::NO_UP_REF };

        if(!sslCtx)
            return ErrorCode::SSL_CTX_NEW_FAILED;

        if(initalize_ssl_context(confCtx, sslCtx) != SGX_SUCCESS)
            return ErrorCode::INVALID_SSL_CONTEXT;

        SSL_CTX_set_verify(sslCtx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, &verify_callback);

        openssl::OpenSSLRef<X509> cert;
        openssl::OpenSSLRef<EVP_PKEY> pkey;
        if (std::tuple<X509*, EVP_PKEY*> ret; load_tls_certificates_and_keys(sslCtx, std::get<0>(ret), std::get<1>(ret)) == SGX_SUCCESS)
        {
            cert = openssl::OpenSSLRef<X509> { std::get<0>(ret), tc4se::openssl::NO_UP_REF };
            pkey = openssl::OpenSSLRef<EVP_PKEY> { std::get<1>(ret), tc4se::openssl::NO_UP_REF};
        }
        else
            return ErrorCode::X509_GENERATION_FAILED;

        globalContext = GlobalContext {
            confCtx, sslCtx, cert, pkey
        };

        return success;
    }

    
}

void t_time(time_t *current_t)
{
    ocall_get_current_time((uint64_t*)current_t);
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
        openssl::OpenSSLRef<SSL> sslSession { SSL_new(globalContext.sslCtx), tc4se::openssl::NO_UP_REF };
        if(!sslSession)
            return ErrorCode::SSL_NEW_FAILED;
        if(SSL_set_fd(sslSession, socketFd) != 1)
            return ErrorCode::SSL_SET_FD_FAILED;

        #ifdef MEASUREMENT_HANDSHAKE
        uint64_t start, end;
        tc4se_getCurrentTime(&start);
        #endif

        auto acceptResult = SSL_accept(sslSession);
        
        #ifdef MEASUREMENT_HANDSHAKE
        tc4se_getCurrentTime(&end); 
        auto elapsed = end - start;
        std::string debug { "SSL_accept " };
        debug.append(std::to_string(socketFd));
        debug.append(" ");
        debug.append(std::to_string(elapsed));
        tc4se_printDebug(debug.c_str());
        #endif

        if(acceptResult != 1)
            return ErrorCode::SSL_ACCEPT_FAILED;

        openssl::SSLConnection conn { sslSession };
        auto res = conn.read();
        if(res.has_error())
            return res.assume_error();

        auto data = res.assume_value();
        
        std::string_view str { payload };
        std::span<uint8_t const> dataSend { reinterpret_cast<uint8_t const*>(str.data()), str.length() };

        if(auto writeRes = conn.write(dataSend); writeRes.has_error())
            return writeRes.assume_error();

        return ErrorCode::SUCCESS;
    }

    ERRORCODE_T tc4se_test_connectPeer(int32_t socketFd, const char* payload)
    {
        openssl::OpenSSLRef<SSL> sslSession { SSL_new(globalContext.sslCtx), tc4se::openssl::NO_UP_REF };
        if(!sslSession)
            return ErrorCode::SSL_NEW_FAILED;
        if(SSL_set_fd(sslSession, socketFd) != 1)
            return ErrorCode::SSL_SET_FD_FAILED;

        #ifdef MEASUREMENT_HANDSHAKE
        uint64_t start, end;
        tc4se_getCurrentTime(&start);
        #endif

        auto ret = SSL_connect(sslSession);

        #ifdef MEASUREMENT_HANDSHAKE
        tc4se_getCurrentTime(&end);
        auto elapsed = end - start;
        std::string debug { "SSL_connect " };
        debug.append(std::to_string(socketFd));
        debug.append(" ");
        debug.append(std::to_string(elapsed));
        tc4se_printDebug(debug.c_str());
        #endif

        if(ret != 1)
        {
            auto err = SSL_get_error(sslSession, ret);
            return ErrorCode::SSL_CONNECT_FAILED;
        }


        openssl::SSLConnection conn { sslSession };
        std::string_view str { payload };
        std::span<uint8_t const> dataSend { reinterpret_cast<uint8_t const*>(str.data()), str.length() };

        if(auto writeRes = conn.write(dataSend); writeRes.has_error())
            return writeRes.assume_error();

        auto res = conn.read();
        if(res.has_error())
            return res.assume_error();

        auto data = res.assume_value();

        return ErrorCode::SUCCESS;
    }
}
