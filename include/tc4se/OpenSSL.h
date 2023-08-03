#pragma once

#ifndef CORE_OPENSSL_H
#define CORE_OPENSSL_H
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <openssl/cmac.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <tuple>
#include <type_traits>
#include <vector>
#include <span>
#include <optional>
#include <unordered_map>

#include <tc4se/ErrorCode.h>
#include <tc4se/Constants.h>

namespace tc4se::openssl
{
    // Forward declaration
    struct CertificateDN
    {
        std::string countryName;
        std::string stateName;
        std::string localityName;
        std::string organizationName;
        std::string organizationUnitName;
        std::string commonName;
        std::string emailAddress;
    };

    namespace detail
    {
        template<typename T> struct is_bytes_container : std::false_type
        {
        };

        template<> struct is_bytes_container<std::vector<uint8_t>> : std::true_type
        {
        };

        template<> struct is_bytes_container<std::string> : std::true_type
        {
        };

        template<typename T> static constexpr bool is_bytes_container_v = is_bytes_container<T>::value;

        template<typename T> struct OpenSSLRefStaticVTable
        {
            static void Free(T* ptr);
            static void UpRef(T* ptr);
        };

        template<> struct OpenSSLRefStaticVTable<char>
        {
            static void Free(char* ptr)
            {
                OPENSSL_free(ptr);
            }
        };

        template<> struct OpenSSLRefStaticVTable<BIGNUM>
        {
            static void Free(BIGNUM* ptr)
            {
                BN_free(ptr);
            }
        };

#define TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(x) \
    template<> struct OpenSSLRefStaticVTable<x> \
    {                                           \
        static void Free(x* ptr)                \
        {                                       \
            x##_free(ptr);                      \
        }                                       \
    };

#define TC_DEFINE_OPENSSL_REF_VTABLE_STACK_OF(X)          \
    template<> struct OpenSSLRefStaticVTable<STACK_OF(X)> \
    {                                                     \
        static void Free(STACK_OF(X) * ptr)               \
        {                                                 \
            sk_##X##_pop_free(ptr, X##_free);             \
        }                                                 \
    };

#define TC_DEFINE_OPENSSL_REF_VTABLE(x)                             \
    template<> inline void OpenSSLRefStaticVTable<x>::Free(x* ptr)  \
    {                                                               \
        x##_free(ptr);                                              \
    }                                                               \
    template<> inline void OpenSSLRefStaticVTable<x>::UpRef(x* ptr) \
    {                                                               \
        x##_up_ref(ptr);                                            \
    }

        // All OpenSSL object that does not qualifies as being reference-counted (i.e., does not have up_ref funciton),
        // must be declared below. If it is declared using the VTABLE variant, it will results in compile error because
        // it tries to look for undefined _up_ref function.
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(X509_REQ)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(X509_EXTENSION)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(X509_STORE_CTX)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(EC_POINT)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(EVP_MD_CTX)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(CMAC_CTX)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(EVP_CIPHER_CTX)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(ECDSA_SIG)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(EC_GROUP)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(EVP_PKEY_CTX)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(ASN1_TYPE)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(ASN1_TIME)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(PKCS12)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(ASN1_OBJECT)
        TC_DEFINE_OPENSSL_REF_VTABLE_NOUPREF(SSL_CONF_CTX)

        TC_DEFINE_OPENSSL_REF_VTABLE_STACK_OF(X509)
        TC_DEFINE_OPENSSL_REF_VTABLE_STACK_OF(X509_INFO)
        TC_DEFINE_OPENSSL_REF_VTABLE_STACK_OF(X509_OBJECT)
        TC_DEFINE_OPENSSL_REF_VTABLE_STACK_OF(ASN1_TYPE)
        TC_DEFINE_OPENSSL_REF_VTABLE_STACK_OF(X509_EXTENSION)

        // All other OpenSSL object that qualifies as being reference-counted, must be declared below. Otherwise, a
        // linking error may happen when trying to use OpenSSLRef with an undefined VTABLE declaration.
        TC_DEFINE_OPENSSL_REF_VTABLE(X509)
        TC_DEFINE_OPENSSL_REF_VTABLE(X509_STORE)
        TC_DEFINE_OPENSSL_REF_VTABLE(EVP_PKEY)
        TC_DEFINE_OPENSSL_REF_VTABLE(SSL_CTX)
        TC_DEFINE_OPENSSL_REF_VTABLE(SSL)
        TC_DEFINE_OPENSSL_REF_VTABLE(BIO)
        TC_DEFINE_OPENSSL_REF_VTABLE(RSA)
        TC_DEFINE_OPENSSL_REF_VTABLE(X509_CRL)
        TC_DEFINE_OPENSSL_REF_VTABLE(EC_KEY)
        TC_DEFINE_OPENSSL_REF_VTABLE(SSL_SESSION)

#undef TC_DEFINE_OPENSSL_REF_VTABLE_NOREFUP
#undef TC_DEFINE_OPENSSL_REF_VTABLE
#undef TC_DEFINE_OPENSSL_REF_VTABLE_STACK_OF

        template<typename T>
        concept HasUpRef = requires(T t) {
                               {
                                   OpenSSLRefStaticVTable<T>::UpRef(&t)
                               };
                           };
    } // namespace detail

    struct NoUpRefTag
    {
    };

    struct UpRefTag
    {
    };

    constexpr NoUpRefTag NO_UP_REF {};
    constexpr UpRefTag UP_REF {};

    template<typename T> class OpenSSLRef
    {
        T* handle {nullptr};

      public:
        OpenSSLRef() {}

        OpenSSLRef(T* obj)
            requires(!detail::HasUpRef<T>)
            : handle(obj)
        {
        }

        OpenSSLRef(T* obj, NoUpRefTag): handle(obj) {}

        OpenSSLRef(T* obj, UpRefTag)
            requires detail::HasUpRef<T>
            : handle(obj)
        {
            detail::OpenSSLRefStaticVTable<T>::UpRef(obj);
        }

        OpenSSLRef(OpenSSLRef const& that)
            requires detail::HasUpRef<T>
            : handle(that.handle)
        {
            detail::OpenSSLRefStaticVTable<T>::UpRef(handle);
        }

        OpenSSLRef(OpenSSLRef&& that): handle(that.handle)
        {
            that.handle = nullptr;
        }

        OpenSSLRef& operator=(OpenSSLRef const& that)
            requires detail::HasUpRef<T>
        {
            if (handle)
                detail::OpenSSLRefStaticVTable<T>::Free(handle);
            handle = that.handle;
            detail::OpenSSLRefStaticVTable<T>::UpRef(handle);
            return *this;
        }

        OpenSSLRef& operator=(OpenSSLRef&& that)
        {
            if (handle)
                detail::OpenSSLRefStaticVTable<T>::Free(handle);
            handle      = that.handle;
            that.handle = nullptr;
            return *this;
        }

        OpenSSLRef& operator=(std::nullptr_t)
        {
            if (handle)
                detail::OpenSSLRefStaticVTable<T>::Free(handle);

            handle = nullptr;
            return *this;
        }

        bool operator!()
        {
            return handle == nullptr;
        }

        bool operator==(std::nullptr_t)
        {
            return handle == nullptr;
        }

        ~OpenSSLRef()
        {
            if (handle)
                detail::OpenSSLRefStaticVTable<T>::Free(handle);
        }

        operator T*() const
        {
            return handle;
        }

        T* operator->() const
        {
            return handle;
        }

        /**
         * @brief Release the pointer stored in this OpenSSLRef container and transfer the ownership elsewhere. This is
         * typically for the OpenSSL API that takes the ownership of the passed object.
         */
        T* transferOwnership()
        {
            auto tmp = handle;
            handle   = nullptr;
            return tmp;
        }
    };
} // namespace tc4se::openssl

namespace tc4se::openssl
{
    namespace detail
    {
        /**
         * @brief Class that uses std::vector<uint8_t> as the backing for OpenSSL BIO object so we don't need to copy
         * buffer back between regular mem BIO buffer to the STL container buffer.
         *
         */
        class VectorBIO
        {
          private:
            static BIO_METHOD* getVectorBIOMethod();

            // instance field per-BIO
            std::vector<uint8_t> buffer;
            OpenSSLRef<BIO> bio;

            int write(char const* data, size_t len, size_t* written);

          public:
            operator BIO*() const
            {
                return bio;
            }
            VectorBIO();
            std::vector<uint8_t>&& getData();
        };

        /**
         * @brief Class that uses std::string as the backing for OpenSSL BIO object so we don't need to copy string
         * buffer back to std::string from the mem BIO buffer
         *
         */
        class StringBIO
        {
          private:
            static BIO_METHOD* getStringBIOMethod();

            // instance field per-BIO
            std::string buffer;
            OpenSSLRef<BIO> bio;

            int write(char const* data, size_t len, size_t* written);

          public:
            operator BIO*() const
            {
                return bio;
            }
            StringBIO();
            std::string&& getData();
        };

        // For DER writing
        template<typename T> struct I2DFuncTrait : std::false_type
        {
        };

        template<typename TOpenSSLType> struct I2DFuncTrait<int (*)(TOpenSSLType*, unsigned char**)> : std::true_type
        {
            using OpenSSLType = TOpenSSLType;
        };

        template<typename T>
        concept I2DFunction = I2DFuncTrait<T>::value;

        template<auto i2dFunc>
            requires I2DFunction<decltype(i2dFunc)>
        using I2DSourceType = typename I2DFuncTrait<decltype(i2dFunc)>::OpenSSLType;

        /**
         * @brief Helper function to interface with OpenSSL's i2d_TYPE function, which the result is automatically
         * written to C++'s STL container.
         *
         * @tparam i2dFunc
         * @param param
         * @return requires
         */
        template<auto i2dFunc>
            requires I2DFunction<decltype(i2dFunc)>
        Expect<std::vector<uint8_t>> i2dVector(I2DSourceType<i2dFunc>* param)
        {
            size_t size = i2dFunc(param, nullptr);
            std::vector<uint8_t> ret(size, 0);

            unsigned char* ptr = ret.data();
            if (i2dFunc(param, &ptr) != size)
                return ErrorCode::OPENSSL_BIO_WRITE_FAILED;

            return std::move(ret);
        }

        // For PEM writing
        template<typename T> struct OpenSSLPEMFunctionTrait : std::false_type
        {
        };

        template<typename TOpenSSLType> struct OpenSSLPEMFunctionTrait<int (*)(BIO*, TOpenSSLType*)> : std::true_type
        {
            using OpenSSLType = TOpenSSLType;
        };

        template<typename T>
        concept OpenSSLPEMFunction = OpenSSLPEMFunctionTrait<T>::value;

        template<auto pemFunc>
            requires OpenSSLPEMFunction<decltype(pemFunc)>
        using OpenSSLPEMSourceType = typename OpenSSLPEMFunctionTrait<decltype(pemFunc)>::OpenSSLType;

        /**
         * @brief Helper function that interfaces with various PEM writing function, which directly results in an
         * std::string object, so we do not need to copy back and forth between buffer and BIO.
         *
         * @tparam pemFunc
         * @param param
         * @return requires
         */
        template<auto pemFunc>
            requires OpenSSLPEMFunction<decltype(pemFunc)>
        Expect<std::string> writePEM(OpenSSLPEMSourceType<pemFunc>* param)
        {
            StringBIO bio;
            if (pemFunc(bio, param) == 0)
                return ErrorCode::OPENSSL_BIO_WRITE_FAILED;

            return std::move(bio.getData());
        }

        // To read d2i
        template<typename T> struct D2IFuncTrait : std::false_type
        {
        };

        template<typename TOpenSSLType>
        struct D2IFuncTrait<TOpenSSLType* (*) (TOpenSSLType**, const unsigned char**, long)> : std::true_type
        {
            using OpenSSLType = TOpenSSLType;
        };

        template<typename T>
        concept D2IFunction = D2IFuncTrait<T>::value;

        template<auto d2iFunc>
            requires D2IFunction<decltype(d2iFunc)>
        using D2ITargetType = typename D2IFuncTrait<decltype(d2iFunc)>::OpenSSLType;

        template<auto d2iFunc>
            requires D2IFunction<decltype(d2iFunc)>
        Expect<OpenSSLRef<D2ITargetType<d2iFunc>>> d2iVector(std::span<uint8_t const> buf)
        {
            const unsigned char* ptr = buf.data();
            auto res                 = d2iFunc(nullptr, &ptr, buf.size());
            if (res == nullptr)
                return ErrorCode::OPENSSL_BIO_READ_FAILED;

            return OpenSSLRef {res, NO_UP_REF};
        }
    } // namespace detail

    class AsymmetricKey
    {
      protected:
        OpenSSLRef<EVP_PKEY> pkey;
        AsymmetricKey() = default;
        AsymmetricKey(OpenSSLRef<EVP_PKEY>&& pkey): pkey(std::move(pkey)) {}
        AsymmetricKey(AsymmetricKey&&);
        AsymmetricKey(AsymmetricKey const&);

      public:
        bool operator==(AsymmetricKey const& that) const;

        operator EVP_PKEY*() const
        {
            return this->pkey;
        }

        uint32_t getBitSize() const;

        uint32_t getEncryptedSize() const
        {
            // EVP_PKEY_size() returns the maximum suitable size for the output buffers for almost all operations that
            // can be done with pkey. So i believe this function is work for EC key also.
            // The size returned is only preliminary and not exact, so the final contents of the target buffer may be
            // smaller.
            return EVP_PKEY_size(this->pkey);
        }

        int32_t getType() const
        {
            return EVP_PKEY_get_base_id(this->pkey);
        }

        virtual ~AsymmetricKey();
    };

    class PublicKey : public AsymmetricKey
    {
      public:
        PublicKey() = default;
        PublicKey(OpenSSLRef<EVP_PKEY>&& ref): AsymmetricKey(std::move(ref)) {}
        PublicKey(PublicKey&&);
        PublicKey(PublicKey const& that);
        static Expect<PublicKey> fromPEM(std::string_view pem);
        static Expect<PublicKey> fromDER(std::span<uint8_t const> der);

        Expect<std::string> writePublicKeyPEM() const;
        Expect<std::vector<uint8_t>> writePublicKeyDER() const;
        Expect<std::vector<uint8_t>>
            encrypt(std::span<uint8_t const> plainData,
                    constants::RSAPaddingMode paddingMode = constants::RSAPaddingMode::PKCS1_OAEP_PADDING) const;
        Expect<void> verify(std::span<uint8_t const> message, std::span<uint8_t const> signature) const;
    };

    class KeyPair : public PublicKey
    {
      public:
        KeyPair() = default;
        KeyPair(OpenSSLRef<EVP_PKEY>&& ref);
        KeyPair(KeyPair&&);
        KeyPair(KeyPair const&);

        static Expect<KeyPair> fromPEM(std::string_view pem);
        static Expect<KeyPair> fromDER(int type, std::span<uint8_t const> der);

        Expect<std::string> writePrivateKeyPEM() const;
        Expect<std::vector<uint8_t>> writePrivateKeyDER() const;
        Expect<std::vector<uint8_t>> decrypt(std::span<uint8_t const> encryptedData) const;
        Expect<std::vector<uint8_t>> sign(std::span<uint8_t const> message) const;
    };

    Expect<OpenSSLRef<BIO>> stringToBio(std::string_view str);

    class X509CertificateSigningRequest;

    class X509Certificate
    {
        friend class OpenSSLFactory;

      private:
        OpenSSLRef<X509> certHandle;
        X509Certificate();

      public:
        static Expect<std::vector<X509Certificate>> fromPEM(std::string_view pem);
        static Expect<X509Certificate> fromDER(std::span<uint8_t const> der);
        static Expect<std::reference_wrapper<X509Certificate const>>
            findForKey(std::vector<X509Certificate> const& certList, PublicKey const& key);
        static Expect<std::string> toPEM(std::vector<X509Certificate> const& chains);

        X509Certificate(PublicKey const& pubKey);

        X509Certificate(X509Certificate const& that);
        X509Certificate(X509Certificate&& that) = default;

        class ExtensionIterator
        {
            friend class X509Certificate;

          private:
            X509Certificate const& ref;
            const int max;
            int pos;

            ExtensionIterator(X509Certificate const& ref, bool end);

          public:
            using iterator_category = std::forward_iterator_tag;
            using difference_type   = std::ptrdiff_t;
            using value_type        = std::pair<ASN1_OBJECT*, ASN1_OCTET_STRING*>;
            using pointer           = value_type;
            using reference         = value_type;

            std::pair<ASN1_OBJECT*, ASN1_OCTET_STRING*> operator*() const;

            ExtensionIterator& operator++()
            {
                pos++;
                return *this;
            }

            bool operator==(ExtensionIterator const& that) const
            {
                return &ref == &that.ref and pos == that.pos;
            }
        };

        class ExtensionCollection
        {
            friend class X509Certificate;

          private:
            X509Certificate const& ref;
            ExtensionCollection(X509Certificate const& ref): ref(ref) {}

          public:
            ExtensionIterator begin() const
            {
                return {ref, false};
            }
            ExtensionIterator end() const
            {
                return {ref, true};
            }

            Expect<std::pair<ASN1_OBJECT*, ASN1_OCTET_STRING*>> operator[](int32_t nid) const;
        };

        ExtensionCollection extensions() const
        {
            return {*this};
        }

        X509Certificate(OpenSSLRef<X509>&& cert): certHandle(std::move(cert)) {}

        Expect<std::vector<uint8_t>> getCert();
        Expect<std::string> toPEM() const;
        Expect<std::vector<uint8_t>> toDER() const;
        Expect<std::string> getDN() const;
        Expect<std::vector<uint8_t>> getSubjectKeyIdentifier() const;

        PublicKey getPubKey() const
        {
            return {
                OpenSSLRef {X509_get_pubkey(this->certHandle), NO_UP_REF}
            };
        }

        operator X509*() const
        {
            return this->certHandle;
        }

        operator X509 const*() const
        {
            return this->certHandle;
        }

        bool operator==(PublicKey const& pubkey) const;

        Expect<void> sign(KeyPair const& signingKey, X509Certificate const& signingCert);
        Expect<void> addExtension(int32_t nid, char const* value, X509V3_CTX* ctx = nullptr);
        Expect<void> addExtension(ASN1_OBJECT* obj, std::span<uint8_t const> data);
        Expect<void> addNameEntry(int32_t nid, std::string_view data);
        Expect<void> addNameEntry(CertificateDN const& certificateDN);
        Expect<void> setValidity(uint64_t validity);
        Expect<void> selfSign(KeyPair const& signingKey);
        Expect<CertificateDN> getCertificateDN() const;
        Expect<std::tuple<time_t, time_t>> getValidityTime(time_t currentTime) const;
        Expect<X509CertificateSigningRequest> toCSR(KeyPair const& pkey) const;
        Expect<std::vector<uint8_t>> getExtensionByOID(std::string const& OID);
    };

    class X509CertificateSigningRequest
    {
        friend class X509Certificate;

      private:
        OpenSSLRef<X509_REQ> csrHandle;
        X509CertificateSigningRequest(OpenSSLRef<X509_REQ>&& req): csrHandle(std::move(req)) {}
        Expect<void> copyExtensionsTo(openssl::X509Certificate& x) const;

      public:
        static Expect<X509CertificateSigningRequest> fromPEM(std::string_view pemCsr);
        static Expect<X509CertificateSigningRequest> fromDER(std::span<uint8_t const> derCsr);
        Expect<X509Certificate> sign(uint32_t validityDays, KeyPair const& signingKey,
                                     X509Certificate const& signingCert, std::function<Expect<void>(X509Certificate& newCert)> beforeSignCallback = {}) const;
        Expect<std::string> toPEM() const;
        Expect<std::vector<uint8_t>> toDER() const;
        operator X509_REQ*() const
        {
            return csrHandle;
        }
        Expect<std::string> getDN() const;
        Expect<void> addExtension(int32_t nid, char const* value, X509V3_CTX* ctx = nullptr) const;
    };

    class X509CertificateRevocationList
    {
      private:
        OpenSSLRef<X509_CRL> crlHandle;
        X509CertificateRevocationList(OpenSSLRef<X509_CRL>&& crl): crlHandle(std::move(crl)) {}

      public:
        static Expect<X509CertificateRevocationList> fromPEM(std::string_view pemCsr);

        operator X509_CRL*() const
        {
            return crlHandle;
        }
    };

    class X509CertificateStore
    {
      private:
        OpenSSLRef<X509_STORE> certStoreHandle;

      public:
        X509CertificateStore();
        X509CertificateStore(OpenSSLRef<X509_STORE>&& handle): certStoreHandle(std::move(handle)) {};
        Expect<void> addCertificate(X509Certificate const& cert);
        Expect<void> addCertificateRevocationList(X509CertificateRevocationList const& crl);
        Expect<void>
            verifyCertificate(X509Certificate const& target,
                              std::optional<std::span<X509Certificate const>> additionalCerts = std::nullopt) const;

        operator X509_STORE*() const
        {
            return certStoreHandle;
        }
    };

    /**
     * @brief Simplified function to convert CRL from DER to PEM without hassle
     *
     * @param crlDER
     * @return Expect<std::string>
     */
    Expect<std::string> crlDERtoPEM(std::span<uint8_t const> crlDER);

    Expect<std::string> objToString(ASN1_OBJECT* obj);

    Expect<std::tuple<KeyPair, std::vector<X509Certificate>>> fromPKCS12PEM(std::span<uint8_t const> pkcs12,
                                                                            std::string const& passcode);

    namespace keygen
    {
        Expect<KeyPair> RSA(int keylength);
        Expect<PublicKey> RSA(std::span<uint8_t const> modulusBin, std::span<uint8_t const> exponentBin);
        Expect<KeyPair> ECDSA();
    } // namespace keygen

    class SSLConnection;

    class SSLContext
    {
      private:
        OpenSSLRef<SSL_CTX> context;
        std::optional<openssl::KeyPair> sslKeypair;
        openssl::X509CertificateStore certStore;

        SSLContext() = default;
        Expect<SSLConnection> createSSL() const;

      public:
        SSLContext(SSLContext&& other): context(std::move(other.context)), sslKeypair(std::move(other.sslKeypair)) {}
        SSLContext& operator=(SSLContext&& other);

        SSLContext(SSLContext const&)            = delete;
        SSLContext& operator=(SSLContext const&) = delete;

        /**
         * @brief Creates a new SSL_CTX object, which holds various configuration and data relevant to SSL/TLS or DTLS
         * session establishment. These are later inherited by the SSL object representing an active session.
         *
         * @param cert
         * @param keyPair
         * @return Expect<SSLContext>
         */
        static Expect<SSLContext> createSSLContext(std::span<openssl::X509Certificate const> cert,
                                                   openssl::KeyPair const& keyPair, bool verifyPeer);

        static Expect<SSLContext> createSSLContext(bool verifyPeer);

        /**
         * @brief Waits for a TLS/SSL client to initiate the TLS/SSL handshake.
         *
         * @param peerFd
         * @param useMutualTLS
         * @return Expect<SSLConnection>
         */
        Expect<SSLConnection> accept(int32_t peerFd, bool waitEarlyData = false) const;

        /**
         * @brief Initiates the TLS/SSL handshake with a server.
         *
         * @param peerFd
         * @param useMutualTLS
         * @return Expect<SSLConnection>
         */
        Expect<SSLConnection> connect(int32_t peerFd,
                                      std::optional<std::span<uint8_t const>> earlyData = std::nullopt) const;

        auto const& getSSLKeypair() const
        {
            return this->sslKeypair;
        }

        operator SSL_CTX*() const
        {
            return this->context;
        }
    };

    class SSLConnection
    {
      private:
        OpenSSLRef<SSL> ssl;
        SSLConnection() = default;

        friend SSLContext;

        /**
         * @brief Try to read all bytes from the specified ssl into the buffer
         *
         * @return Expect<std::vector<uint8_t>>
         */
        Expect<std::vector<uint8_t>> readEarlyData() const;

      public:
        ~SSLConnection();
        SSLConnection(OpenSSLRef<SSL> const& sslObj): ssl(sslObj) {}
        SSLConnection(SSLConnection&& other): ssl(std::move(other.ssl)) {}
        SSLConnection& operator=(SSLConnection&& other);

        SSLConnection(SSLConnection const&)            = delete;
        SSLConnection& operator=(SSLConnection const&) = delete;

        operator SSL*() const
        {
            return ssl;
        }

        /**
         * @brief Returns a pointer to the X509 certificate the peer presented
         *
         * @return Expect<openssl::X509Certificate>
         */
        Expect<openssl::X509Certificate> getPeerCertificate() const;

        /**
         * @brief Returns the result of the verification of the X509 certificate presented by the peer, if any.
         *
         * @return Expect<void>
         */
        Expect<void> verifyPeer() const;

        /**
         * @brief Try to read all bytes from the specified ssl into the buffer
         *
         * @return Expect<std::vector<uint8_t>>
         */
        Expect<std::vector<uint8_t>> read() const;

        /**
         * @brief Write all bytes from the buffer data into the specified ssl connection.
         *
         * @param data
         * @return Expect<void>
         */
        Expect<void> write(std::span<uint8_t const> data) const;
    };

    class TLSManager
    {
      private:
        TLSManager() {}

        std::mutex mappedSSLContextMutex;
        std::unordered_map<int32_t, SSLContext> mappedSSLContext;

      public:
        TLSManager(TLSManager const&)            = delete;
        TLSManager& operator=(TLSManager const&) = delete;

        static TLSManager& getInstance();

        Expect<std::reference_wrapper<SSLContext const>> registerSSLContext(int32_t fd, SSLContext&& sslContextObject);
        Expect<void> unregisterSSLContext(int32_t fd);
        Expect<std::reference_wrapper<SSLContext const>> getRegisteredSSLContext(int32_t fd);
    };

    struct TCPSocket
    {
        int32_t serverFD;

        TCPSocket(int32_t serverFD): serverFD(serverFD) {}
        ~TCPSocket()
        {
            TCPSocket::closeTCPConnection(this->serverFD);
        }

        TCPSocket(TCPSocket const&)            = delete;
        TCPSocket(TCPSocket&& other)           = delete;
        TCPSocket& operator=(TCPSocket const&) = delete;
        TCPSocket& operator=(TCPSocket&&)      = delete;

        operator int32_t() const
        {
            return this->serverFD;
        }

        static Expect<int32_t> openTCPServerConnection(int16_t port);
        static Expect<int32_t> openTCPServerConnection(std::string_view host, uint16_t port);
        static Expect<int32_t> acceptTCPConnection(int32_t serverFd);
        static uint64_t closeTCPConnection(int32_t serverFd);
    };

    Expect<std::array<uint8_t, constants::SHA256_HASH_LENGTH>> computeSHA256Hash(std::span<uint8_t const> message);
} // namespace tc4se::openssl

#endif
