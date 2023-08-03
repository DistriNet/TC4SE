#include "openssl/ossl_typ.h"
#include <cstddef>
#include <openssl/asn1.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <vector>

#include <tc4se/ErrorCode.h>
#include <tc4se/OpenSSL.h>

using namespace tc4se;
using namespace tc4se::openssl;



X509Certificate::X509Certificate(X509Certificate const& that) : certHandle(X509_dup(that.certHandle), NO_UP_REF)
{
    
}

Expect<std::vector<openssl::X509Certificate>> openssl::X509Certificate::fromPEM(std::string_view pem)
{
    OpenSSLRef<BIO> bio {BIO_new_mem_buf(pem.data(), pem.length()), NO_UP_REF};
    if (bio == nullptr)
        return ErrorCode::OPENSSL_BIO_INITIALIZE_FAILED;

    std::vector<openssl::X509Certificate> ret;

    while (true)
    {
        OpenSSLRef<X509> x509 {PEM_read_bio_X509(bio, nullptr, nullptr, nullptr), NO_UP_REF};
        if (x509 == nullptr)
            break;

        ret.emplace_back(std::move(x509));
    }

    if (ret.size() == 0)
        return ErrorCode::OPENSSL_X509_LOAD_FAILED;

    return ret;
}

Expect<X509Certificate> openssl::X509Certificate::fromDER(std::span<uint8_t const> der)
{
    auto x509 = BOOST_OUTCOME_TRYX(detail::d2iVector<d2i_X509>(der));
    return X509Certificate { std::move(x509) };
}

Expect<std::reference_wrapper<X509Certificate const>>
    openssl::X509Certificate::findForKey(std::vector<X509Certificate> const& certList, PublicKey const& key)
{
    auto cert = std::find_if(certList.begin(), certList.end(),
                             [&](auto const& cert)
                             {
#if OPENSSL_VERSION_MAJOR == 3
                                 return EVP_PKEY_eq(cert.getPubKey(), key) == 1;
#else
                                 return EVP_PKEY_cmp(cert.getPubKey(), key) == 1;
#endif
                             });

    if (cert == certList.end())
        return ErrorCode::INVALID_CERTIFICATE_FOR_KEY;

    return std::reference_wrapper {*cert};
}

Expect<std::string> openssl::X509Certificate::toPEM(std::vector<openssl::X509Certificate> const& chains)
{
    if (chains.size() == 0)
        return ErrorCode::OPENSSL_X509_STORE_FAILED;
    std::string ret;
    for (auto& cert: chains)
    {
        BOOST_OUTCOME_TRY(auto currPEM, cert.toPEM());
        ret.append(currPEM);
    }

    return ret;
}

openssl::X509Certificate::ExtensionIterator::ExtensionIterator(openssl::X509Certificate const& ref, bool end):
    ref(ref), max(X509_get_ext_count(ref)), pos(end ? max : 0)
{
}

openssl::X509Certificate::X509Certificate(PublicKey const& pubKey): certHandle {X509_new(), NO_UP_REF}
{
    X509_set_version(certHandle, 2);
    X509_set_pubkey(certHandle, pubKey);
}

Expect<std::string> openssl::objToString(ASN1_OBJECT* obj)
{
    auto len = OBJ_obj2txt(nullptr, 0, obj, 1);
    std::string oidName;
    oidName.resize(len + 1); // Add spare for null character

    if (OBJ_obj2txt(oidName.data(), oidName.size(), obj, 1) == 0)
        return ErrorCode::OPENSSL_GET_EXTENSIONS_FAILED;

    oidName.resize(len); // Remove the null character
    return oidName;
}

std::pair<ASN1_OBJECT*, ASN1_OCTET_STRING*> openssl::X509Certificate::ExtensionIterator::operator*() const
{
    auto extension = X509_get_ext(ref, pos);
    return {X509_EXTENSION_get_object(extension), X509_EXTENSION_get_data(extension)};
}

Expect<std::pair<ASN1_OBJECT*, ASN1_OCTET_STRING*>>
    openssl::X509Certificate::ExtensionCollection::operator[](int32_t nid) const
{
    auto skiExtensionIter = std::find_if(begin(), end(),
                                         [nid](std::pair<ASN1_OBJECT*, ASN1_OCTET_STRING*> const& obj)
                                         {
                                             return OBJ_obj2nid(obj.first) == nid;
                                         });

    if (skiExtensionIter == end())
        return ErrorCode::OPENSSL_X509V3_EXT_NOT_FOUND;

    return *skiExtensionIter;
}

bool openssl::X509Certificate::operator==(openssl::PublicKey const& otherPubkey) const
{
    auto thisPubKey = X509_get0_pubkey(this->certHandle);
    if (thisPubKey == nullptr)
        return false;

#if OPENSSL_VERSION_MAJOR == 3
    return EVP_PKEY_eq(thisPubKey, otherPubkey) == 1;
#else
    return EVP_PKEY_cmp(thisPubKey, otherPubkey) == 1;
#endif
}

Expect<void> openssl::X509Certificate::sign(KeyPair const& signingKey, X509Certificate const& signingCert)
{
    if (signingKey != signingCert)
        return ErrorCode::INVALID_CERTIFICATE_FOR_KEY;

    // Clear existing extension if any
    auto keyIdExt = X509_get_ext_by_NID(this->certHandle, NID_subject_key_identifier, -1);
    if(keyIdExt != -1)
        X509_delete_ext(this->certHandle, keyIdExt);
    auto authKeyIdExt = X509_get_ext_by_NID(this->certHandle, NID_authority_key_identifier, -1);
    if(authKeyIdExt != -1)
        X509_delete_ext(this->certHandle, authKeyIdExt);

    BOOST_OUTCOME_TRY(addExtension(NID_subject_key_identifier, "hash"));

    // Attach the issuer name
    if (!X509_set_issuer_name(certHandle, X509_get_subject_name(signingCert)))
        return ErrorCode::X509_GENERATION_FAILED;

    X509V3_CTX currentExtensionContext;
    X509V3_set_ctx(&currentExtensionContext, signingCert, this->certHandle, NULL, NULL, 0);

    BOOST_OUTCOME_TRY(addExtension(NID_authority_key_identifier, "keyid:always", &currentExtensionContext));

    // Sign
    if (!X509_sign(certHandle, signingKey, EVP_sha256()))
        return ErrorCode::X509_GENERATION_FAILED;

    return success;
}

Expect<std::vector<uint8_t>> openssl::X509Certificate::getSubjectKeyIdentifier() const
{
    BOOST_OUTCOME_TRY(auto skiExtension, extensions()[NID_subject_key_identifier]);

    if (skiExtension.second->type != V_ASN1_OCTET_STRING)
        return ErrorCode::OPENSSL_SUBJECT_KEY_IDENTIFIER_NOT_FOUND;

    BOOST_OUTCOME_TRY(auto skiData,
                      detail::d2iVector<d2i_ASN1_TYPE>(
                          {skiExtension.second->data, static_cast<size_t>(skiExtension.second->length)}));

    if (skiData->type != V_ASN1_OCTET_STRING)
        return ErrorCode::OPENSSL_SUBJECT_KEY_IDENTIFIER_NOT_FOUND;

    return std::vector<uint8_t> {skiData->value.octet_string->data,
                                 skiData->value.octet_string->data + skiData->value.octet_string->length};
}

Expect<void> openssl::X509Certificate::addExtension(int32_t nid, char const* value, X509V3_CTX* ctx)
{
    X509V3_CTX localCtx;
    if (ctx == nullptr)
    {
        ctx = &localCtx;
        X509V3_set_ctx(ctx, nullptr, this->certHandle, NULL, NULL, 0);
    }

    X509V3_set_ctx_nodb(ctx);

    OpenSSLRef ex {X509V3_EXT_conf_nid(NULL, ctx, nid, value)};
    if (ex == nullptr)
        return ErrorCode::X509_GENERATION_FAILED;

    X509_add_ext(certHandle, ex, -1);
    return success;
}

Expect<void> openssl::X509Certificate::addExtension(ASN1_OBJECT* obj, std::span<uint8_t const> data)
{
    OpenSSLRef newExt {X509_EXTENSION_new()};
    OpenSSLRef newStr {ASN1_OCTET_STRING_new()};

    if (!X509_EXTENSION_set_object(newExt, obj) or !ASN1_OCTET_STRING_set(newStr, data.data(), data.size()) or
        !X509_EXTENSION_set_data(newExt, newStr) or !X509_add_ext(this->certHandle, newExt, -1))
        return ErrorCode::X509_GENERATION_FAILED;
    return success;
}

Expect<std::string> openssl::X509Certificate::getDN() const
{
    auto subject = X509_get_subject_name(*this);
    OpenSSLRef bio {BIO_new(BIO_s_mem()), NO_UP_REF};
    if (bio == nullptr)
        return ErrorCode::OPENSSL_BIO_INITIALIZE_FAILED;

    if (X509_NAME_print_ex(bio, subject, 0, 0) != 1)
        return ErrorCode::OPENSSL_BIO_INITIALIZE_FAILED;

    auto bufferLength {BIO_ctrl_pending(bio)};
    if (!bufferLength)
        return ErrorCode::OPENSSL_BIO_INITIALIZE_FAILED;

    std::string buff;
    buff.resize(bufferLength);
    size_t readBytes {};
    if (!BIO_read_ex(bio, buff.data(), buff.size(), &readBytes))
        return ErrorCode::OPENSSL_BIO_READ_FAILED;

    if (readBytes != buff.size())
        return ErrorCode::OPENSSL_BIO_READ_FAILED;

    return buff;
}

Expect<std::string> openssl::X509Certificate::toPEM() const
{
    return detail::writePEM<PEM_write_bio_X509>(certHandle);
}

Expect<std::vector<uint8_t>> openssl::X509Certificate::toDER() const
{
    return detail::i2dVector<i2d_X509>(this->certHandle);
}

Expect<void> openssl::X509Certificate::addNameEntry(int32_t nid, std::string_view data)
{
    X509_NAME* certName = X509_get_subject_name(this->certHandle);
    if (certName == nullptr)
        return ErrorCode::X509_GENERATION_FAILED;

    if (X509_NAME_add_entry_by_NID(certName, nid, MBSTRING_UTF8, reinterpret_cast<uint8_t const*>(data.data()),
                                   data.size(), -1, 0) != 1)
        return ErrorCode::X509_GENERATION_FAILED;

    return success;
}

Expect<void> openssl::X509Certificate::addNameEntry(CertificateDN const& dn)
{
    auto addEntry = [&](int32_t nid, std::string const& x) -> Expect<void>
    {
        if (!x.empty())
            return addNameEntry(nid, x);
        return success;
    };

    // https://www.ibm.com/docs/en/ibm-mq/7.5?topic=certificates-distinguished-names
    // Looks like this structure is not exhaustive
    BOOST_OUTCOME_TRY(addEntry(NID_countryName, dn.countryName));
    BOOST_OUTCOME_TRY(addEntry(NID_stateOrProvinceName, dn.stateName));
    BOOST_OUTCOME_TRY(addEntry(NID_localityName, dn.localityName));
    BOOST_OUTCOME_TRY(addEntry(NID_organizationName, dn.organizationName));
    BOOST_OUTCOME_TRY(addEntry(NID_organizationalUnitName, dn.organizationUnitName));
    BOOST_OUTCOME_TRY(addEntry(NID_commonName, dn.commonName));
    BOOST_OUTCOME_TRY(addEntry(NID_pkcs9_emailAddress, dn.emailAddress));

    return success;
}

Expect<void> openssl::X509Certificate::setValidity(uint64_t validity)
{
    if (!X509_gmtime_adj(X509_get_notBefore(this->certHandle), 0))
        return ErrorCode::X509_GENERATION_FAILED;

    if (!X509_gmtime_adj(X509_get_notAfter(this->certHandle), validity))
        return ErrorCode::X509_GENERATION_FAILED;

    return success;
}

Expect<void> openssl::X509Certificate::selfSign(KeyPair const& signingKey)
{
    return sign(signingKey, *this);
}

Expect<CertificateDN> openssl::X509Certificate::getCertificateDN() const
{
    CertificateDN dn;
    auto subjectName = X509_get_subject_name(this->certHandle);

    if (subjectName == nullptr)
        return ErrorCode::OPENSSL_X509_LOAD_FAILED;

    auto getDN = [&](int32_t nid, std::string& x)
    {
        // Check first if the entry is exist and the length required
        auto lenRequired = X509_NAME_get_text_by_NID(subjectName, nid, nullptr, 0);
        if (lenRequired == -1)
            return;

        // Resize the buffer
        x.resize(lenRequired + 1); // null terminator needs space (C++17 no longer needs this)
        X509_NAME_get_text_by_NID(subjectName, nid, x.data(), x.size());
        x.resize(lenRequired); // excluding the null
    };

    getDN(NID_countryName, dn.countryName);
    getDN(NID_stateOrProvinceName, dn.stateName);
    getDN(NID_localityName, dn.localityName);
    getDN(NID_organizationName, dn.organizationName);
    getDN(NID_organizationalUnitName, dn.organizationUnitName);
    getDN(NID_commonName, dn.commonName);
    getDN(NID_pkcs9_emailAddress, dn.emailAddress);

    return dn;
}

Expect<X509CertificateSigningRequest> openssl::X509Certificate::toCSR(KeyPair const& pkey) const
{
    OpenSSLRef csrHandle {X509_to_X509_REQ(this->certHandle, pkey, EVP_sha256()), NO_UP_REF};
    if (csrHandle == nullptr)
        return ErrorCode::X509_GENERATION_FAILED;

    return X509CertificateSigningRequest {std::move(csrHandle)};
}

/**
 * @brief Convert ASN1_TIME to time_t which is in second
 *
 * @param asnTime
 * @param currentTime
 * @return Expect<time_t>
 */
Expect<time_t> fromASN1Time(ASN1_TIME* asnTime, time_t currentTime)
{
    OpenSSLRef currentTimeASN1 {ASN1_TIME_new()};
    ASN1_TIME_set(currentTimeASN1, currentTime);

    int32_t dayDiff = 0, secondDiff = 0;
    if (!ASN1_TIME_diff(&dayDiff, &secondDiff, asnTime, currentTimeASN1))
        return ErrorCode::OPENSSL_ASN1_TIME_CONVERSION_FAILED;

    time_t totalDiff = (dayDiff * 24 * 60 * 60) + secondDiff;
    return currentTime - totalDiff;
}

Expect<std::tuple<time_t, time_t>> openssl::X509Certificate::getValidityTime(time_t currentTime) const
{
    BOOST_OUTCOME_TRY(auto notBefore, fromASN1Time(X509_get_notBefore(certHandle), currentTime));
    BOOST_OUTCOME_TRY(auto notAfter, fromASN1Time(X509_get_notAfter(certHandle), currentTime));
    return std::make_tuple(notBefore, notAfter);
}

Expect<std::string> openssl::crlDERtoPEM(std::span<uint8_t const> crlDER)
{
    BOOST_OUTCOME_TRY(auto x509crl, detail::d2iVector<d2i_X509_CRL>(crlDER));
    return detail::writePEM<PEM_write_bio_X509_CRL>(x509crl);
}

Expect<X509CertificateSigningRequest> X509CertificateSigningRequest::fromPEM(std::string_view pemCsr)
{
    BOOST_OUTCOME_TRY(auto bio, stringToBio(pemCsr));
    OpenSSLRef x509req {PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr)};
    if (x509req == nullptr)
        return ErrorCode::OPENSSL_X509_REQ_LOAD_FAILED;

    if (X509_REQ_get_subject_name(x509req) == nullptr)
        return ErrorCode::OPENSSL_X509_REQ_LOAD_FAILED;

    return X509CertificateSigningRequest {std::move(x509req)};
}

Expect<X509CertificateSigningRequest> X509CertificateSigningRequest::fromDER(std::span<uint8_t const> derCsr)
{
    auto x509req = BOOST_OUTCOME_TRYX(detail::d2iVector<d2i_X509_REQ>(derCsr));

    if (X509_REQ_get_subject_name(x509req) == nullptr)
        return ErrorCode::OPENSSL_X509_REQ_LOAD_FAILED;

    return X509CertificateSigningRequest { std::move(x509req) };
}

Expect<void> X509CertificateSigningRequest::copyExtensionsTo(openssl::X509Certificate& x) const
{
    OpenSSLRef exts {X509_REQ_get_extensions(this->csrHandle)};

    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++)
    {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        if (!X509_add_ext(x, ext, -1))
            return ErrorCode::X509_GENERATION_FAILED;
    }
    return success;
}

Expect<X509Certificate> X509CertificateSigningRequest::sign(uint32_t validityDays, KeyPair const& signingKey,
                                                            X509Certificate const& signingCert, 
                                                            std::function<Expect<void>(X509Certificate& newCert)> beforeSignCallback) const
{
    PublicKey x509reqPubKey {
        OpenSSLRef {X509_REQ_get_pubkey(this->csrHandle), NO_UP_REF}
    };

    if (X509_REQ_verify(this->csrHandle, x509reqPubKey) != 1)
        return ErrorCode::X509_GENERATION_FAILED;

    X509Certificate newCert {x509reqPubKey};

    auto subjectName {X509_REQ_get_subject_name(this->csrHandle)};
    if (X509_set_subject_name(newCert, subjectName) == 0)
        return ErrorCode::X509_GENERATION_FAILED;

    

    if(beforeSignCallback != nullptr)
        BOOST_OUTCOME_TRYX(beforeSignCallback(newCert));
    

    BOOST_OUTCOME_TRY(newCert.setValidity(validityDays * 24 * 60 * 60));
    BOOST_OUTCOME_TRY(this->copyExtensionsTo(newCert));
    BOOST_OUTCOME_TRY(newCert.sign(signingKey, signingCert));

    return newCert;
}

Expect<std::string> X509CertificateSigningRequest::toPEM() const
{
    return detail::writePEM<PEM_write_bio_X509_REQ>(this->csrHandle);
}

Expect<std::vector<uint8_t>> X509CertificateSigningRequest::toDER() const
{
    return detail::i2dVector<i2d_X509_REQ>(this->csrHandle);
}


Expect<std::string> X509CertificateSigningRequest::getDN() const
{
    auto subject = X509_REQ_get_subject_name(this->csrHandle);
    OpenSSLRef bio {BIO_new(BIO_s_mem()), NO_UP_REF};
    if (bio == nullptr)
        return ErrorCode::OPENSSL_BIO_INITIALIZE_FAILED;

    if (X509_NAME_print_ex(bio, subject, 0, 0) != 1)
        return ErrorCode::OPENSSL_BIO_INITIALIZE_FAILED;

    auto bufferLength {BIO_ctrl_pending(bio)};
    if (!bufferLength)
        return ErrorCode::OPENSSL_BIO_INITIALIZE_FAILED;

    std::string buff;
    buff.resize(bufferLength);
    size_t readBytes {};
    if (!BIO_read_ex(bio, buff.data(), buff.size(), &readBytes))
        return ErrorCode::OPENSSL_BIO_READ_FAILED;

    if (readBytes != buff.size())
        return ErrorCode::OPENSSL_BIO_READ_FAILED;

    return buff;
}

Expect<void> X509CertificateSigningRequest::addExtension(int32_t nid, char const* value, X509V3_CTX* ctx) const
{
    X509V3_CTX localCtx;
    if (ctx == nullptr)
    {
        ctx = &localCtx;
        X509V3_set_ctx(ctx, nullptr, nullptr, this->csrHandle, nullptr, 0);
    }

    X509V3_set_ctx_nodb(ctx);

    X509_EXTENSION* ex; // no need to be freed to avoid double free caused by `OpenSSLRef extensions` below
    ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value);
    if (ex == nullptr)
        return ErrorCode::X509_GENERATION_FAILED;

    // We allocate outside for simplicity
    OpenSSLRef extensions {sk_X509_EXTENSION_new_null()};
    STACK_OF(X509_EXTENSION)* extensionsPtr = extensions;

    sk_X509_EXTENSION_push(extensionsPtr, ex);

    if (!X509_REQ_add_extensions(this->csrHandle, extensionsPtr))
        return ErrorCode::X509_GENERATION_FAILED;

    return success;
}

Expect<std::tuple<KeyPair, std::vector<X509Certificate>>> openssl::fromPKCS12PEM(std::span<uint8_t const> pkcs12DER,
                                                                                 std::string const& passcode)
{
    BOOST_OUTCOME_TRY(auto pkcs12, detail::d2iVector<d2i_PKCS12>(pkcs12DER));

    EVP_PKEY* privateKey = nullptr;
    X509* cert           = nullptr;

    // We allocate outside for simplicity
    OpenSSLRef caCerts {sk_X509_new_null()};
    STACK_OF(X509)* caCertsPtr = caCerts;

    if (!PKCS12_parse(pkcs12, passcode.c_str(), &privateKey, &cert, &caCertsPtr))
        return ErrorCode::OPENSSL_PKCS12_EXTRACTION_FAILED;

    // Don't accept null Private Key and Cert (This should never be the case, I guess)
    if (privateKey == nullptr or cert == nullptr)
        return ErrorCode::OPENSSL_PKCS12_EXTRACTION_FAILED;

    KeyPair keyPair {
        OpenSSLRef {privateKey, NO_UP_REF}
    };
    std::vector<X509Certificate> certChain;

    // Reserve the certificate chain stack
    certChain.reserve(sk_X509_num(caCerts) + 1);

    // Put the root cert
    certChain.emplace_back(OpenSSLRef {cert, NO_UP_REF});

    // Iterate the stack and move to our stack
    while (sk_X509_num(caCerts) != 0)
        certChain.emplace_back(OpenSSLRef {sk_X509_pop(caCerts), NO_UP_REF});

    return std::make_tuple(std::move(keyPair), std::move(certChain));
}

openssl::X509CertificateStore::X509CertificateStore(): certStoreHandle {X509_STORE_new(), NO_UP_REF} {}

Expect<void> openssl::X509CertificateStore::addCertificate(X509Certificate const& cert)
{
    if (X509_STORE_add_cert(certStoreHandle, cert) == 0)
        return ErrorCode::OPENSSL_X509_STORE_FAILED;
    return success;
}

Expect<void> openssl::X509CertificateStore::addCertificateRevocationList(X509CertificateRevocationList const& crl)
{
    if (X509_STORE_add_crl(certStoreHandle, crl) == 0)
        return ErrorCode::OPENSSL_X509_STORE_FAILED;
    return success;
}

Expect<void> openssl::X509CertificateStore::verifyCertificate(
    X509Certificate const& target, std::optional<std::span<X509Certificate const>> additionalCerts) const
{
    OpenSSLRef storeCtx {X509_STORE_CTX_new()};
    if (storeCtx == nullptr)
        return ErrorCode::SSL_STORE_CERTIFICATE_FAILED;

    // Additional certs if any
    STACK_OF(X509)* certStackPtr = nullptr;
    OpenSSLRef certStack {sk_X509_new_null()};
    if (additionalCerts)
    {
        for (auto& cert: *additionalCerts)
        {
            X509_up_ref(cert); // Explicitly up-ref here, so the stack owns also the reference
            sk_X509_push(certStack, cert);
        }

        certStackPtr = certStack;
    }

    X509_STORE_CTX_init(storeCtx, this->certStoreHandle, target, certStackPtr);

    auto verifyStatus = X509_verify_cert(storeCtx);
    auto storeCtxErr = X509_STORE_CTX_get_error(storeCtx);
    if (verifyStatus != 1 or storeCtxErr != X509_V_OK)
        return ErrorCode::CERTIFICATE_VERIFICATION_FAILED;

    return success;
}

Expect<std::vector<uint8_t>> openssl::X509Certificate::getExtensionByOID(std::string const& OID)
{
    int32_t numOfExtensions {X509_get_ext_count(this->certHandle)};
    for (auto i = 0; i < numOfExtensions; ++i)
    {
        X509_EXTENSION* x509Extension {
            X509_get_ext(this->certHandle, i)}; // must not be freed up based on openssl manual guide
        if (x509Extension == nullptr)
            return ErrorCode::X509_EXTENSION_CREATION_FAILED;
        ASN1_OBJECT* asn1Object {
            X509_EXTENSION_get_object(x509Extension)}; // must not be freed up based on openssl manual guide
        if (asn1Object == nullptr)
            return ErrorCode::ASN1_OBJECT_CREATION_FAILED;
        OpenSSLRef initObj {OBJ_txt2obj(OID.c_str(), 1), NO_UP_REF};
        if (initObj == nullptr)
            return ErrorCode::ASN1_OBJECT_CREATION_FAILED;
        if (OBJ_length(initObj) == OBJ_length(asn1Object))
        {
            ASN1_OCTET_STRING* asn1Value {
                X509_EXTENSION_get_data(x509Extension)}; // must not be freed up based on openssl manual guide
            if (asn1Value == nullptr)
                return ErrorCode::ASN1_OBJECT_CREATION_FAILED;
            return {asn1Value->data, asn1Value->data + asn1Value->length};
        }
    }
    return std::vector<uint8_t> {};
}
