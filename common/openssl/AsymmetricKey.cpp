#include <cstdint>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <type_traits>
#include <vector>

#include <tc4se/Constants.h>
#include <tc4se/ErrorCode.h>
#include <tc4se/OpenSSL.h>

using namespace tc4se;
using namespace tc4se::openssl;

Expect<PublicKey> PublicKey::fromPEM(std::string_view pem)
{
    BOOST_OUTCOME_TRY(auto bio, stringToBio(pem));

    PublicKey ret;
    ret.pkey = OpenSSLRef {PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr), NO_UP_REF};

    if (!ret.pkey)
        return ErrorCode::OPENSSL_PUBLICKEY_LOAD_FAILED;

    return ret;
}

Expect<KeyPair> KeyPair::fromPEM(std::string_view pem)
{
    BOOST_OUTCOME_TRY(auto bio, stringToBio(pem));

    OpenSSLRef evpPkey {PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr), NO_UP_REF};

    if (!evpPkey)
        return ErrorCode::OPENSSL_PRIVATEKEY_LOAD_FAILED;

    KeyPair ret;
    ret.pkey = std::move(evpPkey);

    return ret;
}

template<int type> EVP_PKEY* d2i_PrivateKeyWrap(EVP_PKEY** a, const unsigned char** pp, long length)
{
    return d2i_PrivateKey(type, a, pp, length);
}

Expect<KeyPair> KeyPair::fromDER(int type, std::span<uint8_t const> der)
{
    OpenSSLRef<EVP_PKEY> evpPkey;
    switch (type)
    {
    case EVP_PKEY_RSA:
        {
            BOOST_OUTCOME_TRY(evpPkey, detail::d2iVector<d2i_PrivateKeyWrap<EVP_PKEY_RSA>>(der));
            break;
        }
    case EVP_PKEY_EC:
        {
            BOOST_OUTCOME_TRY(evpPkey, detail::d2iVector<d2i_PrivateKeyWrap<EVP_PKEY_EC>>(der));
            break;
        }
    default:
        return ErrorCode::OPENSSL_PRIVATEKEY_LOAD_FAILED;
    }

    KeyPair ret;
    ret.pkey = std::move(evpPkey);
    return ret;
}

Expect<PublicKey> PublicKey::fromDER(std::span<uint8_t const> der)
{
    BOOST_OUTCOME_TRY(auto evpPkey, detail::d2iVector<d2i_PUBKEY>(der));

    PublicKey ret;
    ret.pkey = std::move(evpPkey);
    return ret;
}

Expect<std::vector<uint8_t>> KeyPair::decrypt(std::span<uint8_t const> encryptedData) const
{
    // Decryption failures in the RSA_PKCS1_PADDING mode leak information which can potentially be used to mount a
    // Bleichenbacher padding oracle attack. This is an inherent weakness in the PKCS #1 v1.5 padding design. Prefer
    // RSA_PKCS1_OAEP_PADDING.
    // See: https://www.openssl.org/docs/man1.1.1/man3/RSA_public_encrypt.html

    // Check if key is not RSA key
    if (this->getType() != EVP_PKEY_RSA)
        return ErrorCode::INVALID_KEY_TYPE;

    OpenSSLRef pkeyCtx {EVP_PKEY_CTX_new(this->pkey, ENGINE_get_default_RSA()), NO_UP_REF};
    EVP_PKEY_decrypt_init(pkeyCtx);

    // This is only for RSA...
    if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_OAEP_PADDING) <= 0)
        return ErrorCode::DECRYPTION_FAILED;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pkeyCtx, EVP_sha256()) <= 0)
        return ErrorCode::DECRYPTION_FAILED;

    size_t outlen;

    if (EVP_PKEY_decrypt(pkeyCtx, NULL, &outlen, encryptedData.data(), encryptedData.size()) <= 0)
        return ErrorCode::DECRYPTION_FAILED;

    std::vector<uint8_t> decryptedData(outlen, 0);

    if (int res = EVP_PKEY_decrypt(pkeyCtx, decryptedData.data(), &outlen, encryptedData.data(), encryptedData.size());
        res <= 0)
        return ErrorCode::DECRYPTION_FAILED;

    decryptedData.resize(outlen);
    return decryptedData;
}

Expect<std::vector<uint8_t>> KeyPair::sign(std::span<uint8_t const> message) const
{
    size_t signatureLen;
    OpenSSLRef pkeySignCtx {EVP_MD_CTX_new(), NO_UP_REF};

    if (1 != EVP_DigestSignInit(pkeySignCtx, nullptr, EVP_sha256(), NULL, *this) or
        1 != EVP_DigestSignUpdate(pkeySignCtx, message.data(), message.size()) or
        1 != EVP_DigestSignFinal(pkeySignCtx, NULL, &signatureLen))
        return ErrorCode::SIGNATURE_GENERATION_FAILED;

    std::vector<uint8_t> signature(signatureLen);
    if (1 != EVP_DigestSignFinal(pkeySignCtx, signature.data(), &signatureLen))
        return ErrorCode::SIGNATURE_GENERATION_FAILED;

    signature.resize(signatureLen);
    return signature;
}

Expect<std::string> PublicKey::writePublicKeyPEM() const
{
    return detail::writePEM<PEM_write_bio_PUBKEY>(this->pkey);
}

Expect<std::vector<uint8_t>> PublicKey::writePublicKeyDER() const
{
    return detail::i2dVector<i2d_PUBKEY>(this->pkey);
}

auto writePrivateKeyPEMWrap(BIO* b, EVP_PKEY* k) -> int
{
    return PEM_write_bio_PrivateKey(b, k, nullptr, nullptr, 0, nullptr, nullptr);
}

Expect<std::string> KeyPair::writePrivateKeyPEM() const
{
    return detail::writePEM<writePrivateKeyPEMWrap>(this->pkey);
}

Expect<std::vector<uint8_t>> KeyPair::writePrivateKeyDER() const
{
    return detail::i2dVector<i2d_PrivateKey>(this->pkey);
}

Expect<std::vector<uint8_t>> PublicKey::encrypt(std::span<uint8_t const> plainData,
                                                constants::RSAPaddingMode paddingMode) const
{
    // Check if key is not RSA key
    if (this->getType() != EVP_PKEY_RSA)
        return ErrorCode::INVALID_KEY_TYPE;

    OpenSSLRef pkeyCtx {EVP_PKEY_CTX_new(this->pkey, ENGINE_get_default_RSA()), NO_UP_REF};

    size_t outlen = 0;

    if (EVP_PKEY_encrypt_init(pkeyCtx) <= 0)
        return ErrorCode::ENCRYPTION_FAILED;

    switch (paddingMode)
    {
    case constants::RSAPaddingMode::NO_PADDING:
        {
            // size of plain data must be match with size of RSA key
            if (plainData.size() != this->getEncryptedSize())
                return ErrorCode::ENCRYPTION_FAILED;
            EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_NO_PADDING);
            break;
        }

    default: // default oaep padding
        {
            // Plain data cannot be bigger than the possible size for RSA
            if (plainData.size() > getEncryptedSize() - constants::RSA_PKCS1_OAEP_PADDING_SUBTRACTOR)
                return ErrorCode::PLAINTEXT_TOO_LARGE;
            EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_OAEP_PADDING);
            // MGF1 MD implicitly follows OAEP MD
            EVP_PKEY_CTX_set_rsa_oaep_md(pkeyCtx, EVP_sha256());
            break;
        }
    }

    if (EVP_PKEY_encrypt(pkeyCtx, nullptr, &outlen, plainData.data(), plainData.size()) != 1)
        return ErrorCode::ENCRYPTION_FAILED;

    std::vector<uint8_t> ret(outlen, 0);

    if (EVP_PKEY_encrypt(pkeyCtx, ret.data(), &outlen, plainData.data(), plainData.size()) != 1)
        return ErrorCode::ENCRYPTION_FAILED;

    return ret;
}

Expect<void> PublicKey::verify(std::span<uint8_t const> message, std::span<uint8_t const> signature) const
{
    OpenSSLRef pkeySignCtx {EVP_MD_CTX_new(), NO_UP_REF};

    if (1 != EVP_DigestVerifyInit(pkeySignCtx, NULL, EVP_sha256(), NULL, *this) or
        1 != EVP_DigestVerifyUpdate(pkeySignCtx, message.data(), message.size()) or
        1 != EVP_DigestVerifyFinal(pkeySignCtx, signature.data(), signature.size()))
        return ErrorCode::SIGNATURE_VERIFICATION_FAILED;

    return success;
}

AsymmetricKey::AsymmetricKey(AsymmetricKey&& that): pkey(std::move(that.pkey)) {}

AsymmetricKey::AsymmetricKey(AsymmetricKey const& that): pkey(that.pkey) {}

AsymmetricKey::~AsymmetricKey() {}

uint32_t AsymmetricKey::getBitSize() const
{
    // EVP_PKEY_bits() returns the cryptographic length of the cryptosystem to which the key in pkey belongs, in
    // bits. Note that the definition of cryptographic length is specific to the key cryptosystem.
    #if OPENSSL_VERSION_MAJOR == 3
        return EVP_PKEY_get_bits(this->pkey);
    #else
        return EVP_PKEY_bits(this->pkey);
    #endif
}

bool AsymmetricKey::operator==(AsymmetricKey const& that) const
{
    return EVP_PKEY_cmp(this->pkey, that.pkey) == 1;
}

KeyPair::KeyPair(OpenSSLRef<EVP_PKEY>&& ref): PublicKey(std::move(ref))
{
    // This must be checked that the EVP_PKEY is indeed a keypair, otherwise it is wrong
}

KeyPair::KeyPair(KeyPair&& that): PublicKey(std::move(that)) {}

KeyPair::KeyPair(KeyPair const& that): PublicKey(that) {}

PublicKey::PublicKey(PublicKey&& that): AsymmetricKey(std::move(that)) {}

PublicKey::PublicKey(PublicKey const& that): AsymmetricKey(that) {}

Expect<KeyPair> keygen::RSA(int keylength)
{
    OpenSSLRef evpPkeyCtx {EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), NO_UP_REF};

    if (evpPkeyCtx == nullptr)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    if (EVP_PKEY_keygen_init(evpPkeyCtx) <= 0)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(evpPkeyCtx, keylength) <= 0)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    // EVP_PKEY_CTX_set1_rsa_keygen_pubexp() sets the public exponent value for RSA key generation to the value stored
    // in pubexp. Currently it should be an odd integer. In accordance with the OpenSSL naming convention, the pubexp
    // pointer must be freed independently of the EVP_PKEY_CTX (ie, it is internally copied). If not specified 65537 is
    // used.

    // NOTE: Since the current keygen uses RSA_F4 (0x10001/65537), so we don't need to set that
    EVP_PKEY* generatedKey = nullptr;
    if (EVP_PKEY_keygen(evpPkeyCtx, &generatedKey) <= 0)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    return KeyPair {
        OpenSSLRef {generatedKey, NO_UP_REF}
    };
}

Expect<KeyPair> keygen::ECDSA()
{
    OpenSSLRef evpPkeyCtx {EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), NO_UP_REF};

    if (evpPkeyCtx == nullptr)
        return ErrorCode::EC_KEY_GENERATION_FAILED;

    if (EVP_PKEY_keygen_init(evpPkeyCtx) <= 0)
        return ErrorCode::EC_KEY_GENERATION_FAILED;

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evpPkeyCtx, NID_X9_62_prime256v1) <= 0)
        return ErrorCode::EC_KEY_GENERATION_FAILED;

    // EVP_PKEY_CTX_set_ec_paramgen_curve_nid() sets the EC curve for EC parameter generation to nid. For EC parameter
    // generation this macro must be called or an error occurs because there is no default curve. This function can also
    // be called to set the curve explicitly when generating an EC key.

    EVP_PKEY* generatedKey = nullptr;
    if (EVP_PKEY_keygen(evpPkeyCtx, &generatedKey) <= 0)
        return ErrorCode::EC_KEY_GENERATION_FAILED;

    return KeyPair {
        OpenSSLRef {generatedKey, NO_UP_REF}
    };
}

Expect<PublicKey> keygen::RSA(std::span<uint8_t const> modulusBin, std::span<uint8_t const> exponentBin)
{
    /**
     * Deprecated in openssl 3. (RSA_set0_key, EVP_PKEY_set1_RSA)
     * Should be change using `OSSL_DECODER_CTX_new_for_pkey` or `EVP_PKEY_fromdata`
     * Those function only available in openssl 3
     * https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_fromdata.html
     */
    /*
        // This is example for openssl 3, but not tested yet
        OSSL_PARAM params[] = {OSSL_PARAM_construct_BN("n", modulusBin.data(), modulusBin.size()),
                               OSSL_PARAM_construct_BN("e", exponentBin.data(), exponentBin.size())};

        OpenSSLRef ctx {EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL), NO_UP_REF};
        if (ctx == nullptr)
            return ErrorCode::RSA_KEY_GENERATION_FAILED;

        EVP_PKEY* pkeyPtr = NULL;

        if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
            EVP_PKEY_fromdata(ctx, &pkeyPtr, EVP_PKEY_PUBLIC_KEY, params) <= 0)
            return ErrorCode::RSA_KEY_GENERATION_FAILED;

        OpenSSLRef pkey {pkeyPtr, NO_UP_REF};
        return PublicKey {std::move(evpPkey)};
    */

    OpenSSLRef rsa {RSA_new(), NO_UP_REF};
    if (rsa == nullptr)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    OpenSSLRef modulusBigNum {BN_bin2bn(modulusBin.data(), modulusBin.size(), nullptr)};
    if (modulusBigNum == nullptr)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    OpenSSLRef exponentBigNum {BN_bin2bn(exponentBin.data(), exponentBin.size(), nullptr)};
    if (exponentBigNum == nullptr)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    OpenSSLRef evpPkey {EVP_PKEY_new(), NO_UP_REF};
    if (evpPkey == nullptr)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    // Deprecated
    if (RSA_set0_key(rsa, modulusBigNum.transferOwnership(), exponentBigNum.transferOwnership(), nullptr) != 1)
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    // Deprecated
    if (!EVP_PKEY_set1_RSA(evpPkey, rsa))
        return ErrorCode::RSA_KEY_GENERATION_FAILED;

    return PublicKey {std::move(evpPkey)};
}
