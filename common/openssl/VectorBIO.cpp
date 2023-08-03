#include <openssl/bio.h>

#include <tc4se/ErrorCode.h>
#include <tc4se/OpenSSL.h>

using namespace tc4se;
using namespace tc4se::openssl;
using namespace tc4se::openssl::detail;

Expect<OpenSSLRef<BIO>> openssl::stringToBio(std::string_view str)
{
    if (str.empty())
        return ErrorCode::UNREACHABLE;

    return OpenSSLRef {BIO_new_mem_buf(str.data(), str.length()), NoUpRefTag {}};
}

VectorBIO::VectorBIO()
{
    // Instantiate BIO
    bio = OpenSSLRef {BIO_new(getVectorBIOMethod()), NO_UP_REF};
    BIO_set_data(bio, this);
    BIO_set_init(bio, 1);
}

BIO_METHOD* VectorBIO::getVectorBIOMethod()
{
    static BIO_METHOD* bioMethodHandle = nullptr;

    if (bioMethodHandle != nullptr)
        return bioMethodHandle;

    bioMethodHandle = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "TC4SEVectorBIO");

    BIO_meth_set_create(bioMethodHandle,
                        [](BIO*) -> int
                        {
                            return 1;
                        });

    BIO_meth_set_write_ex(bioMethodHandle,
                          [](BIO* bio, const char* a, size_t b, size_t* c) -> int
                          {
                              return reinterpret_cast<VectorBIO*>(BIO_get_data(bio))->write(a, b, c);
                          });

    return bioMethodHandle;
}

int VectorBIO::write(char const* data, size_t len, size_t* written)
{
    auto lastPos = buffer.size();
    buffer.resize(lastPos + len);
    std::copy_n(data, len, buffer.begin() + lastPos);
    *written = len;
    return 1;
}

std::vector<uint8_t>&& VectorBIO::getData()
{
    return std::move(buffer);
}

StringBIO::StringBIO()
{
    // Instantiate BIO
    bio = OpenSSLRef {BIO_new(getStringBIOMethod()), NO_UP_REF};
    BIO_set_data(bio, this);
    BIO_set_init(bio, 1);
}

BIO_METHOD* StringBIO::getStringBIOMethod()
{
    static BIO_METHOD* bioMethodHandle = nullptr;

    if (bioMethodHandle != nullptr)
        return bioMethodHandle;

    bioMethodHandle = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "TC4SEStringBIO");

    BIO_meth_set_create(bioMethodHandle,
                        [](BIO*) -> int
                        {
                            return 1;
                        });

    BIO_meth_set_write_ex(bioMethodHandle,
                          [](BIO* bio, const char* a, size_t b, size_t* c) -> int
                          {
                              return reinterpret_cast<StringBIO*>(BIO_get_data(bio))->write(a, b, c);
                          });

    return bioMethodHandle;
}

int StringBIO::write(char const* data, size_t len, size_t* written)
{
    auto lastPos = buffer.size();
    buffer.resize(lastPos + len);
    std::copy_n(data, len, buffer.begin() + lastPos);
    *written = len;
    return 1;
}

std::string&& StringBIO::getData()
{
    return std::move(buffer);
}