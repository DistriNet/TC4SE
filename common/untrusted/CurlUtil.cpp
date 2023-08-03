#include <memory>
#include <vector>

#include <curl/curl.h>
#include <llhttp.h>
#include <boost/outcome/success_failure.hpp>

//#include <tc4se/Definitions.h>
#include <tc4se/untrusted/CurlUtil.h>

using namespace tc4se;

// clang-format off
using CURL_ptr       = std::unique_ptr<CURL, decltype([](auto x) { curl_easy_cleanup(x); })>;
using curl_slist_ptr = std::unique_ptr<curl_slist, decltype([](auto x) { curl_slist_free_all(x); })>;
using curl_char_ptr  = std::unique_ptr<char, decltype([](auto x) { curl_free(x); })>;
// clang-format on

template<typename T>
size_t writeMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    size_t realsize {size * nmemb};
    T& mem {*reinterpret_cast<T*>(userp)};
    mem.reserve(realsize);
    std::copy_n(reinterpret_cast<uint8_t*>(contents), realsize, std::back_inserter(mem));

    return realsize;
}

Expect<HTTPPayload> tc4se::sendCurlRequest(std::string_view completeUrl,
                                                            std::span<std::string const> headerListVec,
                                                            std::string_view postFields)
{
    CURL_ptr curlPtr {curl_easy_init()};
    decltype(auto) curl {curlPtr.get()};
    if (!curl)
        return ErrorCode::CURL_INIT_FAILED;

    curl_slist_ptr headerListPtr {curl_slist_append(nullptr, "")};
    decltype(auto) headerList {headerListPtr.get()};

    curl_easy_setopt(curl, CURLOPT_URL, completeUrl.data());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                     CURL_HTTP_VERSION_1_1); // Our HTTP parser does not support beyond HTTP 1.1

    for (decltype(auto) header: headerListVec)
        headerList = curl_slist_append(headerList, header.data());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);

    if (!postFields.empty())
    {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postFields.size());
    }

    std::vector<uint8_t> body;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeMemoryCallback<std::vector<uint8_t>>);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

    CURLcode code {curl_easy_perform(curl)};
    if (code != CURLE_OK)
        return ErrorCode::INVALID_CONNECTION;

    BOOST_OUTCOME_TRY(auto httpPayload, HTTPPayload::parse(std::move(body)));

    return httpPayload;
}

Expect<std::string> tc4se::urlDecode(std::string_view const encodedData)
{
    CURL_ptr curlPtr {curl_easy_init()};
    if (!curlPtr)
        return ErrorCode::CURL_INIT_FAILED;

    int decodedLen;
    curl_char_ptr decodedData {curl_easy_unescape(curlPtr.get(), encodedData.data(), encodedData.size(), &decodedLen)};

    // Copy to std::string so we can free the the pointer using curl_free;
    return std::string {decodedData.get(), static_cast<size_t>(decodedLen)};
}




namespace tc4se
{
    struct ParserVTable
    {
        template<std::string_view HTTPPayload::*field>
        static int dataCallback(llhttp_t* parser, const char* at, size_t length)
        {
            auto request    = static_cast<HTTPPayload*>(parser->data);
            request->*field = std::string_view {at, length};
            return 0;
        }

        static constexpr llhttp_settings_t llhttpVtable {.on_url          = dataCallback<&HTTPPayload::urlRef>,
                                                         .on_header_field = dataCallback<&HTTPPayload::headerKeyTemp>,
                                                         .on_header_value = dataCallback<&HTTPPayload::headerValueTemp>,
                                                         .on_body         = dataCallback<&HTTPPayload::bodyRef>,
                                                         .on_header_value_complete = [](llhttp_t* parser)
                                                         {
                                                             auto request = static_cast<HTTPPayload*>(parser->data);
                                                             request->headersMaps.emplace(request->headerKeyTemp,
                                                                                          request->headerValueTemp);
                                                             if (parser->content_length)
                                                                 request->contentLength = parser->content_length;
                                                             return 0;
                                                         }};
    };
} // namespace sgkms::core

HTTPPayload::HTTPPayload(HTTPPayload&& that):
    rawPayload(std::move(that.rawPayload)), bodyRef(that.bodyRef), urlRef(that.urlRef),
    headersMaps(std::move(that.headersMaps)), contentLength(that.contentLength), method(that.method),
    payloadType(that.payloadType)
{
}

HTTPPayload& HTTPPayload::operator=(HTTPPayload&& other)
{
    if (this != &other)
    {
        this->rawPayload    = std::move(other.rawPayload);
        this->bodyRef       = other.bodyRef;
        this->urlRef        = other.urlRef;
        this->headersMaps   = std::move(other.headersMaps);
        this->contentLength = other.contentLength;
        this->method        = other.method;
        this->payloadType   = other.payloadType;
    }

    return *this;
}

Expect<HTTPPayload> HTTPPayload::parse(std::vector<uint8_t>&& rawRequest)
{
    llhttp_t parser;
    llhttp_init(&parser, HTTP_BOTH, &ParserVTable::llhttpVtable);

    HTTPPayload res {std::move(rawRequest)};
    parser.data = &res;

    auto err    = llhttp_execute(&parser, reinterpret_cast<char const*>(res.rawPayload.data()), res.rawPayload.size());

    if (err != HPE_OK)
        return ErrorCode::HTTP_PARSING_ERROR;

    if (parser.type == HTTP_REQUEST)
    {
        res.payloadType = HTTPPayload::PAYLOAD_REQUEST;
        switch (parser.method)
        {
        case HTTP_GET:
            res.method = HTTPPayload::METHOD_GET;
            break;
        case HTTP_POST:
            res.method = HTTPPayload::METHOD_POST;
            break;
        }
    }
    else
    {
        res.payloadType = HTTPPayload::PAYLOAD_RESPONSE;
    }

    // if (res.parser->method != to_underlying(llhttp_method_t::HTTP_POST))
    //     return ErrorCode::HTTP_METHOD_NOT_ALLOWED;

    // Trim last slash
    res.urlRef = {res.urlRef.begin(), res.urlRef.find_last_not_of('/') + 1};

    return res;
}

Expect<void> HTTPPayload::feed(std::vector<uint8_t>&& incomingPayload)
{
    std::move(incomingPayload.begin(), incomingPayload.end(), std::back_inserter(this->rawPayload));
    BOOST_OUTCOME_TRY(*this, HTTPPayload::parse(std::move(this->rawPayload)));
    return success;
}

Expect<std::string_view> HTTPPayload::getHeader(std::string_view field)
{
    auto it = this->headersMaps.find(field);
    if (it == this->headersMaps.end())
        return ErrorCode::HTTP_HEADER_NOT_FOUND;
    return it->second;
}

HTTPPayload::~HTTPPayload() {};

#ifdef TC_TRUSTED_BUILD
// llhttp shim symbol
extern "C"
{
    uint32_t stderr {0};
    uint32_t fprintf(...)
    {
        return 0;
    }
}
#endif
