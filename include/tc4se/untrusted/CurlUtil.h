#pragma once

#ifndef SGKMS_CORE_UNTRUSTED_CURLUTIL_H
#define SGKMS_CORE_UNTRUSTED_CURLUTIL_H

#include <cstdint>
#include <span>
#include <string_view>

#include <tc4se/ErrorCode.h>

namespace tc4se
{
    class HTTPPayload
    {
        friend struct ParserVTable;

      public:
        enum Method
        {
            METHOD_UNKNOWN = 0,
            METHOD_GET     = 1,
            METHOD_POST    = 2,
        };

        enum PayloadType
        {
            PAYLOAD_REQUEST  = 1,
            PAYLOAD_RESPONSE = 2
        };

      private:
        std::vector<uint8_t> rawPayload;

        std::string_view bodyRef;
        std::string_view urlRef;
        std::unordered_map<std::string_view, std::string_view> headersMaps;

        std::string_view headerKeyTemp;
        std::string_view headerValueTemp;

        uint64_t contentLength;
        Method method {METHOD_UNKNOWN};
        PayloadType payloadType;

        HTTPPayload(std::vector<uint8_t>&& rawPayload): rawPayload(std::move(rawPayload)) {}

      public:
        HTTPPayload(HTTPPayload&&);
        HTTPPayload& operator=(HTTPPayload&&);
        HTTPPayload(HTTPPayload const&) = delete;
        ~HTTPPayload();

        static Expect<HTTPPayload> parse(std::vector<uint8_t>&& rawRequest);
        Expect<void> feed(std::vector<uint8_t>&& incomingPayload);
        Expect<std::string_view> getHeader(std::string_view field);

        uint64_t getContentLength() const
        {
            return contentLength;
        }

        std::string_view getPath() const
        {
            return urlRef;
        }

        std::string_view getBody() const
        {
            return bodyRef;
        }

        Method getMethod() const
        {
            return method;
        }

        PayloadType getPayloadType() const
        {
            return payloadType;
        }
    };

    Expect<HTTPPayload> sendCurlRequest(std::string_view completeUrl, std::span<std::string const> headerListVec = {},
                                        std::string_view postFields = {});

    Expect<std::string> urlDecode(std::string_view const encodedData);
} // namespace tc4se

#endif
