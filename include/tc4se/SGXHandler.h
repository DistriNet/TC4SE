#ifndef SGXHANDLER_H
#define SGXHANDLER_H

#include <functional>
#include <string_view>
#include <stdexcept>
#include <sgx_urts.h>
#include <iostream>
#include <fmt/format.h>

namespace tc4se::sgx
{
    template<typename TFunc> struct EnclaveFuncTrait;

    template<typename TFirst, typename... TArgs>
    struct EnclaveFuncTrait<sgx_status_t (*)(sgx_enclave_id_t, TFirst, TArgs...)>
    {
        using FirstParam              = TFirst;
        static constexpr size_t arity = sizeof...(TArgs) + 1;
    };

    template<> struct EnclaveFuncTrait<sgx_status_t (*)(sgx_enclave_id_t)>
    {
        using FirstParam              = void;
        static constexpr size_t arity = 0;
    };

    class EnclaveHandler
    {
      private:
        sgx_enclave_id_t enclaveId;

      public:
        EnclaveHandler(std::string_view enclaveName, int debug = SGX_DEBUG_FLAG)
        {
            uint32_t ret {};
            ret = sgx_create_enclave(enclaveName.data(), debug, nullptr, nullptr, &enclaveId, nullptr);
            if (ret != SGX_SUCCESS)
                throw std::runtime_error("Failed initializing enclave");
        }

        ~EnclaveHandler()
        {
            sgx_destroy_enclave(enclaveId);
        }

        operator sgx_enclave_id_t() const
        {
            return enclaveId;
        }

        template<auto func, typename... TArgs> auto ecall(TArgs&&... args)
        {
            using FuncTrait = EnclaveFuncTrait<decltype(func)>;

            if constexpr (FuncTrait::arity == sizeof...(TArgs))
            {
                // This case, the function pointer argument has the same with supplied
                // therefore, this ecall function returns void and just pass all args
                sgx_status_t status = std::invoke(func, enclaveId, std::forward<TArgs>(args)...);

                if (status != SGX_SUCCESS)
                    throw std::runtime_error(fmt::format("Unexpected enclave error: {}", (uint64_t) status));

                return;
            }
            else if constexpr (FuncTrait::arity == sizeof...(TArgs) + 1)
            {
                // This case, the caller supplies less one argument than the actual ecall signature
                // therefore, we check if it returns a pointer or not. If it is, then it must be
                // a return value
                static_assert(std::is_pointer_v<typename FuncTrait::FirstParam>);

                std::remove_pointer_t<typename FuncTrait::FirstParam> ret {};
                sgx_status_t status = std::invoke(func, enclaveId, &ret, std::forward<TArgs>(args)...);

                if (status != SGX_SUCCESS)
                    throw std::runtime_error(fmt::format("Unexpected enclave error: {}", (uint64_t) status));

                return ret;
            }
            else
            {
                static_assert(FuncTrait::arity > sizeof...(TArgs), "Wrong parameter");
            }
        }
    };
} // namespace tc4se::sgx

#endif