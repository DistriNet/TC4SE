# TC4SE: Trusted Channel for Secure Enclave

Anonymized source code for the paper submission: **TC4SE: A High-performance Trusted Channel Mechanism for Secure Enclave-based Trusted Execution Environments**

## Requirements
- Intel SGX SDK
- Clang with C++20 (Note: be careful of using more modern Clang >= 14 as it may have a minor quirks with recent SGX SDK)
- Intel SGX SSL (Note: compile the libssl as well, or use the `support_tls` branch, you can use either OpenSSL 1.1.1 or 3.0)
- LibCURL development
- SGX Runtime (PSW and DCAP library installed)
- Git and CMake