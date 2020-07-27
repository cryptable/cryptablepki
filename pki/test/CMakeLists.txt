include_directories (${TEST_SOURCE_DIR}/src)

add_executable (tests main.cpp
        OpenSSLCATest.cpp
        OpenSSLCertificateRequestTest.cpp)

target_link_libraries(tests cryptablepki ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})

enable_testing()
add_test(testing tests)