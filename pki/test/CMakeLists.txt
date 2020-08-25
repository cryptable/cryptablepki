include_directories (${TEST_SOURCE_DIR}/src)

add_executable (tests main.cpp
        OpenSSLCATest.cpp
        OpenSSLCertificateRequestTest.cpp OpenSSLPKCS12Test.cpp OpenSSLKeyTest.cpp OpenSSLCertificateTest.cpp OpenSSLRSASigningTest.cpp)

target_link_libraries(tests
        ${LIBRARY_NAME}
        ${OPENSSL_CRYPTO_LIBRARIES}
        ${OPENSSL_SSL_LIBRARY}
        ${WINDOWS_LIBS}
        ${CONAN_LIBS})

enable_testing()
add_test(testing tests)