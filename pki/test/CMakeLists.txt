include_directories (${TEST_SOURCE_DIR}/src)

add_executable (tests main.cpp
        OpenSSLCATest.cpp
        OpenSSLCertificateRequestTest.cpp)

# set_target_properties(tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${COMMON_DIR}/bin )
target_link_libraries(tests ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} cryptablepki)

enable_testing()
add_test(testing tests)