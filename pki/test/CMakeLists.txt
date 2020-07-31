include_directories (${TEST_SOURCE_DIR}/src)

add_executable (tests main.cpp
        OpenSSLCATest.cpp
        OpenSSLCertificateRequestTest.cpp)

# set_target_properties(tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${COMMON_DIR}/bin )
target_link_libraries(tests cryptablepki ${OPENSSL_CRYPTO_LIBRARIES} ${OPENSSL_SSL_LIBRARY})

enable_testing()
add_test(testing tests)