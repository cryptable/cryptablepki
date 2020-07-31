include_directories (${TEST_SOURCE_DIR}/src)

add_executable (tests main.cpp
        OpenSSLCATest.cpp
        OpenSSLCertificateRequestTest.cpp)

# set_target_properties(tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${COMMON_DIR}/bin )
if(WIN32 OR APPLE)
    target_link_libraries(tests cryptablepki ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
else(WIN32 OR APPLE)
    target_link_libraries(tests cryptablepki ${OPENSSL_APPLINK_SOURCE})
endif(WIN32 OR APPLE)

enable_testing()
add_test(testing tests)