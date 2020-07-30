include_directories (${TEST_SOURCE_DIR}/src)

add_executable (tests main.cpp
        OpenSSLCATest.cpp
        OpenSSLCertificateRequestTest.cpp)

# set_target_properties(tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${COMMON_DIR}/bin )
target_link_libraries(tests ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} cryptablepki)

add_custom_command(TARGET tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${COMMON_DIR}/bin/libssl-1_1-x64.dll"
        $<TARGET_FILE_DIR:tests>)
add_custom_command(TARGET tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${COMMON_DIR}/bin/libcrypto-1_1-x64.dll"
        $<TARGET_FILE_DIR:tests>)

enable_testing()
add_test(testing tests)