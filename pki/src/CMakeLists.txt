
# add the executable
add_library(${LIBRARY_NAME} STATIC
        OpenSSLInit.cpp OpenSSLInit.h
        OpenSSLCA.cpp OpenSSLCA.h
        OpenSSLCertificate.cpp OpenSSLCertificate.h
        OpenSSLCertificateRequest.cpp OpenSSLCertificateRequest.h
        OpenSSLException.h
        OpenSSLX509Name.cpp OpenSSLX509Name.h
        OpenSSLPKCS12.cpp OpenSSLPKCS12.h
        OpenSSLKey.cpp OpenSSLKey.h)

target_include_directories(${LIBRARY_NAME} PUBLIC "${PROJECT_BINARY_DIR}")

install(TARGETS ${LIBRARY_NAME}
        LIBRARY
            DESTINATION lib)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
        COMPONENT devel
        DESTINATION include
        FILES_MATCHING PATTERN "*.h")

# Use --prefix /path/to/install from 3.15 to install the headers