
# add the executable
add_library(cryptablepki
        OpenSSLInit.cpp OpenSSLInit.h
        OpenSSLCA.cpp OpenSSLCA.h
        OpenSSLCertificate.cpp OpenSSLCertificate.h
        OpenSSLCertificateRequest.cpp OpenSSLCertificateRequest.h
        OpenSSLException.h
        OpenSSLX509Name.cpp OpenSSLX509Name.h)

target_include_directories(cryptablepki PUBLIC "${PROJECT_BINARY_DIR}")

install(TARGETS cryptablepki
        LIBRARY
            DESTINATION lib)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
        COMPONENT devel
        DESTINATION include
        FILES_MATCHING PATTERN "*.h")

# Use --prefix /path/to/install from 3.15 to install the headers