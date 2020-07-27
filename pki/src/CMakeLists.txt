
# add the executable
add_library(cryptablepki
        OpenSSLInit.cpp OpenSSLInit.h
        OpenSSLCA.cpp OpenSSLCA.h
        OpenSSLCertificate.cpp OpenSSLCertificate.h
        OpenSSLCertificateRequest.cpp OpenSSLCertificateRequest.h
        OpenSSLException.h
        OpenSSLX509Name.cpp OpenSSLX509Name.h)

target_include_directories(cryptablepki PUBLIC "${PROJECT_BINARY_DIR}")
