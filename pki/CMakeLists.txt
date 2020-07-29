cmake_minimum_required(VERSION 3.8)
project(cryptablepki VERSION 0.1)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(not DEFINED COMMON_DIR)
    set(COMMON_DIR "${CMAKE_SOURCE_DIR}/../common")
endif(not COMMON_DIR)

SET(OPENSSL_ROOT_DIR ${COMMON_DIR})
find_package(OpenSSL)
if(OPENSSL_FOUND)
    MESSAGE("Openssl Version: ${OPENSSL_VERSION}")
    MESSAGE("Openssl Include: ${OPENSSL_INCLUDE_DIR}")
    MESSAGE("Openssl Crypto library: ${OPENSSL_CRYPTO_LIBRARY}")
    MESSAGE("Openssl SSL library: ${OPENSSL_SSL_LIBRARY}")
    MESSAGE("Openssl Crypto libraries: ${OPENSSL_SSL_LIBRARIES}")
    MESSAGE("Openssl APPLINK SOURCES: ${OPENSSL_APPLINK_SOURCE}")
endif(OPENSSL_FOUND)

include_directories(include src ${COMMON_DIR}/include)

add_subdirectory(src)
add_subdirectory(test)