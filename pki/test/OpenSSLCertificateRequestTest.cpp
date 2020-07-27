/*
 * MIT License
 * Author: David Tillemans
 */
#include <catch2/catch.hpp>
#include "OpenSSLCertificateRequest.h"

TEST_CASE( "OpenSSLCertificateRequest Tests", "[success]" ) {

    SECTION( "Generate a Request" ) {
        // Arrange
        std::string dname = "/CN=John Doe/O=Company/C=US";

        // Act
        OpenSSLCertificateRequest openSslCertificateRequest(dname, 2048);

        // Assert
        REQUIRE(openSslCertificateRequest.verify());
    }
}

