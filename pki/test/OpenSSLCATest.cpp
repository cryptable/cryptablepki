/*
 * MIT License
 * Author: David Tillemans
 */
#include <catch2/catch.hpp>
#include <iostream>
#include "OpenSSLCA.h"
using Catch::Matchers::Message;

TEST_CASE( "OpenSSLCATests", "[success]" ) {

    SECTION( "Generate a CA" ) {
        // Arrange
		std::string dname = "/CN=Root CA/O=Company/C=US";

		// Act
        OpenSSLCA openSslca(dname, 2048);

	    // Assert
        REQUIRE(openSslca.getCertificate().verify(openSslca.getCertificate()));
    }

    SECTION( "Sign Certificate Request" ) {
        // Arrange
        std::string dname = "/CN=Root CA/O=Company/C=US";
        OpenSSLCA openSslca(dname, 2048);
        std::string dname_req = "/CN=John Doe/O=Company/C=US";
        OpenSSLCertificateRequest openSslCertificateRequest(dname_req, 2048);

        // Act
        auto certificate = openSslca.certify(openSslCertificateRequest);

        // Assert
        REQUIRE(certificate->verify(openSslca.getCertificate()));
//        std::cout << certificate->getPEM();
    }
}

TEST_CASE( "Failed GeneralNameTests", "[failed]" ) {

    SECTION( "Generate a GeneralName which throws" ) {
        // Arrange

        // Act && Assert

    }
}