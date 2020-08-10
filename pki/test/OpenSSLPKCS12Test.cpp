/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 09/08/2020
 */
#include <catch2/catch.hpp>
#include "OpenSSLPKCS12.h"
#include "OpenSSLCA.h"
#include "OpenSSLCertificate.h"
#include "OpenSSLCertificateRequest.h"

TEST_CASE( "OpenSSLPKCS12Tests", "[success]" ) {

    SECTION( "Generate a PKCS12" ) {
        // Arrange
        OpenSSLCertificateRequest openSslCertificateRequest(std::string("/CN=John Doe/O=Company/C=US"), 2048);
        OpenSSLCA openSslca("/CN=Root CA/O=Company/C=US",4096);
        auto certificate = openSslca.certify(openSslCertificateRequest);

        // Act
        OpenSSLPKCS12 openSslpkcs12(*(certificate.get()),
                                    openSslca.getCertificate(),
                                    openSslCertificateRequest.getKeyPair(),
                                    "system");
        auto pkcs12 = openSslpkcs12.getPKCS12();

        // Assert
        REQUIRE( pkcs12.size() > 0 );
    }

    SECTION( "Generate a PKCS12 object from P12 file" ) {
        // Arrange
        OpenSSLCertificateRequest openSslCertificateRequest(std::string("/CN=John Doe/O=Company/C=US"), 2048);
        OpenSSLCA openSslca("/CN=Root CA/O=Company/C=US",4096);
        auto certificate = openSslca.certify(openSslCertificateRequest);
        OpenSSLPKCS12 openSslpkcs12(*(certificate.get()),
                                    openSslca.getCertificate(),
                                    openSslCertificateRequest.getKeyPair(),
                                    "system");
        auto pkcs12 = openSslpkcs12.getPKCS12();

        // Act
        OpenSSLPKCS12 openSslpkcs121(reinterpret_cast<const char *>(pkcs12.data()), pkcs12.size(), "system");

        // Assert
        REQUIRE( openSslpkcs121.getCertificate().getCommonName() == "John Doe" );
        REQUIRE( openSslpkcs121.getCAs()[0].getCommonName() == "Root CA" );
        REQUIRE( openSslpkcs121.getPrivateKey().getKeyBitlength() == 2048 );
    }

}
