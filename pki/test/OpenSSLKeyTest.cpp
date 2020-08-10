/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 09/08/2020
 */

#include <openssl/evp.h>
#include "catch2/catch.hpp"
#include "OpenSSLKey.h"

TEST_CASE( "OpenSSLKeyTests", "[success]" ) {

    SECTION( "Generate a Key" ) {
        // Arrange

        // Act
        OpenSSLKey openSslKey;

        // Assert
        REQUIRE(openSslKey.getKeyPair() != nullptr);
        REQUIRE( EVP_PKEY_bits(openSslKey.getKeyPair()) == 2048 );
    }

    SECTION( "Generate a key with fixed key size" ) {
        // Arrange

        // Act
        OpenSSLKey openSslKey(4096);

        // Assert
        REQUIRE(openSslKey.getKeyPair() != nullptr);
        REQUIRE(EVP_PKEY_bits(openSslKey.getKeyPair()) == 4096);
    }
}
