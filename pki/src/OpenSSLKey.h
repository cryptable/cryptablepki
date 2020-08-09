/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 09/08/2020
 */
#ifndef CRYPTABLEPKI_OPENSSLKEY_H
#define CRYPTABLEPKI_OPENSSLKEY_H


#include <openssl/ossl_typ.h>

/**
 * EVP_KEY wrapper
 */
class OpenSSLKey {

public:
    /**
     * default constructor, which creates a 2048 bit RSA key
     */
    OpenSSLKey();

    /**
     * Constructor where you can define the RSA bit length
     * @param keyBitLength
     */
    OpenSSLKey(size_t keyBitLength);

    /**
     * Get the key pair pointer
     * @return
     */
    const EVP_PKEY *getKeyPair();

    /**
     * Destructor
     */
    ~OpenSSLKey();

private:
    EVP_PKEY *keyPair;

    size_t bitLength;
};


#endif //CRYPTABLEPKI_OPENSSLKEY_H
/**********************************************************************************/
/* MIT License                                                                    */
/*                                                                                */
/* Copyright (c) 2020 Cryptable BV */
/*                                                                                */
/* Permission is hereby granted, free of charge, to any person obtaining a copy   */
/* of this software and associated documentation files (the "Software"), to deal  */
/* in the Software without restriction, including without limitation the rights   */
/* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      */
/* copies of the Software, and to permit persons to whom the Software is          */
/* furnished to do so, subject to the following conditions:                       */
/*                                                                                */
/* The above copyright notice and this permission notice shall be included in all */
/* copies or substantial portions of the Software.                                */
/*                                                                                */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     */
/* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       */
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    */
/* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         */
/* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  */
/* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  */
/* SOFTWARE.                                                                      */
/**********************************************************************************/