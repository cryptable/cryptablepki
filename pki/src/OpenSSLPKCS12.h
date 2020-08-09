/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 09/08/2020
 */
#ifndef CRYPTABLEPKI_OPENSSLPKCS12_H
#define CRYPTABLEPKI_OPENSSLPKCS12_H

#include <openssl/pkcs12.h>
#include <vector>
#include "OpenSSLCertificate.h"
#include "OpenSSLKey.h"
#include "OpenSSLCA.h"

/**
 * Class to support of PKCS12 files
 */
class OpenSSLPKCS12 {
public:
    /**
     * Create a PKCS12 structure
     * @param certificate
     * @param openSslca
     * @param openSslKey
     * @param password
     */
    OpenSSLPKCS12(OpenSSLCertificate &certificate,
                  OpenSSLCA &openSslca,
                  OpenSSLKey &openSslKey,
                  const std::string &password);

    std::vector<unsigned char> getPKCS12();

    ~OpenSSLPKCS12();

private:
    PKCS12 *pkcs12;
};


#endif //CRYPTABLEPKI_OPENSSLPKCS12_H
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
