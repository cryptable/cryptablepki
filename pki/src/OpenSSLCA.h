/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 20/07/2020
 */
#ifndef OPENSSLCA_H
#define OPENSSLCA_H
#include <string>
#include "OpenSSLCertificate.h"
#include "OpenSSLCertificateRequest.h"
#include "OpenSSLKey.h"

/**
 * The Certification Authority class. This will function as your Certification Authority.
 */
class OpenSSLCA {

public:
    /**
     * Create a selfsigned RSA Root Certification Authority
     * @param rootName
     * @param bitLength
     */
    OpenSSLCA(const std::string &rootName, int bitLength);

    /**
     * Certify a certificate request object to a Certificate. The certification request andcertificate class contains
     * all the conversion function (DER, PEM, ...)
     * @param certificateRequest a certificate request object
     * @return a certificate as an OpenSSLCertificate object
     */
    std::unique_ptr<OpenSSLCertificate> certify(const OpenSSLCertificateRequest *certificateRequest);

    /**
     * Get the Certification Authority certificate of the object
     * @return a certificate as an OpenSSLCertificate object
     */
    const OpenSSLCertificate *getCertificate();

    /**
     * Destructor freeing the OpenSSL structures
     */
    ~OpenSSLCA();

private:

    OpenSSLKey keyPair;

    std::unique_ptr<OpenSSLCertificate> caCertificate;

    long serialNumber;
};


#endif //KSMGMNT_OPENSSLCA_H
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
