/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 09/08/2020
 */
#include <openssl/err.h>
#include <openssl/bio.h>
#include "OpenSSLPKCS12.h"
#include "OpenSSLException.h"

OpenSSLPKCS12::OpenSSLPKCS12(OpenSSLCertificate &certificate,
                             OpenSSLCA &openSslca,
                             OpenSSLKey &openSslKey,
                             const std::string &password) {
    STACK_OF(X509) *x509cas = sk_X509_new_null();
    int status = sk_X509_push(x509cas, const_cast<X509 *>(openSslca.getCertificate()->getX509()));
    if (status == 0) {
        throw OpenSSLException(ERR_get_error());
    }
    pkcs12 = PKCS12_create(password.c_str(),
                           certificate.getCommonName().c_str(),
                           const_cast<EVP_PKEY *>(openSslKey.getKeyPair()),
                           const_cast<X509 *>(certificate.getX509()),
                           x509cas,
                           0, 0, 0, 0, 0);
    if (pkcs12 == nullptr) {
        throw OpenSSLException(ERR_get_error());
    }
    sk_X509_free(x509cas);
}

std::vector<unsigned char> OpenSSLPKCS12::getPKCS12() {
    BIO *bioMem = BIO_new(BIO_s_mem());
    int status = i2d_PKCS12_bio(bioMem, pkcs12);
    if (status <= 0) {
        throw OpenSSLException(ERR_get_error());
    }
    unsigned char *p12Data;
    size_t p12DataLg = BIO_get_mem_data(bioMem, &p12Data);
    return std::move(std::vector<unsigned char>(p12Data, p12Data + p12DataLg));
}

OpenSSLPKCS12::~OpenSSLPKCS12() {
    PKCS12_free(pkcs12);
}