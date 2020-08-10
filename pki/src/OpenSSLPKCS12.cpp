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

OpenSSLPKCS12::OpenSSLPKCS12(const OpenSSLCertificate &certificate,
                             const OpenSSLCertificate &openSslca,
                             const OpenSSLKey &openSslKey,
                             const std::string &password) :
                             certificate(certificate),
                             keyPair(openSslKey),
                             pkcs12{nullptr} {
    caCertificates.push_back(openSslca);

    STACK_OF(X509) *x509cas = sk_X509_new_null();
    int status = sk_X509_push(x509cas, const_cast<X509 *>(openSslca.getX509()));
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
    int decodeLg = i2d_PKCS12_bio(bioMem, pkcs12);
    if (decodeLg <= 0) {
        throw OpenSSLException(ERR_get_error());
    }
    unsigned char *p12Data;
    size_t p12DataLg = BIO_get_mem_data(bioMem, &p12Data);
    return std::move(std::vector<unsigned char>(p12Data, p12Data + p12DataLg));
}

OpenSSLPKCS12::OpenSSLPKCS12(const char *pkcs12Buf, size_t pkcs12BufLg, const std::string &password) : pkcs12{nullptr} {
    BIO *bioMem = BIO_new_mem_buf(pkcs12Buf, pkcs12BufLg);

    if (d2i_PKCS12_bio(bioMem, &pkcs12) == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
    EVP_PKEY *evpPkey = nullptr;
    X509 *x509cert = nullptr;
    STACK_OF(X509) *cas = nullptr;
    if (!PKCS12_parse(pkcs12,
                      password.c_str(),
                      &evpPkey,
                      &x509cert,
                      &cas)) {
        throw OpenSSLException(ERR_get_error());
    }
    certificate = OpenSSLCertificate(x509cert);
    keyPair = OpenSSLKey(evpPkey);
    if (cas != NULL) {
        X509 *tmpCA = sk_X509_pop(cas);
        while (tmpCA) {
            caCertificates.push_back(OpenSSLCertificate(tmpCA));
            tmpCA = sk_X509_pop(cas);
        }
    }

    sk_X509_free(cas);
    X509_free(x509cert);
    EVP_PKEY_free(evpPkey);
    BIO_free(bioMem);
}

const OpenSSLCertificate & OpenSSLPKCS12::getCertificate() const {
    return certificate;
}

const std::vector<OpenSSLCertificate> & OpenSSLPKCS12::getCAs() const {
    return caCertificates;
}

const OpenSSLKey & OpenSSLPKCS12::getPrivateKey() const {
    return keyPair;
}

OpenSSLPKCS12::~OpenSSLPKCS12() {
    PKCS12_free(pkcs12);
}