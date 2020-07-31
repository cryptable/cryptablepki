/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 20/07/2020
 */

#include <openssl/err.h>
#include <openssl/pem.h>
#include "OpenSSLCertificate.h"
#include "OpenSSLException.h"

OpenSSLCertificate::OpenSSLCertificate() {
    // TODO: create Selfsigned certificate
}

OpenSSLCertificate::OpenSSLCertificate(const X509 *x509) {
    x509Certificate = X509_dup((X509 *)x509);
    if (x509Certificate == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
}

bool OpenSSLCertificate::verify(const OpenSSLCertificate *issuerCA) const {
    EVP_PKEY *pkey = NULL;

    if ((pkey = X509_get0_pubkey(issuerCA->getX509())) == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
    int i = X509_verify(x509Certificate, pkey);
    if (i < 0) {
        return false;
    }

    return true;
}

const X509* OpenSSLCertificate::getX509() const {
    return x509Certificate;
}

const std::string OpenSSLCertificate::getPEM() {
    BIO *bioMem = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_X509(bioMem, x509Certificate)) {
        throw OpenSSLException(ERR_get_error());
    }
    char *pem;
    long len = BIO_get_mem_data(bioMem, &pem);
    std::string pemString(pem, len);
    BIO_free(bioMem);
    return pemString;
}

OpenSSLCertificate::~OpenSSLCertificate() {
    X509_free(x509Certificate);
}