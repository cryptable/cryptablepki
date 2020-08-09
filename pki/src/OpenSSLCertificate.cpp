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

const std::string OpenSSLCertificate::getCommonName() {
    X509_NAME *x509Name = X509_get_subject_name(x509Certificate);
    int lastpos = -1;
    lastpos = X509_NAME_get_index_by_NID(x509Name, NID_commonName, lastpos);
    if (lastpos != 0) {
        throw OpenSSLException(ERR_get_error());
    }
    X509_NAME_ENTRY *x509NameEntry = X509_NAME_get_entry(x509Name, lastpos);
    ASN1_STRING *data = X509_NAME_ENTRY_get_data(x509NameEntry);
    return std::string((char *)ASN1_STRING_get0_data(data), ASN1_STRING_length(data));
}