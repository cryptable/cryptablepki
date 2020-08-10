/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 21/07/2020
 */
#include "OpenSSLCertificateRequest.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include "OpenSSLException.h"
#include "OpenSSLCertificate.h"
#include "OpenSSLX509Name.h"

OpenSSLCertificateRequest::OpenSSLCertificateRequest() : certificateRequest{nullptr}{

}

OpenSSLCertificateRequest::OpenSSLCertificateRequest(const char *req, size_t reqLg) {
    certificateRequest = d2i_X509_REQ(NULL, reinterpret_cast<const unsigned char **>(&req), reqLg);
    if (certificateRequest == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
}

OpenSSLCertificateRequest::OpenSSLCertificateRequest(const std::string &pemRequest) {
    BIO *pemBIO = BIO_new_mem_buf(pemRequest.data(), pemRequest.size());
    if (pemBIO == NULL) {
        throw std::bad_alloc();
    }
    certificateRequest = PEM_read_bio_X509_REQ(pemBIO, NULL, NULL, NULL);

    BIO_free(pemBIO);
}


OpenSSLCertificateRequest::OpenSSLCertificateRequest(const std::string &dname, size_t bitLength): keyPair(bitLength) {

    certificateRequest = X509_REQ_new();
    if (certificateRequest == NULL) {
        throw std::bad_alloc();
    }
    OpenSSLX509Name subjectName(dname.c_str());
    X509_REQ_set_subject_name(certificateRequest, subjectName.getX509Name());
    X509_REQ_set_pubkey(certificateRequest, const_cast<EVP_PKEY *>(keyPair.getKeyPair()));
    X509_REQ_set_version(certificateRequest, 0L);

    // TODO: Sign Certificate Request (Almost Identical as OpenSSLCA class DRY)
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        throw std::bad_alloc();
    }
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX *pkctx = NULL;
    if (!EVP_DigestSignInit(mdctx, &pkctx, md, NULL, const_cast<EVP_PKEY *>(keyPair.getKeyPair()))) {
        throw OpenSSLException(ERR_get_error());
    }
    if (!X509_REQ_sign_ctx(certificateRequest, mdctx)) {
        throw OpenSSLException(ERR_get_error());
    }
}

OpenSSLCertificateRequest::OpenSSLCertificateRequest(const OpenSSLCertificateRequest &openSslCertificateRequest) {
    this->keyPair = openSslCertificateRequest.keyPair;
    this->certificateRequest = X509_REQ_dup(openSslCertificateRequest.certificateRequest);
}

OpenSSLCertificateRequest & OpenSSLCertificateRequest::operator=(
        const OpenSSLCertificateRequest &openSslCertificateRequest) {
    if (this->certificateRequest) {
        X509_REQ_free(this->certificateRequest);
    }
    this->keyPair = openSslCertificateRequest.keyPair;
    this->certificateRequest = X509_REQ_dup(openSslCertificateRequest.certificateRequest);
    return *this;
}

bool OpenSSLCertificateRequest::verify() {
    EVP_PKEY *pkey = NULL;

    if ((pkey = X509_REQ_get0_pubkey(certificateRequest)) == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
    int i = X509_REQ_verify(certificateRequest, pkey);
    if (i < 0) {
        return false;
    }

    return true;
}

const X509_REQ *OpenSSLCertificateRequest::getX509_REQ() const {
    return certificateRequest;
}

const OpenSSLKey &OpenSSLCertificateRequest::getKeyPair() {
    return keyPair;
}

OpenSSLCertificateRequest::~OpenSSLCertificateRequest() {
    X509_REQ_free(certificateRequest);
}
