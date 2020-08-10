/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 20/07/2020
 */
#include <memory>
#include <functional>
#include <openssl/x509v3.h>
#include "OpenSSLCA.h"
#include "OpenSSLX509Name.h"
#include "OpenSSLException.h"

#define FIVE_YEARS   (5*365 + 1)
#define ONE_YEAR     365

OpenSSLCA::OpenSSLCA(const std::string &rootName, int bitLength) : serialNumber{1L}, keyPair(bitLength) {

    // TODO: Create the Certificate
    auto x509Certificate = std::unique_ptr<X509,std::function<void(X509 *ptr)>>(X509_new(), X509_free );
    OpenSSLX509Name subject(rootName);
    if (!x509Certificate) {
        throw std::bad_alloc();
    }
    if (!X509_set_version(x509Certificate.get(), 2)) {
        throw OpenSSLException(ERR_get_error());
    }
    X509_set_subject_name(x509Certificate.get(), subject.getX509Name());
    X509_set_issuer_name(x509Certificate.get(), subject.getX509Name());

    auto asn1SerialNumber = std::unique_ptr<ASN1_INTEGER,std::function<void(ASN1_INTEGER *ptr)>>(ASN1_INTEGER_new(), ASN1_INTEGER_free );
    if (!asn1SerialNumber) {
        throw std::bad_alloc();
    }
    ASN1_INTEGER_set(asn1SerialNumber.get(), serialNumber);
    X509_set_serialNumber(x509Certificate.get(), asn1SerialNumber.get());
    serialNumber++;
    if (X509_gmtime_adj(X509_getm_notBefore(x509Certificate.get()), 0) == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
    if (X509_time_adj_ex(X509_getm_notAfter(x509Certificate.get()), FIVE_YEARS, 0, NULL) == NULL) {
        throw OpenSSLException(ERR_get_error());
    }

    if (!X509_set_pubkey(x509Certificate.get(),
                         const_cast<EVP_PKEY *>(keyPair.getKeyPair()))) {
        throw OpenSSLException(ERR_get_error());
    }

    X509_EXTENSION *basicConstraint = X509V3_EXT_conf_nid(NULL,
            NULL,
            NID_basic_constraints,
            "critical,CA:true,pathlen:0");
    if (basicConstraint == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
    if (!X509_add_ext(x509Certificate.get(), basicConstraint, -1)) {
        throw OpenSSLException(ERR_get_error());
    }
    X509_EXTENSION *keyUsage = X509V3_EXT_conf_nid(NULL,
            NULL,
            NID_key_usage,
            "critical, digitalSignature, keyCertSign, cRLSign");
    if (keyUsage == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
    if (!X509_add_ext(x509Certificate.get(), keyUsage, -1)) {
        throw OpenSSLException(ERR_get_error());
    }

#if 0 // Basic Constraint
    BASIC_CONSTRAINTS *bc;
    i2d_ASN1_INTEGER()
    i2d_BASIC_CONSTRAINTS(bs,)
    // NID_basic_constraints
    X509_add1_ext_i2d(x509Certificate, NID_basic_constraints, , 1, )
#endif

    // TODO: Sign Certificate
    auto mdctx = std::unique_ptr<EVP_MD_CTX,std::function<void(EVP_MD_CTX *ptr)>>(EVP_MD_CTX_new(), EVP_MD_CTX_free );
    if (!mdctx) {
        throw std::bad_alloc();
    }
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX *pkctx = NULL;
    if (!EVP_DigestSignInit(mdctx.get(), &pkctx, md, NULL, const_cast<EVP_PKEY *>(keyPair.getKeyPair()))) {
        throw OpenSSLException(ERR_get_error());
    }
    if (!X509_sign_ctx(x509Certificate.get(), mdctx.get())) {
        throw OpenSSLException(ERR_get_error());
    }
    caCertificate = OpenSSLCertificate(x509Certificate.get());
}

std::unique_ptr<OpenSSLCertificate> OpenSSLCA::certify(const OpenSSLCertificateRequest &certificateRequest) {

    auto x509Certificate = std::unique_ptr<X509,std::function<void(X509 *ptr)>>(X509_new(), X509_free );
    if (!x509Certificate) {
        throw std::bad_alloc();
    }
    X509_set_subject_name(x509Certificate.get(), X509_REQ_get_subject_name(certificateRequest.getX509_REQ()));
    X509_set_issuer_name(x509Certificate.get(), X509_get_subject_name(caCertificate.getX509()));
    X509_set_pubkey(x509Certificate.get(), X509_REQ_get0_pubkey((X509_REQ *)certificateRequest.getX509_REQ()));
    if (X509_gmtime_adj(X509_getm_notBefore(x509Certificate.get()), 0) == NULL) {
        throw OpenSSLException(ERR_get_error());
    }
    if (X509_time_adj_ex(X509_getm_notAfter(x509Certificate.get()), ONE_YEAR, 0, NULL) == NULL) {
        throw OpenSSLException(ERR_get_error());
    }

    auto mdctx = std::unique_ptr<EVP_MD_CTX,std::function<void(EVP_MD_CTX *ptr)>>(EVP_MD_CTX_new(), EVP_MD_CTX_free );
    if (!mdctx) {
        throw std::bad_alloc();
    }
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX *pkctx = NULL;
    if (!EVP_DigestSignInit(mdctx.get(), &pkctx, md, NULL, const_cast<EVP_PKEY *>(keyPair.getKeyPair()))) {
        throw OpenSSLException(ERR_get_error());
    }
    if (!X509_sign_ctx(x509Certificate.get(), mdctx.get())) {
        throw OpenSSLException(ERR_get_error());
    }

    std::unique_ptr<OpenSSLCertificate> certificate=
            std::unique_ptr<OpenSSLCertificate>(new OpenSSLCertificate(x509Certificate.get()));

    return certificate;
}

const OpenSSLCertificate &OpenSSLCA::getCertificate() const {
    return caCertificate;
}

OpenSSLCA::~OpenSSLCA() {
}