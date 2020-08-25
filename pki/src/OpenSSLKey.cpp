/*
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 09/08/2020
 */
#include <exception>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include "OpenSSLKey.h"
#include "OpenSSLException.h"

OpenSSLKey::OpenSSLKey() : OpenSSLKey(2048) {
}

OpenSSLKey::OpenSSLKey(size_t keyBitLength) : bitLength{keyBitLength}, keyPair{nullptr} {
    EVP_PKEY_CTX *ctx = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        throw std::bad_alloc();
    }
    int status = 0;
    if ((status = EVP_PKEY_keygen_init(ctx)) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenSSLException(status);
    }
    if ((status = RSA_pkey_ctx_ctrl(ctx,
                                    EVP_PKEY_OP_KEYGEN,
                                    EVP_PKEY_CTRL_RSA_KEYGEN_BITS,
                                    bitLength, NULL)) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenSSLException(status);
    }

    if ((status = EVP_PKEY_keygen(ctx, &keyPair)) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenSSLException(status);
    }
    EVP_PKEY_CTX_free(ctx);
}

OpenSSLKey::OpenSSLKey(const std::string &hexModulus,
                       const std::string &hexExponent,
                       const std::string &hexPrivate,
                       const std::string &hexP,
                       const std::string &hexQ,
                       const std::string &hexDP,
                       const std::string &hexDQ,
                       const std::string &hexIQMP) {
    int ret = 0;
    RSA* rsa = RSA_new();
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    ret = BN_hex2bn(&n, hexModulus.c_str());
    ret = BN_hex2bn(&e, hexExponent.c_str());
    ret = BN_hex2bn(&d, hexPrivate.c_str());
/*
    ret = BN_hex2bn(rsa->p, hexP.c_str());
    ret = BN_hex2bn(rsa->q, hexQ.c_str());
    ret = BN_hex2bn(rsa->dmp1, hexDP.c_str());
    ret = BN_hex2bn(rsa->dmq1, hexDQ.c_str());
    ret = BN_hex2bn(rsa->iqmp, hexIQMP.c_str());
*/
    RSA_set0_key(rsa, n, e, d);
    this->keyPair = EVP_PKEY_new();
    ret = EVP_PKEY_set1_RSA(this->keyPair, rsa);

    RSA_free(rsa);
}

OpenSSLKey::OpenSSLKey(EVP_PKEY *evpPkey) {
    this->keyPair = evpPkey;
    this->bitLength = EVP_PKEY_bits(evpPkey);
    EVP_PKEY_up_ref(this->keyPair);
}

OpenSSLKey::OpenSSLKey(const OpenSSLKey &openSslKey) {
    this->bitLength = openSslKey.bitLength;
    this->keyPair = openSslKey.keyPair;
    EVP_PKEY_up_ref(this->keyPair);
}

OpenSSLKey & OpenSSLKey::operator=(const OpenSSLKey &openSslKey) {
    if (this->keyPair) {
        EVP_PKEY_free(this->keyPair);
    }
    this->bitLength = openSslKey.bitLength;
    this->keyPair = openSslKey.keyPair;
    EVP_PKEY_up_ref(this->keyPair);
    return *this;
}

const EVP_PKEY * OpenSSLKey::getKeyPair() const {
    return keyPair;
}

size_t OpenSSLKey::getKeyBitlength() const {
    return bitLength;
}

OpenSSLKey::~OpenSSLKey() {
    EVP_PKEY_free(keyPair);
}