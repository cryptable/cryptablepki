/*
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 09/08/2020
 */
#include <openssl/evp.h>
#include <exception>
#include <openssl/rsa.h>
#include "OpenSSLKey.h"
#include "OpenSSLException.h"

OpenSSLKey::OpenSSLKey() {
    OpenSSLKey(2048);
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

const EVP_PKEY * OpenSSLKey::getKeyPair() {
    return keyPair;
}

OpenSSLKey::~OpenSSLKey() {
    EVP_PKEY_free(keyPair);
}