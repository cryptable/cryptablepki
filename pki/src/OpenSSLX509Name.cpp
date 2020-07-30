/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 21/07/2020
 */
#include <cstring>
#include "OpenSSLX509Name.h"
#include "OpenSSLException.h"

OpenSSLX509Name::OpenSSLX509Name(const std::string &name) : name{name} {
    parseName(name, MBSTRING_ASC);
}

OpenSSLX509Name::OpenSSLX509Name(const X509_NAME *x509Nm) {
    x509Name = X509_NAME_dup((X509_NAME *)x509Nm);
    if (x509Name == NULL) {
        throw std::bad_alloc();
    }
    char *x509str = X509_NAME_oneline(x509Name, NULL, 0);
    if (x509str == NULL) {
        X509_NAME_free(x509Name);
        throw std::bad_alloc();
    }
    name = std::string(X509_NAME_oneline(x509Name, NULL, 0));
}

/**
 * Parses a string name to X509 Name structure
 * @param name string of the distinguished name in /cn=John Does/O=Company
 * @param chtype can be MBSTRING_ASC | MBSTRING_UTF8
 * @return
 */
void OpenSSLX509Name::parseName(const std::string &name, int chtype)
{
    const char *cp = name.c_str();
    int nextismulti = 0;
    char *work;

    if (*cp++ != '/') {
        throw OpenSSLException("name is expected to be in the format "
                               "/type0=value0/type1=value1/type2=... where characters may "
                               "be escaped by \\. This name is not in that format: '%s'\n");
    }
    x509Name = X509_NAME_new();
    if (x509Name == NULL) {
        throw std::bad_alloc();
    }
    work = OPENSSL_strdup(cp);
    if (work == NULL)
        throw std::bad_alloc();

    while (*cp) {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp && *cp != '=')
            *bp++ = *cp++;
        if (*cp == '\0') {
            OPENSSL_free(work);
            throw OpenSSLException("Hit end of string before finding the equals.\n");
        }
        *bp++ = '\0';
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *) bp;
        for (; *cp && *cp != '/'; *bp++ = *cp++) {
            if (*cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                OPENSSL_free(work);
                throw OpenSSLException("Hit escape character at end of string\n");
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp)
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            OPENSSL_free(work);
            throw OpenSSLException("Unknown attribute in name\n");
        }
        if (*valstr == '\0') {
            OPENSSL_free(work);
            throw OpenSSLException("No value provided for an attribute in name\n");
        }
        if (!X509_NAME_add_entry_by_NID(x509Name, nid, chtype,
                                        valstr, strlen((char *) valstr),
                                        -1, ismulti ? -1 : 0)) {
            OPENSSL_free(work);
            throw OpenSSLException("No value provided for an attribute in name\n");
        }
    }

    OPENSSL_free(work);
}

OpenSSLX509Name::~OpenSSLX509Name() {
    X509_NAME_free(x509Name);
}