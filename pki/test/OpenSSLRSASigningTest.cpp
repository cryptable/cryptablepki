/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 21/08/2020
 */
#include <catch2/catch.hpp>
#include <string>
#include <vector>
#include "OpenSSLKey.h"
#include "OpenSSLException.h"
#include "openssl/sha.h"

int get_base64_length(int dataLg) {
    int len = 4 * (dataLg / 3);
    int rst = (4 % len);
    if (rst) {
        return len + (4 - rst);
    }
    else {
        return len;
    }
}

int get_length_base64(int dataLg) {
    return (3 * (dataLg / 4));
}

static std::string to_base64(const std::vector<unsigned char> &data) {
    std::unique_ptr<char[]> b64Data(new char[get_base64_length(data.size())]);
    int b64DataLg = EVP_EncodeBlock((unsigned char *)b64Data.get(), data.data(), data.size());
    if (b64DataLg == -1) {
        throw OpenSSLException("EVP_EncodeBlock 2 failed");
    }
    return std::string(b64Data.get(), b64DataLg);
}

static std::vector<unsigned char> from_base64(const std::string &b64Data) {
    std::unique_ptr<char[]> data(new char[get_length_base64(b64Data.size())]);
    int dataLg = EVP_DecodeBlock((unsigned char *)data.get(), (const unsigned char *) b64Data.data(), b64Data.size());
    if (dataLg == -1) {
        throw OpenSSLException("EVP_EncodeBlock 2 failed");
    }
    return std::vector<unsigned char>(data.get(), data.get()+dataLg); // That's ugly :-(
}

static std::string to_uri(const std::string &base64) {
    std::string result = base64.substr(0, base64.find('='));
    replace(result.begin(), result.end(), '+','-');
    replace(result.begin(), result.end(), '/','_');
    return result;
}

static std::string from_uri(const std::string &uri) {
    std::string result = uri;
    replace(result.begin(), result.end(), '-','+');
    replace(result.begin(), result.end(), '_','/');
    switch (uri.size() % 4) {
        case 0: break;
        case 2: result += "=="; break;
        case 3: result += "="; break;
        default: throw OpenSSLException("Illegal Base64");
    }
    return result;
}

static std::string to_base64_uri(const std::vector<unsigned char> &data) {
    std::string base64 = to_base64(data);
    return to_uri(base64);
}

static std::vector<unsigned char> from_base64_uri(const std::string &uriData) {
    std::string base64 = from_uri(uriData);
    return from_base64(base64);
}

TEST_CASE( "OpenSSL Signine Tests", "[success]" ) {

    SECTION( "Generate a PKCS12" ) {
        std::string b64Mod = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                         "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                         "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                         "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                         "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                         "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
        std::string b64Exp = "AQAB";
        std::string b64D = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
                           "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
                           "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
                           "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
                           "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
                           "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";
        std::string b64P = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
                           "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
                           "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";
        std::string b64Q = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
                           "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
                           "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";
        std::string b64DP = "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
                            "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
                            "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0";
        std::string b64DQ = "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
                            "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
                            "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU";
        std::string b64IQMP = "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
                              "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
                              "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U";
        std::string payload = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        std::vector<unsigned char> mod = from_base64_uri(b64Mod);
        std::vector<unsigned char> exp = from_base64_uri(b64Exp);
        std::vector<unsigned char> d = from_base64_uri(b64D);
        std::vector<unsigned char> p = from_base64_uri(b64P);
        std::vector<unsigned char> q = from_base64_uri(b64Q);
        std::vector<unsigned char> dp = from_base64_uri(b64DP);
        std::vector<unsigned char> dq = from_base64_uri(b64DQ);
        std::vector<unsigned char> iqmp = from_base64_uri(b64IQMP);
        OpenSSLKey rsa(OPENSSL_buf2hexstr(mod.data(), mod.size()),
                       OPENSSL_buf2hexstr(exp.data(), exp.size()),
                       OPENSSL_buf2hexstr(d.data(), d.size()),
                       OPENSSL_buf2hexstr(p.data(), p.size()),
                       OPENSSL_buf2hexstr(q.data(), q.size()),
                       OPENSSL_buf2hexstr(dp.data(), dp.size()),
                       OPENSSL_buf2hexstr(dq.data(), dq.size()),
                       OPENSSL_buf2hexstr(iqmp.data(), iqmp.size()));
        std::vector<unsigned char> hash(32);
        SHA256(reinterpret_cast<const unsigned char *>(payload.data()), payload.size(), hash.data());

    }
}