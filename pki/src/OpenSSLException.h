/*
 * Copyright (c) 2020 Cryptable BV. All rights reserved.
 * (MIT License)
 * Author: "David Tillemans"
 * Date: 21/07/2020
 */

#ifndef OPENSSLEXCEPTION_H
#define OPENSSLEXCEPTION_H
#include <stdexcept>
#include <string>
#include <openssl/err.h>

/**
 * General Exception class, which tries to retrieve the error message from openssl errorcode
 */
class OpenSSLException : public std::exception {

public:
    /**
     * Constructor which needs the openssl error code
     * @param error the error code, which can be given using the function ERR_get_error() or the return code from the
     * openssl function
     */
    OpenSSLException(unsigned long error) : errorCode{error} {
        errorMessage = ERR_error_string(error, NULL);
    };

    /**
     * Non standard openssl errors, can use this interface and give the message as a string. The error code = 0x90010001
     * @param message error message as a standard string
     */
    OpenSSLException(const std::string &message) : errorCode{0x90010001}, errorMessage{message} {
    };

    /**
     * Return the error code
     * @return
     */
    unsigned long code() {
        return errorCode;
    };

    /**
     * Implements the standard insterface of std::exception
     * @return
     */
    virtual char const * what() const noexcept override {
        return errorMessage.c_str();
    };

    /**
     * return the error message as in the what().
     * @return
     */
    operator std::string() const { return errorMessage; };

private:

    unsigned long errorCode;

    std::string errorMessage;
};


#endif // OPENSSLEXCEPTION_H
/**********************************************************************************/
/* MIT License                                                                    */
/*                                                                                */
/* Copyright (c) 2020 Cryptable BV */
/*                                                                                */
/* Permission is hereby granted, free of charge, to any person obtaining a copy   */
/* of this software and associated documentation files (the "Software"), to deal  */
/* in the Software without restriction, including without limitation the rights   */
/* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      */
/* copies of the Software, and to permit persons to whom the Software is          */
/* furnished to do so, subject to the following conditions:                       */
/*                                                                                */
/* The above copyright notice and this permission notice shall be included in all */
/* copies or substantial portions of the Software.                                */
/*                                                                                */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     */
/* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       */
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    */
/* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         */
/* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  */
/* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  */
/* SOFTWARE.                                                                      */
/**********************************************************************************/
