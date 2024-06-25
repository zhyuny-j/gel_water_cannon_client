#include "CryptogramUtil.h"

#include <iostream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

char* hmacKey = new char[32];

void setHmacKey(const char* newHmacKey, int bodyLengh) {
    memcpy(hmacKey, newHmacKey, bodyLengh);
    
}

unsigned char* encryptBodyWithHMac(const char* body, int bodySize) {
    
    unsigned char* result;
    unsigned int result_len = -1;

    char* bodyBuffer = (char*)calloc(bodySize, sizeof(char));
    memcpy(bodyBuffer, body, bodySize);


    // Create HMAC-SHA256
    result = HMAC(EVP_sha256(), hmacKey, strlen(hmacKey), (unsigned char*)bodyBuffer, bodySize, NULL, &result_len);
    free(bodyBuffer);

    if (result != NULL) {
        
    }
    else {
        std::cerr << "Failed to create HMAC" << std::endl;
    }
    return result;
}