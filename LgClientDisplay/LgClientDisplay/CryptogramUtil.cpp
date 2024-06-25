#include "CryptogramUtil.h"

#include <iostream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

char* hmacKey = new char[32];

void setHmacKey(const char* newHmacKey, int bodyLengh) {
    memcpy(hmacKey, newHmacKey, bodyLengh);
    std::cout << "[setHmacKey] HmacKey: ";
    for (size_t i = 0; i < strlen(hmacKey); ++i) {
        printf("%02x", hmacKey[i]);
    }
    printf("\n");
	//strcpy_s(hmacKey, sizeof(hmacKey), newHmacKey);
}

unsigned char* encryptBodyWithHMac(const char* body, int bodySize) {
    
    unsigned char* result;
    unsigned int result_len = -1;

    char* bodyBuffer = (char*)calloc(bodySize, sizeof(char));
    memcpy(bodyBuffer, body, bodySize);

    //TODO: delete this code
    std::cout << "[encryptBodyWithHMac] HmacKey: ";
    for (size_t i = 0; i < strlen(hmacKey); ++i) {
        printf("%02x ", hmacKey[i]);
    }
    printf("\n");

    //TODO: delete this code
    std::cout << "[encryptBodyWithHMac] BodyBuffer: ";
    for (size_t i = 0; i < bodySize; ++i) {
        printf("%02x ", bodyBuffer[i]);
    }
    printf("\n");
    

    // Create HMAC-SHA256
    result = HMAC(EVP_sha256(), hmacKey, strlen(hmacKey), (unsigned char*)bodyBuffer, bodySize, NULL, &result_len);
    free(bodyBuffer);

    if (result != NULL) {
        std::cout << "[encryptBodyWithHMac] HMAC-SHA256: ";

        //TODO: delete this code
        for (size_t i = 0; i < result_len; ++i) {
            printf("%02x", result[i]);
        }
        printf("\n\n");
    }
    else {
        std::cerr << "Failed to create HMAC" << std::endl;
    }
    return result;
}