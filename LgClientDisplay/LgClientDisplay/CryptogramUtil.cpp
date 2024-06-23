#include "CryptogramUtil.h"

#include <iostream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

char* hmacKey = new char[32];

void setHmacKey(const char* newHmacKey) {
	strcpy_s(hmacKey, strlen(newHmacKey)+1, newHmacKey);
}

unsigned char* encryptBodyWithHMac(const char* body, int bodySize) {
    
    unsigned char* result;
    unsigned int result_len = -1;

    char* bodyBuffer = (char*)calloc(bodySize, sizeof(char));
    memcpy(bodyBuffer, body, bodySize);

    //TODO: delete this code
    std::cout << "BodyBuffer: ";
    for (size_t i = 0; i < bodySize; ++i) {
        printf("%02x", bodyBuffer[i]);
    }
    printf("\n");
    

    // Create HMAC-SHA256
    unsigned char hmacResult[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH = 32
    result = HMAC(EVP_sha256(), hmacKey, strlen(hmacKey), (unsigned char*)bodyBuffer, bodySize, hmacResult, &result_len);
    free(bodyBuffer);

    if (result != NULL) {
        std::cout << "HMAC-SHA256: ";

        //TODO: delete this code
        for (size_t i = 0; i < result_len; ++i) {
            printf("%02x", hmacResult[i]);
        }
        printf("\n");
    }
    else {
        std::cerr << "Failed to create HMAC" << std::endl;
    }
    return result;
}