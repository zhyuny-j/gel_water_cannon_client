#include "CrytogramUtil.h"

#include <iostream>
#include <openssl/hmac.h>
#include <openssl/evp.h>

char* hmacKey;

void setHmacKey(const char* newHmacKey) {
	char* hmacKey = (char*)calloc(strlen(newHmacKey) + 1, sizeof(char));
	strcpy_s(hmacKey, sizeof(hmacKey), newHmacKey);
}

unsigned char* encryptBodyWithHMac(const char* body) {
    
    unsigned char* result;
    unsigned int result_len = -1;

    // Create HMAC-SHA256
    result = HMAC(EVP_sha256(), hmacKey, strlen(hmacKey), (unsigned char*)body, strlen(body), NULL, &result_len);

    if (result != NULL) {
        std::cout << "HMAC-SHA256: ";

        //TODO: delete this code
        for (size_t i = 0; i < result_len; ++i) {
            printf("%02x", result[i]);
        }
        printf("\n");
    }
    else {
        std::cerr << "Failed to create HMAC" << std::endl;
    }
    return result;
}