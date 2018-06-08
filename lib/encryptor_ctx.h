#ifndef FSE_ENCRYPTOR_CTX_H
#define FSE_ENCRYPTOR_CTX_H

#include <stdint.h>

typedef struct {
    // for AES-256 CBC it is 32 bytes
    unsigned char* key;
    // for AES-256 CBC it is 16 bytes
    unsigned char* iv;
    // 32 bytes, required by sodium library
    unsigned char* shuffle_seed;
} EncryptionCtx;

#endif //FSE_ENCRYPTOR_CTX_H
