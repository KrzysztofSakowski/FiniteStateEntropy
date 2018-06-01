#ifndef FSE_ENCRYPTOR_CTX_H
#define FSE_ENCRYPTOR_CTX_H

#include <stdint.h>

typedef struct {
    uint32_t BLOCK_ID;
    unsigned char salt[16];
    const unsigned char* key; // TODO: size 32?
    const unsigned char* iv; // TODO: size 32?
    const unsigned char* seed; // TODO: size 32?
} EncryptionCtx;

#endif //FSE_ENCRYPTOR_CTX_H
