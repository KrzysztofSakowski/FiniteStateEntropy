#ifndef FSE_ENCRYPTOR_H
#define FSE_ENCRYPTOR_H

#define FSE_STATIC_LINKING_ONLY
#include "fse.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef FSE_FUNCTION_TYPE ShuffleType;
typedef FSE_DECODE_TYPE UnshuffleType;

void pre_compression_shuffle(ShuffleType* ptr, size_t SIZE);

void pre_decompression_shuffle(UnshuffleType* ptr, size_t SIZE);

void rotate(ShuffleType* first, ShuffleType* middle, ShuffleType* last);

void rotate2(UnshuffleType* first, UnshuffleType* middle, UnshuffleType* last);

int aes_encrypt(unsigned char* dst, const unsigned char* src, size_t SRC_SIZE);

int aes_decrypt(unsigned char* dst, const unsigned char* src, size_t SRC_SIZE);

int calc_seed(const unsigned char *key_data, size_t KEY_SIZE,
              const unsigned char* salt, size_t SALT_SIZE, uint32_t BLOCK_ID, unsigned char* out_sha);

#ifdef __cplusplus
}
#endif

#endif //FSE_ENCRYPTOR_H
