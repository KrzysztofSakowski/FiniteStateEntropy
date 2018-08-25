#ifndef FSE_ENCRYPTOR_H
#define FSE_ENCRYPTOR_H

#define FSE_STATIC_LINKING_ONLY
#include "fse.h"
#include "encryptor_ctx.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef FSE_FUNCTION_TYPE ShuffleType;
typedef FSE_DECODE_TYPE UnshuffleType;

void init_ctx(EncryptionCtx *ctx, uint32_t block_id, const unsigned char *key_data, size_t KEY_DATA_SIZE,
              const unsigned char* salt, size_t SALT_SIZE);

void deinit_ctx(EncryptionCtx *ctx);

void pre_compression_shuffle(ShuffleType* ptr, size_t SIZE, const unsigned char* SEED);

void pre_decompression_shuffle(UnshuffleType* ptr, size_t SIZE, const unsigned char* SEED);

void bit_rotate_64(uint64_t *n, unsigned int c);

void rotate(ShuffleType* first, ShuffleType* middle, ShuffleType* last);

void rotate2(UnshuffleType* first, UnshuffleType* middle, UnshuffleType* last);

int aes_encrypt(unsigned char *dst, const unsigned char *src, size_t SRC_SIZE,
                const unsigned char* key, const unsigned char* iv);

int aes_decrypt(unsigned char* dst, const unsigned char* src, size_t SRC_SIZE,
                const unsigned char* key, const unsigned char* iv);

int calc_seed(const unsigned char *key_data, size_t KEY_SIZE,
              const unsigned char* salt, size_t SALT_SIZE, uint32_t BLOCK_ID, unsigned char* out_sha);

int is_operation_successful(size_t result);

size_t compress_with_blocks(void *dst, size_t dstCapacity, const void *src, size_t srcSize, const unsigned char *KEY,
                            size_t KEY_DATA_SIZE, const unsigned char *SALT, uint32_t BLOCK_SIZE);

size_t decompress_with_blocks(void *dst, size_t dstCapacity, const void *src, size_t srcSize, const unsigned char *KEY,
                              size_t KEY_DATA_SIZE, const unsigned char *SALT);

#ifdef __cplusplus
}
#endif

#endif //FSE_ENCRYPTOR_H
