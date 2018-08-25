#include "encryptor.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <sodium.h>

#include <stdlib.h>
#include <assert.h>

#include <stdint.h>
#if UINTPTR_MAX == 0xffffffff
#define SHUFFLE_32
#elif UINTPTR_MAX == 0xffffffffffffffff
#define SHUFFLE_64
#endif

static const size_t SHUFFLE_BLOCK_SIZE = 8;

// https://stackoverflow.com/questions/776508/best-practices-for-circular-shift-rotate-operations-in-c
void bit_rotate_64(uint64_t *n, unsigned int c)
{
    c = (sizeof(uint64_t) - c) * CHAR_BIT; // changes rotate left to rotate right and bytes to bits
    const unsigned int mask = (CHAR_BIT*sizeof(*n) - 1);  // assumes width is a power of 2.

    c &= mask;
    *n = (*n<<c) | (*n>>( (-c)&mask ));
}

void swap(ShuffleType* a, ShuffleType* b)
{
    ShuffleType tmp = *a;
    *a = *b;
    *b = tmp;
}

void rotate(ShuffleType* first, ShuffleType* middle, ShuffleType* last)
{
    ShuffleType* next = middle;
    while (first!=next)
    {
        swap (first++,next++);
        if (next==last) next=middle;
        else if (first==middle) middle=next;
    }
}

void swap2(UnshuffleType* a, UnshuffleType* b)
{
    UnshuffleType tmp = *a;
    *a = *b;
    *b = tmp;
}

void rotate2(UnshuffleType* first, UnshuffleType* middle, UnshuffleType* last)
{
    UnshuffleType* next = middle;
    while (first!=next)
    {
        swap2 (first++, next++);
        if (next==last) next=middle;
        else if (first==middle) middle=next;
    }
}

void pre_compression_shuffle(ShuffleType* ptr, const size_t SIZE, const unsigned char* SEED)
{
    const size_t BUFFER_SIZE = SIZE / SHUFFLE_BLOCK_SIZE + sizeof(size_t);
    unsigned char* buffer = (unsigned char*) malloc(BUFFER_SIZE);
    randombytes_buf_deterministic(buffer, BUFFER_SIZE, SEED);

    size_t i, shuffle;

    for (i = 0; i+SHUFFLE_BLOCK_SIZE <= SIZE; i += SHUFFLE_BLOCK_SIZE)
    {
        shuffle = buffer[i/SHUFFLE_BLOCK_SIZE] % SHUFFLE_BLOCK_SIZE;

#ifdef SHUFFLE_64
        bit_rotate_64((uint64_t *)(ptr + i), (unsigned int) shuffle);
#else
        rotate(ptr+i, ptr+i+shuffle, ptr+i+SHUFFLE_BLOCK_SIZE);
#endif
    }

    shuffle = *((size_t*)(buffer + BUFFER_SIZE - sizeof(size_t))) % SIZE;

    rotate(ptr, ptr+shuffle, ptr+SIZE);

    free(buffer);
}

void pre_decompression_shuffle(UnshuffleType *ptr, const size_t SIZE, const unsigned char* SEED)
{
    const size_t BUFFER_SIZE = SIZE / SHUFFLE_BLOCK_SIZE + sizeof(size_t);
    unsigned char* buffer = (unsigned char*) malloc(BUFFER_SIZE);
    randombytes_buf_deterministic(buffer, BUFFER_SIZE, SEED);

    unsigned char* ptr_copy = (unsigned char*) malloc(SIZE);

    size_t i, shuffle;

    for (i = 0; i < SIZE; ++i)
        ptr_copy[i] = ptr[i].symbol;

    for (i = 0; i+SHUFFLE_BLOCK_SIZE <= SIZE; i += SHUFFLE_BLOCK_SIZE)
    {
        shuffle = buffer[i/SHUFFLE_BLOCK_SIZE] % SHUFFLE_BLOCK_SIZE;

#ifdef SHUFFLE_64
        bit_rotate_64((uint64_t *)(ptr_copy + i), (unsigned int) shuffle);
#else
        rotate(ptr_copy+i, ptr_copy+i+shuffle, ptr_copy+i+SHUFFLE_BLOCK_SIZE);
#endif
    }

    shuffle = *((size_t*)(buffer + BUFFER_SIZE - sizeof(size_t))) % SIZE;

    rotate(ptr_copy, ptr_copy+shuffle, ptr_copy+SIZE);

    for (i = 0; i < SIZE; ++i)
        ptr[i].symbol = ptr_copy[i];

    free(buffer);
    free(ptr_copy);
}

int aes_encrypt(unsigned char *dst, const unsigned char *src, const size_t SRC_SIZE,
                const unsigned char* key, const unsigned char* iv)
{
    EVP_CIPHER_CTX* en;
    en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(en);
    EVP_EncryptInit_ex(en, EVP_aes_256_cbc(), NULL, key, iv);

    int update_len, final_len;

    EVP_EncryptUpdate(en, dst, &update_len, src, (int)SRC_SIZE);

    EVP_EncryptFinal_ex(en, dst + update_len, &final_len);

    EVP_CIPHER_CTX_cleanup(en);
    EVP_CIPHER_CTX_free(en);

    return update_len + final_len;
}

int aes_decrypt(unsigned char *dst, const unsigned char *src, size_t SRC_SIZE,
                const unsigned char* key, const unsigned char* iv)
{
    EVP_CIPHER_CTX* de;
    de = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(de);

    EVP_DecryptInit_ex(de, EVP_aes_256_cbc(), NULL, key, iv);

    int update_len, final_len;

    EVP_DecryptUpdate(de, dst, &update_len, src, (int)SRC_SIZE);
    EVP_DecryptFinal_ex(de, dst + update_len, &final_len);

    EVP_CIPHER_CTX_cleanup(de);
    EVP_CIPHER_CTX_free(de);

    return update_len + final_len;
}

int calc_seed(const unsigned char *key_data, const size_t KEY_SIZE,
              const unsigned char* salt, const size_t SALT_SIZE, const uint32_t BLOCK_ID, unsigned char* out_sha)
{
    SHA256_CTX context;

    if(!SHA256_Init(&context))
        return 0;

    if(!SHA256_Update(&context, key_data, KEY_SIZE))
        return 0;

    if(!SHA256_Update(&context, salt, SALT_SIZE))
        return 0;

    if(!SHA256_Update(&context, &BLOCK_ID, sizeof(uint32_t)))
        return 0;

    if(!SHA256_Final(out_sha, &context))
        return 0;

    return 1;
}

void init_ctx(EncryptionCtx *ctx, uint32_t block_id, const unsigned char *key_data, const size_t KEY_DATA_SIZE,
              const unsigned char* salt, const size_t SALT_SIZE)
{
    assert(SALT_SIZE == 16);

    ctx->iv = malloc(SALT_SIZE);
    memcpy(ctx->iv, salt, SALT_SIZE);

    ctx->key = malloc(32);
    ctx->shuffle_seed = malloc(32);

    int result;

    result = calc_seed(key_data, KEY_DATA_SIZE, salt, SALT_SIZE, block_id, ctx->key);
    assert(result == 1);
    result = calc_seed(key_data, KEY_DATA_SIZE, salt, SALT_SIZE, block_id, ctx->shuffle_seed);
    assert(result == 1);
}

void deinit_ctx(EncryptionCtx *ctx)
{
    // TODO: memset 0?
    free(ctx->iv);
    free(ctx->key);
    free(ctx->shuffle_seed);
}

int is_operation_successful(size_t result)
{
    int operation_failed = result == 0 || result == 1 || FSE_isError(result);
    return !operation_failed;
}

size_t compression_helper(void* dst, size_t dstCapacity, const void* src, size_t srcSize, const unsigned char *KEY,
                          size_t KEY_DATA_SIZE, const unsigned char *SALT, uint32_t block_id)
{
    EncryptionCtx ctx;

    init_ctx(&ctx, block_id, KEY, KEY_DATA_SIZE, SALT, 16);

    size_t compression_result = FSE_compress(dst, dstCapacity, src, srcSize, &ctx);

    deinit_ctx(&ctx);

    return compression_result;
}

size_t compress_with_blocks(void *dst, size_t dstCapacity, const void *src, size_t srcSize, const unsigned char *KEY,
                            size_t KEY_DATA_SIZE, const unsigned char *SALT, const uint32_t BLOCK_SIZE)
{
    const int USE_ENCRYPTION = KEY != NULL && KEY_DATA_SIZE > 0 && SALT != NULL;
    const uint32_t block_count = (uint32_t)(srcSize / BLOCK_SIZE);

    size_t src_offset = 0;
    // block count + block_count * nth_block_size
    size_t dst_offset = sizeof(uint32_t) + block_count * sizeof(uint32_t);

    ((uint32_t*)dst)[0] = block_count;
    uint32_t block_id;

    for (block_id = 0; block_id+1 < block_count; ++block_id)
    {
        size_t compression_result;

        if (USE_ENCRYPTION)
            compression_result = compression_helper(dst + dst_offset, dstCapacity - dst_offset,
                                                    src + src_offset, BLOCK_SIZE, KEY, KEY_DATA_SIZE, SALT, block_id);
        else
            compression_result = FSE_compress(dst + dst_offset, dstCapacity - dst_offset, src + src_offset, BLOCK_SIZE,
                                              NULL);


        if (!is_operation_successful(compression_result))
            return compression_result;

        // +1 is compensation for block_count which size is uint32_t
        ((uint32_t*)dst)[block_id+1] = (uint32_t)compression_result;

        src_offset += BLOCK_SIZE;
        dst_offset += compression_result;
    }

    { // special treatment for the last block
        size_t compression_result;

        if (USE_ENCRYPTION)
            compression_result = compression_helper(dst + dst_offset, dstCapacity - dst_offset, src + src_offset,
                                                    srcSize - src_offset, KEY, KEY_DATA_SIZE, SALT, block_count - 1);
        else
            compression_result = FSE_compress(dst + dst_offset, dstCapacity - dst_offset, src + src_offset,
                                              srcSize - src_offset, NULL);

        if (!is_operation_successful(compression_result))
            return compression_result;

        // +1 is compensation for block_count which size is uint32_t
        ((uint32_t*)dst)[block_id+1] = (uint32_t)compression_result;

        dst_offset += compression_result;
    }

    return dst_offset;
}

size_t decompression_helper(void* dst, size_t dstCapacity, const void* src, size_t srcSize, const unsigned char *KEY,
        size_t KEY_DATA_SIZE, const unsigned char *SALT, uint32_t block_id)
{
    EncryptionCtx ctx;

    init_ctx(&ctx, block_id, KEY, KEY_DATA_SIZE, SALT, 16);

    size_t decompression_result = FSE_decompress(dst, dstCapacity, src, srcSize, &ctx);

    deinit_ctx(&ctx);

    return decompression_result;
}

size_t decompress_with_blocks(void *dst, size_t dstCapacity, const void *src, size_t srcSize, const unsigned char *KEY,
                              size_t KEY_DATA_SIZE, const unsigned char *SALT)
{
    const int USE_ENCRYPTION = KEY != NULL && KEY_DATA_SIZE > 0 && SALT != NULL;

    const uint32_t block_count = ((uint32_t*)src)[0];

    // block count + block_count * nth_block_size
    size_t src_offset = sizeof(uint32_t) + block_count * sizeof(uint32_t);
    size_t dst_offset = 0;
    uint32_t block_id;

    for (block_id = 0; block_id+1 < block_count; ++block_id)
    {
        // +1 is compensation for block_count which size is uint32_t
        uint32_t current_block_size = ((uint32_t*)src)[block_id+1];

        size_t decompression_result;

        if (USE_ENCRYPTION)
            decompression_result = decompression_helper(dst + dst_offset, dstCapacity - dst_offset, src + src_offset,
                                                        current_block_size, KEY, KEY_DATA_SIZE, SALT, block_id);
        else
            decompression_result = FSE_decompress(dst + dst_offset, dstCapacity - dst_offset, src + src_offset,
                                                  current_block_size, NULL);


        if (!is_operation_successful(decompression_result))
            return decompression_result;

        src_offset += current_block_size;
        dst_offset += decompression_result;
    }

    { // special treatment for the last block
        // +1 is compensation for block_count which size is uint32_t
        uint32_t current_block_size = ((uint32_t*)src)[1+block_id];

        size_t decompression_result;

        if (USE_ENCRYPTION)
            decompression_result = decompression_helper(dst + dst_offset, dstCapacity - dst_offset, src + src_offset,
                                                        current_block_size, KEY, KEY_DATA_SIZE, SALT, block_count - 1);
        else
            decompression_result = FSE_decompress(dst + dst_offset, dstCapacity - dst_offset, src + src_offset,
                                                  current_block_size, NULL);


        if (!is_operation_successful(decompression_result))
            return decompression_result;

        dst_offset += decompression_result;
    }

    return dst_offset;
}
