#include "encryptor.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#include <sodium.h>

#include <stdlib.h>


static const size_t SHUFFLE_BLOCK_SIZE = 8;
unsigned char SEED[randombytes_SEEDBYTES] = {
    1, 2, 3, 4, 5, 6, 7, 8
};

void swap(ShuffleType* a, ShuffleType* b)
{
    ShuffleType tmp = *a;
    *a = *b;
    *b = tmp;
}

void swap2(UnshuffleType* a, UnshuffleType* b)
{
    UnshuffleType tmp = *a;
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

void pre_compression_shuffle(ShuffleType* ptr, const size_t SIZE)
{
    const size_t BUFFER_SIZE = SIZE / SHUFFLE_BLOCK_SIZE + sizeof(size_t);
    unsigned char* buffer = (unsigned char*) malloc(BUFFER_SIZE);
    randombytes_buf_deterministic(buffer, BUFFER_SIZE, SEED);

    size_t i, shuffle;

    for (i = 0; i+SHUFFLE_BLOCK_SIZE <= SIZE; i += SHUFFLE_BLOCK_SIZE)
    {
        shuffle = buffer[i] % SHUFFLE_BLOCK_SIZE;
        rotate(ptr+i, ptr+i+shuffle, ptr+i+SHUFFLE_BLOCK_SIZE);
    }

    shuffle = *((size_t*)(buffer + BUFFER_SIZE - sizeof(size_t))) % SIZE;

    rotate(ptr, ptr+shuffle, ptr+SIZE);

    free(buffer);
}

void pre_decompression_shuffle(UnshuffleType *ptr, const size_t SIZE)
{
    const size_t BUFFER_SIZE = SIZE / SHUFFLE_BLOCK_SIZE + sizeof(size_t);
    unsigned char* buffer = (unsigned char*) malloc(BUFFER_SIZE);
    randombytes_buf_deterministic(buffer, BUFFER_SIZE, SEED);

    size_t i, shuffle;

    for (i = 0; i+SHUFFLE_BLOCK_SIZE <= SIZE; i += SHUFFLE_BLOCK_SIZE)
    {
        shuffle = buffer[i] % SHUFFLE_BLOCK_SIZE;
        rotate2(ptr+i, ptr+i+shuffle, ptr+i+SHUFFLE_BLOCK_SIZE);
    }

    shuffle = *((size_t*)(buffer + BUFFER_SIZE - sizeof(size_t))) % SIZE;

    rotate2(ptr, ptr+shuffle, ptr+SIZE);

    free(buffer);
}

int aes_encrypt(unsigned char *dst, const unsigned char *src, const size_t SRC_SIZE)
{
    unsigned char key[32] = {
            1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8
    };
    unsigned char iv[16] = {
            1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8
    };

    EVP_CIPHER_CTX en;
    EVP_CIPHER_CTX_init(&en);
    EVP_EncryptInit_ex(&en, EVP_aes_256_cbc(), NULL, key, iv);

    int update_len, final_len;

    EVP_EncryptUpdate(&en, dst, &update_len, src, (int)SRC_SIZE);

    EVP_EncryptFinal_ex(&en, dst + update_len, &final_len);

    EVP_CIPHER_CTX_cleanup(&en);

    return update_len + final_len;
}

int aes_decrypt(unsigned char *dst, const unsigned char *src, size_t SRC_SIZE) {

    unsigned char key[32] = {
            1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8
    };
    unsigned char iv[32] = {
            1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8
    };

    EVP_CIPHER_CTX de;
    EVP_CIPHER_CTX_init(&de);

    EVP_DecryptInit_ex(&de, EVP_aes_256_cbc(), NULL, key, iv);

    int update_len, final_len;

    EVP_DecryptUpdate(&de, dst, &update_len, src, (int)SRC_SIZE);
    EVP_DecryptFinal_ex(&de, dst + update_len, &final_len);

    EVP_CIPHER_CTX_cleanup(&de);

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
