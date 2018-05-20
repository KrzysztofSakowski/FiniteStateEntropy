#include "encryptor.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

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
