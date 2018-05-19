#include <stdlib.h>
#include "encryptor.h"

static const int SHUFFLE_BLOCK_SIZE = 8;
const unsigned int SEED = 35256658;

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
    srand(SEED);

    int i, shuffle;

    for (i = 0; i+SHUFFLE_BLOCK_SIZE <= SIZE; i += SHUFFLE_BLOCK_SIZE)
    {
        shuffle = rand() % SHUFFLE_BLOCK_SIZE;
        rotate(ptr+i, ptr+i+shuffle, ptr+i+SHUFFLE_BLOCK_SIZE);
    }

    shuffle = rand() % SIZE;

    rotate(ptr, ptr+shuffle, ptr+SIZE);
}

void pre_decompression_shuffle(UnshuffleType *ptr, const size_t SIZE)
{
    srand(SEED);

    int i, shuffle;

    for (i = 0; i+SHUFFLE_BLOCK_SIZE <= SIZE; i += SHUFFLE_BLOCK_SIZE)
    {
        shuffle = rand() % SHUFFLE_BLOCK_SIZE;
        rotate2(ptr+i, ptr+i+shuffle, ptr+i+SHUFFLE_BLOCK_SIZE);
    }

    shuffle = rand() % SIZE;

    rotate2(ptr, ptr+shuffle, ptr+SIZE);
}
