#include "encryptor.h"

static const int SHUFFLE_BLOCK_SIZE = 8; // required to be even
static const int MAGIC_SIZE = 4;


void pre_compression_shuffle(FSE_FUNCTION_TYPE* ptr, const unsigned SIZE)
{
    int i;

    unsigned char buffer[sizeof(FSE_FUNCTION_TYPE) * SHUFFLE_BLOCK_SIZE];

    for (i = 0; i+SHUFFLE_BLOCK_SIZE <= SIZE; i += SHUFFLE_BLOCK_SIZE)
    {
        int shuffle = MAGIC_SIZE;
        shuffle %= SHUFFLE_BLOCK_SIZE;

        memcpy(buffer, ptr+i+SHUFFLE_BLOCK_SIZE-shuffle, shuffle * sizeof(FSE_FUNCTION_TYPE));
        memmove(ptr+i+shuffle, ptr+i, (SHUFFLE_BLOCK_SIZE-shuffle) * sizeof(FSE_FUNCTION_TYPE));
        memcpy(ptr+i, buffer, shuffle * sizeof(FSE_FUNCTION_TYPE));
    }
}

void pre_decompression_shuffle(FSE_decode_t *ptr, unsigned SIZE)
{
    int i;

    FSE_decode_t buffer[SHUFFLE_BLOCK_SIZE];

    for (i = 0; i+SHUFFLE_BLOCK_SIZE <= SIZE; i += SHUFFLE_BLOCK_SIZE)
    {
        int shuffle = MAGIC_SIZE;
        shuffle %= SHUFFLE_BLOCK_SIZE;

        memcpy(buffer, ptr+i+shuffle, shuffle * sizeof(FSE_decode_t));
        memmove(ptr+i+shuffle, ptr+i, (SHUFFLE_BLOCK_SIZE-shuffle) * sizeof(FSE_decode_t));
        memcpy(ptr+i, buffer, shuffle * sizeof(FSE_decode_t));
    }
}
