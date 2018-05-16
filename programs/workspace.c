#include "mem.h"
#include "fse.h"

#include <stdio.h>
#include <stdlib.h>


size_t read_file(BYTE *buffer, size_t BUFFER_SIZE)
{
    FILE *f;
    size_t read_bytes = 0;

    f = fopen("proba.bin", "rb");
    if (f)
        read_bytes = fread(buffer, sizeof(BYTE), BUFFER_SIZE, f);
    else
        printf("Error when opening the file");

    fclose(f);

    return read_bytes;
}

int main(int argc, char** argv)
{
    // read sample data
    const size_t BUFFER_SIZE = 100000;
    BYTE* buffer = (BYTE*) malloc(BUFFER_SIZE);

    size_t read_bytes = read_file(buffer, BUFFER_SIZE);

    printf("Read %zu\n", read_bytes);

    buffer[0] = 17;
    buffer[1] = 17;
    buffer[2] = 255;

    // compress
    BYTE* compressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t compression_result = FSE_compress(compressed_buffer, BUFFER_SIZE, buffer, read_bytes);

    if (compression_result == 0 || compression_result == 1 || FSE_isError(compression_result))
        printf("Compression error: %zu\n", compression_result);
    else
        printf("Compression OK: %zu/%zu, ratio: %f\n", compression_result, read_bytes, (float)(compression_result)/read_bytes);

    // decompress
    BYTE* decompressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t decompression_result = FSE_decompress(decompressed_buffer, BUFFER_SIZE, compressed_buffer, compression_result);

    if (decompression_result == 0 || decompression_result == 1 || FSE_isError(decompression_result))
        printf("Decompression error: %zu\n", decompression_result);
    else
        printf("Decompression OK: %zu/%zu, ratio: %f\n", decompression_result, read_bytes, (float)(decompression_result)/read_bytes);

    // compare

    int is_ok;

    if (decompression_result == read_bytes)
    {
        int cmp_result = memcmp(buffer, decompressed_buffer, read_bytes);
        is_ok = (cmp_result == 0);
    }
    else
        is_ok = 0;

    if (is_ok)
        puts("Procedure OK");
    else
        puts("!!! FAILURE !!!");

    free(decompressed_buffer);
    free(compressed_buffer);
    free(buffer);
    return 0;
}
