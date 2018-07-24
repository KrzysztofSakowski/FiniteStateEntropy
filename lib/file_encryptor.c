#include "file_encryptor.h"

#include <stdio.h>
#include <stdlib.h>

long fileSize(FILE *fp)
{
    fseek(fp, 0, SEEK_END);
    long bytes = ftell(fp);
    rewind(fp);
    return bytes;
}

int compress_file(const char *in_file_path, const char *out_file_path, const unsigned char *KEY, size_t KEY_DATA_SIZE,
                  const unsigned char *SALT)
{
    FILE* in_file = fopen(in_file_path, "rb");
    if (!in_file)
    {
        printf("Error when opening the file: %s\n", in_file_path);
        return -1;
    }

    const size_t in_file_size = (size_t)fileSize(in_file);

    // read sample data
    BYTE* buffer = (BYTE*) malloc(in_file_size);
    size_t read_bytes = fread(buffer, sizeof(unsigned char), in_file_size, in_file);

    fclose(in_file);

    // compress
    BYTE* compressed_data = (BYTE*) malloc(in_file_size);

    size_t compressed_data_size = compress_with_blocks(compressed_data, in_file_size, buffer, read_bytes, KEY,
                                                       KEY_DATA_SIZE, SALT);

    free(buffer);

    // save to file
    FILE* out_file = fopen(out_file_path, "wb");
    if (!out_file)
    {
        printf("Error when opening the file: %s\n", out_file_path);
        free(compressed_data);
        return -1;
    }

    uint64_t decompressed_data_size_serialize = (uint64_t)read_bytes;
    // write size
    fwrite(&decompressed_data_size_serialize, sizeof(decompressed_data_size_serialize), 1, out_file);
    // write data
    fwrite(compressed_data, sizeof(unsigned char), compressed_data_size, out_file);

    fclose(out_file);
    free(compressed_data);

    return 0;
}

int decompress_file(const char *in_file_path, const char *out_file_path, const unsigned char *KEY, size_t KEY_DATA_SIZE,
                    const unsigned char *SALT)
{
    FILE* in_file = fopen(in_file_path, "rb");
    if (!in_file)
    {
        printf("Error when opening the file: %s\n", in_file_path);
        return -1;
    }

    const size_t in_file_size = (size_t)fileSize(in_file);

    // read compressed data
    uint64_t decompressed_data_size_serialize;
    BYTE* compressed_data = (BYTE*) malloc(in_file_size);

    // read size
    fread(&decompressed_data_size_serialize, sizeof(decompressed_data_size_serialize), 1, in_file);
    // read data
    fread(compressed_data, sizeof(unsigned char), in_file_size, in_file);
    fclose(in_file);

    // decompress
    BYTE* decompressed_data = (BYTE*) malloc(decompressed_data_size_serialize);

    size_t decompressed_data_size = decompress_with_blocks(decompressed_data, decompressed_data_size_serialize,
                                                           compressed_data, in_file_size, KEY, KEY_DATA_SIZE, SALT);

    // save to file
    FILE* out_file = fopen(out_file_path, "wb");
    if (!out_file)
    {
        printf("Error when opening the file: %s\n", out_file_path);
        free(decompressed_data);
        return -1;
    }

    fwrite(decompressed_data, sizeof(unsigned char), decompressed_data_size, out_file);

    fclose(out_file);
    free(decompressed_data);

    return 0;
}
