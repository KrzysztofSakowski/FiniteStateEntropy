#include "gtest/gtest.h"

#include <fse.h>
#include <encryptor.h>

#include <vector>
#include <algorithm>


class EncryptorTest : public testing::Test {
protected:
    const static int SHUFFLE_STEP = 7;
};

TEST_F(EncryptorTest, Shuffle)
{
    std::vector<ShuffleType> data = {
      0, 1, 2, 3, 4, 5, 6, 7
    };

    auto data2 = data;

    rotate(data.data(), data.data()+SHUFFLE_STEP,  data.data()+data.size());

    std::rotate(data2.begin(), data2.begin()+SHUFFLE_STEP, data2.end());

    ASSERT_EQ(data, data2);
}

TEST_F(EncryptorTest, Unshuffle)
{
    std::vector<FSE_DECODE_TYPE> data = {
            {0, 0, 0}, {1, 1, 1}, {2, 2, 2}, {3, 3, 3}, {4, 4, 4}, {5, 5, 5}, {6, 6, 6}, {7, 7, 7}
    };

    auto data2 = data;

    rotate2(data.data(), data.data()+SHUFFLE_STEP,  data.data()+data.size());

    std::rotate(data2.begin(), data2.begin()+SHUFFLE_STEP, data2.end());

    for (size_t i = 0; i < data.size(); ++i)
    {
        const auto& s1 = data[i];
        const auto& s2 = data2[i];

        ASSERT_EQ(s1.nbBits, s2.nbBits);
        ASSERT_EQ(s1.newState, s2.newState);
        ASSERT_EQ(s1.symbol, s2.symbol);
    }
}

size_t read_file(BYTE* buffer, size_t BUFFER_SIZE)
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

TEST(Integration, IO)
{
    // read sample data
    const size_t BUFFER_SIZE = 100000;
    BYTE* buffer = (BYTE*) malloc(BUFFER_SIZE);

    size_t read_bytes = read_file(buffer, BUFFER_SIZE);

    printf("Read %zu\n", read_bytes);

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

    ASSERT_TRUE(is_ok);

    free(decompressed_buffer);
    free(compressed_buffer);
    free(buffer);
}

