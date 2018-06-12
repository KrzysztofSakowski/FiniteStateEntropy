#include "gtest/gtest.h"

#include <vector>
#include <algorithm>

#include <fse.h>
#include <encryptor.h>
#include <encryptor_ctx.h>


class EncryptorTest : public testing::Test {
protected:
    const static int SHUFFLE_STEP = 7;

    void SetUp() override
    {
        const char *key_data = "abcd";
        const char *salt = "abcdefghabcdefgh";

        int result = calc_seed((const unsigned char*)key_data, strlen(key_data), (const unsigned char*)salt, strlen(salt), 0, seed);

        ASSERT_EQ(1, result);
    }

    const unsigned char KEY[32] = {
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8
    };

    const unsigned char IV[16] = {
            1, 6, 3, 4, 7, 6, 7, 8, 1, 3, 5, 4, 5, 6, 7, 8
    };

    unsigned char seed[32];

    size_t decompression_helper(void* dst, size_t dstCapacity, const void* src, size_t srcSize, uint32_t block_id)
    {
        EncryptionCtx ctx;

        init_ctx(&ctx, block_id, KEY, 32, IV, 16);

        size_t decompression_result = FSE_decompress(dst, dstCapacity, src, srcSize, &ctx);

        bool decompressionFailed = decompression_result == 0 || decompression_result == 1 || FSE_isError(decompression_result);

        deinit_ctx(&ctx);

        return decompression_result;
    }
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
    std::vector<UnshuffleType> data = {
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

TEST_F(EncryptorTest, EncryptSingleBlock)
{
    // read sample data
    const size_t BUFFER_SIZE = 100000;
    BYTE* buffer = (BYTE*) malloc(BUFFER_SIZE);

    size_t read_bytes = read_file(buffer, BUFFER_SIZE);

    EncryptionCtx ctx;

    init_ctx(&ctx, 0, KEY, 32, IV, 16);

    // compress
    BYTE* compressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t compression_result = FSE_compress(compressed_buffer, BUFFER_SIZE, buffer, read_bytes, &ctx);

    ASSERT_TRUE(is_operation_successful(compression_result));

    // decompress
    BYTE* decompressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t decompression_result = FSE_decompress(decompressed_buffer, BUFFER_SIZE, compressed_buffer, compression_result, &ctx);

    ASSERT_TRUE(is_operation_successful(decompression_result));

    // compare
    {
        int is_ok;

        if (decompression_result == read_bytes)
        {
            int cmp_result = memcmp(buffer, decompressed_buffer, read_bytes);
            is_ok = (cmp_result == 0);
        }
        else
            is_ok = 0;

        ASSERT_TRUE(is_ok);
    }

    deinit_ctx(&ctx);

    free(decompressed_buffer);
    free(compressed_buffer);
    free(buffer);
}

TEST_F(EncryptorTest, EncryptManyBlocks)
{
    const size_t BUFFER_SIZE = 100000;

    // get data
    BYTE* buffer = (BYTE*) malloc(BUFFER_SIZE);

    size_t read_bytes = read_file(buffer, BUFFER_SIZE);

    // compress
    BYTE* compressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t compression_result = compress_with_blocks(compressed_buffer, BUFFER_SIZE, buffer, BUFFER_SIZE, KEY, IV);

    ASSERT_TRUE(is_operation_successful(compression_result));

    // decompress
    uint32_t compressed_block_count = ((uint32_t*)compressed_buffer)[0];
    ASSERT_EQ(compressed_block_count, 3);

    size_t compressed_offset = sizeof(uint32_t) + (compressed_block_count-1) * sizeof(uint16_t);
    size_t decompressed_offset = 0;
    BYTE* decompress_buffer = (BYTE*) malloc(BUFFER_SIZE);

    for (uint32_t block_id = 0; block_id+1 < compressed_block_count; ++block_id)
    {
        auto current_block_compressed_size = ((uint16_t*)compressed_buffer)[block_id+2];

        size_t decompression_result = decompression_helper(decompress_buffer + decompressed_offset, BUFFER_SIZE - decompressed_offset,
                                                           compressed_buffer + compressed_offset, current_block_compressed_size, block_id);

        compressed_offset += current_block_compressed_size;
        decompressed_offset += decompression_result;
    }

    {
        size_t decompression_result = decompression_helper(decompress_buffer + decompressed_offset,
                                                           BUFFER_SIZE - decompressed_offset,
                                                           compressed_buffer + compressed_offset,
                                                           compression_result - compressed_offset,
                                                           compressed_block_count - 1);

        decompressed_offset += decompression_result;
    }

    // compare
    {
        int is_ok;

        ASSERT_EQ(decompressed_offset, read_bytes);

        if (decompressed_offset == read_bytes)
        {
            int cmp_result = memcmp(buffer, decompress_buffer, read_bytes);
            is_ok = (cmp_result == 0);
        }
        else
            is_ok = 0;

        ASSERT_TRUE(is_ok);
    }

    // clean up
    free(buffer);
    free(compressed_buffer);
    free(decompress_buffer);
}
