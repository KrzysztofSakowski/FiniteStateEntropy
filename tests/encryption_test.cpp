#include "gtest/gtest.h"

#include "helper.h"

#include <encryptor.h>

#include <algorithm>
#include <climits>
#include <vector>


class EncryptorTest : public ::testing::TestWithParam<const char*> {
public:
    static const char* FILE_70;
    static const char* FILE_30;

protected:
    const unsigned char KEY[32] = {
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8
    };

    const unsigned char IV[16] = {
            1, 6, 3, 4, 7, 6, 7, 8, 1, 3, 5, 4, 5, 6, 7, 8
    };
};

const char* EncryptorTest::FILE_70 = "proba_70.bin";
const char* EncryptorTest::FILE_30 = "proba_30.bin";

INSTANTIATE_TEST_CASE_P(DifferentBinaryFiles, EncryptorTest,
                        ::testing::ValuesIn({EncryptorTest::FILE_70, EncryptorTest::FILE_30}));

TEST_P(EncryptorTest, EncryptSingleBlockNull)
{
    const char* FILE_NAME = GetParam();

    // read sample data
    const size_t BUFFER_SIZE = 100000;
    BYTE* buffer = (BYTE*) malloc(BUFFER_SIZE);

    size_t read_bytes = read_file(buffer, BUFFER_SIZE, FILE_NAME);
    ASSERT_TRUE(read_bytes > 0);

    // compress
    BYTE* compressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t compression_result = FSE_compress(compressed_buffer, BUFFER_SIZE, buffer, read_bytes, NULL);

    ASSERT_TRUE(is_operation_successful(compression_result));

    // decompress
    BYTE* decompressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t decompression_result = FSE_decompress(decompressed_buffer, BUFFER_SIZE, compressed_buffer, compression_result, NULL);

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

    free(decompressed_buffer);
    free(compressed_buffer);
    free(buffer);
}

TEST_P(EncryptorTest, EncryptSingleBlock)
{
    const char* FILE_NAME = GetParam();

    // read sample data
    const size_t BUFFER_SIZE = 100000;
    BYTE* buffer = (BYTE*) malloc(BUFFER_SIZE);

    size_t read_bytes = read_file(buffer, BUFFER_SIZE, FILE_NAME);
    ASSERT_TRUE(read_bytes > 0);

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

TEST_P(EncryptorTest, EncryptManyBlocks)
{
    const char* FILE_NAME = GetParam();

    const size_t BUFFER_SIZE = 100000;

    // get data
    BYTE* buffer = (BYTE*) malloc(BUFFER_SIZE);

    size_t read_bytes = read_file(buffer, BUFFER_SIZE, FILE_NAME);
    ASSERT_TRUE(read_bytes > 0);

    // compress
    BYTE* compressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t compression_result = compress_with_blocks(compressed_buffer, BUFFER_SIZE, buffer, BUFFER_SIZE, KEY, 32, IV);

    ASSERT_TRUE(is_operation_successful(compression_result));

    // decompress
    BYTE* decompress_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t decompression_result = decompress_with_blocks(decompress_buffer, BUFFER_SIZE,
                                                         compressed_buffer, compression_result, KEY, 32, IV);

    ASSERT_TRUE(is_operation_successful(decompression_result));

    // compare
    {
        int is_ok;

        ASSERT_EQ(decompression_result, read_bytes);

        if (decompression_result == read_bytes)
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

TEST_P(EncryptorTest, CustomKey)
{
    const char* FILE_NAME = GetParam();

    const size_t BUFFER_SIZE = 100000;
    const unsigned char CUSTOM_KEY[] = {43, 23, 123, 33, 40, 4};

    // get data
    BYTE* buffer = (BYTE*) malloc(BUFFER_SIZE);

    size_t read_bytes = read_file(buffer, BUFFER_SIZE, FILE_NAME);
    ASSERT_TRUE(read_bytes > 0);

    // compress
    BYTE* compressed_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t compression_result = compress_with_blocks(compressed_buffer, BUFFER_SIZE, buffer, BUFFER_SIZE, CUSTOM_KEY, 6, IV);

    ASSERT_TRUE(is_operation_successful(compression_result));

    // decompress
    BYTE* decompress_buffer = (BYTE*) malloc(BUFFER_SIZE);
    size_t decompression_result = decompress_with_blocks(decompress_buffer, BUFFER_SIZE, compressed_buffer,
                                                         compression_result, CUSTOM_KEY, 6, IV);

    ASSERT_TRUE(is_operation_successful(decompression_result));

    // compare
    {
        int is_ok;

        ASSERT_EQ(decompression_result, read_bytes);

        if (decompression_result == read_bytes)
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
