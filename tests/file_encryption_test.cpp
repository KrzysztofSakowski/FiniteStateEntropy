#include "gtest/gtest.h"

#include "file_encryptor.h"

#include "helpers.h"

class FileEncryptorTest : public ::testing::TestWithParam<const char *>
{
public:
    static const char *FILE_70;
    static const char *FILE_30;
    static const size_t BUFFER_SIZE = 2'000'000; // 2MB
    static constexpr unsigned char IV[16] =
    {
            1, 6, 3, 4, 7, 6, 7, 8, 1, 3, 5, 4, 5, 6, 7, 8
    };
};

const char *FileEncryptorTest::FILE_70 = "proba_70.bin";
const char *FileEncryptorTest::FILE_30 = "proba_30.bin";

INSTANTIATE_TEST_CASE_P(DifferentBinaryFiles, FileEncryptorTest,
                        ::testing::ValuesIn({FileEncryptorTest::FILE_70, FileEncryptorTest::FILE_30}));

TEST_P(FileEncryptorTest, WithoutEncryption)
{
    const char *IN_FILE = GetParam();
    const char *COMPRESSED_FILE = "compressed.bin";
    const char *OUT_FILE = "out.bin";

    compress_file(IN_FILE, COMPRESSED_FILE, NULL, 0, NULL);

    decompress_file(COMPRESSED_FILE, OUT_FILE, NULL, 0, NULL);

    // verify
    BYTE *in_buffer = (BYTE *) malloc(BUFFER_SIZE);
    BYTE *out_buffer = (BYTE *) malloc(BUFFER_SIZE);

    const size_t in_bytes = read_file(in_buffer, BUFFER_SIZE, IN_FILE);
    ASSERT_TRUE(in_bytes > 0);

    const size_t out_bytes = read_file(out_buffer, BUFFER_SIZE, OUT_FILE);
    ASSERT_TRUE(out_bytes > 0);

    ASSERT_EQ(in_bytes, out_bytes);
    ASSERT_EQ(memcmp(in_buffer, out_buffer, in_bytes), 0);

    free(in_buffer);
    free(out_buffer);
}

TEST_P(FileEncryptorTest, WithEncryption)
{
    const char *IN_FILE = GetParam();
    const char *COMPRESSED_FILE = "compressed.bin";
    const char *OUT_FILE = "out.bin";
    const unsigned char CUSTOM_KEY[] = {43, 2, 34, 0, 40, 255, 77};

    compress_file(IN_FILE, COMPRESSED_FILE, CUSTOM_KEY, 7, IV);

    decompress_file(COMPRESSED_FILE, OUT_FILE, CUSTOM_KEY, 7, IV);

    // verify
    BYTE *in_buffer = (BYTE *) malloc(BUFFER_SIZE);
    BYTE *out_buffer = (BYTE *) malloc(BUFFER_SIZE);

    const size_t in_bytes = read_file(in_buffer, BUFFER_SIZE, IN_FILE);
    ASSERT_TRUE(in_bytes > 0);

    const size_t out_bytes = read_file(out_buffer, BUFFER_SIZE, OUT_FILE);
    ASSERT_TRUE(out_bytes > 0);

    ASSERT_EQ(in_bytes, out_bytes);
    ASSERT_EQ(memcmp(in_buffer, out_buffer, in_bytes), 0);

    free(in_buffer);
    free(out_buffer);
}
