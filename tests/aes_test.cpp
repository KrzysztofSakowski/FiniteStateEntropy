#include "gtest/gtest.h"

#include <encryptor.h>

#include <openssl/aes.h>

#include <algorithm>


TEST(AESTest, Encrypt)
{
    const char *data = "3fasf34sv4afg4g3bhmjymd5vhtst";
    const size_t SIZE = strlen(data);
    auto encrypted_data = (char*)malloc(SIZE + AES_BLOCK_SIZE);

    for (size_t i = 0; i <SIZE; ++i)
        encrypted_data[i] = 0;

    auto result = aes_encrypt((unsigned char*)encrypted_data, (const unsigned char*)data, SIZE);

    ASSERT_TRUE(std::any_of(encrypted_data, encrypted_data+SIZE, [](char c) {
        return c != 0;
    }));

    auto decrypted_data = (char*)malloc(SIZE);

    aes_decrypt((unsigned char*)decrypted_data, (unsigned char*)encrypted_data, result);

    ASSERT_EQ(0, memcmp(data, decrypted_data, SIZE));

    free(decrypted_data);
    free(encrypted_data);
}

TEST(Seed, CalcSHA)
{
    const char *key_data = "3fasf34sv4afg4g3bhmjymd5vhtst";
    size_t KEY_SIZE = strlen(key_data);
    const char *salt = "3asd23dad2";
    size_t SALT_SIZE = strlen(salt);

    std::unique_ptr<unsigned char[]> out_sha = std::make_unique<unsigned char[]>(32);

    for (size_t i = 0; i <32; ++i)
        out_sha[i] = 0;

    auto result = calc_seed((const unsigned char*)key_data, KEY_SIZE, (const unsigned char*)salt, SALT_SIZE, 0, out_sha.get());

    ASSERT_TRUE(std::any_of(out_sha.get(), out_sha.get()+32, [](char c) {
        return c != 0;
    }));

    ASSERT_EQ(1, result);
}
