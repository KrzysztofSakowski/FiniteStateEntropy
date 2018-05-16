#include "gtest/gtest.h"

#include <encryptor.h>


TEST(Shuffle, Shuffle)
{
    unsigned char data[] = {
      0, 1, 2, 3, 4, 5, 6, 7
    };

    pre_compression_shuffle(data, 8);

    ASSERT_EQ(data[0], 4);
    ASSERT_EQ(data[7], 3);
}


TEST(Shuffle, Shuffle2)
{
    FSE_decode_t data[] = {
            {0, 0, 0}, {1, 1, 1}, {2, 2, 2}, {3, 3, 3}, {4, 4, 4}, {5, 5, 5}, {6, 6, 6}, {7, 7, 7}
    };

    pre_decompression_shuffle(data, 8);

    ASSERT_EQ(data[0].newState, 4);
    ASSERT_EQ(data[7].newState, 3);
}

