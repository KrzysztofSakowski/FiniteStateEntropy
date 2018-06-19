#include "gtest/gtest.h"

#include <encryptor.h>

#include <algorithm>
#include <vector>

const static int SHUFFLE_STEP = 7;

TEST(EncryptorHelper, BitRotate)
{
    std::vector<ShuffleType> data = {
            0, 1, 2, 3, 4, 5, 6, 7
    };

    auto data2 = data;

    bit_rotate_64(reinterpret_cast<uint64_t *>(data.data()), SHUFFLE_STEP);

    std::rotate(data2.begin(), data2.begin() + SHUFFLE_STEP, data2.end());

    ASSERT_EQ(data, data2);
}

TEST(EncryptorHelper, Shuffle)
{
    std::vector<ShuffleType> data = {
            0, 1, 2, 3, 4, 5, 6, 7
    };

    auto data2 = data;

    rotate(data.data(), data.data() + SHUFFLE_STEP, data.data() + data.size());

    std::rotate(data2.begin(), data2.begin() + SHUFFLE_STEP, data2.end());

    ASSERT_EQ(data, data2);
}

TEST(EncryptorHelper, Unshuffle)
{
    std::vector<UnshuffleType> data = {
            {0, 0, 0},
            {1, 1, 1},
            {2, 2, 2},
            {3, 3, 3},
            {4, 4, 4},
            {5, 5, 5},
            {6, 6, 6},
            {7, 7, 7}
    };

    auto data2 = data;

    rotate2(data.data(), data.data() + SHUFFLE_STEP, data.data() + data.size());

    std::rotate(data2.begin(), data2.begin() + SHUFFLE_STEP, data2.end());

    for (size_t i = 0; i < data.size(); ++i)
    {
        const auto &s1 = data[i];
        const auto &s2 = data2[i];

        ASSERT_EQ(s1.nbBits, s2.nbBits);
        ASSERT_EQ(s1.newState, s2.newState);
        ASSERT_EQ(s1.symbol, s2.symbol);
    }
}
