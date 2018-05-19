#ifndef FSE_ENCRYPTOR_H
#define FSE_ENCRYPTOR_H

#define FSE_STATIC_LINKING_ONLY
#include "fse.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef FSE_FUNCTION_TYPE ShuffleType;
typedef FSE_DECODE_TYPE UnshuffleType;

void pre_compression_shuffle(ShuffleType* ptr, size_t SIZE);

void pre_decompression_shuffle(UnshuffleType* ptr, size_t SIZE);

void rotate(ShuffleType* first, ShuffleType* middle, ShuffleType* last);

void rotate2(UnshuffleType* first, UnshuffleType* middle, UnshuffleType* last);

#ifdef __cplusplus
}
#endif

#endif //FSE_ENCRYPTOR_H
