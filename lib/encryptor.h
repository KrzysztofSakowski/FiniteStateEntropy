#ifndef FSE_ENCRYPTOR_H
#define FSE_ENCRYPTOR_H

#include "fse.h"

#ifdef __cplusplus
extern "C"{
#endif


void pre_compression_shuffle(FSE_FUNCTION_TYPE* ptr, unsigned SIZE);

void pre_decompression_shuffle(FSE_decode_t* ptr, unsigned SIZE);

#ifdef __cplusplus
}
#endif

#endif //FSE_ENCRYPTOR_H
