#ifndef FSE_FILE_ENCRYPTOR_H
#define FSE_FILE_ENCRYPTOR_H

#include "encryptor.h"

#ifdef __cplusplus
extern "C" {
#endif

int compress_file(const char *in_file_path, const char *out_file_path, const unsigned char *KEY, size_t KEY_DATA_SIZE,
                  const unsigned char *SALT, uint32_t BLOCK_SIZE);

int decompress_file(const char *in_file_path, const char *out_file_path, const unsigned char *KEY,
                    size_t KEY_DATA_SIZE, const unsigned char *SALT);

#ifdef __cplusplus
}
#endif

#endif //FSE_FILE_ENCRYPTOR_H
