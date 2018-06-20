#include "helpers.h"

#include <cstdio>

size_t read_file(unsigned char* buffer, size_t BUFFER_SIZE, const char* FILE_NAME)
{
    FILE *f;
    size_t read_bytes = 0;

    f = fopen(FILE_NAME, "rb");
    if (f)
        read_bytes = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, f);
    else
    {
        printf("Error when opening the file: %s\n", FILE_NAME);
        return 0;
    }

    fclose(f);

    return read_bytes;
}
