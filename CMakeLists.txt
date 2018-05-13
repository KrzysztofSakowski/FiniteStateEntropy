cmake_minimum_required(VERSION 3.7)
project(fse)

include_directories(lib/)

find_package(OpenSSL REQUIRED)
include_directories(${OpenSSL_INCLUDE_DIR})

set(LIB_SRC
        lib/fse_decompress.c
        lib/entropy_common.c
        lib/huf_compress.c
        lib/huf_decompress.c
        lib/fseU16.c
        lib/fse_compress.c
        lib/fseU16.h
        lib/bitstream.h
        lib/huf.h
        lib/fse.h
        lib/mem.h
        lib/error_private.h
        lib/error_public.h
        )

set(PROGRAM_SRC
        programs/zlibh.c
        programs/zlibh.h
        programs/xxhash.c
        programs/xxhash.h
        programs/bench.c
        programs/bench.h
        programs/fileio.c
        programs/fileio.h
        )

add_executable(commandline    ${LIB_SRC} ${PROGRAM_SRC} programs/commandline.c)
add_executable(fullbench      ${LIB_SRC} ${PROGRAM_SRC} programs/fullbench.c)
add_executable(probaGenerator ${LIB_SRC} ${PROGRAM_SRC} programs/probaGenerator.c)
add_executable(aes_test       ${LIB_SRC} ${PROGRAM_SRC} programs/aes_test.c)
add_executable(workspace      ${LIB_SRC} ${PROGRAM_SRC} programs/workspace.c)

target_link_libraries(aes_test ${OPENSSL_LIBRARIES})
