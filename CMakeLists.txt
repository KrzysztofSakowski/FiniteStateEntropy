cmake_minimum_required(VERSION 3.7)
project(fse)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

include_directories(lib/)

find_package(OpenSSL REQUIRED)
include_directories(${OpenSSL_INCLUDE_DIR})

find_package(sodium REQUIRED)
include_directories(${sodium_INCLUDE_DIR})

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
        lib/encryptor.h
        lib/encryptor.c
        lib/encryptor_ctx.h
        lib/file_encryptor.c
        lib/file_encryptor.h
        lib/hist.c
        lib/hist.c
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

add_library(fse ${LIB_SRC})

add_subdirectory(tests)

add_executable(commandline    ${PROGRAM_SRC} programs/commandline.c)
add_executable(fullbench      ${PROGRAM_SRC} programs/fullbench.c)
add_executable(probaGenerator programs/probaGenerator.c)
add_executable(encryptionBenchmark programs/encryptionBenchmark.cpp)

target_link_libraries(commandline         fse ${OPENSSL_LIBRARIES} ${sodium_LIBRARY_RELEASE})
target_link_libraries(fullbench           fse ${OPENSSL_LIBRARIES} ${sodium_LIBRARY_RELEASE})
target_link_libraries(encryptionBenchmark fse ${OPENSSL_LIBRARIES} ${sodium_LIBRARY_RELEASE})
target_link_libraries(probaGenerator)
