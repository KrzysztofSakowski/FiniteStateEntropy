cmake_minimum_required(VERSION 3.7)

set(REPO ${CMAKE_SOURCE_DIR})

project(Test)

include(CTest)
enable_testing()

include(${REPO}/3rd_party/DownloadProject/DownloadProject.cmake)
download_project(
        PROJ                googletest
        GIT_REPOSITORY      https://github.com/google/googletest.git
        GIT_TAG             master
        UPDATE_DISCONNECTED 1
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/data/proba_70.bin ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/data/proba_30.bin ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR} EXCLUDE_FROM_ALL)

set(test_SRCS
        encryption_test.cpp
        aes_test.cpp
        helper_test.cpp
        helpers.h
        helpers.cpp
        )

add_executable(runUnitTests gtest.cpp ${test_SRCS})
target_link_libraries(runUnitTests gtest fse ${OPENSSL_LIBRARIES} ${sodium_LIBRARY_RELEASE})
