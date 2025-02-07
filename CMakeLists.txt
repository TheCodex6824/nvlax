#[[  This file is part of nvlax.

     nvlax is free software: you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
     OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
     LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  #]]

cmake_minimum_required(VERSION 3.28)

project(nvlax CXX)

include(ExternalProject)
include(FetchContent)

option(LIEF_EXAMPLES "" OFF)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)

FetchContent_Declare(LIEF
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG 0.16.3
    EXCLUDE_FROM_ALL
)

FetchContent_Declare(PPK_ASSERT
    GIT_REPOSITORY https://github.com/gpakosz/PPK_ASSERT.git
    GIT_TAG 833b8b7ea49aea540a49f07ad08bf0bae1faac32
    EXCLUDE_FROM_ALL
)

FetchContent_Declare(ZYDIS
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG maintenance/v4
    EXCLUDE_FROM_ALL
)

FetchContent_MakeAvailable(LIEF)
FetchContent_MakeAvailable(PPK_ASSERT)
FetchContent_MakeAvailable(ZYDIS)

# PPK_ASSERT doesn't have builtin cmake support
add_library(ppk_assert STATIC
    ${ppk_assert_SOURCE_DIR}/src/ppk_assert.cpp
    ${ppk_assert_SOURCE_DIR}/src/ppk_assert.h
)
target_include_directories(ppk_assert PUBLIC ${ppk_assert_SOURCE_DIR}/src)

add_executable(nvlax_encode
        src/common.cc
        src/lax_encode.cc
)

add_executable(nvlax_fbc
        src/common.cc
        src/lax_fbc.cc
)

set_property(TARGET nvlax_encode nvlax_fbc PROPERTY CXX_STANDARD 17)
set_property(TARGET nvlax_encode nvlax_fbc PROPERTY CXX_STANDARD_REQUIRED YES)
set_property(TARGET nvlax_encode nvlax_fbc PROPERTY CXX_EXTENSIONS NO)

target_link_libraries(nvlax_encode PRIVATE Zydis LIEF::LIEF ppk_assert)
target_link_libraries(nvlax_fbc PRIVATE Zydis LIEF::LIEF ppk_assert)

install(TARGETS nvlax_encode nvlax_fbc)
