cmake_minimum_required(VERSION 2.8)
include (ExternalProject)

ExternalProject_Add (tcglib
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/tcg
    PREFIX tcg
    CMAKE_ARGS -DBIG_ENDIAN:BOOL=${TARGET_BIG_ENDIAN}
    INSTALL_COMMAND "")

project (tlib)

option (DEBUG "Debug mode" OFF)

option (HOST_BIG_ENDIAN "Host big endian" OFF)
set (HOST_ARCH "i386" CACHE STRING "Host architecture")
set (HOST_WORD_SIZE "64" CACHE STRING "Host word size")

option (TARGET_BIG_ENDIAN "Target big endian" OFF)
set (TARGET_ARCH "" CACHE STRING "Target architecture")
set (TARGET_WORD_SIZE "32" CACHE STRING "Target word size")

set_property (CACHE HOST_ARCH PROPERTY STRINGS i386 arm)
set_property (CACHE TARGET_ARCH PROPERTY STRINGS i386 arm arm-m sparc ppc)

if(NOT HOST_ARCH)
    message (FATAL_ERROR "Host architecture not set")
endif()

if(NOT TARGET_ARCH)
    message (FATAL_ERROR "Target architecture not set")
endif()

string (TOUPPER "${HOST_ARCH}" HOST_ARCH_U)
string (TOUPPER "${TARGET_ARCH}" TARGET_ARCH_U)

if(TARGET_BIG_ENDIAN)
    add_definitions (
        -DTARGET_WORDS_BIGENDIAN=1)
endif()

if(HOST_WORD_SIZE EQUAL 64)
    add_definitions (-fPIC)
endif()

if(DEBUG)
    add_definitions (-g3)
else()
    add_definitions (-O2)
endif()

add_definitions (-Wall)
add_definitions (-Wextra)
add_definitions (-Wno-unused-parameter)
add_definitions (-Wno-sign-compare)

set (TARGET_ACTUAL_ARCH ${TARGET_ARCH})
if("${TARGET_ARCH}" STREQUAL "arm-m")
    set (TARGET_ACTUAL_ARCH "arm")
endif()
string (TOUPPER "${TARGET_ACTUAL_ARCH}" TARGET_ACTUAL_ARCH_U)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fomit-frame-pointer")
add_definitions (
    -DCONFIG_NEED_MMU
    -DCONFIG_${HOST_ARCH_U}_DIS=1
    -DCONFIG_${TARGET_ACTUAL_ARCH_U}_DIS=1

    -DTCG_TARGET_${HOST_ARCH_U}

    -DHOST_BITS_${HOST_WORD_SIZE}
    -DHOST_${HOST_ARCH_U}=1
    -DHOST_LONG_BITS=${HOST_WORD_SIZE}

    -DTARGET_SHORT_ALIGNMENT=2
    -DTARGET_INT_ALIGNMENT=4
    -DTARGET_LONG_ALIGNMENT=4
    -DTARGET_LLONG_ALIGNMENT=4
    -DTARGET_ARCH=${TARGET_ACTUAL_ARCH}
    -DTARGET_${TARGET_ACTUAL_ARCH_U}=1
    -DTARGET_PHYS_ADDR_BITS=${TARGET_WORD_SIZE})

if("${TARGET_ARCH}" STREQUAL "arm-m")
    add_definitions (-DTARGET_PROTO_ARM_M=1)
endif()

set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fomit-frame-pointer")
if(${HOST_WORD_SIZE} EQUAL 64)
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--wrap=memcpy")
endif()

include_directories (
    tcg
    fpu
    include
    include_empty
    tcg/${HOST_ARCH}
    arch/${TARGET_ACTUAL_ARCH})

file (GLOB SOURCES
    "*.c"
    "fpu/*.c"
    "arch/*.c"
    "external/*.c"
    "arch/${TARGET_ACTUAL_ARCH}/*.c")

add_library (tlib SHARED ${SOURCES})

add_dependencies (tlib tcglib)

target_link_libraries (tlib
    m
    rt
    pthread
    ${CMAKE_CURRENT_BINARY_DIR}/tcg/src/tcglib-build/libtcg.a)


