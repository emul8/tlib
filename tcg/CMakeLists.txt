cmake_minimum_required(VERSION 2.8)

project (tcg)

option (BIG_ENDIAN "Big endian" OFF)
set (HOST_LONG_BITS 0 CACHE INT "Host word size (0 - autodetection)")
set (HOST_ARCHITECTURE "i386" CACHE STRING "Host architecture")
set_property (CACHE HOST_ARCHITECTURE PROPERTY STRINGS i386 arm)
set (TARGET_LONG_BITS 32 CACHE INT "Target word size")

if(HOST_LONG_BITS EQUAL 0)
    # Determine bitness
    # 32 or 64 bits
    set (HOST_LONG_BITS 32 CACHE INT "Host word size (0 - autodetection)" FORCE)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set (HOST_LONG_BITS 64 CACHE INT "Host word size (0 - autodetection)" FORCE)
    endif()
endif()

string (TOUPPER ${HOST_ARCHITECTURE} HOST_UPPER)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fomit-frame-pointer")
if(HOST_LONG_BITS EQUAL 64)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif()

if(BIG_ENDIAN)
    add_definitions (-DTARGET_WORDS_BIGENDIAN)
endif()

add_definitions (
    -DTCG_STANDALONE
    -DCONFIG_NEED_MMU
    -DCONFIG_SOFTMMU
    -DNEED_CPU_H
    -DTARGET_LONG_BITS=${TARGET_LONG_BITS}
    -DNDEBUG
    -DTCG_TARGET_${HOST_UPPER}
    -DHOST_LONG_BITS=${HOST_LONG_BITS})

include_directories (${HOST_ARCHITECTURE})

add_library (tcg STATIC
    additional.c
    optimize.c
    tcg.c)

