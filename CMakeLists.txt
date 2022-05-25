cmake_minimum_required(VERSION 3.12)

project(ChainlinkMeshNetwork)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR})
set(LLVM_ENABLE_RTTI ON)

include(CTest)
include(ExternalProject)

find_program(MAKE_EXECUTABLE
    NAMES gmake mingw32-make make
    NAMES_PER_DIR
    DOC "GNU Make"
    )

option(BUILD_SHARED_LIBS "Whether to build dynamically-linked binaries and libraries" ON)

# Add local OpenSSL
set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/openssl)
if (NOT ${BUILD_SHARED_LIBS})
    set(OPENSSL_ADDITIONAL_CONFIG_ARG "no-shared")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "")
endif ()
ExternalProject_Add(OpenSSL SOURCE_DIR ${OPENSSL_DIR}
    PATCH_COMMAND ""
    CONFIGURE_COMMAND cd <SOURCE_DIR> && ./Configure --prefix=${CMAKE_INSTALL_PREFIX} --libdir=lib ${OPENSSL_ADDITIONAL_CONFIG_ARG}
    BUILD_COMMAND ${MAKE_EXECUTABLE} -j${Ncpu} -C <SOURCE_DIR> ${_targ}
    INSTALL_COMMAND ${MAKE_EXECUTABLE} -j${Ncpu} -C <SOURCE_DIR> install
    )

# Add local Poco
set(ENABLE_ACTIVERECORD OFF CACHE BOOL "")
set(ENABLE_ACTIVERECORD_COMPILER OFF CACHE BOOL "")
set(ENABLE_CRYPTO OFF CACHE BOOL "")
set(ENABLE_DATA OFF CACHE BOOL "")
set(ENABLE_DATA_MYSQL OFF CACHE BOOL "")
set(ENABLE_DATA_ODBC OFF CACHE BOOL "")
set(ENABLE_DATA_POSTGRESQL OFF CACHE BOOL "")
set(ENABLE_DATA_SQLITE OFF CACHE BOOL "")
set(ENABLE_JSON OFF CACHE BOOL "")
set(ENABLE_JWT OFF CACHE BOOL "")
set(ENABLE_MONGODB OFF CACHE BOOL "")
set(ENABLE_NETSSL OFF CACHE BOOL "")
set(ENABLE_PAGECOMPILER OFF CACHE BOOL "")
set(ENABLE_PAGECOMPILER_FILE2PAGE OFF CACHE BOOL "")
set(ENABLE_POCODOC OFF CACHE BOOL "")
set(ENABLE_REDIS OFF CACHE BOOL "")
set(ENABLE_TESTS OFF CACHE BOOL "")
set(ENABLE_XML OFF CACHE BOOL "")
set(ENABLE_ZIP OFF CACHE BOOL "")
set(OPENSSL_ROOT_DIR ${OPENSSL_DIR})
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dependencies/poco ${CMAKE_INSTALL_PREFIX}/poco)

# Add local flatbuffers
set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dependencies/flatbuffers ${CMAKE_INSTALL_PREFIX}/flatbuffers)

# Add local Protodata compiler
set(PROTODATA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/protodata)
ExternalProject_Add(Protodata SOURCE_DIR ${PROTODATA_DIR}
    PATCH_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${MAKE_EXECUTABLE} -j${Ncpu} -C <SOURCE_DIR> ${_targ}
    INSTALL_COMMAND install -m755 <SOURCE_DIR>/pd ${CMAKE_INSTALL_PREFIX}/bin/pd
    )

# Add local WireGuard kernel interface as a linkable library
set(LINUX_WG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/embeddable-wg-library/contrib/embeddable-wg-library)
add_library(linux-wg-interface STATIC "${LINUX_WG_DIR}/wireguard.c")
target_include_directories(linux-wg-interface PUBLIC "${LINUX_WG_DIR}")

# Prevent use of deprecated OpenSSL functions
add_compile_definitions(OPENSSL_NO_DEPRECATED)

enable_testing()
add_subdirectory(lib)
add_subdirectory(server)
