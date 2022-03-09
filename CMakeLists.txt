cmake_minimum_required(VERSION 3.12)

project(WireguardMeshNetwork)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR})

include(CTest)
include(ExternalProject)

find_program(MAKE_EXECUTABLE
    NAMES gmake mingw32-make make
    NAMES_PER_DIR
    DOC "GNU Make"
    )

set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/openssl)
ExternalProject_Add(OpenSSL SOURCE_DIR ${OPENSSL_DIR}
    PATCH_COMMAND ""
    CONFIGURE_COMMAND cd ${OPENSSL_DIR} && ./Configure --prefix=${CMAKE_INSTALL_PREFIX} --libdir=lib
    BUILD_COMMAND ${MAKE_EXECUTABLE} -j${Ncpu} -C ${OPENSSL_DIR} ${_targ}
    INSTALL_COMMAND ${MAKE_EXECUTABLE} -j${Ncpu} -C ${OPENSSL_DIR} install
    )

set(BUILD_SHARED_LIBS NO)
set(ENABLE_ACTIVERECORD OFF)
set(ENABLE_ACTIVERECORD_COMPILER OFF)
set(ENABLE_CRYPTO OFF)
set(ENABLE_DATA OFF)
set(ENABLE_DATA_MYSQL OFF)
set(ENABLE_DATA_ODBC OFF)
set(ENABLE_DATA_POSTGRESQL OFF)
set(ENABLE_DATA_SQLITE OFF)
set(ENABLE_JSON OFF)
set(ENABLE_JWT OFF)
set(ENABLE_MONGODB OFF)
set(ENABLE_NETSSL OFF)
set(ENABLE_PAGECOMPILER OFF)
set(ENABLE_PAGECOMPILER_FILE2PAGE OFF)
set(ENABLE_REDIS OFF)
set(ENABLE_XML OFF)
set(ENABLE_ZIP OFF)
set(OPENSSL_ROOT_DIR ${OPENSSL_DIR})
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dependencies/poco ${CMAKE_INSTALL_PREFIX}/poco)

set(LINUX_WG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/embeddable-wg-library/contrib/embeddable-wg-library)
add_library(linux-wg-interface SHARED STATIC "${LINUX_WG_DIR}/wireguard.c")
target_include_directories(linux-wg-interface PUBLIC "${LINUX_WG_DIR}")

# Prevent use of deprecated OpenSSL functions
add_compile_definitions(OPENSSL_NO_DEPRECATED)

enable_testing()
add_subdirectory(lib)
add_subdirectory(server)
