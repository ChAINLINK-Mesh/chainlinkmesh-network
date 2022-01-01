cmake_minimum_required(VERSION 3.12)

project(lib-wgmesh)

set(CMAKE_CXX_STANDARD 20)
include(ExternalProject)

set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR})
set(SRC_DIRECTORY src)
set(HEADER_FILES
        certificates.hpp
        public-protocol.hpp
        scope-exit.hpp
        )
set(SOURCE_FILES
        certificates.cpp
        public-protocol.cpp
        )

list(TRANSFORM HEADER_FILES PREPEND "${SRC_DIRECTORY}/")
list(TRANSFORM SOURCE_FILES PREPEND "${SRC_DIRECTORY}/")

set(BASE_COMPILE_ARGS
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        )

find_program(MAKE_EXECUTABLE
        NAMES gmake mingw32-make make
        NAMES_PER_DIR
        DOC "GNU Make"
        )

SET(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/openssl)
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
set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/openssl)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/poco ${CMAKE_INSTALL_PREFIX}/poco)

add_library(${PROJECT_NAME} SHARED STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_INSTALL_PREFIX}/include PUBLIC ${SRC_DIRECTORY})
target_compile_options(${PROJECT_NAME} PRIVATE ${BASE_COMPILE_ARGS})
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER ${HEADER_FILES})
target_link_directories(${PROJECT_NAME} PUBLIC ${CMAKE_INSTALL_PREFIX}/lib)
target_link_libraries(${PROJECT_NAME} PUBLIC Poco::Net crypto pthread)

# TODO: Replace with proper check for available UBSAN lib.
if (NOT ${CMAKE_CROSSCOMPILING})
    target_compile_options(${PROJECT_NAME} PUBLIC -fsanitize=undefined)
    target_link_options(${PROJECT_NAME} PUBLIC -fsanitize=undefined)
endif ()

install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION ${LIB_WGMESH_INSTALL_LIB_DIR}
        PUBLIC_HEADER DESTINATION ${LIB_WGMESH_INSTALL_LIB_DIR}
        )

# Tests

MACRO(SUBDIRLIST result curdir)
    FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
    SET(dirlist "")
    FOREACH (child ${children})
        IF (IS_DIRECTORY ${curdir}/${child})
            LIST(APPEND dirlist ${child})
        ENDIF ()
    ENDFOREACH ()
    SET(${result} ${dirlist})
ENDMACRO()

SUBDIRLIST(SUBDIRS "${CMAKE_CURRENT_SOURCE_DIR}/tests")

FOREACH (subdir ${SUBDIRS})
    add_executable(${subdir} tests/test_base.cpp tests/${subdir}/test.cpp)
    target_compile_options(${subdir} PRIVATE ${BASE_COMPILE_ARGS})
    target_link_libraries(${subdir} ${PROJECT_NAME})
    add_test(NAME ${subdir}
            COMMAND ${subdir}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}
            )
ENDFOREACH ()