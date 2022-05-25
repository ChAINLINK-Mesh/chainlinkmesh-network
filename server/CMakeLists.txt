cmake_minimum_required(VERSION 3.12)

project(chainlinkmesh-server)

set(SRC_DIRECTORY src)
set(HEADER_FILES
    app.hpp
    linux-netlink.hpp
    linux-wireguard-manager.hpp
    server.hpp
    validators.hpp
    )
set(SOURCE_FILES
    app.cpp
    linux-netlink.cpp
    linux-wireguard-manager.cpp
    server.cpp
    validators.cpp
    )

list(TRANSFORM HEADER_FILES PREPEND "${SRC_DIRECTORY}/")
list(TRANSFORM SOURCE_FILES PREPEND "${SRC_DIRECTORY}/")

set(BASE_COMPILE_ARGS
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -Wno-unused-local-typedefs
    -Wno-unused-parameter
    -Wno-unused-variable
    )

set(NL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/libnl)
ExternalProject_Add(LibNL SOURCE_DIR ${NL_DIR}
    PATCH_COMMAND ""
    CONFIGURE_COMMAND cd <SOURCE_DIR> && ./autogen.sh && ./configure --prefix ${CMAKE_INSTALL_PREFIX} --disable-cli
    BUILD_COMMAND ${MAKE_EXECUTABLE} -j${Ncpu} -C <SOURCE_DIR> ${_targ}
    INSTALL_COMMAND ${MAKE_EXECUTABLE} -j${Ncpu} -C <SOURCE_DIR> install
    )

add_library("lib-${PROJECT_NAME}" STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_include_directories("lib-${PROJECT_NAME}" PUBLIC ${SRC_DIRECTORY} "${CMAKE_INSTALL_PREFIX}/include/libnl3")
target_compile_options("lib-${PROJECT_NAME}" PRIVATE ${BASE_COMPILE_ARGS})
target_link_libraries("lib-${PROJECT_NAME}" PUBLIC lib-chainlinkmesh linux-wg-interface Poco::Util)

if (DEFINED ${BUILD_SHARED_LIBS} AND NOT ${BUILD_SHARED_LIBS})
    target_link_libraries("lib-${PROJECT_NAME}" PUBLIC nl-3.a nl-route-3.a)
    message(STATUS "Using static Netlink lib")
else ()
    target_link_libraries("lib-${PROJECT_NAME}" PUBLIC nl-3.so nl-route-3.so)
    if (DEFINED ${BUILD_SHARED_LIBS})
        set(DEF "ON")
    else ()
        set(DEF "OFF")
    endif ()
    message(STATUS "Using dynamic SSL lib")
endif ()

add_executable(${PROJECT_NAME} "src/main.cpp")
target_link_libraries(${PROJECT_NAME} PUBLIC "lib-${PROJECT_NAME}")

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
    SET(TEST_NAME "server_${subdir}")
    add_executable(${TEST_NAME} tests/test_base.cpp tests/${subdir}/test.cpp)
    target_include_directories(${TEST_NAME}  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    IF (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}/Makefile")
        ExternalProject_Add(
            "${TEST_NAME}_Makefile" SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}"
            PATCH_COMMAND ""
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ${MAKE_EXECUTABLE} -C "${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}" PATH="${CMAKE_BINARY_DIR}:$ENV{PATH}"
            BUILD_ALWAYS true
            INSTALL_COMMAND ""
        )
    add_dependencies(${TEST_NAME}  "${TEST_NAME}_Makefile")
    ENDIF ()
    target_compile_options(${TEST_NAME} PRIVATE ${BASE_COMPILE_ARGS})
    target_link_libraries(${TEST_NAME} PRIVATE "lib-${PROJECT_NAME}")
    add_test(NAME ${TEST_NAME}
        COMMAND ${TEST_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}
        )
ENDFOREACH ()
