cmake_minimum_required(VERSION 3.12)

project(wgmesh-server)

set(CMAKE_CXX_STANDARD 20)

set(SRC_DIRECTORY src)
set(HEADER_FILES
        server.hpp
        )
set(SOURCE_FILES
        server.cpp
        )

list(TRANSFORM HEADER_FILES PREPEND "${SRC_DIRECTORY}/")
list(TRANSFORM SOURCE_FILES PREPEND "${SRC_DIRECTORY}/")

set(BASE_COMPILE_ARGS
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        )

add_library("lib-${PROJECT_NAME}" STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_include_directories("lib-${PROJECT_NAME}" PUBLIC ${SRC_DIRECTORY})
target_link_libraries("lib-${PROJECT_NAME}" PUBLIC lib-wgmesh)

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
                BUILD_COMMAND ${MAKE_EXECUTABLE} -C "${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}"
                BUILD_ALWAYS true
                INSTALL_COMMAND ""
        )
    add_dependencies(${TEST_NAME}  "${TEST_NAME}_Makefile")
    ENDIF ()
    target_compile_options(${TEST_NAME} PRIVATE ${BASE_COMPILE_ARGS})
    target_link_libraries(${TEST_NAME} "lib-${PROJECT_NAME}")
    add_test(NAME ${TEST_NAME}
            COMMAND ${TEST_NAME}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}
            )
ENDFOREACH ()
