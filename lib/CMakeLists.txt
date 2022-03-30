cmake_minimum_required(VERSION 3.12)

project(lib-wgmesh)

set(SRC_DIRECTORY src)
set(HEADER_FILES
    certificates.hpp
    clock.hpp
    literals.hpp
    node.hpp
    private-protocol.hpp
    public-protocol.hpp
    types.hpp
    utilities.hpp
    wireguard.hpp
    )
set(SOURCE_FILES
    certificates.cpp
    clock.cpp
    literals.cpp
    node.cpp
    public-protocol.cpp
    utilities.cpp
    wireguard.cpp
    )

list(TRANSFORM HEADER_FILES PREPEND "${SRC_DIRECTORY}/")
list(TRANSFORM SOURCE_FILES PREPEND "${SRC_DIRECTORY}/")

set(BASE_COMPILE_ARGS
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    )

add_library(${PROJECT_NAME} STATIC "${SOURCE_FILES}" "${HEADER_FILES}")
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_INSTALL_PREFIX}/include ${SRC_DIRECTORY})
target_compile_options(${PROJECT_NAME} PRIVATE ${BASE_COMPILE_ARGS})
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${HEADER_FILES}")
target_link_directories(${PROJECT_NAME} PUBLIC ${CMAKE_INSTALL_PREFIX}/lib)
target_link_libraries(${PROJECT_NAME} PUBLIC Poco::Net pthread)

if (DEFINED ${BUILD_SHARED_LIBS} AND NOT ${BUILD_SHARED_LIBS})
    target_link_libraries(${PROJECT_NAME} PUBLIC crypto.a)
else ()
    target_link_libraries(${PROJECT_NAME} PUBLIC crypto.so)
endif ()

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
    target_include_directories(${subdir} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    IF (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}/Makefile")
        ExternalProject_Add(
            "${subdir}_Makefile" SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}"
            PATCH_COMMAND ""
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ${MAKE_EXECUTABLE} -C "${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}"
            BUILD_ALWAYS true
            INSTALL_COMMAND ""
        )
        add_dependencies(${subdir} "${subdir}_Makefile")
    ENDIF ()
    target_compile_options(${subdir} PRIVATE ${BASE_COMPILE_ARGS})
    target_link_libraries(${subdir} ${PROJECT_NAME})
    add_test(NAME ${subdir}
        COMMAND ${subdir}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}
        )
ENDFOREACH ()
