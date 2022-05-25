cmake_minimum_required(VERSION 3.12)

project(lib-chainlinkmesh)

set(SRC_DIRECTORY src)
set(HEADER_FILES
    certificates.hpp
    clock.hpp
    debug.hpp
    error.hpp
    literals.hpp
    node.hpp
    peers.hpp
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
    peers.cpp
    private-protocol.cpp
    public-protocol.cpp
    types.cpp
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
    -Wno-unused-local-typedefs
    -Wno-unused-parameter
    -Wno-unused-variable
    )

# Add schemas build
set(SCHEMA_DIRECTORY schemas)
file(GLOB SCHEMAS "${SCHEMA_DIRECTORY}/*.fbs")
set(FLATBUFFERS_FLATC_SCHEMA_EXTRA_ARGS "--gen-object-api")
build_flatbuffers("${SCHEMAS}" "" schema_build "" "${CMAKE_INSTALL_PREFIX}/schemas" "" "")
add_library(schema INTERFACE)
get_target_property(SCHEMA_INCLUDE_DIR schema_build GENERATED_INCLUDES_DIR)
target_include_directories(schema INTERFACE ${SCHEMA_INCLUDE_DIR})
target_link_libraries(schema INTERFACE FlatBuffers)
add_dependencies(schema schema_build)

add_library(${PROJECT_NAME} STATIC "${SOURCE_FILES}" "${HEADER_FILES}")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_INSTALL_PREFIX}/include" ${SRC_DIRECTORY})
target_compile_options(${PROJECT_NAME} PRIVATE ${BASE_COMPILE_ARGS})
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${HEADER_FILES}")
target_link_directories(${PROJECT_NAME} PUBLIC ${CMAKE_INSTALL_PREFIX}/lib)
target_link_libraries(${PROJECT_NAME} PUBLIC schema Poco::Net pthread)

if (DEFINED BUILD_SHARED_LIBS AND NOT ${BUILD_SHARED_LIBS})
    target_link_libraries(${PROJECT_NAME} PUBLIC crypto.a)
    message(STATUS "Using static SSL lib")
else ()
    target_link_libraries(${PROJECT_NAME} PUBLIC crypto.so)
    if (DEFINED ${BUILD_SHARED_LIBS})
        set(DEF "ON")
    else ()
        set(DEF "OFF")
    endif ()
    message(STATUS "Using dynamic SSL lib")
endif ()

# TODO: Replace with proper check for available UBSAN lib.
if (NOT ${CMAKE_CROSSCOMPILING})
    target_compile_options(${PROJECT_NAME} PUBLIC -fsanitize=undefined)
    target_link_options(${PROJECT_NAME} PUBLIC -fsanitize=undefined)
endif ()

if (NOT DEFINED LIB_CHAINLINKMESH_INSTALL_LIB_DIR)
    set(LIB_CHAINLINKMESH_INSTALL_LIB_DIR ".")
endif ()

install(TARGETS "${PROJECT_NAME}"
    ARCHIVE DESTINATION "${LIB_CHAINLINKMESH_INSTALL_LIB_DIR}"
    LIBRARY DESTINATION "${LIB_CHAINLINKMESH_INSTALL_LIB_DIR}"
    PUBLIC_HEADER DESTINATION "${LIB_CHAINLINKMESH_INSTALL_LIB_DIR}"
    RUNTIME DESTINATION "${LIB_CHAINLINKMESH_INSTALL_LIB_DIR}"
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
            BUILD_COMMAND ${MAKE_EXECUTABLE} -C "${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}" PATH="${CMAKE_INSTALL_PREFIX}/bin:$ENV{PATH}"
            BUILD_ALWAYS true
            INSTALL_COMMAND ""
        )
        add_dependencies(${subdir} "${subdir}_Makefile")
    ENDIF ()
    target_compile_options(${subdir} PRIVATE ${BASE_COMPILE_ARGS})
    target_link_libraries(${subdir} PRIVATE ${PROJECT_NAME})
    add_test(NAME ${subdir}
        COMMAND ${subdir}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${subdir}
        )
ENDFOREACH ()
