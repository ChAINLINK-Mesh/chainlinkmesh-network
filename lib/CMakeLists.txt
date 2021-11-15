cmake_minimum_required(VERSION 3.12)

project(lib-wgmesh)

set(CMAKE_CXX_STANDARD 20)
include(ExternalProject)

set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR})
set(SRC_DIRECTORY src)

set(HEADER_FILES
	certificates.hpp
)

set(SOURCE_FILES
	certificates.cpp
)

list(TRANSFORM SOURCE_FILES PREPEND "${SRC_DIRECTORY}/")

ExternalProject_Add(LibreSSL SOURCE_DIR ${CMAKE_INSTALL_PREFIX}/../dependencies/libressl
	PATCH_COMMAND "./autogen.sh"
	CMAKE_ARGS
		-DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
)
add_library(lib-wgmesh SHARED STATIC ${SOURCE_FILES})
target_include_directories(lib-wgmesh PRIVATE ${CMAKE_INSTALL_PREFIX}/include)
target_compile_options(lib-wgmesh PRIVATE -Wall -Wextra -Wpedantic -Werror)

# TODO: Replace with proper check for available UBSAN lib.
if (NOT ${CMAKE_CROSSCOMPILING})
	target_compile_options(lib-wgmesh PRIVATE -fsanitize=undefined)
endif()

install(TARGETS lib-wgmesh
	LIBRARY DESTINATION ${LIB_WGMESH_INSTALL_LIB_DIR}
	PUBLIC_HEADER DESTINATION ${LIB_WGMESH_INSTALL_LIB_DIR}
)