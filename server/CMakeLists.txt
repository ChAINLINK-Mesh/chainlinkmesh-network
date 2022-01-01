cmake_minimum_required(VERSION 3.12)

project(wgmesh-server)

set(CMAKE_CXX_STANDARD 20)

set(SRC_DIRECTORY src)
set(HEADER_FILES
        server.hpp
        )
set(SOURCE_FILES
        server.cpp
        main.cpp
        )

list(TRANSFORM HEADER_FILES PREPEND "${SRC_DIRECTORY}/")
list(TRANSFORM SOURCE_FILES PREPEND "${SRC_DIRECTORY}/")

set(BASE_COMPILE_ARGS
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        )

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} PUBLIC lib-wgmesh)