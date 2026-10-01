cmake_minimum_required(VERSION 3.15)
project(IceBreaker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(version SHARED
    src/dllmain.cpp
    src/version.def
)

target_include_directories(version PRIVATE src)
