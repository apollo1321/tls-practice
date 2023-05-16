cmake_minimum_required(VERSION 3.24)
project(tls-practice)

set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

# For clangd to work
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})

find_package(OpenSSL REQUIRED)
find_package(CLI11 REQUIRED)
find_package(fmt REQUIRED)

add_executable(https_client main.cpp)
target_link_libraries(https_client CLI11::CLI11 OpenSSL::SSL fmt::fmt)
install(TARGETS https_client)
