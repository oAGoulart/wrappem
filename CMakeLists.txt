# WrappEm CMake building file
cmake_minimum_required(VERSION 3.10)

project(wrappem VERSION 0.1.0 LANGUAGES C CXX)

add_executable(wrappem wrappem.cpp)
target_include_directories(wrappem PUBLIC ./..)
