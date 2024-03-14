cmake_minimum_required(VERSION 3.16)

project(pinch-example VERSION 1.0.0)

find_package(pinch REQUIRED)

add_executable(pinch-example example-1.cpp)
target_link_libraries(pinch-example pinch::pinch)
